import os, re, shutil, subprocess, tempfile, base64, urllib.request, asyncio, struct, hashlib, json, time, traceback, binascii, sys
from collections import OrderedDict, defaultdict, deque, namedtuple
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional, Union, Any, Callable
from enum import Enum

try:
    from luaparser import ast as lua_ast
    HAS_LUAPARSER = True
except ImportError:
    HAS_LUAPARSER = False

UNLUAC_JAR_URL = "https://github.com/scratchminer/unluac/releases/download/v2023.03.22/unluac.jar"
UNLUAC_LOCAL_PATH = os.environ.get('UNLUAC_PATH') or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'unluac.jar')

LUA_KEYWORDS = {
    'function', 'local', 'end', 'return', 'if', 'then', 'else', 'elseif',
    'for', 'while', 'do', 'repeat', 'until', 'not', 'and', 'or',
    'nil', 'true', 'false', 'in', 'break', 'print', 'require',
    'pcall', 'xpcall', 'loadstring', 'load', 'pairs', 'ipairs',
    'setmetatable', 'getmetatable', 'rawset', 'rawget', 'tostring', 'tonumber',
    'table', 'string', 'math', 'coroutine', 'debug', 'io', 'os',
    'unpack', 'select', 'type', 'assert', 'error', 'next', 'rawequal',
}

REJECT_SIGNATURES = [
    "class DeobfEngine",
    "_run_lua_harness",
    "LuaASTWalker",
    "def _beautify",
    "import os, re",
    "UNLUAC_JAR_URL",
]

GOOD_PATTERNS = [
    r'game:GetService',
    r'workspace',
    r'Instance\.new',
    r'Vector3',
    r'UDim2',
    r'Enum\.',
    r'Players',
    r'LocalPlayer',
]

BAD_PATTERNS = [
    r'import\s+os',
    r'from\s+collections',
    r'class\s+\w+',
    r'def\s+\w+',
    r'subprocess\.',
]

VM_SIGNALS = [
    r'while true do',
    r'\[\d+\]',
    r'pcall\(function',
    r'bit\.bxor',
    r'string\.byte',
]

LOAD_PATTERNS = [
    "loadstring",
    "load(",
    "assert(load",
    "pcall(load",
]


def _find_balanced_end(content, open_brace_index):
    depth = 0
    quote = None
    in_long_string = False
    long_match = None
    idx = open_brace_index
    while idx < len(content):
        char = content[idx]
        if in_long_string:
            if char == ']' and content[idx:idx+len(long_match)] == long_match:
                in_long_string = False
                idx += len(long_match)
                continue
            idx += 1
            continue
        if quote:
            if char == '\\':
                idx += 2
                continue
            if char == quote:
                quote = None
            idx += 1
            continue
        if char == '[':
            m = re.match(r'\[=*\[', content[idx:])
            if m:
                long_match = ']' + m.group(0)[2:-1] + ']'
                in_long_string = True
                idx += len(m.group(0))
                continue
        if char in ("'", '"'):
            quote = char
        elif char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                return idx + 1
        idx += 1
    return -1


def _find_all_table_bodies(source):
    bodies = []
    idx = 0
    while idx < len(source):
        brace_pos = source.find('{', idx)
        if brace_pos == -1:
            break
        end = _find_balanced_end(source, brace_pos)
        if end != -1:
            bodies.append(source[brace_pos:end])
            idx = end
        else:
            idx = brace_pos + 1
    return bodies


def _parse_table_entries(body):
    inner = body[1:-1]
    entries = []
    depth = 0
    current = ""
    in_str = False
    quote = None
    in_long_str = False
    long_match = None
    i = 0
    while i < len(inner):
        c = inner[i]
        if in_long_str:
            current += c
            if c == ']' and i + len(long_match) <= len(inner) and inner[i:i+len(long_match)] == long_match:
                in_long_str = False
                current += long_match[1:]
                i += len(long_match)
                continue
            i += 1
            continue
        if in_str:
            current += c
            if c == '\\':
                if i + 1 < len(inner):
                    current += inner[i+1]
                    i += 2
                    continue
            elif c == quote:
                in_str = False
            i += 1
            continue
        if c == '[':
            m = re.match(r'\[=*\[', inner[i:])
            if m:
                long_match = ']' + m.group(0)[2:-1] + ']'
                in_long_str = True
                current += m.group(0)
                i += len(m.group(0))
                continue
        if c in ('"', "'"):
            in_str = True
            quote = c
            current += c
            i += 1
            continue
        if c == '{':
            depth += 1
            current += c
            i += 1
            continue
        if c == '}':
            depth -= 1
            current += c
            i += 1
            continue
        if c == ',' and depth == 0:
            entries.append(current.strip())
            current = ""
            i += 1
            continue
        current += c
        i += 1
    if current.strip():
        entries.append(current.strip())
    parsed = []
    for e in entries:
        if not e:
            continue
        if (e.startswith('"') and e.endswith('"')) or (e.startswith("'") and e.endswith("'")):
            parsed.append(e[1:-1])
        elif e.startswith('[[') and e.endswith(']]'):
            parsed.append(e[2:-2])
        elif e.lstrip('-').isdigit():
            parsed.append(int(e))
        elif e.replace('.', '', 1).lstrip('-').isdigit():
            parsed.append(float(e))
        elif e in ('true', 'false', 'nil'):
            parsed.append(e)
        else:
            parsed.append(e)
    return parsed


def _lua_unescape(s):
    result = bytearray()
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            nc = s[i+1]
            if nc == 'n':
                result.append(0x0A)
                i += 2
            elif nc == 'r':
                result.append(0x0D)
                i += 2
            elif nc == 't':
                result.append(0x09)
                i += 2
            elif nc == '\\':
                result.append(0x5C)
                i += 2
            elif nc == '"':
                result.append(0x22)
                i += 2
            elif nc == "'":
                result.append(0x27)
                i += 2
            elif nc == 'a':
                result.append(0x07)
                i += 2
            elif nc == 'b':
                result.append(0x08)
                i += 2
            elif nc == 'f':
                result.append(0x0C)
                i += 2
            elif nc == 'v':
                result.append(0x0B)
                i += 2
            elif nc == 'x' and i + 3 < len(s):
                try:
                    result.append(int(s[i+2:i+4], 16))
                except ValueError:
                    pass
                i += 4
            elif nc.isdigit():
                j = i + 1
                while j < len(s) and s[j].isdigit() and j - (i + 1) < 3:
                    j += 1
                try:
                    val = int(s[i+1:j])
                    if val <= 255:
                        result.append(val)
                except ValueError:
                    pass
                i = j
            else:
                result.append(ord(nc) if ord(nc) < 256 else 0x3F)
                i += 2
        else:
            b = ord(s[i])
            if b <= 0x7F:
                result.append(b)
            elif b <= 0x7FF:
                result.append(0xC0 | (b >> 6))
                result.append(0x80 | (b & 0x3F))
            elif b <= 0xFFFF:
                result.append(0xE0 | (b >> 12))
                result.append(0x80 | ((b >> 6) & 0x3F))
                result.append(0x80 | (b & 0x3F))
            else:
                result.append(0xF0 | (b >> 18))
                result.append(0x80 | ((b >> 12) & 0x3F))
                result.append(0x80 | ((b >> 6) & 0x3F))
                result.append(0x80 | (b & 0x3F))
            i += 1
    return bytes(result)


def _is_self_capture(text):
    if not text:
        return False
    hits = 0
    for sig in REJECT_SIGNATURES:
        if sig in text:
            hits += 1
    return hits >= 2


def _readability_score(code):
    if not code:
        return 0
    score = 0
    keywords = [
        'function', 'local', 'return', 'if', 'then',
        'game', 'workspace', 'Instance', 'Vector3',
        'pairs', 'ipairs', 'for', 'while'
    ]
    for kw in keywords:
        score += code.count(kw) * 2
    identifiers = re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b', code)
    if identifiers:
        avg_ident_len = sum(len(x) for x in identifiers) / len(identifiers)
        if avg_ident_len > 3:
            score += 20
    gibberish = re.findall(r'[A-Za-z0-9]{20,}', code)
    score -= len(gibberish) * 5
    entropy_chars = len(set(code))
    score += min(entropy_chars, 30)
    for pat in GOOD_PATTERNS:
        if re.search(pat, code):
            score += 25
    for pat in BAD_PATTERNS:
        if re.search(pat, code):
            score -= 40
    lua_structures = len(re.findall(
        r'\b(function|if|then|end|for|while|local|return)\b',
        code
    ))
    if lua_structures >= 6:
        score += 40
    hex_noise = len(re.findall(r'\\x[0-9A-Fa-f]{2}', code))
    score -= hex_noise
    vm_signal_count = 0
    for pat in VM_SIGNALS:
        if re.search(pat, code):
            vm_signal_count += 1
    if vm_signal_count >= 3:
        score -= 30
    return score


class LuaASTWalker:
    @staticmethod
    def walk(node):
        yield node
        if hasattr(node, 'body'):
            if isinstance(node.body, list):
                for child in node.body:
                    yield from LuaASTWalker.walk(child)
            elif node.body is not None:
                yield from LuaASTWalker.walk(node.body)
        if hasattr(node, 'values'):
            for child in node.values:
                yield from LuaASTWalker.walk(child)
        if hasattr(node, 'targets'):
            for child in node.targets:
                yield from LuaASTWalker.walk(child)
        if hasattr(node, 'fields'):
            for field in node.fields:
                yield from LuaASTWalker.walk(field.value)
                if hasattr(field, 'key') and field.key is not None:
                    yield from LuaASTWalker.walk(field.key)
        if hasattr(node, 'condition') and node.condition is not None:
            yield from LuaASTWalker.walk(node.condition)
        if hasattr(node, 'args'):
            for child in node.args:
                yield from LuaASTWalker.walk(child)
        if hasattr(node, 'func') and node.func is not None:
            yield from LuaASTWalker.walk(node.func)
        if hasattr(node, 'start') and node.start is not None:
            yield from LuaASTWalker.walk(node.start)
        if hasattr(node, 'end') and node.end is not None:
            yield from LuaASTWalker.walk(node.end)
        if hasattr(node, 'step') and node.step is not None:
            yield from LuaASTWalker.walk(node.step)
        if hasattr(node, 'iterators'):
            for child in node.iterators:
                yield from LuaASTWalker.walk(child)
        if hasattr(node, 'else_body') and node.else_body is not None:
            if isinstance(node.else_body, list):
                for child in node.else_body:
                    yield from LuaASTWalker.walk(child)
            else:
                yield from LuaASTWalker.walk(node.else_body)
        if hasattr(node, 'name') and hasattr(node.name, 'id'):
            yield node.name


class DeobfEngine:
    def __init__(self):
        self.unluac_path = UNLUAC_LOCAL_PATH
        self.capabilities = {
            'structural_parsing', 'balanced_brace_scanning',
            'custom_base64_decode', 'shuffle_range_recovery',
            'raw_base64_fallback', 'flexible_alphabet_extraction',
            'lua_runtime_harness', 'luaparser_ast_extraction',
            'unicode_preserving_unescape', 'long_string_tokenization',
            'encoded_data_extraction', 'lua_index_correction',
            'table_diagnostics', 'escaped_alphabet_recovery',
            'arithmetic_table_evaluation', 'harness_error_logging',
            'deep_runtime_hooks', 'readability_scoring',
            'recursive_execution', 'bytecode_interception',
            'table_concat_hook', 'environment_deep_inspection',
            'multi_candidate_scoring', 'unluac_integration',
            'self_capture_rejection', 'debug_hook_tracing',
            'sandboxed_execution', 'delayed_capture',
            'filtered_debug_hook', 'recursive_concat_fix',
            'roblox_stubs', 'vm_signal_detection',
            'syntax_density_scoring', 'char_stream_accumulation'
        }
        self._java_available = shutil.which('java') is not None

    def get_capabilities(self):
        return list(self.capabilities)

    def _run_lua_harness(self, source):
        harness = r'''
local captures = {}
local concat_cache = {}
local char_cache = {}

local function save(tag, data)
    if type(data) ~= "string" then return end
    if #data < 20 then return end
    table.insert(captures, {tag = tag, data = data})
end

local real_loadstring = loadstring
local real_load = load
_G.loadstring = function(code, ...)
    save("loadstring", code)
    return real_loadstring(code, ...)
end
_G.load = function(code, ...)
    save("load", code)
    return real_load(code, ...)
end

local real_concat = table.concat
table.concat = function(tbl, sep, i, j)
    local result = real_concat(tbl, sep, i, j)
    if type(result) == "string" then
        table.insert(concat_cache, result)
        local combined = real_concat(concat_cache)
        if #combined > 500 then
            save("concat_chain", combined)
        end
    end
    return result
end

if string.dump then
    local real_dump = string.dump
    string.dump = function(fn, ...)
        local bc = real_dump(fn, ...)
        save("bytecode", bc)
        return bc
    end
end

if debug and debug.sethook then
    debug.sethook(function(event)
        local info = debug.getinfo(2, "Slnfu")
        if not info then return end
        if info.what ~= "Lua" then return end
        if info.short_src and info.short_src:find("tmp") then return end
        if info.func then
            local ok, dumped = pcall(string.dump, info.func)
            if ok and dumped and #dumped > 50 then
                save("hookdump", dumped)
            end
        end
    end, "c")
end

local real_char = string.char
string.char = function(...)
    local s = real_char(...)
    char_cache[#char_cache+1] = s
    if #char_cache > 50 then
        save("charstream", table.concat(char_cache))
    end
    if #s > 20 then
        save("char", s)
    end
    return s
end

local safe_env = {
    string = string,
    table = table,
    math = math,
    pairs = pairs,
    ipairs = ipairs,
    tonumber = tonumber,
    tostring = tostring,
    type = type,
    unpack = unpack,
    loadstring = _G.loadstring,
    load = _G.load,
    pcall = pcall,
    xpcall = xpcall,
    print = print,
    error = error,
    assert = assert,
    select = select,
    next = next,
    setmetatable = setmetatable,
    getmetatable = getmetatable,
    rawequal = rawequal,
    rawset = rawset,
    rawget = rawget,
    bit = bit,
    bit32 = bit32,
    utf8 = utf8,
    coroutine = coroutine,
    debug = debug,
    os = {
        clock = os.clock,
        time = os.time,
    },
    getgenv = function() return safe_env end,
    getrenv = function() return safe_env end,
    hookfunction = function(a, b) return a end,
    newcclosure = function(f) return f end,
    checkcaller = function() return false end,
    islclosure = function() return true end,
}
safe_env._G = safe_env

local f, err = loadfile("_SRCFILE_")
if not f then
    print("ERR:COMPILE:" .. tostring(err))
    return
end

if setfenv then
    setfenv(f, safe_env)
end

local success, result = pcall(f)

for _ = 1, 5000000 do end

pcall(function()
    for k, v in pairs(_G) do
        if type(v) == "string" and #v > 100 then
            save("env_string", v)
        end
    end
end)

if debug and debug.sethook then
    debug.sethook()
end

if #captures > 0 then
    for _, cap in ipairs(captures) do
        print("CAP:" .. cap.tag .. ":" .. cap.data)
    end
    return
end

if not success then
    print("ERR:RUNTIME:" .. tostring(result))
    return
end

print("ERR:NO_OUTPUT")
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as src_tmp:
            src_tmp.write(source)
            src_path = src_tmp.name

        harness = harness.replace('_SRCFILE_', src_path)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as tmp:
            tmp.write(harness)
            tmp_path = tmp.name

        captures = []
        errors = []
        try:
            for lua_bin in ['lua5.1', 'lua']:
                try:
                    result = subprocess.run(
                        [lua_bin, tmp_path],
                        capture_output=True, text=True, timeout=30
                    )
                    for line in result.stdout.splitlines():
                        if line.startswith('CAP:'):
                            captures.append(line[4:])
                        elif line.startswith('ERR:'):
                            errors.append(line[4:])
                    for line in result.stderr.splitlines():
                        if line.strip():
                            errors.append(line.strip())
                    if captures:
                        break
                    if errors:
                        break
                except FileNotFoundError:
                    errors.append(f"{lua_bin} not found")
                    continue
                except subprocess.TimeoutExpired:
                    errors.append("timeout")
                    break
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            try:
                os.unlink(src_path)
            except OSError:
                pass

        if captures:
            best = None
            best_score = -1
            for cap in captures:
                if ':' in cap:
                    tag, data = cap.split(':', 1)
                else:
                    tag, data = 'unknown', cap
                if _is_self_capture(data):
                    continue
                if '\x1bLua' in data or '\\27Lua' in repr(data):
                    try:
                        raw = data.encode('latin-1')
                        if raw[:4] == b'\x1bLua' and self._java_available:
                            dec, _ = self._run_unluac(raw)
                            if dec:
                                data = dec
                    except:
                        pass
                score = _readability_score(data)
                if score > best_score:
                    best = data
                    best_score = score
            if best:
                current = best
                for _ in range(3):
                    should_recurse = False
                    for pat in LOAD_PATTERNS:
                        if pat in current:
                            should_recurse = True
                            break
                    if should_recurse:
                        nested_result, _ = self._run_lua_harness(current)
                        if nested_result:
                            nested_score = _readability_score(nested_result)
                            if nested_score > _readability_score(current):
                                current = nested_result
                            else:
                                break
                        else:
                            break
                    else:
                        break
                return current, None
            return None, 'no readable captures'
        return None, '; '.join(errors) if errors else 'no output'

    def process(self, source):
        diags = []
        try:
            harness_result, harness_error = self._run_lua_harness(source)
            if harness_result:
                score = _readability_score(harness_result)
                diags.append(f"harness: {len(harness_result)} chars score={score}")
                beautified = self._beautify(harness_result)
                if score >= 45 and self._validate_lua(beautified):
                    return beautified, 'lua_harness', 'Readable Lua recovered', []
                elif score >= 60:
                    return beautified, 'lua_harness_highscore', 'High-score Lua output', []
                elif len(harness_result) > 100:
                    return harness_result, 'lua_harness_raw', 'Lua harness raw output', []
            elif harness_error:
                diags.append(f"harness error: {harness_error[:200]}")

            bodies = _find_all_table_bodies(source)
            table_stats = []
            for body in bodies:
                entries = _parse_table_entries(body)
                strings = [e for e in entries if isinstance(e, str)]
                if len(strings) >= 10:
                    avg = sum(len(s) for s in strings) / len(strings)
                    table_stats.append(f"n={len(strings)} avg={avg:.1f} sample={strings[0][:20]}")

            if table_stats:
                diags.append("tables: " + "; ".join(table_stats[:5]))
            else:
                diags.append("no tables with 10+ strings found")

            alphabet, alpha_var = self._extract_alphabet_enhanced(source)
            if alphabet:
                diags.append(f"alphabet: {len(alphabet)} entries")
                encoded_chunks = self._extract_encoded_data_enhanced(source, alpha_var, bodies)
                if encoded_chunks:
                    diags.append(f"encoded_chunks: {len(encoded_chunks)}")
                    shuffle_ranges = self._extract_shuffle(source)
                    decoded = self._decode_prometheus(encoded_chunks, alphabet, shuffle_ranges)
                    if decoded:
                        score = _readability_score(decoded)
                        diags.append(f"decoded: {len(decoded)} chars score={score}")
                        beautified = self._beautify(decoded)
                        if score >= 45 and self._validate_lua(beautified):
                            return beautified, 'static_decode', 'Structural decode', []
                        elif score >= 60:
                            return beautified, 'static_decode_highscore', 'High-score static decode', []
                        elif len(decoded) > 100:
                            return decoded, 'static_decode_raw', 'Structural decode raw output', []
            else:
                diags.append("no alphabet table found")

            diag_str = '; '.join(diags) if diags else 'no strategies produced output'
            return '', 'unable', diag_str, []
        except Exception as e:
            return '', 'error', str(e), []

    def _extract_alphabet_enhanced(self, source):
        if HAS_LUAPARSER:
            try:
                tree = lua_ast.parse(source)
                for node in LuaASTWalker.walk(tree):
                    if hasattr(node, 'targets') and hasattr(node, 'values') and node.values:
                        if hasattr(node.values[0], 'fields') and len(node.values[0].fields) >= 30:
                            entries = []
                            for field in node.values[0].fields:
                                if hasattr(field, 'value') and hasattr(field.value, 's'):
                                    entries.append(field.value.s)
                            if len(entries) >= 30:
                                unescaped = []
                                for s in entries:
                                    raw = _lua_unescape(s)
                                    if len(raw) == 1:
                                        unescaped.append(chr(raw[0]))
                                    else:
                                        unescaped.append(s)
                                if len(unescaped) >= 30:
                                    avg_len = sum(len(c) for c in unescaped) / len(unescaped)
                                    if avg_len <= 2.0:
                                        var_name = node.targets[0].id if node.targets and hasattr(node.targets[0], 'id') else 'R'
                                        return unescaped, var_name
            except Exception:
                pass

        best = None
        best_var = None
        best_score = 0
        for m in re.finditer(r'local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{', source):
            var_name = m.group(1)
            open_brace = source.find('{', m.start())
            end = _find_balanced_end(source, open_brace)
            if end == -1:
                continue
            body = source[open_brace:end]
            entries = _parse_table_entries(body)
            strings = [e for e in entries if isinstance(e, str)]
            n = len(strings)
            if n < 20:
                continue

            unescaped_candidates = []
            for s in strings:
                raw = _lua_unescape(s)
                if len(raw) == 1:
                    unescaped_candidates.append(chr(raw[0]))
                else:
                    unescaped_candidates.append(s)

            single_char_count = sum(1 for c in unescaped_candidates if len(c) == 1)
            if single_char_count >= 20:
                best = unescaped_candidates
                best_var = var_name
                break

        if not best:
            for m in re.finditer(r'local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{', source):
                var_name = m.group(1)
                open_brace = source.find('{', m.start())
                end = _find_balanced_end(source, open_brace)
                if end == -1:
                    continue
                body = source[open_brace:end]
                entries = _parse_table_entries(body)
                strings = [e for e in entries if isinstance(e, str)]
                n = len(strings)
                if n < 30:
                    continue
                avg_len = sum(len(s) for s in strings) / n
                if avg_len > 3.0:
                    continue
                score = n - abs(n - 64)
                if score > best_score:
                    best_score = score
                    best = strings
                    best_var = var_name

        return best, best_var

    def _extract_encoded_data_enhanced(self, source, alphabet_var, all_table_bodies):
        chunks = []
        for m in re.finditer(
            r'(?:local\s+)?([A-Za-z_]\w*)\s*=\s*((?:"[^"]*"\s*(?:\.\.\s*)?)+)',
            source
        ):
            var = m.group(1)
            if var == alphabet_var:
                continue
            raw = m.group(2)
            parts = re.findall(r'"([^"]*)"', raw)
            combined = ''.join(parts)
            if len(combined) > 20:
                chunks.append(combined)

        if not chunks:
            for body in all_table_bodies:
                entries = _parse_table_entries(body)
                strings = [e for e in entries if isinstance(e, str)]
                if len(strings) < 10:
                    continue
                sample = strings[0]
                if len(sample) > 10 and '\\' in sample:
                    for s in strings:
                        raw = _lua_unescape(s)
                        if raw and len(raw) > 0:
                            chunks.append(raw.decode('latin-1', errors='replace'))
                    if chunks:
                        break

        return chunks if chunks else None

    def _extract_strings_fallback(self, source, alphabet_var):
        all_strings = []
        for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', source):
            s = m.group(1)
            if len(s) > 10:
                all_strings.append(s)
        return all_strings if all_strings else None

    def _extract_shuffle(self, source):
        ranges = []
        for m in re.finditer(r'for\s+(\w+)\s*=\s*(\d+)\s*,\s*(\d+)\s*do', source):
            try:
                start_val = int(m.group(2))
                end_val = int(m.group(3))
                body_start = source.find('do', m.end())
                if body_start == -1:
                    continue
                end_pos = source.find('end', body_start)
                if end_pos == -1:
                    continue
                inner = source[body_start+2:end_pos]
                swaps = re.findall(r'\w+\[\w+\]\s*=\s*\w+\[\w+\]', inner)
                if len(swaps) >= 1:
                    ranges.append((start_val, end_val))
            except:
                continue
        for m in re.finditer(r'for\s+\w+\s*,\s*\w+\s+in\s+ipairs\s*\(\s*\w+\s*\)\s*do', source):
            try:
                body_start = source.find('do', m.end())
                if body_start == -1:
                    continue
                end_pos = source.find('end', body_start)
                if end_pos == -1:
                    continue
                inner = source[body_start+2:end_pos]
                swaps = re.findall(r'\w+\[\w+\]\s*=\s*\w+\[\w+\]', inner)
                if len(swaps) >= 1:
                    ranges.append((1, len(swaps) * 2))
            except:
                continue
        return ranges if ranges else None

    def _decode_prometheus(self, encoded_chunks, alphabet, shuffle_ranges):
        rev_map = {}
        for i, entry in enumerate(alphabet, start=1):
            if isinstance(entry, str) and len(entry) >= 1:
                rev_map[entry] = i
        if len(rev_map) < 20:
            return None
        working = list(encoded_chunks)
        if shuffle_ranges:
            for lo, hi in shuffle_ranges:
                lo_idx, hi_idx = lo - 1, hi - 1
                if 0 <= lo_idx < len(working) and 0 <= hi_idx < len(working) and lo_idx < hi_idx:
                    working[lo_idx:hi_idx+1] = working[lo_idx:hi_idx+1][::-1]
        decoded_chunks = []
        for s in working:
            if not isinstance(s, str):
                continue
            raw = _lua_unescape(s) if isinstance(s, str) and '\\' in s else s.encode('latin-1', errors='replace')
            if not raw:
                continue
            buf, bits, out = 0, 0, bytearray()
            for b in raw:
                ch = chr(b) if b < 256 else ''
                if ch == '=':
                    break
                if ch not in rev_map:
                    continue
                buf = (buf << 6) | rev_map[ch]
                bits += 6
                while bits >= 8:
                    bits -= 8
                    out.append((buf >> bits) & 0xFF)
            if out:
                decoded_chunks.append(bytes(out))
        if not decoded_chunks:
            return None
        combined = b''.join(decoded_chunks)
        for enc in ('utf-8', 'latin-1'):
            try:
                text = combined.decode(enc)
                if len(text) > 50:
                    return text
            except:
                continue
        return combined.decode('latin-1', errors='replace')

    def _beautify(self, code):
        if not code:
            return code
        code = code.replace('\r\n', '\n').replace('\r', '\n')
        lines = [''.join(c for c in line if c.isprintable() or c == '\t').rstrip() for line in code.split('\n')]
        code = '\n'.join(lines)
        code = re.sub(r'\n{3,}', '\n\n', code)
        indent = 0
        formatted = []
        for line in code.split('\n'):
            stripped = line.strip()
            if not stripped:
                formatted.append('')
                continue
            if re.match(r'^(end|until|else|elseif)\b', stripped):
                indent = max(0, indent - 1)
            formatted.append('    ' * indent + stripped)
            safe = re.sub(r'(?:\'[^\']*\'|"[^"]*"|--[^\n]*|\[=*\[.*?\]=*\])', '', stripped, flags=re.DOTALL)
            opens = len(re.findall(r'\b(function|then|do|repeat)\b', safe))
            closes = len(re.findall(r'\b(end|until)\b', safe))
            indent += opens - closes
            if stripped.startswith(('else', 'elseif')):
                indent += 1
            indent = max(indent, 0)
        return '\n'.join(formatted)

    def _validate_lua(self, code):
        if not code or len(code) < 20:
            return False
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False) as tmp:
            tmp.write(code)
            tmp_path = tmp.name
        try:
            for lua_bin in ['lua5.1', 'lua']:
                try:
                    result = subprocess.run(
                        [lua_bin, '-p', tmp_path],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        return True
                    break
                except FileNotFoundError:
                    continue
                except subprocess.TimeoutExpired:
                    break
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        if HAS_LUAPARSER:
            try:
                lua_ast.parse(code)
                return True
            except Exception:
                pass
        return False

    def _run_unluac(self, bytecode):
        if not self._java_available:
            return None, "no java"
        if not os.path.isfile(self.unluac_path):
            self._ensure_unluac_jar()
        if not os.path.isfile(self.unluac_path):
            return None, "no unluac.jar"
        if bytecode[:4] != b'\x1bLua':
            return None, "not lua bytecode"
        with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
            tmp.write(bytecode)
            tmp_path = tmp.name
        try:
            r = subprocess.run(['java', '-jar', self.unluac_path, '--rawstring', tmp_path], capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout, None
            if r.stderr and 'version' in r.stderr.lower():
                r2 = subprocess.run(['java', '-jar', self.unluac_path, tmp_path], capture_output=True, text=True, timeout=30)
                if r2.returncode == 0 and r2.stdout.strip():
                    return r2.stdout, None
                return None, r2.stderr[:300]
            return None, r.stderr[:200] if r.stderr else 'no output'
        except subprocess.TimeoutExpired:
            return None, "timeout"
        except Exception as e:
            return None, str(e)
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except:
                    pass

    def _ensure_unluac_jar(self):
        try:
            os.makedirs(os.path.dirname(self.unluac_path), exist_ok=True)
            urllib.request.urlretrieve(UNLUAC_JAR_URL, self.unluac_path)
        except:
            pass
