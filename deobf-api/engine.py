import os, re, shutil, subprocess, tempfile, base64, urllib.request, asyncio, struct, hashlib, json, time, traceback, binascii, sys, math, resource, signal
from collections import OrderedDict, defaultdict, deque, namedtuple, Counter
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional, Union, Any, Callable
from enum import Enum

try:
    from luaparser import ast as lua_ast
    from luaparser.lexer import LuaLexer
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

VM_PATTERNS = [
    r'VIP',
    r'OP_[A-Z]+',
    r'pcall\(function',
    r'string\.byte',
    r'bit32?',
    r'_ENV',
    r'getfenv',
    r'setfenv',
    r'coroutine\.wrap',
    r'while true do',
    r'repeat.+until',
    r'::[A-Za-z_]+::',
    r'goto',
]

TAMPER_PATTERNS = [
    "__metatable",
    "hookfunction",
    "newcclosure",
    "checkcaller",
    "islclosure",
    "Tamper Detected",
]

LOAD_PATTERNS = [
    "loadstring",
    "load(",
    "assert(load",
    "pcall(load",
]


def _shannon_entropy(data):
    if not data:
        return 0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_lua_bytecode(raw):
    return raw[:4] == b'\x1bLua'


def _is_probably_text(data):
    if not data:
        return False
    if isinstance(data, str):
        raw = data.encode('latin-1', errors='ignore')
    else:
        raw = data
    if len(raw) < 50:
        return False
    if _is_lua_bytecode(raw):
        return False
    printable = sum(1 for b in raw if 32 <= b <= 126 or b in (9, 10, 13))
    ratio = printable / len(raw)
    if ratio < 0.60:
        return False
    null_bytes = raw.count(b'\x00')
    if null_bytes > len(raw) * 0.15:
        return False
    entropy = _shannon_entropy(raw)
    if entropy > 7.2:
        return False
    return True


def _decode_numeric_escapes(s):
    return re.sub(
        r'\\(\d{1,3})',
        lambda m: chr(int(m.group(1)) % 256),
        s
    )


def _decode_hex_blob(s):
    if re.fullmatch(r'[0-9A-Fa-f]+', s) and len(s) >= 4 and len(s) % 2 == 0:
        try:
            return bytes.fromhex(s)
        except:
            pass
    return None


def _try_reverse(s):
    if isinstance(s, str):
        return s[::-1]
    return s


def _try_base64_decode(s):
    try:
        padded = s + '=' * (-len(s) % 4)
        return base64.b64decode(padded)
    except:
        return None


def _looks_like_vm_blob(s):
    if re.search(r'[A-Z]=\d+', s):
        return True
    if len(re.findall(r'\d{5,}', s)) > 8:
        return True
    return False


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
        decoded = _decode_numeric_escapes(e)
        if (decoded.startswith('"') and decoded.endswith('"')) or (decoded.startswith("'") and decoded.endswith("'")):
            parsed.append(decoded[1:-1])
        elif decoded.startswith('[[') and decoded.endswith(']]'):
            parsed.append(decoded[2:-2])
        elif decoded.lstrip('-').isdigit():
            parsed.append(int(decoded))
        elif decoded.replace('.', '', 1).lstrip('-').isdigit():
            parsed.append(float(decoded))
        elif decoded in ('true', 'false', 'nil'):
            parsed.append(decoded)
        else:
            parsed.append(decoded)
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


def _score_lua_validity(code):
    if not code or len(code) < 20:
        return -100
    try:
        lua_ast.parse(code)
        return 100
    except Exception as e:
        msg = str(e).lower()
        if "expected" in msg:
            return -40
        if "malformed" in msg:
            return -80
        return -20


def _readability_score(code):
    if not code:
        return 0
    score = 0
    funcs = len(re.findall(r'\bfunction\b', code))
    ends = len(re.findall(r'\bend\b', code))
    if abs(funcs - ends) <= 2 and funcs > 0:
        score += 30
    locals_count = len(re.findall(r'\blocal\b', code))
    if locals_count > 0:
        score += locals_count * 2
    identifiers = re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b', code)
    if identifiers:
        avg_ident_len = sum(len(x) for x in identifiers) / len(identifiers)
        if avg_ident_len > 3:
            score += 15
        words = re.findall(r'[A-Za-z_]{4,}', code)
        if words:
            unique_ratio = len(set(words)) / max(len(words), 1)
            if unique_ratio < 0.20:
                score -= 20
    gibberish = re.findall(r'[A-Za-z0-9]{20,}', code)
    score -= len(gibberish) * 3
    for pat in GOOD_PATTERNS:
        if re.search(pat, code):
            score += 35
    for pat in BAD_PATTERNS:
        if re.search(pat, code):
            score -= 50
    for pat in TAMPER_PATTERNS:
        if pat in code:
            score -= 80
    lua_structures = len(re.findall(
        r'\b(function|if|then|end|for|while|local|return)\b',
        code
    ))
    if lua_structures >= 4:
        score += 30
    hex_noise = len(re.findall(r'\\x[0-9A-Fa-f]{2}', code))
    score -= hex_noise
    vm_count = 0
    for pat in VM_PATTERNS:
        if re.search(pat, code):
            vm_count += 1
    score -= vm_count * 20
    entropy = _shannon_entropy(code)
    if entropy > 6.5:
        score -= 30
    return score


def _total_score(code):
    if not code:
        return -1000
    syntax = _score_lua_validity(code)
    readability = _readability_score(code)
    return syntax + readability


def _recursive_decode(data, depth=0, visited=None, max_ops=None):
    if max_ops is None:
        max_ops = [0]
    if depth > 5 or max_ops[0] > 500:
        return data
    if visited is None:
        visited = set()
    if isinstance(data, bytes):
        text_candidates = []
        for enc in ('utf-8', 'latin-1'):
            try:
                text_candidates.append(data.decode(enc, errors='replace'))
            except:
                pass
    else:
        text_candidates = [data]
    best = data if isinstance(data, str) else (text_candidates[0] if text_candidates else data.decode('latin-1', errors='replace'))
    best_score = _total_score(best) if isinstance(best, str) else -1000
    for text in text_candidates:
        if not isinstance(text, str):
            continue
        text_hash = hashlib.sha256(text.encode('utf-8', errors='replace')).hexdigest()
        if text_hash in visited:
            continue
        visited.add(text_hash)
        for fn_name, fn in [
            ('base64', lambda t: _try_base64_decode(t)),
            ('hex', lambda t: _decode_hex_blob(t)),
            ('reverse', lambda t: _try_reverse(t)),
        ]:
            if max_ops[0] > 500:
                break
            max_ops[0] += 1
            try:
                out = fn(text)
                if out:
                    if isinstance(out, bytes):
                        for enc in ('utf-8', 'latin-1'):
                            try:
                                out_text = out.decode(enc, errors='replace')
                                if len(re.findall(r'[{}();=]', out_text)) < 5:
                                    continue
                                lua_kw_count = sum(1 for kw in LUA_KEYWORDS if kw in out_text)
                                if lua_kw_count < 3:
                                    continue
                                score = _total_score(out_text)
                                if score > best_score:
                                    best = out_text
                                    best_score = score
                                    deeper = _recursive_decode(out_text, depth + 1, visited, max_ops)
                                    deeper_score = _total_score(deeper)
                                    if deeper_score > best_score:
                                        best = deeper
                                        best_score = deeper_score
                            except:
                                pass
                    elif isinstance(out, str):
                        if len(re.findall(r'[{}();=]', out)) < 5:
                            continue
                        lua_kw_count = sum(1 for kw in LUA_KEYWORDS if kw in out)
                        if lua_kw_count < 3:
                            continue
                        score = _total_score(out)
                        if score > best_score:
                            best = out
                            best_score = score
                            deeper = _recursive_decode(out, depth + 1, visited, max_ops)
                            deeper_score = _total_score(deeper)
                            if deeper_score > best_score:
                                best = deeper
                                best_score = deeper_score
            except:
                pass
    if isinstance(best, bytes):
        try:
            best = best.decode('utf-8', errors='replace')
        except:
            best = best.decode('latin-1', errors='replace')
    return best


def _structural_beautify(code):
    if not code:
        return code
    code = code.replace('\r\n', '\n').replace('\r', '\n')
    code = re.sub(r'[ \t]+', ' ', code)
    code = re.sub(r'\n{3,}', '\n\n', code)
    return code.strip()


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
        self.visited_hashes = set()
        self.seen_captures = set()
        self.decode_operations = 0
        self.capabilities = {
            'structural_parsing', 'balanced_brace_scanning',
            'custom_base64_decode', 'shuffle_range_recovery',
            'lua_runtime_harness', 'luaparser_ast_extraction',
            'unicode_preserving_unescape', 'long_string_tokenization',
            'encoded_data_extraction', 'lua_index_correction',
            'table_diagnostics', 'numeric_escape_recovery',
            'readability_scoring', 'bytecode_interception',
            'self_capture_rejection', 'native_execution',
            'binary_safe_subprocess', 'base64_capture_encoding',
            'vm_signal_detection', 'binary_text_separation',
            'hash_recursion_prevention', 'binary_detection',
            'xor_bruteforce_layer', 'multi_candidate_ranking',
            'entropy_scoring', 'tamper_pattern_detection',
            'selective_hook_sandbox', 'runtime_alphabet_recovery',
            'rolling_xor_transform', 'recursive_decode_chain',
            'vm_blob_filtering', 'hex_decode', 'reverse_decode',
            'deferred_capture_return', 'table_insert_hook',
            'pcall_hook', 'recursion_guard', 'execution_limits',
            'syntax_weighted_scoring', 'control_flow_repair',
            'safe_beautifier', 'ast_normalization',
            'raw_score_fallback', 'unconditional_harness_return',
            'full_stdlib_native_env', 'extended_instruction_limit',
            'pure_lua51_bit32', 'recursive_cycle_detection',
            'hard_xor_filters', 'native_environment_execution',
            'adaptive_instruction_limits', 'memory_limits',
            'process_group_isolation', 'capture_deduplication',
            'table_mutation_hooks', 'staged_execution_passes',
            'runtime_state_snapshots'
        }
        self._java_available = shutil.which('java') is not None

    def get_capabilities(self):
        return list(self.capabilities)

    def _set_process_limits(self):
        try:
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_CPU, (25, 30))
            resource.setrlimit(resource.RLIMIT_NPROC, (50, 50))
            resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        except:
            pass

    def _rolling_xor(self, data, key):
        out = bytearray()
        k = key
        for b in data:
            out.append(b ^ k)
            k = (k * 13 + 17) & 0xFF
        return bytes(out)

    def _try_xor_bruteforce(self, data):
        best = None
        best_score = -1000
        if isinstance(data, str):
            raw = data.encode('latin-1', errors='ignore')
        else:
            raw = data
        for key in range(1, 256):
            if self.decode_operations > 500:
                break
            self.decode_operations += 1
            try:
                decoded = bytes([b ^ key for b in raw])
                text = decoded.decode('utf-8', errors='replace')
                if len(re.findall(r'[{}();=]', text)) < 5:
                    continue
                lua_kw_count = sum(1 for kw in LUA_KEYWORDS if kw in text)
                if lua_kw_count < 3:
                    continue
                score = _total_score(text)
                if score > best_score:
                    best_score = score
                    best = text
            except:
                continue
        if best and best_score > 20:
            return best
        for key in range(1, 256):
            if self.decode_operations > 500:
                break
            self.decode_operations += 1
            try:
                decoded = self._rolling_xor(raw, key)
                text = decoded.decode('utf-8', errors='replace')
                if len(re.findall(r'[{}();=]', text)) < 5:
                    continue
                lua_kw_count = sum(1 for kw in LUA_KEYWORDS if kw in text)
                if lua_kw_count < 3:
                    continue
                score = _total_score(text)
                if score > best_score:
                    best_score = score
                    best = text
            except:
                continue
        if best and best_score > 25:
            return best
        return None

    def _run_lua_harness(self, source, depth=0, instruction_limit=500000):
        if depth > 3:
            return None, 'max recursion depth'
        source_hash = hashlib.sha256(source.encode('utf-8', errors='replace')).hexdigest()
        if source_hash in self.visited_hashes:
            return None, 'recursion detected'
        self.visited_hashes.add(source_hash)

        harness = r'''
local captures = {}
local CALL_DEPTH = 0
local MAX_DEPTH = 25

local b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

local function b64encode(data)
    local result = {}
    local padding = ""
    for i = 1, #data, 3 do
        local a, b, c = data:byte(i, i+2)
        b = b or 0
        c = c or 0
        local n = a * 65536 + b * 256 + c
        local c1 = math.floor(n / 262144) % 64
        local c2 = math.floor(n / 4096) % 64
        local c3 = math.floor(n / 64) % 64
        local c4 = n % 64
        table.insert(result, b64chars:sub(c1+1, c1+1))
        table.insert(result, b64chars:sub(c2+1, c2+1))
        if i + 1 > #data then
            padding = "=="
            break
        end
        table.insert(result, b64chars:sub(c3+1, c3+1))
        if i + 2 > #data then
            padding = "="
            break
        end
        table.insert(result, b64chars:sub(c4+1, c4+1))
    end
    return table.concat(result) .. padding
end

local function looks_textual(s)
    local printable = 0
    for i = 1, #s do
        local b = s:byte(i)
        if (b >= 32 and b <= 126) or b == 10 or b == 13 or b == 9 then
            printable = printable + 1
        end
    end
    return printable / #s > 0.75
end

local function save(tag, data)
    if type(data) ~= "string" then return end
    if #data < 20 then return end
    if not looks_textual(data) then return end
    if CALL_DEPTH > MAX_DEPTH then return end
    CALL_DEPTH = CALL_DEPTH + 1
    local encoded = b64encode(data)
    table.insert(captures, {tag = tag, data = encoded, raw_length = #data})
    CALL_DEPTH = CALL_DEPTH - 1
end

local real_loadstring = loadstring
local real_load = load
local INSIDE_LOAD = false

_G.loadstring = function(code, ...)
    if not INSIDE_LOAD then
        INSIDE_LOAD = true
        save("loadstring", code)
        INSIDE_LOAD = false
    end
    return real_loadstring(code, ...)
end
_G.load = function(code, ...)
    if not INSIDE_LOAD then
        INSIDE_LOAD = true
        save("load", code)
        INSIDE_LOAD = false
    end
    return real_load(code, ...)
end

local real_char = string.char
string.char = function(...)
    local out = real_char(...)
    if #out > 40 and looks_textual(out) then
        save("string_char", out)
    end
    return out
end

local real_concat = table.concat
table.concat = function(t, sep, i, j)
    local out = real_concat(t, sep, i, j)
    if type(out) == "string" and #out > 80 and looks_textual(out) then
        save("concat", out)
    end
    return out
end

local real_insert = table.insert
table.insert = function(t, v, ...)
    if type(v) == "string" and #v > 20 and looks_textual(v) then
        save("table_insert", v)
    end
    return real_insert(t, v, ...)
end

local real_setmetatable = setmetatable
setmetatable = function(t, mt)
    if mt and type(mt) == "table" then
        save("setmetatable", "metatable_set")
    end
    return real_setmetatable(t, mt)
end

local real_getmetatable = getmetatable
getmetatable = function(t)
    local mt = real_getmetatable(t)
    if mt and type(mt) == "table" then
        save("getmetatable", "metatable_get")
    end
    return mt
end

local real_pcall = pcall
_G.pcall = function(fn, ...)
    if type(fn) == "function" then
        local is_lua_closure = false
        if debug and debug.getinfo then
            local info = debug.getinfo(fn)
            if info and info.what == "Lua" then
                is_lua_closure = true
            end
        end
        if is_lua_closure then
            local ok, dumped = real_pcall(string.dump, fn)
            if ok and dumped and #dumped > 50 then
                save("pcall_fn", dumped)
            end
        end
    end
    return real_pcall(fn, ...)
end

if string.dump then
    local real_dump = string.dump
    string.dump = function(fn, ...)
        local bc = real_dump(fn, ...)
        save("bytecode", bc)
        return bc
    end
end

os.execute = function() error("os.execute blocked") end
io.popen = function() error("io.popen blocked") end

local f, err = loadfile("_SRCFILE_")
if not f then
    print("ERR:COMPILE:" .. tostring(err))
    return
end

local bit32 = bit32 or nil
if not bit32 then
    local function bit_bor(a, b)
        local r, m = 0, 1
        while a > 0 or b > 0 do
            local abit, bbit = a % 2, b % 2
            if abit + bbit > 0 then r = r + m end
            a, b, m = math.floor(a/2), math.floor(b/2), m * 2
        end
        return r
    end
    local function bit_band(a, b)
        local r, m = 0, 1
        while a > 0 and b > 0 do
            local abit, bbit = a % 2, b % 2
            if abit + bbit == 2 then r = r + m end
            a, b, m = math.floor(a/2), math.floor(b/2), m * 2
        end
        return r
    end
    local function bit_bxor(a, b)
        local r, m = 0, 1
        while a > 0 or b > 0 do
            local abit, bbit = a % 2, b % 2
            if abit ~= bbit then r = r + m end
            a, b, m = math.floor(a/2), math.floor(b/2), m * 2
        end
        return r
    end
    local function bit_lshift(v, n)
        return math.floor(v * (2 ^ n)) % 4294967296
    end
    local function bit_rshift(v, n)
        return math.floor(v / (2 ^ n))
    end
    bit32 = {
        bxor = bit_bxor,
        band = bit_band,
        bor = bit_bor,
        lshift = bit_lshift,
        rshift = bit_rshift,
        arshift = bit_rshift,
    }
end
_G.bit32 = bit32
_G.bit = bit32

if debug and debug.sethook then
    debug.sethook(function()
        error("instruction limit")
    end, "", _INSTRLIMIT_)
end

local success, result = pcall(f)

if debug and debug.sethook then
    debug.sethook()
end

collectgarbage("collect")

pcall(function()
    for k, v in pairs(_G) do
        if type(v) == "string" and #v > 100 and looks_textual(v) then
            save("env_string", v)
        end
        if type(v) == "table" and #v > 10 then
            save("large_table", "table_with_" .. tostring(#v) .. "_entries")
        end
    end
end)

for _, cap in ipairs(captures) do
    print("CAP:" .. cap.tag .. ":" .. cap.data)
end

if #captures == 0 then
    if not success then
        print("ERR:RUNTIME:" .. tostring(result))
        return
    end
    print("ERR:NO_OUTPUT")
end
'''
        harness = harness.replace('_SRCFILE_', src_path := None)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as src_tmp:
            src_tmp.write(source)
            src_path = src_tmp.name

        harness = harness.replace('_SRCFILE_', src_path).replace('_INSTRLIMIT_', str(instruction_limit))
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
                        capture_output=True,
                        timeout=30,
                        preexec_fn=self._set_process_limits
                    )
                    stdout = result.stdout.decode('latin-1', errors='replace')
                    stderr = result.stderr.decode('latin-1', errors='replace')
                    for line in stdout.splitlines():
                        if line.startswith('CAP:'):
                            captures.append(line[4:])
                        elif line.startswith('ERR:'):
                            errors.append(line[4:])
                    for line in stderr.splitlines():
                        if line.strip():
                            errors.append(line.strip())
                    if captures:
                        break
                    if errors and 'instruction limit' in ' '.join(errors).lower() and instruction_limit < 5000000:
                        self.visited_hashes.discard(source_hash)
                        return self._run_lua_harness(source, depth, instruction_limit * 4)
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
            candidates = []
            for cap in captures:
                if ':' in cap:
                    tag, data = cap.split(':', 1)
                else:
                    tag, data = 'unknown', cap
                try:
                    decoded_data = base64.b64decode(data).decode('latin-1', errors='replace')
                except Exception:
                    decoded_data = data
                capture_hash = hashlib.sha256(decoded_data.encode('utf-8', errors='replace')).hexdigest()
                if capture_hash in self.seen_captures:
                    continue
                self.seen_captures.add(capture_hash)
                if _is_self_capture(decoded_data):
                    continue
                if not _is_probably_text(decoded_data):
                    raw_check = decoded_data.encode('latin-1', errors='ignore')
                    if _is_lua_bytecode(raw_check) and self._java_available:
                        try:
                            dec, _ = self._run_unluac(raw_check)
                            if dec:
                                decoded_data = dec
                        except:
                            pass
                    else:
                        continue
                decoded_data = _recursive_decode(decoded_data)
                score = _total_score(decoded_data)
                syntax_ok = self._validate_lua(decoded_data)
                if score >= 55:
                    candidates.append({
                        'data': decoded_data,
                        'score': score,
                        'syntax_ok': syntax_ok,
                        'tag': tag
                    })

            candidates.sort(key=lambda x: (x['syntax_ok'], x['score']), reverse=True)

            for candidate in candidates[:3]:
                if candidate['syntax_ok'] and candidate['score'] >= 55:
                    result = candidate['data']
                    result = _structural_beautify(result)
                    if result and result != source and depth < 3:
                        recursive_result, _ = self._run_lua_harness(result, depth + 1)
                        if recursive_result and _total_score(recursive_result) > _total_score(result):
                            return recursive_result, None
                    return result, None

            if candidates:
                best = candidates[0]['data']
                best = _structural_beautify(best)
                return best, None
            return None, 'no readable captures'
        return None, '; '.join(errors) if errors else 'no output'

    def process(self, source):
        diags = []
        try:
            harness_result, harness_error = self._run_lua_harness(source)
            if harness_result:
                score = _total_score(harness_result)
                diags.append(f"harness: {len(harness_result)} chars score={score}")
                if score >= 55:
                    if self._validate_lua(harness_result):
                        return harness_result, 'lua_harness_raw', 'Raw harness capture (valid Lua)', []
                    beautified = _structural_beautify(harness_result)
                    if self._validate_lua(beautified):
                        return beautified, 'lua_harness_beautified', 'Beautified harness capture', []
                    return harness_result, 'lua_harness_raw_score', f'High-score unvalidated capture (score={score})', []
                elif len(harness_result) > 100:
                    return _structural_beautify(harness_result), 'lua_harness_fallback', 'Fallback harness output', []
            elif harness_error:
                diags.append(f"harness error: {harness_error[:200]}")

            bodies = _find_all_table_bodies(source)
            table_stats = []
            for body in bodies:
                entries = _parse_table_entries(body)
                strings = [e for e in entries if isinstance(e, str)]
                strings = [s for s in strings if not _looks_like_vm_blob(s)]
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
                        decoded = _recursive_decode(decoded)
                        score = _total_score(decoded)
                        diags.append(f"decoded: {len(decoded)} chars score={score}")
                        beautified = _structural_beautify(decoded)
                        if score >= 55 and self._validate_lua(beautified):
                            return beautified, 'static_decode', 'Structural decode', []
                        elif len(decoded) > 100:
                            if score >= 55:
                                recursive_result, _ = self._run_lua_harness(decoded)
                                if recursive_result and _total_score(recursive_result) > score:
                                    beautified = _structural_beautify(recursive_result)
                                    return beautified, 'recursive_decode', 'Recursive decode improved', []
                            return beautified, 'static_decode_raw', 'Structural decode raw output', []
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
                        if hasattr(node.values[0], 'fields') and len(node.values[0].fields) >= 15:
                            entries = []
                            for field in node.values[0].fields:
                                if hasattr(field, 'value') and hasattr(field.value, 's'):
                                    entries.append(_decode_numeric_escapes(field.value.s))
                            if len(entries) >= 15:
                                unescaped = []
                                for s in entries:
                                    raw = _lua_unescape(s)
                                    if len(raw) == 1:
                                        unescaped.append(chr(raw[0]))
                                    else:
                                        unescaped.append(s)
                                if len(unescaped) >= 15:
                                    avg_len = sum(len(c) for c in unescaped) / len(unescaped)
                                    if avg_len <= 8.0:
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
            strings = [s for s in strings if not _looks_like_vm_blob(s)]
            n = len(strings)
            if n < 10:
                continue

            unescaped_candidates = []
            for s in strings:
                raw = _lua_unescape(s)
                if len(raw) == 1:
                    unescaped_candidates.append(chr(raw[0]))
                else:
                    unescaped_candidates.append(s)

            single_char_count = sum(1 for c in unescaped_candidates if len(c) == 1)
            if single_char_count >= 10:
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
                strings = [s for s in strings if not _looks_like_vm_blob(s)]
                n = len(strings)
                if n < 15:
                    continue
                avg_len = sum(len(s) for s in strings) / n
                if avg_len > 8.0:
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
                chunks.append(_decode_numeric_escapes(combined))

        if not chunks:
            for body in all_table_bodies:
                entries = _parse_table_entries(body)
                strings = [e for e in entries if isinstance(e, str)]
                strings = [s for s in strings if not _looks_like_vm_blob(s)]
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
                all_strings.append(_decode_numeric_escapes(s))
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
        if len(rev_map) < 10:
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
        decoded = combined.decode('latin-1', errors='replace')
        xor_result = self._try_xor_bruteforce(decoded)
        if xor_result:
            return xor_result
        return decoded if len(decoded) > 50 else None

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
                        capture_output=True,
                        timeout=10
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
            r = subprocess.run(
                ['java', '-jar', self.unluac_path, '--rawstring', tmp_path],
                capture_output=True,
                timeout=30
            )
            stdout = r.stdout.decode('latin-1', errors='replace')
            stderr = r.stderr.decode('latin-1', errors='replace')
            if r.returncode == 0 and stdout.strip():
                return stdout, None
            if stderr and 'version' in stderr.lower():
                r2 = subprocess.run(
                    ['java', '-jar', self.unluac_path, tmp_path],
                    capture_output=True,
                    timeout=30
                )
                stdout2 = r2.stdout.decode('latin-1', errors='replace')
                stderr2 = r2.stderr.decode('latin-1', errors='replace')
                if r2.returncode == 0 and stdout2.strip():
                    return stdout2, None
                return None, stderr2[:300]
            return None, stderr[:200] if stderr else 'no output'
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
