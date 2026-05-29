import os, re, shutil, subprocess, tempfile, base64, urllib.request, asyncio, struct, hashlib, json, time, traceback, binascii, sys, math, resource, signal, io, contextlib, threading, uuid
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


@contextlib.contextmanager
def _suppress_stderr():
    old_stderr = sys.stderr
    sys.stderr = io.StringIO()
    try:
        yield
    finally:
        sys.stderr = old_stderr


def _shannon_entropy(data):
    if not data:
        return 0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_lua_bytecode(raw):
    return raw[:4] == b'\x1bLua'


def _is_self_capture(text):
    if not text:
        return False
    for sig in REJECT_SIGNATURES:
        if sig in text:
            return True
    return False


def _is_probably_text(data):
    if not data:
        return False
    if isinstance(data, str):
        raw = data.encode('latin-1', errors='ignore')
    else:
        raw = data
    if len(raw) < 10:
        return False
    if _is_lua_bytecode(raw):
        return False
    printable = sum(1 for b in raw if 32 <= b <= 126 or b in (9, 10, 13))
    if (printable / len(raw)) < 0.60:
        return False
    if raw.count(b'\x00') > len(raw) * 0.15:
        return False
    if _shannon_entropy(raw) > 7.2:
        return False
    return True


def _try_base64_decode(s):
    try:
        s = s.replace('-', '+').replace('_', '/')
        padded = s + '=' * (-len(s) % 4)
        return base64.b64decode(padded, validate=True)
    except Exception:
        return None


def _decode_numeric_escapes(s):
    """Decode Lua numeric escapes: \\076 -> 'L'"""
    return re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))), s)


def _lua_score(text):
    """Score a string on how likely it is to be readable Lua source."""
    score = sum(1 for kw in LUA_KEYWORDS if kw in text) * 8
    for pat in [r'local\s+\w+', r'function\s*\(', r'end\b', r'return\b', r'if\s+.+\s+then']:
        if re.search(pat, text):
            score += 15
    if _shannon_entropy(text.encode(errors='ignore')) < 7:
        score += 10
    if text.count('(') == text.count(')'):
        score += 10
    funcs = text.count('function')
    ends  = text.count('end')
    if funcs > 0 and ends >= funcs:
        score += 25
    return score


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
# WeAreDevs alphabet extraction
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def _extract_wearedevs_alphabet(source):
    """
    WeAreDevs stores the custom base64 alphabet as a Lua charâindex lookup table.
    Every entry is: identifier = arithmetic_expr  OR  ["\\NNN"] = arithmetic_expr
    where the value evaluates to an integer 0..63.

    Example:
        local N={M=685299-685257; V=615891+-615871, ["\055"]=135105-135089, ...}

    We parse all 64 entries, evaluate their arithmetic, and reconstruct the
    alphabet string (index 0 â char, index 1 â char, â¦, index 63 â char).
    """
    # Find all large Lua table blocks in the source
    for table_match in re.finditer(r'local\s+\w+\s*=\s*\{([^}]{400,})\}', source):
        body = table_match.group(1)
        entries = {}

        # Single-letter identifier keys:  M=685299-685257
        for m in re.finditer(r'\b([A-Za-z_])\s*=\s*([-\d+*()\s]{3,60}?)(?=[,;\}]|$)', body):
            key = m.group(1)
            try:
                val = int(eval(re.sub(r'\s+', '', m.group(2))))
                if 0 <= val <= 63:
                    entries[key] = val
            except Exception:
                pass

        # Numeric-escape keys:  ["\055"]=135105-135089
        for m in re.finditer(r'\["\\(\d{1,3})"\]\s*=\s*([-\d+*()\s]{3,60}?)(?=[,;\}]|$)', body):
            key = chr(int(m.group(1)))
            try:
                val = int(eval(re.sub(r'\s+', '', m.group(2))))
                if 0 <= val <= 63:
                    entries[key] = val
            except Exception:
                pass

        if len(entries) < 60:
            continue

        # Reconstruct alphabet string indexed 0..63
        alpha_map = {v: k for k, v in entries.items()}
        if len(alpha_map) < 60:
            continue

        alphabet = ''.join(alpha_map.get(i, '') for i in range(64))
        if len(alphabet) == 64 and '?' not in alphabet and len(set(alphabet)) == 64:
            return alphabet

    # Fallback: look for a plain 64-char string literal
    for m in re.finditer(r'["\']([A-Za-z0-9+/]{64})["\']', source):
        candidate = m.group(1)
        if len(set(candidate)) == 64:
            return candidate

    return None


def _custom_b64_decode(s, alpha):
    """Decode base64 string using a custom 64-char alphabet."""
    reverse = {c: i for i, c in enumerate(alpha)}
    bits = 0; bit_count = 0; out = bytearray()
    for c in s.rstrip('='):
        if c not in reverse:
            continue
        bits = (bits << 6) | reverse[c]
        bit_count += 6
        if bit_count >= 8:
            bit_count -= 8
            out.append((bits >> bit_count) & 0xFF)
    return bytes(out)


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
# WeAreDevs string-table decoder
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def _extract_r_table_strings(source):
    """
    Extract the R string table from WeAreDevs obfuscated Lua.
    The table is: local R={"\076\049..."; "\108\084...", ...}
    Entries are separated by ; or , and all are quoted strings of numeric escapes.
    """
    # Find the R table: starts right after "local R={"
    m = re.search(r'local\s+R\s*=\s*\{(.*?)\}(?=local\s+function)', source, re.DOTALL)
    if not m:
        # Broader fallback: first large table of only quoted strings
        m = re.search(r'\{((?:\s*"[^"]*"\s*[;,]?\s*){10,})\}', source, re.DOTALL)
    if not m:
        return None

    body = m.group(1)
    # Extract all quoted values
    raw_entries = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
    if not raw_entries:
        return None

    # Decode numeric escapes to get the encoded b64 strings
    return [_decode_numeric_escapes(s) for s in raw_entries]


def _extract_shuffle_ops(source):
    """
    Extract swap operations from the shuffle loop.
    Format: for E,l in ipairs({{A;B},{C;D},...}) do ... end
    where A,B,C,D can be arithmetic expressions.
    """
    ops = []
    m = re.search(r'ipairs\s*\(\s*\{(.*?)\}\s*\)', source, re.DOTALL)
    if not m:
        return ops
    inner = m.group(1)
    for pair in re.finditer(r'\{([^}]+)\}', inner):
        parts = re.split(r'[;,]', pair.group(1))
        if len(parts) >= 2:
            try:
                a = int(eval(re.sub(r'\s+', '', parts[0])))
                b = int(eval(re.sub(r'\s+', '', parts[1])))
                ops.append((a, b))
            except Exception:
                pass
    return ops


def _wearedevs_decode(source):
    """
    Full WeAreDevs v1.0.0 deobfuscation pipeline:
      1. Extract the custom base64 alphabet from the N lookup table
      2. Extract all encoded strings from the R table
      3. Apply any shuffle operations
      4. Decode each string with the custom alphabet
      5. Return decoded strings and diagnostics
    """
    diag = {}

    # Step 1: alphabet
    alphabet = _extract_wearedevs_alphabet(source)
    diag['custom_alphabet'] = alphabet is not None
    diag['alphabet_preview'] = alphabet[:8] + '...' if alphabet else None

    if not alphabet:
        return {'success': False, 'reason': 'could not extract custom alphabet', 'diagnostics': diag}

    # Step 2: string table
    encoded_strings = _extract_r_table_strings(source)
    if not encoded_strings:
        return {'success': False, 'reason': 'could not extract R string table', 'diagnostics': diag}

    diag['string_count'] = len(encoded_strings)

    # Step 3: shuffle
    shuffle_ops = _extract_shuffle_ops(source)
    diag['shuffle_ops'] = len(shuffle_ops)
    strings = list(encoded_strings)
    for a, b in shuffle_ops:
        ai, bi = a - 1, b - 1
        if 0 <= ai < len(strings) and 0 <= bi < len(strings):
            strings[ai], strings[bi] = strings[bi], strings[ai]

    # Step 4: decode each string
    decoded = []
    for s in strings:
        if not s:
            decoded.append('')
            continue
        try:
            raw = _custom_b64_decode(s, alphabet)
            text = raw.decode('utf-8', errors='replace')
            decoded.append(text)
        except Exception:
            decoded.append(s)  # keep as-is if decode fails

    diag['decoded_count'] = len(decoded)

    # Step 5: score the output
    readable = [s for s in decoded if s and _is_probably_text(s)]
    lua_hits  = sum(1 for s in decoded if any(kw in s for kw in LUA_KEYWORDS))
    diag['readable_strings'] = len(readable)
    diag['lua_keyword_hits'] = lua_hits

    if lua_hits < 2 and len(readable) < 3:
        return {
            'success': False,
            'reason': f'decoded {len(decoded)} strings but only {lua_hits} contain Lua keywords',
            'diagnostics': diag,
            'decoded_strings': decoded,
        }

    return {
        'success': True,
        'decoded_strings': decoded,
        'reason': f'decoded {len(decoded)} strings ({lua_hits} with Lua keywords)',
        'diagnostics': diag,
    }


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
# Table helpers (for Prometheus)
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def _find_balanced_end(content, open_brace_index):
    depth = 0; quote = None; in_long_string = False; long_match = None
    idx = open_brace_index
    while idx < len(content):
        char = content[idx]
        if in_long_string:
            if char == ']' and content[idx:idx+len(long_match)] == long_match:
                in_long_string = False; idx += len(long_match); continue
            idx += 1; continue
        if quote:
            if char == '\\': idx += 2; continue
            if char == quote: quote = None
            idx += 1; continue
        if char == '[':
            m = re.match(r'\[=*\[', content[idx:])
            if m:
                long_match = ']' + m.group(0)[2:-1] + ']'; in_long_string = True
                idx += len(m.group(0)); continue
        if char in ("'", '"'): quote = char
        elif char == '{': depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0: return idx + 1
        idx += 1
    return -1


def _find_all_table_bodies(source):
    bodies = []; idx = 0
    while idx < len(source):
        brace_pos = source.find('{', idx)
        if brace_pos == -1: break
        end = _find_balanced_end(source, brace_pos)
        if end != -1:
            bodies.append(source[brace_pos:end]); idx = end
        else:
            idx = brace_pos + 1
    return bodies


def _parse_table_entries(body):
    inner = body[1:-1]; entries = []; depth = 0; current = ""
    in_str = False; quote = None; in_long_str = False; long_match = None; i = 0
    while i < len(inner):
        c = inner[i]
        if in_long_str:
            current += c
            if c == ']' and i + len(long_match) <= len(inner) and inner[i:i+len(long_match)] == long_match:
                in_long_str = False; current += long_match[1:]; i += len(long_match); continue
            i += 1; continue
        if in_str:
            current += c
            if c == '\\':
                if i + 1 < len(inner): current += inner[i+1]; i += 2; continue
            elif c == quote: in_str = False
            i += 1; continue
        if c == '[':
            m = re.match(r'\[=*\[', inner[i:])
            if m:
                long_match = ']' + m.group(0)[2:-1] + ']'; in_long_str = True
                current += m.group(0); i += len(m.group(0)); continue
        if c in ('"', "'"): in_str = True; quote = c; current += c; i += 1; continue
        if c == '{': depth += 1; current += c; i += 1; continue
        if c == '}': depth -= 1; current += c; i += 1; continue
        if c in (',', ';') and depth == 0:
            entries.append(current.strip()); current = ""; i += 1; continue
        current += c; i += 1
    if current.strip(): entries.append(current.strip())
    parsed = []
    for e in entries:
        if not e: continue
        e = e.strip()
        if e.lstrip('-').isdigit(): parsed.append(int(e))
        elif e.replace('.', '', 1).lstrip('-').isdigit(): parsed.append(float(e))
        elif (e.startswith('"') and e.endswith('"')) or (e.startswith("'") and e.endswith("'")): parsed.append(e[1:-1])
        elif e.startswith('[[') and e.endswith(']]'): parsed.append(e[2:-2])
        else: parsed.append(e)
    return parsed


@dataclass
class DiagnosticEvent:
    stage: str
    success: bool
    message: str
    line: Optional[int] = None
    column: Optional[int] = None
    snippet: Optional[str] = None
    exception_type: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


class DeobfEngine:
    def __init__(self):
        self.unluac_path = UNLUAC_LOCAL_PATH
        self._java_available = shutil.which('java') is not None
        self.trace = []

    def get_capabilities(self):
        return {
            'lua_harness': True,
            'prometheus_vm': True,
            'wearedevs_decode': True,
            'unluac': self._java_available and os.path.isfile(self.unluac_path),
            'luaparser': HAS_LUAPARSER,
        }

    def _trace(self, stage, success, message):
        self.trace.append(DiagnosticEvent(stage=stage, success=success, message=message))

    def _set_process_limits(self):
        try:
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_CPU, (40, 45))
            resource.setrlimit(resource.RLIMIT_NPROC, (30, 30))
            resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
        except Exception:
            pass

    def _run_lua_harness(self, source):
        harness = r'''
local captures = {}
local hook_stats = {loadstring=0,load=0,char=0,concat=0,insert=0,pcall=0,bytecode=0,env_string=0,rejected_size=0}
local CALL_DEPTH = 0
local MAX_DEPTH = 25
local b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
local function b64encode(data)
    local result = {}
    local padding = ""
    for i = 1, #data, 3 do
        local a, b, c = data:byte(i, i+2)
        b = b or 0; c = c or 0
        local n = a * 65536 + b * 256 + c
        local c1 = math.floor(n / 262144) % 64
        local c2 = math.floor(n / 4096) % 64
        local c3 = math.floor(n / 64) % 64
        local c4 = n % 64
        table.insert(result, b64chars:sub(c1+1, c1+1))
        table.insert(result, b64chars:sub(c2+1, c2+1))
        if i + 1 > #data then padding = "=="; break end
        table.insert(result, b64chars:sub(c3+1, c3+1))
        if i + 2 > #data then padding = "="; break end
        table.insert(result, b64chars:sub(c4+1, c4+1))
    end
    return table.concat(result) .. padding
end
local real_insert = table.insert
local function save(tag, data)
    if type(data) ~= "string" then return end
    if #data < 20 then hook_stats["rejected_size"] = (hook_stats["rejected_size"] or 0) + 1; return end
    if CALL_DEPTH > MAX_DEPTH then return end
    CALL_DEPTH = CALL_DEPTH + 1
    real_insert(captures, {tag=tag, data=b64encode(data), raw_length=#data})
    CALL_DEPTH = CALL_DEPTH - 1
end
local real_loadstring = loadstring
local real_load = load or loadstring
local INSIDE_LOAD = false
_G.loadstring = function(code, ...)
    hook_stats.loadstring = (hook_stats.loadstring or 0) + 1
    if not INSIDE_LOAD then INSIDE_LOAD = true; save("loadstring", code); INSIDE_LOAD = false end
    return real_loadstring(code, ...)
end
if load then
    _G.load = function(code, ...)
        hook_stats.load = (hook_stats.load or 0) + 1
        if not INSIDE_LOAD then INSIDE_LOAD = true; save("load", code); INSIDE_LOAD = false end
        return real_load(code, ...)
    end
end
local real_char = string.char
string.char = function(...)
    hook_stats.char = (hook_stats.char or 0) + 1
    local out = real_char(...)
    if #out > 40 then save("string_char", out) end
    return out
end
local real_concat = table.concat
table.concat = function(t, sep, i, j)
    hook_stats.concat = (hook_stats.concat or 0) + 1
    local out = real_concat(t, sep, i, j)
    if type(out) == "string" and #out > 80 then save("concat", out) end
    return out
end
local real_insert_hook = table.insert
table.insert = function(t, v, ...)
    hook_stats.insert = (hook_stats.insert or 0) + 1
    if type(v) == "string" and #v > 20 then save("table_insert", v) end
    return real_insert_hook(t, v, ...)
end
local real_pcall = pcall
_G.pcall = function(fn, ...)
    hook_stats.pcall = (hook_stats.pcall or 0) + 1
    if type(fn) == "function" and debug and debug.getinfo then
        local info = debug.getinfo(fn)
        if info and info.what == "Lua" then
            local ok, dumped = real_pcall(string.dump, fn)
            if ok and dumped and #dumped > 50 then save("pcall_fn", dumped) end
        end
    end
    return real_pcall(fn, ...)
end
if string.dump then
    local real_dump = string.dump
    string.dump = function(fn, ...)
        hook_stats.bytecode = (hook_stats.bytecode or 0) + 1
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
else
    local bit32 = bit32 or nil
    if not bit32 then
        local function bxor(a,b) local r,m=0,1; while a>0 or b>0 do local ab,bb=a%2,b%2; if ab~=bb then r=r+m end; a,b,m=math.floor(a/2),math.floor(b/2),m*2 end; return r end
        local function band(a,b) local r,m=0,1; while a>0 and b>0 do if a%2+b%2==2 then r=r+m end; a,b,m=math.floor(a/2),math.floor(b/2),m*2 end; return r end
        local function bor(a,b)  local r,m=0,1; while a>0 or b>0  do if a%2+b%2>0  then r=r+m end; a,b,m=math.floor(a/2),math.floor(b/2),m*2 end; return r end
        bit32={bxor=bxor,band=band,bor=bor,lshift=function(v,n) return math.floor(v*(2^n))%4294967296 end,rshift=function(v,n) return math.floor(v/(2^n)) end}
        bit32.arshift=bit32.rshift
    end
    _G.bit32=bit32; _G.bit=bit32
    if debug and debug.sethook then debug.sethook(function() error("instruction limit") end,"",500000) end
    local success, result = pcall(f)
    if debug and debug.sethook then debug.sethook() end
    collectgarbage("collect")
    pcall(function()
        for k,v in pairs(_G) do
            if type(v)=="string" and #v>20 then hook_stats.env_string=(hook_stats.env_string or 0)+1; save("env_string",v) end
        end
    end)
    for _,cap in ipairs(captures) do print("CAP:"..cap.tag..":"..cap.data) end
    if #captures==0 then
        if not success then print("ERR:RUNTIME:"..tostring(result))
        else print("ERR:NO_OUTPUT") end
    end
end
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as src_tmp:
            src_tmp.write(source); src_path = src_tmp.name
        harness = harness.replace('_SRCFILE_', src_path)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as tmp:
            tmp.write(harness); tmp_path = tmp.name
        captures = []
        try:
            for lua_bin in ['lua5.1', 'lua']:
                try:
                    proc = subprocess.Popen(
                        [lua_bin, tmp_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        preexec_fn=self._set_process_limits, start_new_session=True)
                    try:
                        stdout, _ = proc.communicate(timeout=45)
                        stdout = stdout.decode('latin-1', errors='replace')
                    except subprocess.TimeoutExpired:
                        try: os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        except: pass
                        proc.wait(); break
                    for line in stdout.splitlines():
                        if line.startswith('CAP:'):
                            captures.append(line[4:])
                    if captures: break
                except FileNotFoundError:
                    continue
        finally:
            for p in (tmp_path, src_path):
                try: os.unlink(p)
                except OSError: pass
        if captures:
            candidates = []
            for cap in captures:
                tag, data = cap.split(':', 1) if ':' in cap else ('unknown', cap)
                try:
                    decoded_data = base64.b64decode(data).decode('latin-1', errors='replace')
                except Exception:
                    decoded_data = data
                if _is_self_capture(decoded_data): continue
                if not _is_probably_text(decoded_data):
                    raw_check = decoded_data.encode('latin-1', errors='ignore')
                    if _is_lua_bytecode(raw_check) and self._java_available:
                        try:
                            dec, _ = self._run_unluac(raw_check)
                            if dec: decoded_data = dec
                        except: pass
                    else:
                        if sum(1 for kw in LUA_KEYWORDS if kw in decoded_data) < 3: continue
                candidates.append({'data': decoded_data, 'tag': tag})
            if candidates:
                return max(candidates, key=lambda x: len(x['data']))['data']
        return None

    def _run_unluac(self, bytecode):
        if not self._java_available: return None, "no java"
        if not os.path.isfile(self.unluac_path): self._ensure_unluac_jar()
        if not os.path.isfile(self.unluac_path): return None, "no unluac.jar"
        if bytecode[:4] != b'\x1bLua': return None, "not lua bytecode"
        with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
            tmp.write(bytecode); tmp_path = tmp.name
        try:
            r = subprocess.run(['java', '-jar', self.unluac_path, '--rawstring', tmp_path],
                               capture_output=True, timeout=10)
            stdout = r.stdout.decode('latin-1', errors='replace')
            return (stdout, None) if r.returncode == 0 and stdout.strip() else (None, "unluac failed")
        except subprocess.TimeoutExpired: return None, "timeout"
        except Exception as e: return None, str(e)
        finally:
            try: os.unlink(tmp_path)
            except: pass

    def _ensure_unluac_jar(self):
        try:
            os.makedirs(os.path.dirname(self.unluac_path), exist_ok=True)
            urllib.request.urlretrieve(UNLUAC_JAR_URL, self.unluac_path)
        except: pass

    def _detect_prometheus_vm(self, source):
        score = sum(1 for p in [r'pc\s*=', r'opcode', r'instructions?\[',
                                  r'while\s+true\s+do', r'bit32', r'band\(']
                    if re.search(p, source))
        return score >= 3

    def _prometheus_decompile(self, source):
        bodies = _find_all_table_bodies(source)
        instructions = []
        for body in bodies:
            entries = _parse_table_entries(body)
            nums = [e for e in entries if isinstance(e, int)]
            if len(nums) >= 10: instructions = nums; break
        if not instructions:
            m = re.search(r'\{([\d,\s]{50,})\}', source)
            if m:
                instructions = [int(n.strip()) for n in m.group(1).split(',') if n.strip().isdigit()]
        constants = []
        cm = re.search(r'local\s+\w+\s*=\s*\{([^}]+)\}', source)
        if cm:
            constants = [e for e in _parse_table_entries('{' + cm.group(1) + '}') if isinstance(e, str)]
        if not instructions: return None
        lines = []; ip = 0
        while ip < len(instructions):
            op = instructions[ip]; ip += 1
            if op == 0:
                idx = instructions[ip] if ip < len(instructions) else 0; ip += 1
                lines.append(f"loadk {json.dumps(constants[idx-1] if 1 <= idx <= len(constants) else 'nil')}")
            elif op == 1:
                a = instructions[ip] if ip < len(instructions) else 0; ip += 1
                b = instructions[ip] if ip < len(instructions) else 0; ip += 1
                lines.append(f"{constants[a-1] if 1<=a<=len(constants) else f'var{a}'} = {constants[b-1] if 1<=b<=len(constants) else f'var{b}'}")
            elif op == 2:
                a = instructions[ip] if ip < len(instructions) else 0; ip += 1
                lines.append(f"call {constants[a-1] if 1<=a<=len(constants) else f'var{a}'}")
            else:
                lines.append(f"-- op {op}")
        return '\n'.join(lines)

    def process(self, source):
        self.trace = []

        # Outer base64 peel
        cleaned = re.sub(r'\s+', '', source.strip())
        if re.match(r'^[A-Za-z0-9+/=]+$', cleaned):
            decoded = _try_base64_decode(cleaned)
            if decoded:
                for enc in ('utf-8', 'latin-1'):
                    try:
                        text = decoded.decode(enc, errors='replace')
                        if len(text) > 50:
                            source = text
                            self._trace("base64_peel", True, f"outer base64 decoded ({len(text)} chars)")
                            break
                    except: pass

        # WeAreDevs (primary strategy â runs before Prometheus)
        self._trace("wearedevs_detect", True, "checking for WeAreDevs obfuscation")
        wd = _wearedevs_decode(source)
        if wd['success']:
            decoded_strings = wd['decoded_strings']
            diag = wd['diagnostics']
            self._trace("wearedevs_decode", True,
                        f"decoded {diag.get('decoded_count',0)} strings, "
                        f"{diag.get('lua_keyword_hits',0)} with Lua keywords")
            # Build a readable summary output of the string table
            output_lines = []
            for i, s in enumerate(decoded_strings):
                if s:
                    output_lines.append(f"-- [{i}] {s!r}")
            result = '\n'.join(output_lines)
            return result, 'wearedevs_decode', wd['reason'], [vars(t) for t in self.trace]
        else:
            self._trace("wearedevs_decode", False,
                        f"{wd['reason']} | diag: {json.dumps(wd.get('diagnostics', {}))}")

        # Prometheus VM
        if self._detect_prometheus_vm(source):
            self._trace("prometheus_detect", True, "Prometheus VM detected")
            result = self._prometheus_decompile(source)
            if result and len(result) >= 50 and _is_probably_text(result):
                self._trace("prometheus_decompile", True, f"{len(result)} chars")
                return result, 'prometheus_vm', 'Prometheus VM decompiled', [vars(t) for t in self.trace]

        # Lua harness
        self._trace("lua_harness", True, "running Lua execution harness")
        harness_result = self._run_lua_harness(source)
        if harness_result:
            self._trace("lua_harness", True, f"captured {len(harness_result)} chars")
            return harness_result, 'lua_harness', 'Lua harness capture', [vars(t) for t in self.trace]
        self._trace("lua_harness", False, "harness produced no output")

        diag_msg = json.dumps(wd.get('diagnostics', {}), indent=2)
        return '', 'unable', f'no strategies produced output\n{diag_msg}', [vars(t) for t in self.trace]


job_store = {}
job_lock = threading.Lock()


def _run_job(job_id, source):
    engine = DeobfEngine()
    try:
        result, method, diagnostic, trace = engine.process(source)
        with job_lock:
            job_store[job_id] = {
                'status': 'complete', 'result': result, 'detected': method,
                'diagnostic': diagnostic, 'trace': trace,
                'result_length': len(result) if result else 0
            }
    except Exception as e:
        with job_lock:
            job_store[job_id] = {
                'status': 'error', 'error': str(e),
                'traceback': traceback.format_exc()[:4000]
            }


def submit_job(source):
    job_id = str(uuid.uuid4())
    with job_lock:
        job_store[job_id] = {'status': 'processing', 'created': time.time()}
    threading.Thread(target=_run_job, args=(job_id, source), daemon=True).start()
    return job_id


def get_job(job_id):
    with job_lock:
        return job_store.get(job_id)
