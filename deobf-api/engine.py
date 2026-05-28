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


def _try_base64_decode(s):
    try:
        padded = s + '=' * (-len(s) % 4)
        return base64.b64decode(padded)
    except:
        return None


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
        e = e.strip()
        if e.lstrip('-').isdigit():
            parsed.append(int(e))
        elif e.replace('.', '', 1).lstrip('-').isdigit():
            parsed.append(float(e))
        elif (e.startswith('"') and e.endswith('"')) or (e.startswith("'") and e.endswith("'")):
            parsed.append(e[1:-1])
        elif e.startswith('[[') and e.endswith(']]'):
            parsed.append(e[2:-2])
        else:
            parsed.append(e)
    return parsed


class DeobfEngine:
    def __init__(self):
        self.unluac_path = UNLUAC_LOCAL_PATH
        self._java_available = shutil.which('java') is not None

    def _set_process_limits(self):
        try:
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_CPU, (40, 45))
            resource.setrlimit(resource.RLIMIT_NPROC, (30, 30))
            resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
        except:
            pass

    def _run_lua_harness(self, source):
        harness = r'''
local captures = {}
local hook_stats = {loadstring=0, load=0, char=0, concat=0, insert=0, pcall=0, bytecode=0, env_string=0, rejected_size=0}
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

local real_insert = table.insert

local function save(tag, data)
    if type(data) ~= "string" then return end
    if #data < 20 then
        hook_stats["rejected_size"] = (hook_stats["rejected_size"] or 0) + 1
        return
    end
    if CALL_DEPTH > MAX_DEPTH then return end
    CALL_DEPTH = CALL_DEPTH + 1
    local encoded = b64encode(data)
    real_insert(captures, {tag = tag, data = encoded, raw_length = #data})
    CALL_DEPTH = CALL_DEPTH - 1
end

local real_loadstring = loadstring
local real_load = load or loadstring
local INSIDE_LOAD = false

_G.loadstring = function(code, ...)
    hook_stats.loadstring = (hook_stats.loadstring or 0) + 1
    if not INSIDE_LOAD then
        INSIDE_LOAD = true
        save("loadstring", code)
        INSIDE_LOAD = false
    end
    return real_loadstring(code, ...)
end
if load then
    _G.load = function(code, ...)
        hook_stats.load = (hook_stats.load or 0) + 1
        if not INSIDE_LOAD then
            INSIDE_LOAD = true
            save("load", code)
            INSIDE_LOAD = false
        end
        return real_load(code, ...)
    end
end

local real_char = string.char
string.char = function(...)
    hook_stats.char = (hook_stats.char or 0) + 1
    local out = real_char(...)
    if #out > 40 then
        save("string_char", out)
    end
    return out
end

local real_concat = table.concat
table.concat = function(t, sep, i, j)
    hook_stats.concat = (hook_stats.concat or 0) + 1
    local out = real_concat(t, sep, i, j)
    if type(out) == "string" and #out > 80 then
        save("concat", out)
    end
    return out
end

local real_insert_hook = table.insert
table.insert = function(t, v, ...)
    hook_stats.insert = (hook_stats.insert or 0) + 1
    if type(v) == "string" and #v > 20 then
        save("table_insert", v)
    end
    return real_insert_hook(t, v, ...)
end

local real_pcall = pcall
_G.pcall = function(fn, ...)
    hook_stats.pcall = (hook_stats.pcall or 0) + 1
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
        end, "", 500000)
    end

    local success, result = pcall(f)

    if debug and debug.sethook then
        debug.sethook()
    end

    collectgarbage("collect")

    pcall(function()
        for k, v in pairs(_G) do
            if type(v) == "string" and #v > 20 then
                hook_stats.env_string = (hook_stats.env_string or 0) + 1
                save("env_string", v)
            end
        end
    end)

    for _, cap in ipairs(captures) do
        print("CAP:" .. cap.tag .. ":" .. cap.data)
    end

    if #captures == 0 then
        if not success then
            print("ERR:RUNTIME:" .. tostring(result))
        else
            print("ERR:NO_OUTPUT")
        end
    end
end
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
                    proc = subprocess.Popen(
                        [lua_bin, tmp_path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        preexec_fn=self._set_process_limits,
                        start_new_session=True
                    )
                    try:
                        stdout, stderr = proc.communicate(timeout=45)
                        stdout = stdout.decode('latin-1', errors='replace')
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        except:
                            pass
                        proc.wait()
                        errors.append("timeout")
                        break
                    for line in stdout.splitlines():
                        if line.startswith('CAP:'):
                            captures.append(line[4:])
                    if captures:
                        break
                except FileNotFoundError:
                    continue
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
                        lua_kw_check = sum(1 for kw in LUA_KEYWORDS if kw in decoded_data)
                        if lua_kw_check < 3:
                            continue
                candidates.append({'data': decoded_data, 'tag': tag})

            if candidates:
                best = max(candidates, key=lambda x: len(x['data']))
                return best['data']

        return None

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
                timeout=10
            )
            stdout = r.stdout.decode('latin-1', errors='replace')
            if r.returncode == 0 and stdout.strip():
                return stdout, None
            return None, "unluac failed"
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

    def _detect_prometheus_vm(self, source):
        bodies = _find_all_table_bodies(source)
        for body in bodies:
            entries = _parse_table_entries(body)
            nums = [e for e in entries if isinstance(e, int)]
            if len(nums) >= 10:
                return True
        num_table_pattern = re.search(r'\{[\d,\s]{50,}\}', source)
        if num_table_pattern:
            return True
        return False

    def _prometheus_decompile(self, source):
        bodies = _find_all_table_bodies(source)
        instructions = []
        constants = []
        for body in bodies:
            entries = _parse_table_entries(body)
            nums = [e for e in entries if isinstance(e, int)]
            if len(nums) >= 10:
                instructions = nums
                break
        if not instructions:
            num_match = re.search(r'\{([\d,\s]{50,})\}', source)
            if num_match:
                nums_str = num_match.group(1)
                instructions = [int(n.strip()) for n in nums_str.split(',') if n.strip().isdigit()]
        const_match = re.search(r'local\s+(\w+)\s*=\s*\{([^}]+)\}', source)
        if const_match:
            const_body = '{' + const_match.group(2) + '}'
            const_entries = _parse_table_entries(const_body)
            constants = [e for e in const_entries if isinstance(e, str)]
        if not instructions:
            return None
        lines = []
        ip = 0
        while ip < len(instructions):
            op = instructions[ip]
            ip += 1
            if op == 0:
                idx = instructions[ip] if ip < len(instructions) else 0
                ip += 1
                val = constants[idx - 1] if 1 <= idx <= len(constants) else 'nil'
                lines.append(f"loadk {json.dumps(val)}")
            elif op == 1:
                a = instructions[ip] if ip < len(instructions) else 0
                ip += 1
                name = constants[a - 1] if 1 <= a <= len(constants) else f"var{a}"
                b = instructions[ip] if ip < len(instructions) else 0
                ip += 1
                val = constants[b - 1] if 1 <= b <= len(constants) else f"var{b}"
                lines.append(f"{name} = {val}")
            elif op == 2:
                a = instructions[ip] if ip < len(instructions) else 0
                ip += 1
                name = constants[a - 1] if 1 <= a <= len(constants) else f"var{a}"
                lines.append(f"call {name}")
            else:
                lines.append(f"-- op {op}")
        return '\n'.join(lines)

    def process(self, source):
        decoded = _try_base64_decode(source.strip())
        if decoded:
            for enc in ('utf-8', 'latin-1'):
                try:
                    decoded_str = decoded.decode(enc)
                    if len(decoded_str) > 50 and ('local' in decoded_str or 'function' in decoded_str or '{' in decoded_str):
                        source = decoded_str
                        break
                except:
                    continue

        if self._detect_prometheus_vm(source):
            result = self._prometheus_decompile(source)
            if result:
                return result, 'prometheus_vm', 'Prometheus VM decompiled', []

        harness_result = self._run_lua_harness(source)
        if harness_result:
            return harness_result, 'lua_harness', 'Lua harness capture', []

        return '', 'unable', 'no strategies produced output', []


job_store = {}
job_lock = threading.Lock()


def _run_job(job_id, source):
    engine = DeobfEngine()
    try:
        result, method, diagnostic, trace = engine.process(source)
        result_data = {
            'status': 'complete',
            'result': result,
            'detected': method,
            'diagnostic': diagnostic,
            'trace': trace,
            'result_length': len(result) if result else 0
        }
        with job_lock:
            job_store[job_id] = result_data
    except Exception as e:
        error_data = {
            'status': 'error',
            'error': str(e),
            'traceback': traceback.format_exc()[:4000]
        }
        with job_lock:
            job_store[job_id] = error_data


def submit_job(source):
    job_id = str(uuid.uuid4())
    with job_lock:
        job_store[job_id] = {'status': 'processing', 'created': time.time()}
    thread = threading.Thread(target=_run_job, args=(job_id, source), daemon=True)
    thread.start()
    return job_id


def get_job(job_id):
    with job_lock:
        return job_store.get(job_id)
