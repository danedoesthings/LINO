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
    with _suppress_stderr():
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
    if depth > 10 or max_ops[0] > 500:
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


def _repair_control_flow(code):
    if not code:
        return code
    funcs = len(re.findall(r'\bfunction\b', code))
    ends = len(re.findall(r'\bend\b', code))
    while ends < funcs:
        code = code.rstrip() + "\nend"
        ends += 1
    opens = len(re.findall(r'\b(if|for|while)\b', code))
    closes = len(re.findall(r'\bend\b', code))
    while closes < opens + funcs:
        code = code.rstrip() + "\nend"
        closes += 1
    return code


def _safe_beautify(code):
    if not code:
        return code

    class State(Enum):
        CODE = 1
        STRING_SINGLE = 2
        STRING_DOUBLE = 3
        LONG_STRING = 4
        COMMENT_LINE = 5
        COMMENT_BLOCK = 6

    state = State.CODE
    indent_level = 0
    output_lines = []
    line_buf = []
    indent_str = "    "

    outdent_keywords = {"end", "until", "else", "elseif"}
    indent_after = {"function", "then", "do", "repeat", "else", "elseif"}

    i = 0
    n = len(code)

    while i < n:
        c = code[i]

        if state == State.CODE:
            if c == '-' and i + 1 < n and code[i + 1] == '-':
                line_buf.append(c)
                line_buf.append(code[i + 1])
                i += 2
                if i < n and code[i] == '[' and i + 1 < n and code[i + 1] == '[':
                    state = State.COMMENT_BLOCK
                    line_buf.append(code[i])
                    line_buf.append(code[i + 1])
                    i += 2
                else:
                    state = State.COMMENT_LINE
                continue
            elif c == '"':
                state = State.STRING_DOUBLE
                line_buf.append(c)
                i += 1
                continue
            elif c == "'":
                state = State.STRING_SINGLE
                line_buf.append(c)
                i += 1
                continue
            elif c == '[':
                j = i
                equal_count = 0
                while j + 1 < n and code[j + 1] == '=':
                    equal_count += 1
                    j += 1
                if j + 1 < n and code[j + 1] == '[':
                    state = State.LONG_STRING
                    for _ in range(2 + equal_count):
                        line_buf.append(code[i])
                        i += 1
                    continue

            if c == '\n':
                line_str = ''.join(line_buf).rstrip('\n\r')
                if line_str:
                    trimmed = line_str.lstrip()
                    first_word = trimmed.split()[0] if trimmed else ''
                    if first_word in outdent_keywords:
                        indent_level = max(0, indent_level - 1)
                    output_lines.append(indent_str * indent_level + trimmed)
                    last_word = trimmed.rsplit()[-1] if trimmed.split() else ''
                    if last_word in indent_after:
                        indent_level += 1
                line_buf = []
                i += 1
                continue

            line_buf.append(c)
            i += 1

        elif state == State.STRING_DOUBLE:
            line_buf.append(c)
            if c == '\\' and i + 1 < n:
                line_buf.append(code[i + 1])
                i += 2
                continue
            if c == '"':
                state = State.CODE
            i += 1

        elif state == State.STRING_SINGLE:
            line_buf.append(c)
            if c == '\\' and i + 1 < n:
                line_buf.append(code[i + 1])
                i += 2
                continue
            if c == "'":
                state = State.CODE
            i += 1

        elif state == State.LONG_STRING:
            line_buf.append(c)
            if c == ']':
                j = i + 1
                equal_count = 0
                while j < n and code[j] == '=':
                    equal_count += 1
                    j += 1
                if j < n and code[j] == ']':
                    for _ in range(1 + equal_count):
                        line_buf.append(code[i])
                        i += 1
                    state = State.CODE
                    continue
            i += 1

        elif state == State.COMMENT_LINE:
            line_buf.append(c)
            if c == '\n':
                state = State.CODE
            i += 1

        elif state == State.COMMENT_BLOCK:
            line_buf.append(c)
            if c == ']':
                j = i + 1
                equal_count = 0
                while j < n and code[j] == '=':
                    equal_count += 1
                    j += 1
                if j < n and code[j] == ']':
                    for _ in range(1 + equal_count):
                        line_buf.append(code[i])
                        i += 1
                    state = State.CODE
                    continue
            i += 1

    if line_buf:
        line_str = ''.join(line_buf).rstrip('\n\r')
        if line_str:
            trimmed = line_str.lstrip()
            first_word = trimmed.split()[0] if trimmed else ''
            if first_word in outdent_keywords:
                indent_level = max(0, indent_level - 1)
            output_lines.append(indent_str * indent_level + trimmed)

    return '\n'.join(output_lines)


class DeobfEngine:
    def __init__(self):
        self.unluac_path = UNLUAC_LOCAL_PATH
        self.visited_hashes = set()
        self.seen_captures = set()
        self.decode_operations = 0
        self._java_available = shutil.which('java') is not None

    def _set_process_limits(self):
        try:
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_CPU, (40, 45))
            resource.setrlimit(resource.RLIMIT_NPROC, (30, 30))
            resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
        except:
            pass

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
        return best

    def _detect_prometheus_vm(self, source):
        bodies = _find_all_table_bodies(source)
        for body in bodies:
            entries = _parse_table_entries(body)
            nums = [e for e in entries if isinstance(e, int)]
            if len(nums) > 50:
                return True
        return False

    def _prometheus_decompile(self, source):
        bodies = _find_all_table_bodies(source)
        instructions = []
        constants = []
        for body in bodies:
            entries = _parse_table_entries(body)
            nums = [e for e in entries if isinstance(e, int)]
            if len(nums) > 50:
                instructions = nums
                break
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
        if self._detect_prometheus_vm(source):
            result = self._prometheus_decompile(source)
            if result:
                return result, 'prometheus_vm', 'Prometheus VM decompiled', []

        return '', 'unable', 'no strategies produced output', []

    def _extract_alphabet_enhanced(self, source):
        return None, None

    def _extract_encoded_data_enhanced(self, source, alphabet_var, all_table_bodies):
        return None

    def _extract_shuffle(self, source):
        return None

    def _decode_prometheus(self, encoded_chunks, alphabet, shuffle_ranges):
        return None

    def _validate_lua(self, code):
        if not code or len(code) < 20:
            return False
        if HAS_LUAPARSER:
            try:
                lua_ast.parse(code)
                return True
            except Exception:
                pass
        return False

    def _ensure_unluac_jar(self):
        pass


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
