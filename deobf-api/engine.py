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
        s = s.replace('-', '+').replace('_', '/')
        padded = s + '=' * (-len(s) % 4)
        return base64.b64decode(padded, validate=True)
    except:
        return None


def _extract_custom_b64_alphabet(source):
    for m in re.finditer(r'["\'`]([A-Za-z0-9+/]{64})[\"\'`]', source):
        candidate = m.group(1)
        if len(set(candidate)) == 64:
            return candidate
    for m in re.finditer(r'local\s+\w+\s*=\s*["\'`]([A-Za-z0-9+/]{60,})[\"\'`]', source):
        candidate = m.group(1)[:64]
        if len(candidate) == 64 and len(set(candidate)) == 64:
            return candidate
    concat_m = re.search(r'["\'`]([A-Za-z0-9+/]{20,})[\"\'`]\s*\.\.\s*["\'`]([A-Za-z0-9+/]{20,})[\"\'`]', source)
    if concat_m:
        combined = concat_m.group(1) + concat_m.group(2)
        if len(combined) >= 64 and len(set(combined[:64])) == 64:
            return combined[:64]
    return None


def _custom_b64_decode(s, alpha):
    reverse = {c: i for i, c in enumerate(alpha)}
    s_clean = s.rstrip('=')
    bits = 0
    bit_count = 0
    out = bytearray()
    for c in s_clean:
        if c not in reverse:
            continue
        bits = (bits << 6) | reverse[c]
        bit_count += 6
        if bit_count >= 8:
            bit_count -= 8
            out.append((bits >> bit_count) & 0xFF)
    return bytes(out)


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


def _join_concat_literals(source):
    pattern = r'"([^"]*)"\s*\.\.\s*"([^"]*)"'
    while re.search(pattern, source):
        source = re.sub(
            pattern,
            lambda m: '"' + m.group(1) + m.group(2) + '"',
            source
        )
    return source


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
        if c in (',', ';') and depth == 0:
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


def _decode_numeric_escapes(s):
    return re.sub(
        r'\\(\d{1,3})',
        lambda m: chr(int(m.group(1)) % 256),
        s
    )


def _extract_shuffle_pairs(source):
    pairs = []
    for body in _find_all_table_bodies(source):
        if re.search(r'\{\s*\d+\s*,\s*\d+\s*\}', body):
            nested = re.findall(r'\{\s*(-?\d+)\s*,\s*(-?\d+)\s*\}', body)
            for a, b in nested:
                pairs.append((int(a), int(b)))
    return pairs


def _extract_b64_substrings(s):
    s = re.sub(r'"\s*\.\.\s*"', '', s)
    s = re.sub(r"'\s*\.\.\s*'", '', s)
    results = []
    for m in re.finditer(r'"([^"]+)"|\'([^\']+)\'', s):
        val = (m.group(1) or m.group(2)).strip()
        if val and re.match(r'^[A-Za-z0-9+/]+=*$', val):
            results.append(val)
    if results:
        return results
    for part in re.split(r'[;,]', s):
        part = part.strip().strip('"\'')
        if part and re.match(r'^[A-Za-z0-9+/]+=*$', part):
            results.append(part)
    if results:
        return results
    cleaned = s.strip().strip('"\'')
    if cleaned and re.match(r'^[A-Za-z0-9+/]+=*$', cleaned):
        results.append(cleaned)
    return results


def _merge_b64_fragments(chunks):
    merged = []
    current = ""
    for chunk in chunks:
        current += chunk
        if len(current) % 4 == 0:
            merged.append(current)
            current = ""
    if current:
        merged.append(current)
    return merged


def _recursive_decode(data, depth=0):
    if depth > 4:
        return data
    original = data
    if isinstance(data, str):
        data = _decode_numeric_escapes(data)
        b64 = _try_base64_decode(data)
        if b64:
            try:
                data = b64.decode('utf-8', errors='replace')
            except:
                pass
        rev = data[::-1]
        if _lua_score(rev) > _lua_score(data):
            data = rev
        if re.fullmatch(r'[0-9a-fA-F]+', data):
            try:
                data = bytes.fromhex(data).decode('utf-8', errors='replace')
            except:
                pass
        if data == original:
            return data
        return _recursive_decode(data, depth + 1)
    return data


def _lua_score(text):
    score = 0
    keyword_hits = sum(1 for kw in LUA_KEYWORDS if kw in text)
    score += keyword_hits * 8
    structural_patterns = [
        r'local\s+\w+',
        r'function\s*\(',
        r'\w+\s*=\s*',
        r'end\b',
        r'return\b',
        r'if\s+.+\s+then',
    ]
    for pattern in structural_patterns:
        if re.search(pattern, text):
            score += 15
    entropy = _shannon_entropy(text.encode(errors='ignore'))
    if entropy < 7:
        score += 10
    if len(text.splitlines()) > 3:
        score += 10
    if text.count("(") == text.count(")"):
        score += 10
    funcs = text.count("function")
    ends = text.count("end")
    if funcs > 0 and ends >= funcs:
        score += 25
    return score


def _extract_loader_payloads(source):
    payloads = []
    patterns = [
        r'loadstring\s*\((.*?)\)',
        r'load\s*\((.*?)\)',
    ]
    for pattern in patterns:
        for m in re.finditer(pattern, source, re.S):
            payloads.append(m.group(1))
    return payloads


def _wearedevs_decode(source):
    source = _join_concat_literals(source)
    alphabet = _extract_custom_b64_alphabet(source)
    diagnostics = {
        "table_count": 0,
        "candidate_tables": 0,
        "base64_chunks": 0,
        "decoded_chunks": 0,
        "lua_score": 0,
        "entropy": None,
        "rejections": [],
        "custom_alphabet": alphabet is not None
    }
    bodies = _find_all_table_bodies(source)
    diagnostics["table_count"] = len(bodies)
    if not bodies:
        return {"success": False, "reason": "no table bodies found", "diagnostics": diagnostics}
    for body_index, body in enumerate(bodies):
        entries = _parse_table_entries(body)
        strings = [e for e in entries if isinstance(e, str) and len(e) > 2]
        string_count = len(strings)
        if string_count < 3:
            diagnostics["rejections"].append({
                "table": body_index, "reason": "not enough strings",
                "string_count": string_count
            })
            continue
        diagnostics["candidate_tables"] += 1
        step1 = [_decode_numeric_escapes(s) if '\\' in s else s for s in strings]
        all_chunks = []
        for s in step1:
            decoded = _recursive_decode(s)
            if isinstance(decoded, str) and re.match(r'^[A-Za-z0-9+/]+=*$', decoded.strip()):
                all_chunks.append(decoded.strip())
                diagnostics["base64_chunks"] += 1
            else:
                sub = _extract_b64_substrings(decoded if isinstance(decoded, str) else s)
                if sub:
                    all_chunks.extend(sub)
                    diagnostics["base64_chunks"] += len(sub)
        chunk_count = len(all_chunks)
        if chunk_count < 3:
            diagnostics["rejections"].append({
                "table": body_index, "reason": "not enough base64 chunks",
                "string_count": string_count,
                "chunk_count": chunk_count
            })
            continue
        all_chunks = _merge_b64_fragments(all_chunks)
        swaps = _extract_shuffle_pairs(source)
        for a, b in swaps:
            ai, bi = a - 1, b - 1
            if 0 <= ai < len(all_chunks) and 0 <= bi < len(all_chunks):
                all_chunks[ai], all_chunks[bi] = all_chunks[bi], all_chunks[ai]
        decoded_chunks = []
        for chunk in all_chunks:
            if alphabet:
                try:
                    b64 = _custom_b64_decode(chunk, alphabet)
                except Exception:
                    b64 = None
            else:
                b64 = _try_base64_decode(chunk)
            if not b64:
                continue
            for enc in ('utf-8', 'latin-1'):
                try:
                    text = b64.decode(enc, errors='replace')
                    decoded_chunks.append(text)
                    diagnostics["decoded_chunks"] += 1
                    break
                except Exception:
                    pass
        if not decoded_chunks:
            diagnostics["rejections"].append({
                "table": body_index, "reason": "no decodable chunks",
                "string_count": string_count,
                "chunk_count": chunk_count
            })
            continue
        candidates = []
        for chunk in decoded_chunks:
            score = _lua_score(chunk)
            if score > 20:
                candidates.append((score, chunk))
        if candidates:
            full_text = max(candidates, key=lambda x: x[0])[1]
        else:
            full_text = ''.join(decoded_chunks)
        diagnostics["entropy"] = round(_shannon_entropy(full_text.encode()), 3)
        score = _lua_score(full_text)
        diagnostics["lua_score"] = score
        if score < 15:
            diagnostics["rejections"].append({
                "table": body_index, "reason": "lua score too low",
                "string_count": string_count,
                "chunk_count": chunk_count,
                "score": score
            })
            continue
        loader_payloads = _extract_loader_payloads(full_text)
        if loader_payloads:
            for payload in loader_payloads:
                rec_result = _recursive_decode(payload)
                if isinstance(rec_result, str) and _lua_score(rec_result) > _lua_score(full_text):
                    full_text = rec_result
        return {"success": True, "output": full_text, "reason": "decoded successfully", "diagnostics": diagnostics}
    return {"success": False, "reason": "all candidate tables rejected", "diagnostics": diagnostics}


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

    def _trace(self, stage, success, message, line=None, column=None, snippet=None, exc=None):
        self.trace.append(DiagnosticEvent(
            stage=stage, success=success, message=message,
            line=line, column=column, snippet=snippet,
            exception_type=type(exc).__name__ if exc else None
        ))

    def _validate_lua(self, code, stage="unknown"):
        if not HAS_LUAPARSER:
            self._trace(stage, True, "luaparser not available, skipping validation")
            return {"valid": True}
        try:
            with _suppress_stderr():
                lua_ast.parse(code)
            self._trace(stage, True, "lua validation passed")
            return {"valid": True}
        except Exception as e:
            info = self._extract_parse_error(code, e)
            self._trace(stage, False, str(e), line=info.get("line"),
                       column=info.get("column"), snippet=info.get("snippet"), exc=e)
            return {"valid": False, "error": str(e), "line": info.get("line"),
                    "column": info.get("column"), "snippet": info.get("snippet")}

    def _extract_parse_error(self, code, error):
        text = str(error)
        line, column = None, None
        m = re.search(r'line\s+(\d+)', text, re.I)
        if m:
            line = int(m.group(1))
        c = re.search(r'column\s+(\d+)', text, re.I)
        if c:
            column = int(c.group(1))
        snippet = None
        if line:
            lines = code.splitlines()
            start = max(0, line - 3)
            end = min(len(lines), line + 2)
            context = []
            for i in range(start, end):
                prefix = ">>" if i + 1 == line else "  "
                context.append(f"{prefix} {i+1}: {lines[i]}")
            snippet = "\n".join(context)
        return {"line": line, "column": column, "snippet": snippet}

    def _token_diagnostics(self, code):
        if not HAS_LUAPARSER:
            return []
        issues = []
        try:
            lexer = LuaLexer()
            tokens = list(lexer.get_tokens(code))
            for i in range(len(tokens)-1):
                cur = str(tokens[i][1])
                nxt = str(tokens[i+1][1])
                combo = cur + nxt
                if re.search(r'\d+end\b', combo):
                    issues.append({"type": "missing_separator_number_end", "tokens": combo})
                if combo == "endlocal":
                    issues.append({"type": "missing_separator_end_local", "tokens": combo})
                if combo == "thenlocal":
                    issues.append({"type": "missing_separator_then_local", "tokens": combo})
                if combo == ".. ..":
                    issues.append({"type": "broken_concat"})
                if combo == "..." or combo == "....":
                    issues.append({"type": "vararg_corruption"})
        except Exception as e:
            issues.append({"type": "tokenizer_failure", "error": str(e)})
        return issues

    def _auto_fix(self, code):
        fixes = [
            (r'(?<=\d)(end\b)', r'\n\1'),
            (r'end\s+local', 'end\nlocal'),
            (r'\.\s+\.', '..'),
            (r',\s*,', ','),
            (r'(?<=\))(local\b)', r'\n\1'),
            (r'end(function\b)', r'end\n\1'),
            (r'until(local\b)', r'until\n\1'),
        ]
        for pattern, repl in fixes:
            code = re.sub(pattern, repl, code)
        return code

    def _save_snapshot(self, stage, content):
        os.makedirs("snapshots", exist_ok=True)
        path = os.path.join("snapshots", f"{int(time.time())}_{stage}.lua")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def _detect_prometheus_vm(self, source):
        vm_score = 0
        patterns = [
            r'pc\s*=',
            r'opcode',
            r'instructions?\[',
            r'while\s+true\s+do',
            r'bit32',
            r'band\(',
        ]
        for p in patterns:
            if re.search(p, source):
                vm_score += 1
        return vm_score >= 3

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
        self.trace = []
        candidates = [source]
        last_wd_diag = None

        cleaned = re.sub(r'\s+', '', source.strip())
        if re.match(r'^[A-Za-z0-9+/=]+$', cleaned):
            decoded = _try_base64_decode(cleaned)
            if decoded:
                for enc in ('utf-8', 'latin-1'):
                    try:
                        text = decoded.decode(enc, errors='replace')
                        if len(text) > 50:
                            candidates.insert(0, text)
                            self._trace("base64_peel", True, f"decoded outer base64, {len(text)} chars")
                            break
                    except:
                        pass
                else:
                    self._trace("base64_peel", False, "base64 decoded but no text encoding succeeded")

        for src in candidates:
            if self._detect_prometheus_vm(src):
                self._trace("prometheus_detect", True, "VM bytecode table detected")
                result = self._prometheus_decompile(src)
                if result:
                    self._trace("prometheus_decompile", True, f"decompiled {len(result)} chars")
                    if len(result) >= 50 and _is_probably_text(result):
                        validation = self._validate_lua(result, "prometheus_output")
                        if validation["valid"]:
                            return result, 'prometheus_vm', 'Prometheus VM decompiled', [vars(t) for t in self.trace]
                        else:
                            repaired = self._auto_fix(result)
                            if self._validate_lua(repaired, "prometheus_repaired")["valid"]:
                                return repaired, 'prometheus_vm_repaired', 'Prometheus VM decompiled (repaired)', [vars(t) for t in self.trace]
                    else:
                        self._trace("prometheus_output", False, f"output too short or non-textual ({len(result)} chars)")
                else:
                    self._trace("prometheus_decompile", False, "decompilation produced no output")

            self._trace("wearedevs_decode", True, "attempting WeAreDevs string table decode")
            wd = _wearedevs_decode(src)
            self._trace("wearedevs_decode", wd["success"], wd["reason"])
            if not wd["success"]:
                d = wd["diagnostics"]
                diag_lines = [
                    f"tables: {d.get('table_count', 0)} total",
                    f"candidates: {d.get('candidate_tables', 0)}",
                    f"custom_alphabet: {d.get('custom_alphabet', False)}",
                    f"rejections:"
                ]
                for r in d.get("rejections", [])[:5]:
                    diag_lines.append(f"  table {r.get('table', '?')}: {r.get('reason', 'unknown')} "
                                      f"(strs={r.get('string_count', '?')} chunks={r.get('chunk_count', '?')} "
                                      f"score={r.get('score', r.get('keyword_hits', '?'))} "
                                      f"kw={r.get('keyword_hits', '?')})")
                diag_lines.append(f"entropy: {d.get('entropy', '?')}")
                diag_lines.append(f"decoded_chunks: {d.get('decoded_chunks', 0)}")
                last_wd_diag = "\n".join(diag_lines)
                self._trace("wearedevs_stats", False, last_wd_diag)
            else:
                wd_result = wd["output"]
                wd_diag = wd.get("diagnostics", {})
                d = wd_diag
                diag_lines = [
                    f"tables: {d.get('table_count', 0)} total",
                    f"candidates: {d.get('candidate_tables', 0)}",
                    f"custom_alphabet: {d.get('custom_alphabet', False)}",
                    f"lua_score: {d.get('lua_score', '?')}",
                    f"entropy: {d.get('entropy', '?')}",
                    f"decoded_chunks: {d.get('decoded_chunks', 0)}",
                    f"output_size: {len(wd_result)} chars",
                ]
                last_wd_diag = "\n".join(diag_lines)

                if len(wd_result) < 50 or not _is_probably_text(wd_result):
                    self._trace("wearedevs_output", False, f"output too short or non-textual ({len(wd_result)} chars), skipping")
                    continue
                token_issues = self._token_diagnostics(wd_result)
                if token_issues:
                    self._trace("token_issues", False, json.dumps(token_issues)[:1000])
                validation = self._validate_lua(wd_result, "wearedevs_output")
                if validation["valid"]:
                    return wd_result, 'wearedevs_decode', 'WeAreDevs string table decoded', [vars(t) for t in self.trace]
                else:
                    repaired = self._auto_fix(wd_result)
                    if self._validate_lua(repaired, "wearedevs_repaired")["valid"]:
                        return repaired, 'wearedevs_decode_repaired', 'WeAreDevs decoded (repaired)', [vars(t) for t in self.trace]
                    self._save_snapshot("failed_wearedevs", wd_result)
                    self._trace("wearedevs_decode", False, "output failed lua validation and repair")

        failed_diag = last_wd_diag if last_wd_diag else "no strategies produced output"
        self._trace("process", False, "all strategies exhausted")
        return '', 'unable', failed_diag, [vars(t) for t in self.trace]


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
