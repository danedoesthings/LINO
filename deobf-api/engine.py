import os
import re
import shutil
import subprocess
import tempfile
import base64
import urllib.request
import struct
import hashlib
import json
import sys
import io
import math
import time
import uuid
import threading
import contextlib
import resource
import signal
import traceback
import zlib
import binascii
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

from env_logger import JobLogger
from var_renamer import VarRenamer
from instruction_decoder import WeAreDevsVMLifter
from state_machine_devirt import StateMachineLifter, StateMachineAnalyzer

try:
    from lupa_executor import _lupa_decode_wearedevs, _lupa_run, HAS_LUPA
except ImportError:
    HAS_LUPA = False
    def _lupa_decode_wearedevs(source): return None, ["lupa_executor not found"]
    def _lupa_run(source, timeout_seconds=30): return None, ["lupa_executor not found"]

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
    return re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))), s)

def _lua_score(text):
    score = sum(1 for kw in LUA_KEYWORDS if kw in text) * 8
    for pat in [r'local\s+\w+', r'function\s*\(', r'end\b', r'return\b', r'if\s+.+\s+then']:
        if re.search(pat, text):
            score += 15
    if _shannon_entropy(text.encode(errors='ignore')) < 7:
        score += 10
    if text.count('(') == text.count(')'):
        score += 10
    funcs = text.count('function')
    ends = text.count('end')
    if funcs > 0 and ends >= funcs:
        score += 25
    return score

def _is_readable_identifier(s):
    if not s:
        return False
    if len(s) > 50:
        return False
    if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', s):
        return True
    if s in LUA_KEYWORDS:
        return True
    if re.match(r'^[a-zA-Z_][a-zA-Z0-9_.]*$', s) and len(s) <= 30:
        return True
    return False

def _extract_wearedevs_alphabet(source):
    for table_match in re.finditer(r'local\s+\w+\s*=\s*\{([^}]{400,})\}', source):
        body = table_match.group(1)
        entries = {}
        for m in re.finditer(r'\b([A-Za-z_])\s*=\s*([-\d+*()\s]{3,60}?)(?=[,;\}]|$)', body):
            key = m.group(1)
            try:
                val = int(eval(re.sub(r'\s+', '', m.group(2))))
                if 0 <= val <= 63:
                    entries[key] = val
            except Exception:
                pass
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
        alpha_map = {v: k for k, v in entries.items()}
        if len(alpha_map) < 60:
            continue
        alphabet = ''.join(alpha_map.get(i, '') for i in range(64))
        if len(alphabet) == 64 and '?' not in alphabet and len(set(alphabet)) == 64:
            return alphabet
    for m in re.finditer(r'["\']([A-Za-z0-9+/]{64})["\']', source):
        candidate = m.group(1)
        if len(set(candidate)) == 64:
            return candidate
    return None

def _custom_b64_decode(s, alpha):
    reverse = {c: i for i, c in enumerate(alpha)}
    bits = 0
    bit_count = 0
    out = bytearray()
    for c in s.rstrip('='):
        if c not in reverse:
            continue
        bits = (bits << 6) | reverse[c]
        bit_count += 6
        if bit_count >= 8:
            bit_count -= 8
            out.append((bits >> bit_count) & 0xFF)
    return bytes(out)

def _extract_r_table_strings(source):
    m = re.search(r'local\s+R\s*=\s*\{(.*?)\}(?=local\s+function)', source, re.DOTALL)
    if not m:
        m = re.search(r'\{((?:\s*"[^"]*"\s*[;,]?\s*){10,})\}', source, re.DOTALL)
    if not m:
        return None
    body = m.group(1)
    raw_entries = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
    if not raw_entries:
        return None
    return [_decode_numeric_escapes(s) for s in raw_entries]

def _extract_shuffle_ops(source):
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

def _apply_shuffle_range_reversal(strings, ops):
    result = list(strings)
    for lo, hi in ops:
        lo -= 1
        hi -= 1
        while lo < hi:
            result[lo], result[hi] = result[hi], result[lo]
            lo += 1
            hi -= 1
    return result

def _decode_string_fully(s, alphabet):
    if not s:
        return ''
    if _is_readable_identifier(s):
        return s
    if len(s) == 1:
        return s
    if _is_probably_text(s) and _shannon_entropy(s.encode('latin-1', errors='ignore')) < 6.5:
        return s
    try:
        raw = _custom_b64_decode(s, alphabet)
        if raw and len(raw) >= 1:
            try:
                text = raw.decode('utf-8')
                if text and (re.match(r'^[\x20-\x7E]+$', text) or _is_readable_identifier(text) or _is_probably_text(text)):
                    return text
            except Exception:
                pass
            try:
                text = raw.decode('latin-1', errors='replace')
                if _is_probably_text(text):
                    return text
            except Exception:
                pass
    except Exception:
        pass
    if re.match(r'^[A-Za-z0-9+/=]+$', s.strip()):
        try:
            padded = s.strip() + '=' * (-len(s.strip()) % 4)
            raw = base64.b64decode(padded, validate=False)
            if raw:
                try:
                    text = raw.decode('utf-8')
                    if text and (re.match(r'^[\x20-\x7E]+$', text) or _is_probably_text(text)):
                        return text
                except Exception:
                    pass
                try:
                    text = raw.decode('latin-1', errors='replace')
                    if _is_probably_text(text):
                        return text
                except Exception:
                    pass
        except Exception:
            pass
    return s

def _wearedevs_decode(source):
    diag = {}
    alphabet = _extract_wearedevs_alphabet(source)
    diag['custom_alphabet'] = alphabet is not None
    diag['alphabet_preview'] = alphabet[:8] + '...' if alphabet else None
    if not alphabet:
        return {'success': False, 'reason': 'could not extract custom alphabet', 'diagnostics': diag}
    encoded_strings = _extract_r_table_strings(source)
    if not encoded_strings:
        return {'success': False, 'reason': 'could not extract R string table', 'diagnostics': diag}
    diag['string_count'] = len(encoded_strings)
    shuffle_ops = _extract_shuffle_ops(source)
    diag['shuffle_ops'] = len(shuffle_ops)
    strings = _apply_shuffle_range_reversal(encoded_strings, shuffle_ops)
    decoded = [_decode_string_fully(s, alphabet) for s in strings]
    diag['decoded_count'] = len(decoded)
    readable = [s for s in decoded if s and _is_probably_text(s)]
    lua_hits = sum(1 for s in decoded if any(kw in s for kw in LUA_KEYWORDS))
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

def _get_e_offset(source):
    m = re.search(r'local\s+function\s+E\s*\(E\)\s*return\s+R\[E\+\((-?\d+(?:[+\-]\d+)*)\)\]', source)
    if m:
        try:
            return int(eval(re.sub(r'\s+', '', m.group(1))))
        except Exception:
            pass
    return None

def _eval_arith(expr):
    expr = re.sub(r'\s+', '', str(expr))
    if not re.match(r'^[\-\d+*()\s]+$', expr):
        return None
    try:
        result = eval(expr)
        if isinstance(result, (int, float)):
            return int(result)
    except Exception:
        pass
    return None

def _replace_e_calls(code, strings, offset):
    def repl(m):
        n = _eval_arith(m.group(1))
        if n is None:
            return m.group(0)
        lua_idx = n + offset
        py_idx = lua_idx - 1
        if 0 <= py_idx < len(strings):
            return json.dumps(strings[py_idx])
        return m.group(0)
    return re.sub(r'\bE\s*\((-?\d+(?:[+\-*]\d+)*)\)', repl, code)

def _simplify_arithmetic(code):
    def repl(m):
        inner = m.group(1)
        if re.match(r'^[\-\d +*()\t]+$', inner):
            val = _eval_arith(inner)
            if val is not None:
                return str(val)
        return m.group(0)
    prev = None
    while prev != code:
        prev = code
        code = re.sub(r'\(([^\(\)]+)\)', repl, code)
    return code

def _simplify_bare_arithmetic(code):
    def repl(m):
        try:
            val = int(eval(m.group(0)))
            return str(val)
        except Exception:
            return m.group(0)
    code = re.sub(r'-?\d+\s*\+\s*-\d+', repl, code)
    code = re.sub(r'-?\d+\s*-\s*-\d+', repl, code)
    return code

def _strip_bootstrap(source):
    markers = [
        'return(function(R,M,Y,r,m,N,h,d,o,l,q,I,w,g,S,z,Q,T,e,O,J)',
        'return(function(R,M,Y,r,m,N,h,d,o,l,q,I,w,g',
        'return(function(',
    ]
    for marker in markers:
        pos = source.find(marker)
        if pos != -1:
            return source[pos:]
    return source

def _add_spacing(code):
    code = re.sub(r'(?<!\n)(end\b)', r'\n\1', code)
    code = re.sub(r'(?<!\n)(local\s)', r'\n\1', code)
    code = re.sub(r'(?<!\n)(return\b)', r'\n\1', code)
    code = re.sub(r'(?<!\n)(if\s)', r'\n\1', code)
    code = re.sub(r'(?<!\n)(else\b)', r'\n\1', code)
    code = re.sub(r'(?<!\n)(while\s)', r'\n\1', code)
    code = re.sub(r'(?<!\n)(for\s)', r'\n\1', code)
    code = re.sub(r'\n{3,}', '\n\n', code)
    return code

def _extract_real_code_from_vm(source, decoded_strings):
    lines = []
    api_calls = []
    fenv_vars = {}
    if 'getfenv' in source or 'getfenv' in decoded_strings:
        lines.append('local fenv = getfenv and getfenv() or _ENV')
    pcall_idx = None
    for i, s in enumerate(decoded_strings):
        if s == 'pcall':
            pcall_idx = i + 1
            break
    named_keys = []
    for s in decoded_strings:
        if s and re.match(r'^[A-Za-z_][A-Za-z0-9_]{3,}$', s) and s not in {
            'error','table','string','math','print','pcall','tostring','tonumber',
            'setmetatable','getmetatable','unpack','select','type','assert',
            'floor','ceil','random','concat','insert','remove','byte','char',
            'sub','gsub','gmatch','find','format','byte','char','upper','lower',
        }:
            named_keys.append(s)
    string_refs = re.findall(r'R\["([A-Za-z_][A-Za-z0-9_]{3,})"\]', source)
    for ref in sorted(set(string_refs)):
        if ref not in fenv_vars:
            fenv_vars[ref] = f'local {ref} = fenv["{ref}"]' if 'fenv' in '\n'.join(lines) else f'local {ref} = _ENV["{ref}"]'
    return lines, fenv_vars, named_keys

def _format_substituted_lua(code, decoded_strings):
    inner_start = None
    m = re.search(r'return\s*\(function\s*\(R,M,Y,r,m,N,h,d,o,l,q,I,w,g,S,z,Q,T,e,O,J\)', code)
    if m:
        inner_start = m.start()
    if inner_start is not None:
        code = code[inner_start:]
    accessed = sorted(set(re.findall(r'R\["([^"]+)"\]', code)))
    print_found = 'print' in decoded_strings
    error_found = 'error' in decoded_strings
    setmeta_found = 'setmetatable' in decoded_strings
    result_lines = []
    result_lines.append('-- Deobfuscated via WeAreDevs string substitution')
    result_lines.append('-- Original script accesses the following globals:')
    for a in accessed:
        result_lines.append(f'--   {a}')
    result_lines.append('')
    result_lines.append('local fenv = getfenv and getfenv() or _ENV')
    result_lines.append('')
    if accessed:
        for name in accessed:
            safe = re.sub(r'[^A-Za-z0-9_]', '_', name)
            result_lines.append(f'local {safe} = fenv["{name}"]')
        result_lines.append('')
    for s in decoded_strings:
        if s and not s.startswith('__') and len(s) > 8 and re.match(r'^[A-Za-z0-9_]+$', s):
            if s not in {'setmetatable','getmetatable','tostring','tonumber','loadstring',
                         'string','table','math','print','error','pcall','unpack','select',
                         'type','assert','pairs','ipairs','require','rawget','rawset',
                         'floor','ceil','random','concat','insert','remove','byte','char',
                         'sub','gsub','gmatch','find','format','upper','lower','reverse'}:
                result_lines.append(f'-- Identified internal name: {repr(s)}')
    result_lines.append('')
    result_lines.append('-- Full substituted VM (arithmetic simplified, string table resolved):')
    result_lines.append(code)
    return '\n'.join(result_lines)

def _wearedevs_string_substitution(source, decoded_strings):
    alphabet = _extract_wearedevs_alphabet(source)
    if not alphabet:
        return None
    offset = _get_e_offset(source)
    if offset is None:
        return None
    result = source
    result = _replace_e_calls(result, decoded_strings, offset)
    result = _simplify_arithmetic(result)
    result = _simplify_bare_arithmetic(result)
    result = _strip_bootstrap(result)
    result = _add_spacing(result)
    if len(result) > 200:
        return result
    return None

def _extract_vm_structure(source):
    result = {
        'dispatch_loop': None, 'instruction_table': None, 'register_table': None,
        'constant_table': None, 'handlers': [], 'handler_map': {},
        'ip_variable': 'B', 'dispatch_variable': 'l', 'handler_table_var': 'C',
        'instruction_table_var': 'I', 'register_table_var': 'Q', 'constant_table_var': 'R',
        'dispatch_map': {},
    }
    ip_match = re.search(r'while\s+(\w+)\s+do\s+local\s+(\w+)\s*=\s*\{[^}]*\}\s*\[\s*(\w+)\s*\[\s*(\w+)\s*\]\s*\]', source, re.DOTALL)
    if ip_match:
        result['dispatch_variable'] = ip_match.group(1)
        result['handler_table_var'] = ip_match.group(2)
        result['instruction_table'] = ip_match.group(3)
        result['ip_variable'] = ip_match.group(4)
    while_match = re.search(r'(while\s+(\w+)\s+do\s+.*?end\s*(?:\)\s*\)|$))', source, re.DOTALL)
    if while_match:
        result['dispatch_loop'] = while_match.group(1)
    inst_match = re.search(r'local\s+(\w+)\s*=\s*\{([\d,\s]{50,})\}', source)
    if inst_match:
        result['instruction_table_var'] = inst_match.group(1)
        nums = [int(n.strip()) for n in inst_match.group(2).split(',') if n.strip().lstrip('-').isdigit()]
        result['instruction_table'] = nums
    reg_match = re.search(r'local\s+(\w+)\s*=\s*\{(\s*(?:\d+\s*,\s*)*\d+\s*)\}', source)
    if reg_match:
        result['register_table_var'] = reg_match.group(1)
    return result

def _extract_instruction_stream(source, vm_structure):
    instructions = []
    inst_data = vm_structure.get('instruction_table', [])
    if not inst_data or not isinstance(inst_data, list):
        inst_match = re.search(r'local\s+\w+\s*=\s*\{([\d,\s]+)\}', source)
        if inst_match:
            inst_data = [int(n.strip()) for n in inst_match.group(1).split(',') if n.strip().lstrip('-').isdigit()]
        else:
            table_bodies = _find_all_table_bodies(source)
            for body in table_bodies:
                entries = _parse_table_entries(body)
                nums = [e for e in entries if isinstance(e, int) and e >= 0]
                if len(nums) >= 20:
                    inst_data = nums
                    break
    return inst_data

def _is_wearedevs_vm(source):
    score = 0
    if re.search(r'while\s+\w+\s+do\s+local\s+\w+\s*=\s*\{', source):
        score += 3
    if re.search(r'local\s+\w+\s*=\s*\{[\d,\s]{50,}\}', source):
        score += 2
    if re.search(r'local\s+R\s*=\s*\{', source):
        score += 2
    if re.search(r'local\s+N\s*=\s*\{', source):
        score += 2
    if re.search(r'Q\s*\[\s*I\s*\[\s*B', source):
        score += 3
    if re.search(r'for\s+E,l\s+in\s+ipairs', source):
        score += 1
    return score >= 3

def _is_state_machine_vm(source):
    return bool(re.search(r'while\s+\w+\s+do\s+if\s+\w+\s*<\s*[\d]+\s+then', source)) and not re.search(r'local\s+\w+\s*=\s*\{[\d,\s]{50,}\}', source)

def _looks_like_real_code(text):
    if not text or len(text) < 50:
        return False
    lines = text.splitlines()
    structural_kw = {'function', 'while', 'for', 'if', 'repeat', 'print', 'local'}
    count = sum(1 for line in lines if any(kw in line for kw in structural_kw))
    return count >= 2

class Unveiler:
    def __init__(self, java_available, unluac_path, lua_harness_fn, run_unluac_fn):
        self.java_available = java_available
        self.unluac_path = unluac_path
        self._run_lua_harness = lua_harness_fn
        self._run_unluac = run_unluac_fn
        self.trace = []
        self.max_layers = 10
    
    def _log(self, stage, success, message):
        self.trace.append({'stage': stage, 'success': success, 'message': message, 'timestamp': time.time()})
    
    def unveil(self, source):
        self.trace = []
        peeled = self._peel_outer_base64(source)
        if peeled != source:
            self._log("outer_b64_peel", True, f"decoded outer base64 ({len(peeled)} chars)")
            source = peeled
        
        wd = _wearedevs_decode(source)
        if wd['success']:
            decoded_strings = wd['decoded_strings']
            self._log("wearedevs_decode", True, f"decoded {wd['diagnostics'].get('decoded_count',0)} strings")
            
            analyzer = StateMachineAnalyzer(source, decoded_strings)
            if analyzer.detect_state_machine():
                self._log("state_machine_detected", True, "state machine VM pattern found")
                state_lifted = analyzer.full_reconstruct()
                if state_lifted and len(state_lifted) > 100:
                    self._log("state_machine_reconstruct", True, f"reconstructed {len(state_lifted)} chars of original code")
                    return state_lifted, 'state_machine_devirt', 'State machine fully reconstructed'
            
            self._log("harness", True, "executing Lua harness with artifact capture")
            harness_result = self._run_lua_harness(source)
            if harness_result and _looks_like_real_code(harness_result):
                self._log("harness_success", True, f"captured {len(harness_result)} chars of real code")
                return harness_result, 'lua_harness', 'Harness captured original source'
            
            self._log("print_capture", True, "trying print/warn capture via lua5.1 subprocess")
            lupa_out, lupa_trace = _lupa_decode_wearedevs(source)
            for t in lupa_trace:
                self._log("print_capture_trace", True, t)
            if lupa_out and len(lupa_out.strip()) > 0:
                self._log("print_capture_success", True, f"captured {len(lupa_out)} chars of output")
                header = "-- [Deobfuscated via print/warn capture]\n"
                return header + lupa_out, 'print_capture', 'Captured runtime output'
            
            subst_result = _wearedevs_string_substitution(source, decoded_strings)
            if subst_result:
                self._log("string_substitution", True, f"produced {len(subst_result)} chars")
                lifter = WeAreDevsVMLifter(decoded_strings)
                lifted = lifter.lift(subst_result)
                if lifted and _looks_like_real_code(lifted):
                    self._log("vm_lift", True, f"VM lifted: {len(lifted)} chars")
                    header = "-- Deobfuscated via VM lifting\n"
                    return header + lifted, 'wearedevs_vm_lifted', 'VM devirtualized'
                self._log("vm_lift", False, "VM lift produced no meaningful output, trying state machine lifter")
                
                state_lifter = StateMachineLifter(subst_result, decoded_strings)
                state_lifted = state_lifter.lift()
                if state_lifted and _looks_like_real_code(state_lifted):
                    self._log("state_machine_lift", True, f"State machine lifted: {len(state_lifted)} chars")
                    header = "-- Deobfuscated via state machine devirtualization\n"
                    return header + state_lifted, 'state_machine_devirt', 'State machine VM devirtualized'
                
                self._log("vm_lift", False, "VM lift produced no meaningful output, using substitution result")
                header = "-- Deobfuscated via string-table substitution\n"
                return header + subst_result, 'wearedevs_string_substitution', 'String-table substitution complete'
            
            vm_result = self._attempt_vm_lift(source, decoded_strings)
            if vm_result:
                return vm_result, 'wearedevs_vm_lifted', 'VM lifted'
            
            lines = [f"-- [{i}] {s!r}" for i, s in enumerate(decoded_strings) if s]
            return '\n'.join(lines), 'wearedevs_decode', 'Decoded string table (no harness capture)'
        
        if self._detect_prometheus_vm(source):
            self._log("prometheus_detect", True, "Prometheus VM detected")
            result = self._prometheus_decompile(source)
            if result and len(result) >= 50:
                return result, 'prometheus_vm', 'Prometheus VM decompiled'
        
        self._log("print_capture_fallback", True, "trying print/warn capture as fallback")
        lupa_out, _ = _lupa_decode_wearedevs(source)
        if lupa_out and len(lupa_out.strip()) > 0:
            self._log("print_capture_fallback_success", True, f"captured {len(lupa_out)} chars")
            return lupa_out, 'print_capture', 'Captured runtime output (fallback)'
        
        self._log("harness_fallback", True, "running harness as final attempt")
        harness_result = self._run_lua_harness(source)
        if harness_result:
            return harness_result, 'lua_harness', 'Harness captured output'
        
        recursive_result = self._recursive_unveil(source)
        if recursive_result and recursive_result != source:
            return recursive_result, 'recursive_unveil', 'Multi-layer unwrapping'
        
        return '', 'unable', 'All strategies failed'
    
    def _peel_outer_base64(self, text):
        cleaned = re.sub(r'\s+', '', text.strip())
        if re.match(r'^[A-Za-z0-9+/=]+$', cleaned):
            decoded = _try_base64_decode(cleaned)
            if decoded:
                for enc in ('utf-8', 'latin-1'):
                    try:
                        dec_text = decoded.decode(enc)
                        if len(dec_text) > 50:
                            return dec_text
                    except:
                        pass
        return text
    
    def _attempt_vm_lift(self, source, decoded_strings):
        self._log("vm_lift_attempt", True, "trying static VM lift")
        if not _is_wearedevs_vm(source):
            self._log("vm_lift_detect", False, "no VM dispatch pattern")
            return None
        try:
            lifter = WeAreDevsVMLifter(decoded_strings)
            return lifter.lift(source)
        except Exception:
            pass
        return None
    
    def _recursive_unveil(self, source, depth=0):
        if depth > self.max_layers:
            return None
        self._log(f"recursive_layer_{depth}", True, f"attempting layer {depth}")
        if re.match(r'^[A-Za-z0-9+/=]+$', source.strip()):
            decoded = _try_base64_decode(source.strip())
            if decoded:
                try:
                    text = decoded.decode('utf-8')
                    if _is_probably_text(text) and text != source:
                        result = self._recursive_unveil(text, depth+1)
                        return result if result else text
                except:
                    pass
        try:
            alpha = _extract_wearedevs_alphabet(source)
            if alpha:
                decoded = _custom_b64_decode(source.strip(), alpha)
                if decoded and decoded != source.encode('latin-1'):
                    text = decoded.decode('latin-1', errors='replace')
                    if _is_probably_text(text) and text != source:
                        result = self._recursive_unveil(text, depth+1)
                        return result if result else text
        except:
            pass
        for key in range(1, 256):
            try:
                raw = source.encode('latin-1')
                decoded = bytes(b ^ key for b in raw)
                if _is_lua_bytecode(decoded) and self.java_available:
                    text, _ = self._run_unluac(decoded)
                    if text:
                        return text
                text = decoded.decode('utf-8', errors='replace')
                if _looks_like_real_code(text):
                    return text
            except:
                pass
        try:
            raw = source.encode('latin-1')
            dec = zlib.decompress(raw)
            text = dec.decode('utf-8', errors='replace')
            if _looks_like_real_code(text):
                return text
        except:
            pass
        try:
            if re.match(r'^[0-9a-fA-F]+$', source.strip()):
                raw = binascii.unhexlify(source.strip())
                text = raw.decode('utf-8', errors='replace')
                if _looks_like_real_code(text):
                    return text
        except:
            pass
        return None
    
    def _detect_prometheus_vm(self, source):
        score = sum(1 for p in [r'pc\s*=', r'opcode', r'instructions?\[', r'while\s+true\s+do', r'bit32', r'band\('] if re.search(p, source))
        return score >= 3
    
    def _prometheus_decompile(self, source):
        bodies = _find_all_table_bodies(source)
        instructions = []
        for body in bodies:
            entries = _parse_table_entries(body)
            nums = [e for e in entries if isinstance(e, int)]
            if len(nums) >= 10:
                instructions = nums
                break
        if not instructions:
            m = re.search(r'\{([\d,\s]{50,})\}', source)
            if m:
                instructions = [int(n.strip()) for n in m.group(1).split(',') if n.strip().isdigit()]
        constants = []
        cm = re.search(r'local\s+\w+\s*=\s*\{([^}]+)\}', source)
        if cm:
            constants = [e for e in _parse_table_entries('{' + cm.group(1) + '}') if isinstance(e, str)]
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
                lines.append(f"loadk {json.dumps(constants[idx-1] if 1 <= idx <= len(constants) else str(idx))}")
            elif op == 1:
                a = instructions[ip] if ip < len(instructions) else 0
                ip += 1
                b = instructions[ip] if ip < len(instructions) else 0
                ip += 1
                lines.append(f"{constants[a-1] if 1<=a<=len(constants) else f'var{a}'} = {constants[b-1] if 1<=b<=len(constants) else f'var{b}'}")
            elif op == 2:
                a = instructions[ip] if ip < len(instructions) else 0
                ip += 1
                lines.append(f"call {constants[a-1] if 1<=a<=len(constants) else f'var{a}'}")
            else:
                lines.append(f"-- op {op}")
        return '\n'.join(lines)

class DeobfEngine:
    def __init__(self):
        self.unluac_path = UNLUAC_LOCAL_PATH
        self._java_available = shutil.which('java') is not None
        self.trace = []
        self.unveiler = Unveiler(
            java_available=self._java_available,
            unluac_path=self.unluac_path,
            lua_harness_fn=self._run_lua_harness,
            run_unluac_fn=self._run_unluac
        )
        self.var_renamer = VarRenamer()
        self._hook_stats = defaultdict(int)
    
    def get_capabilities(self):
        return {
            'lua_harness': True,
            'prometheus_vm': True,
            'wearedevs_decode': True,
            'wearedevs_vm_lift': True,
            'state_machine_devirt': True,
            'unluac': self._java_available and os.path.isfile(self.unluac_path),
            'luaparser': HAS_LUAPARSER,
            'var_renamer': True,
            'hooking': True,
        }
    
    def _trace(self, stage, success, message):
        self.trace.append(DiagnosticEvent(stage=stage, success=success, message=message))
    
    def _set_process_limits(self):
        try:
            resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_CPU, (300, 305))
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
if not INSIDE_LOAD then INSIDE_LOAD = true; save("load", tostring(code)); INSIDE_LOAD = false end
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
if type(out) == "string" and #out > 20 then save("concat", out) end
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
local print_lines = {}
local real_print = print
_G.print = function(...)
local parts = {}
for i = 1, select('#', ...) do
local v = select(i, ...)
parts[i] = tostring(v)
end
local line = table.concat(parts, "\t")
table.insert(print_lines, line)
end
local real_warn = warn
if warn then
_G.warn = function(...)
local parts = {}
for i = 1, select('#', ...) do
local v = select(i, ...)
parts[i] = tostring(v)
end
local line = "WARN: " .. table.concat(parts, "\t")
table.insert(print_lines, line)
end
end
local state_log = {}
if not getfenv then
getfenv = function(f)
if f then
local i = 1
while true do
local name, value = debug.getupvalue(f, i)
if not name then break end
if name == "_ENV" then return value end
i = i + 1
end
end
return _G
end
end
if not newproxy then
newproxy = function(addmeta)
local p = {}
if addmeta then
local mt = {}
setmetatable(p, mt)
end
return p
end
end
if not unpack then
unpack = table.unpack or function(t, i, j)
j = j or #t
i = i or 1
if i > j then return end
return t[i], unpack(t, i + 1, j)
end
end
local f, err = loadfile("_SRCFILE_")
if not f then
real_print("ERR:COMPILE:" .. tostring(err))
else
local bit32 = bit32 or nil
if not bit32 then
local function bxor(a,b) local r,m=0,1; while a>0 or b>0 do local ab,bb=a%2,b%2; if ab~=bb then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end
local function band(a,b) local r,m=0,1; while a>0 and b>0 do if a%2+b%2==2 then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end
local function bor(a,b) local r,m=0,1; while a>0 or b>0 do if a%2+b%2>0 then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end
bit32={bxor=bxor,band=band,bor=bor,lshift=function(v,n) return math.floor(v*(2^n))%4294967296 end,rshift=function(v,n) return math.floor(v/(2^n)) end}
bit32.arshift=bit32.rshift
end
_G.bit32=bit32
_G.bit=bit32
local success, result = pcall(f)
collectgarbage("collect")
pcall(function()
for k,v in pairs(_G) do
if type(v)=="string" and #v>20 then hook_stats.env_string=(hook_stats.env_string or 0)+1; save("env_"..k, v) end
end
end)
if success and type(result) == "function" then
if string.dump then
local bc = string.dump(result)
if bc and #bc > 50 then save("function_return", bc) end
end
end
for _,cap in ipairs(captures) do real_print("CAP:"..cap.tag..":"..cap.data) end
if #state_log > 0 then
local joined = table.concat(state_log, ",")
real_print("CAP:state_trace:" .. b64encode(joined))
end
if #print_lines > 0 then
local joined = table.concat(print_lines, "\n")
real_print("CAP:print_output:" .. b64encode(joined))
end
if #captures==0 and #print_lines==0 then
if not success then real_print("ERR:RUNTIME:"..tostring(result))
else real_print("ERR:NO_OUTPUT") end
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
        try:
            for lua_bin in ['lua5.1', 'lua']:
                try:
                    proc = subprocess.Popen(
                        [lua_bin, tmp_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        preexec_fn=self._set_process_limits, start_new_session=True)
                    try:
                        stdout, _ = proc.communicate(timeout=300)
                        stdout = stdout.decode('latin-1', errors='replace')
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        except:
                            pass
                    proc.wait()
                    for line in stdout.splitlines():
                        if line.startswith('CAP:'):
                            captures.append(line[4:])
                    if captures:
                        break
                except FileNotFoundError:
                    continue
        finally:
            for p in (tmp_path, src_path):
                try:
                    os.unlink(p)
                except OSError:
                    pass
        if captures:
            candidates = []
            for cap in captures:
                tag, data = cap.split(':', 1) if ':' in cap else ('unknown', cap)
                try:
                    decoded_data = base64.b64decode(data).decode('latin-1', errors='replace')
                except Exception:
                    decoded_data = data
                if _is_self_capture(decoded_data):
                    continue
                if tag == 'print_output':
                    if decoded_data.strip():
                        candidates.append({'data': decoded_data, 'tag': tag})
                    continue
                if tag in ('state_trace',):
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
                        if sum(1 for kw in LUA_KEYWORDS if kw in decoded_data) < 3:
                            continue
                candidates.append({'data': decoded_data, 'tag': tag})
            if candidates:
                return max(candidates, key=lambda x: len(x['data']))['data']
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
            r = subprocess.run(['java', '-jar', self.unluac_path, '--rawstring', tmp_path], capture_output=True, timeout=30)
            stdout = r.stdout.decode('latin-1', errors='replace')
            return (stdout, None) if r.returncode == 0 and stdout.strip() else (None, "unluac failed")
        except subprocess.TimeoutExpired:
            return None, "timeout"
        except Exception as e:
            return None, str(e)
        finally:
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
    
    def _apply_var_renamer(self, code):
        try:
            return self.var_renamer.rename(code)
        except:
            return code
    
    def process(self, source, logger=None):
        self.trace = []
        self._hook_stats.clear()
        result, method, diagnostic = self.unveiler.unveil(source)
        for entry in self.unveiler.trace:
            self._trace(entry['stage'], entry['success'], entry['message'])
        if result and method in ('lua_harness', 'wearedevs_vm_lifted', 'state_machine_devirt', 'recursive_unveil', 'wearedevs_string_substitution', 'print_capture'):
            self._trace("var_rename", True, "applying variable renamer")
            result = self._apply_var_renamer(result)
            self._hook_stats['var_rename_applied'] = 1
        if logger:
            for entry in self.unveiler.trace:
                logger.add_trace(entry['stage'], entry['success'], entry['message'])
            logger.finish(result, method, diagnostic)
            logger.to_dict()['hook_stats'] = dict(self._hook_stats)
        return result, method, diagnostic, [vars(t) for t in self.trace]

job_store = {}
job_lock = threading.Lock()

def _run_job(job_id, source):
    engine = DeobfEngine()
    logger = JobLogger()
    logger.start_job(job_id, engine.get_capabilities())
    try:
        result, method, diagnostic, trace = engine.process(source, logger)
        with job_lock:
            job_store[job_id] = {
                'status': 'complete',
                'result': result,
                'detected': method,
                'diagnostic': diagnostic,
                'trace': trace,
                'result_length': len(result) if result else 0,
                'log_json': logger.to_json()
            }
    except Exception as e:
        logger.add_error(str(e), e)
        logger.finish()
        with job_lock:
            job_store[job_id] = {
                'status': 'error',
                'error': str(e),
                'traceback': traceback.format_exc()[:4000],
                'log_json': logger.to_json()
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
