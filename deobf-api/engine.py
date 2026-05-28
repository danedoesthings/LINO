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
            return '', 'prometheus_vm_empty', 'VM detected but decompilation produced no output', []
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
