import os, re, shutil, subprocess, tempfile, base64, urllib.request, hashlib, json, sys, io, math, time, uuid, threading, contextlib, resource, signal, traceback, zlib, binascii
from collections import defaultdict, Counter, deque
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any, Set

try:
    from luaparser import ast as lua_ast
    from luaparser.astnodes import *
    HAS_LUAPARSER = True
except ImportError:
    HAS_LUAPARSER = False

from env_logger import JobLogger
from var_renamer import VarRenamer

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

JOB_STORAGE_DIR = '/data'
JOB_STORAGE_FILE = os.path.join(JOB_STORAGE_DIR, 'deobf_jobs.json')
os.makedirs(JOB_STORAGE_DIR, exist_ok=True)

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

def _is_readable_identifier(s):
    if not s:
        return False
    if len(s) > 50:
        return False
    if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', s):
        return True
    if s in LUA_KEYWORDS:
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

def _decode_full_r_table(source):
    alphabet = _extract_wearedevs_alphabet(source)
    if not alphabet:
        return None
    raw = _extract_r_table_strings(source)
    if not raw:
        return None
    shuffle_ops = _extract_shuffle_ops(source)
    strings = list(raw)
    for a, b in shuffle_ops:
        ai, bi = a - 1, b - 1
        if 0 <= ai < len(strings) and 0 <= bi < len(strings):
            strings[ai], strings[bi] = strings[bi], strings[ai]
    decoded = []
    for s in strings:
        if not s:
            decoded.append('')
            continue
        if _is_readable_identifier(s):
            decoded.append(s)
            continue
        try:
            raw = _custom_b64_decode(s, alphabet)
            if raw and len(raw) >= 1:
                try:
                    text = raw.decode('utf-8')
                    if text and _is_probably_text(text):
                        decoded.append(text)
                        continue
                except:
                    pass
                try:
                    text = raw.decode('latin-1', errors='replace')
                    if text and _is_probably_text(text):
                        decoded.append(text)
                        continue
                except:
                    pass
        except:
            pass
        decoded.append(s)
    return decoded

def _wearedevs_decode(source):
    diag = {}
    strings = _decode_full_r_table(source)
    if not strings:
        return {'success': False, 'reason': 'could not decode R table', 'diagnostics': diag}
    diag['decoded_count'] = len(strings)
    lua_hits = sum(1 for s in strings if any(kw in str(s) for kw in LUA_KEYWORDS))
    diag['lua_keyword_hits'] = lua_hits
    return {
        'success': True,
        'decoded_strings': strings,
        'reason': f'decoded {len(strings)} strings',
        'diagnostics': diag,
    }

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
        except:
            pass
    return None

def safe_eval_int(expr):
    expr = re.sub(r'\s+', '', str(expr))
    def clean_doubles(s):
        old = ''
        while old != s:
            old = s
            s = s.replace('--', '+').replace('+-', '-').replace('-+', '-').replace('++', '+')
        return s
    expr = clean_doubles(expr)
    while '(' in expr:
        m = re.search(r'\(([^()]+)\)', expr)
        if not m:
            break
        inner = safe_eval_int(m.group(1))
        expr = expr[:m.start()] + str(inner) + expr[m.end():]
        expr = clean_doubles(expr)
    while True:
        m = re.search(r'(-?\d+)([\*/%])(-?\d+)', expr)
        if not m:
            break
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        if op == '*': res = a * b
        elif op == '/': res = a // b if b != 0 else 0
        elif op == '%': res = a % b if b != 0 else 0
        expr = expr[:m.start()] + str(res) + expr[m.end():]
        expr = clean_doubles(expr)
    tokens = re.findall(r'([+-]?\d+)', expr)
    if tokens:
        return sum(int(t) for t in tokens)
    try:
        return int(expr)
    except:
        return None

def global_fold_math_regex(code):
    def repl(m):
        res = safe_eval_int(m.group(0))
        return str(res) if res is not None else m.group(0)
    for _ in range(5):
        code = re.sub(r'\(([^()a-zA-Z_]+)\)', repl, code)
        code = re.sub(r'\b(-\d+|\d+)\s*([+\-*/%])\s*(-\d+|\d+)\b', repl, code)
    return code

def _substitute_e_calls(source, full_strings):
    source = global_fold_math_regex(source)
    offset = _get_e_offset(source)
    if offset is None:
        return source
    def repl(m):
        inner = m.group(1)
        n = safe_eval_int(inner)
        if n is None:
            return m.group(0)
        lua_idx = n + offset
        py_idx = lua_idx - 1
        if 0 <= py_idx < len(full_strings):
            val = full_strings[py_idx]
            if not val:
                return 'nil'
            return json.dumps(str(val))
        return m.group(0)
    return re.sub(r'\bE\s*\(\s*([^)]+)\s*\)', repl, source)

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

def _looks_like_real_code(text):
    if not text or len(text) < 20:
        return False
    lines = text.splitlines()
    keywords = {'function', 'while', 'for', 'if', 'repeat', 'print', 'local', 'return'}
    count = sum(1 for line in lines if any(kw in line for kw in keywords))
    return count >= 1

def _escape_lua_string(s):
    return json.dumps(s)

def _format_clean_vm(code):
    code = re.sub(r'(?<!\n)\b(end)\b', r'\n\1\n', code)
    code = re.sub(r'(?<!\n)\b(local\s)', r'\n\1', code)
    code = re.sub(r'(?<!\n)\b(return\b)', r'\n\1', code)
    code = re.sub(r'(?<!\n)\b(if\s)', r'\n\1', code)
    code = re.sub(r'(?<!\n)\b(else\b)', r'\n\1\n', code)
    code = re.sub(r'(?<!\n)\b(elseif\b)', r'\n\1', code)
    code = re.sub(r'(?<!\n)\b(while\s)', r'\n\1', code)
    code = re.sub(r'(?<!\n)\b(for\s)', r'\n\1', code)
    code = re.sub(r'\}\s*\{', '}, {', code)
    code = '\n'.join([line.strip() for line in code.split('\n') if line.strip()])
    return code

class RobustASTConstantFolder(lua_ast.ASTVisitor):
    def visit_BinaryOp(self, node):
        node.left = self.visit(node.left)
        node.right = self.visit(node.right)
        if isinstance(node.left, Number) and isinstance(node.right, Number):
            try:
                left_val = float(node.left.n)
                right_val = float(node.right.n)
                op = node.op
                if op == '+': result = left_val + right_val
                elif op == '-': result = left_val - right_val
                elif op == '*': result = left_val * right_val
                elif op == '/': result = left_val / right_val if right_val != 0 else 0
                elif op == '%': result = left_val % right_val if right_val != 0 else 0
                else: return node
                str_res = str(int(result)) if result == int(result) else str(result)
                return Number(str_res)
            except:
                pass
        return node
    def visit_UnaryOp(self, node):
        node.operand = self.visit(node.operand)
        if isinstance(node.operand, Number) and node.op == '-':
            try:
                val = -float(node.operand.n)
                str_res = str(int(val)) if val == int(val) else str(val)
                return Number(str_res)
            except:
                pass
        return node
    def visit(self, node):
        if node is None: return None
        method = getattr(self, 'visit_' + type(node).__name__, None)
        if method: return method(node)
        for child_name, child in node.children():
            if isinstance(child, list):
                for i, item in enumerate(child):
                    child[i] = self.visit(item)
            elif child is not None:
                setattr(node, child_name, self.visit(child))
        return node

class ASTTableResolver(lua_ast.ASTVisitor):
    def __init__(self, strings):
        self.strings = strings
    def visit_Index(self, node):
        node.value = self.visit(node.value)
        node.idx = self.visit(node.idx)
        if isinstance(node.value, Name) and node.value.id == 'R':
            if isinstance(node.idx, Number):
                idx = int(node.idx.n)
                if 1 <= idx <= len(self.strings):
                    val = self.strings[idx - 1]
                    if isinstance(val, str) and _is_readable_identifier(val):
                        return String(f'"{val}"', val)
                    elif val:
                        safe = _escape_lua_string(str(val))
                        return String(safe, str(val))
        return node
    def visit(self, node):
        if node is None: return None
        method = getattr(self, 'visit_' + type(node).__name__, None)
        if method: return method(node)
        for child_name, child in node.children():
            if isinstance(child, list):
                for i, item in enumerate(child):
                    child[i] = self.visit(item)
            elif child is not None:
                setattr(node, child_name, self.visit(child))
        return node

class BinaryTreeUnflattener:
    def __init__(self, while_node, state_var_name):
        self.while_node = while_node
        self.state_var = state_var_name
        self.state_map = {}
    def extract_all_candidate_states(self, source_code):
        return set(int(n) for n in re.findall(r'-?\d+', source_code))
    def evaluate_path(self, node, state_value):
        if node is None: return None
        if isinstance(node, Block):
            for stmt in node.block:
                if isinstance(stmt, If):
                    res = self.evaluate_path(stmt, state_value)
                    if res is not None: return res
            return node
        if isinstance(node, If):
            if isinstance(node.test, BinOp) and isinstance(node.test.left, Name) and node.test.left.id == self.state_var:
                if isinstance(node.test.right, Number):
                    right_val = int(node.test.right.n)
                    op = node.test.op
                    condition_met = False
                    if op == '<': condition_met = state_value < right_val
                    elif op == '<=': condition_met = state_value <= right_val
                    elif op == '>': condition_met = state_value > right_val
                    elif op == '>=': condition_met = state_value >= right_val
                    elif op == '==': condition_met = state_value == right_val
                    elif op == '~=': condition_met = state_value != right_val
                    if condition_met:
                        return self.evaluate_path(node.body, state_value)
                    else:
                        return self.evaluate_path(node.else_body, state_value)
            return node
        return None
    def find_next_state(self, leaf_block):
        class Finder(lua_ast.ASTVisitor):
            def __init__(self, var):
                self.var = var
                self.next_state = None
            def visit_Assign(self, node):
                for target in node.targets:
                    if isinstance(target, Name) and target.id == self.var:
                        if node.values and isinstance(node.values[0], Number):
                            self.next_state = int(node.values[0].n)
        f = Finder(self.state_var)
        f.visit(leaf_block)
        return f.next_state
    def reconstruct(self, initial_state, raw_body_source):
        candidates = self.extract_all_candidate_states(raw_body_source)
        for state in candidates:
            leaf = self.evaluate_path(self.while_node.body, state)
            if leaf and hasattr(leaf, 'block') and len(leaf.block) > 0:
                self.state_map[state] = leaf
        sequential_body = Block([])
        current_state = initial_state
        visited = set()
        while current_state is not None and current_state not in visited:
            visited.add(current_state)
            if current_state not in self.state_map:
                break
            leaf_block = self.state_map[current_state]
            for stmt in leaf_block.block:
                is_state_assign = False
                if isinstance(stmt, Assign):
                    for target in stmt.targets:
                        if isinstance(target, Name) and target.id == self.state_var:
                            is_state_assign = True
                            break
                if not is_state_assign:
                    sequential_body.block.append(stmt)
            current_state = self.find_next_state(leaf_block)
        return Chunk(sequential_body)

class ASTDecompiler:
    def __init__(self, source, full_strings):
        self.source = source
        self.strings = full_strings
    def _is_virtual_machine(self, source):
        vm_indicators = [
            r'return\s*\(?\s*function\s*\([a-zA-Z0-9_,\s]+\)',
            r'while\s+[a-zA-Z0-9_]+\s*do\s+if\s+[a-zA-Z0-9_]+\s*<\s*\d+\s*then',
            r'[a-zA-Z0-9_]+\[[a-zA-Z0-9_]+\]\s*=\s*[a-zA-Z0-9_]+\[[a-zA-Z0-9_]+\]\s*[+\-]\s*\d+'
        ]
        hits = sum(1 for ind in vm_indicators if re.search(ind, source))
        return hits >= 2
    def decompile(self):
        prepared = _substitute_e_calls(self.source, self.strings)
        prepared = global_fold_math_regex(prepared)
        prepared = _strip_bootstrap(prepared)
        is_vm = self._is_virtual_machine(prepared)
        if not HAS_LUAPARSER:
            return _format_clean_vm(prepared)
        try:
            tree = lua_ast.parse(prepared)
        except:
            return _format_clean_vm(prepared)
        folder = RobustASTConstantFolder()
        tree = folder.visit(tree)
        resolver = ASTTableResolver(self.strings)
        tree = resolver.resolve(tree)
        if is_vm:
            class WhileFinder(lua_ast.ASTVisitor):
                def __init__(self):
                    self.target_while = None
                    self.var_name = None
                def visit_While(self, node):
                    if isinstance(node.condition, Name):
                        self.target_while = node
                        self.var_name = node.condition.id
            finder = WhileFinder()
            finder.visit(tree)
            if finder.target_while:
                unflat = BinaryTreeUnflattener(finder.target_while, finder.var_name)
                candidates = unflat.extract_all_candidate_states(prepared)
                if candidates:
                    entry = min(candidates)
                    tree = unflat.reconstruct(entry, prepared)
        try:
            final_code = lua_ast.to_lua_source(tree)
            if is_vm:
                return "-- [VM DETECTED] Math & Strings Devirtualized\n" + _format_clean_vm(final_code)
            return final_code
        except:
            return _format_clean_vm(prepared)

# =============================================================================
# UPGRADED INSTRUMENTER with comment safety, smart splitting, and beautifier
# =============================================================================
class Instrumenter:
    """Post-processes deobfuscated Lua code to add environment logging, opcode hooks,
    meaningful variable renaming, fixing broken comments, and a multi-pass layout beautifier."""
    
    def instrument(self, code):
        code = global_fold_math_regex(code)
        
        # ---- Fix accidental comment triggers (e.g., "--" from double negatives) ----
        processed_lines = []
        for line in code.split('\n'):
            if "--" in line and not any(safe_header in line for safe_header in [
                "[HOOK OP]", "[VM DETECTED]", "Advanced Semantic", "Deobfuscated & Instrumented"
            ]):
                line = line.replace("--", " - - ")
            processed_lines.append(line)
        code = '\n'.join(processed_lines)

        # ---- Separate keywords crushed next to numbers ----
        code = re.sub(r'([0-9a-zA-Z_])\s*(and|or|not|then|do|end|else|elseif)\b', r'\1 \2', code)
        code = re.sub(r'\b(and|or|not|then|do|end|else|elseif)\s*([0-9a-zA-Z_])', r'\1 \2', code)

        # ---- Inject environment logger and opcode hooks ----
        lines = code.split('\n')
        output = []
        inserted_env = False
        inserted_hook = False
        state_var = 'l'

        for line in lines:
            m = re.search(r'while\s+(\w+)\s+do', line)
            if m:
                state_var = m.group(1)
                break

        i = 0
        while i < len(lines):
            line = lines[i].rstrip()
            if not inserted_env and re.match(r'^(local\s+)?function\b|^return\s*\(?\s*function', line):
                output.append(line)
                output.append('    -- Advanced Semantic Environment Logger Proxy')
                output.append('    local originalEnv = getfenv and getfenv() or _ENV')
                output.append('    local loggedEnv = setmetatable({}, {')
                output.append('        __index = function(t, k)')
                output.append('            local v = originalEnv[k]')
                output.append('            print(string.format("[ENV READ] Global Access: \'%s\' -> Value: %s", tostring(k), tostring(v)))')
                output.append('            if k == "HttpService" or k == "request" then')
                output.append('                print("   ↳ [RENAME HINT] Targets: httpResponse")')
                output.append('            elseif k == "LocalPlayer" or k == "Character" then')
                output.append('                print("   ↳ [RENAME HINT] Targets: character")')
                output.append('            elseif type(v) == "function" then')
                output.append('                print("   ↳ [RENAME HINT] Targets: loadedFunc")')
                output.append('            end')
                output.append('            return v')
                output.append('        end,')
                output.append('        __newindex = function(t, k, v)')
                output.append('            print(string.format("[ENV WRITE] Global Modified: \'%s\' = %s", tostring(k), tostring(v)))')
                output.append('            originalEnv[k] = v')
                output.append('        end')
                output.append('    })')
                output.append('    if getfenv then setfenv(1, loggedEnv) else _ENV = loggedEnv end')
                inserted_env = True
                i += 1
                continue
            if not inserted_hook and f'while {state_var} do' in line:
                output.append(line)
                output.append(f'        print(string.format("[HOOK OP] State ID: %d", {state_var}))')
                inserted_hook = True
                i += 1
                continue
            output.append(line)
            i += 1
        code = '\n'.join(output)

        # ---- Global Variable Role Mapping ----
        renames = {
            r'\bR\b': 'EncryptedStrings',
            r'\bE\b': 'GetString',
            r'\bl\b': 'stateId',
            r'\bQ\b': 'VirtualStack',
            r'\bI\b': 'InstructionTable',
            r'\bw\b': 'AllocSlot',
            r'\bM\b': 'PackArgs',
            r'\bY\b': 'CallEnv',
            r'\bN\b': 'AlphabetMap',
            r'\bh\b': 'charFunc',
            r'\bJ\b': 'FuncWrap',
        }
        for pat, repl in renames.items():
            code = re.sub(pat, repl, code)

        return self.beautify_formatting(code)

    def beautify_formatting(self, code):
        code = re.sub(r';', '\n', code)
        code = re.sub(r'\n\s*\n', '\n', code)

        # ---- Multi-Statement Line Splitter ----
        control_keywords = {'then','do','and','or','not','else','elseif','return',
                           'local','function','in','for','while','repeat','until','if'}
        splitter_pattern = r'([a-zA-Z0-9_]+|\)|\]|\})\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*([=\(\[{])'
        def statement_replacer(m):
            preceding_token = m.group(1)
            if preceding_token in control_keywords:
                return m.group(0)
            return f"{preceding_token}\n{m.group(2)}{m.group(3)}"
        for _ in range(3):
            code = re.sub(splitter_pattern, statement_replacer, code)

        # ---- Indentation Pass ----
        lines = code.split('\n')
        indent_level = 0
        beautified = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            first_word = line.split()[0] if line.split() else ""
            clean_first = re.sub(r'[^a-zA-Z0-9_]', '', first_word)
            if clean_first in ('end','else','elseif') or line.startswith('}') or line.startswith(')'):
                indent_level = max(0, indent_level - 1)
            beautified.append('    ' * indent_level + line)
            if not (line.startswith('end') or line.endswith('end')):
                if any(line.endswith(tok) or (tok + ' ') in line for tok in ['then', 'do']) or line.endswith('{') or 'function(' in line:
                    indent_level += 1
            if clean_first in ('else', 'elseif'):
                indent_level += 1
        return '\n'.join(beautified)

# =============================================================================
# UNVEILER & ENGINE
# =============================================================================

class Unveiler:
    def __init__(self, java_available, unluac_path, run_unluac_fn, run_lua_harness_fn):
        self.java_available = java_available
        self.unluac_path = unluac_path
        self._run_unluac = run_unluac_fn
        self._run_lua_harness = run_lua_harness_fn
        self.trace = []
    def _log(self, stage, success, message):
        self.trace.append({'stage': stage, 'success': success, 'message': message, 'timestamp': time.time()})
    def unveil(self, source):
        self.trace = []
        full_strings = _decode_full_r_table(source)
        if not full_strings:
            self._log("decode", False, "could not decode R table")
            return '', 'unable', 'String decode failed'
        self._log("decode", True, f"decoded {len(full_strings)} strings")
        self._log("harness", True, "executing harness with Roblox stubs")
        harness_result = self._run_lua_harness(source)
        if harness_result and _looks_like_real_code(harness_result):
            self._log("harness_success", True, f"captured {len(harness_result)} chars")
            return harness_result, 'lua_harness', 'Harness captured original source'
        self._log("ast_decompile", True, "attempting AST decompilation")
        decompiler = ASTDecompiler(source, full_strings)
        result = decompiler.decompile()
        if result and _looks_like_real_code(result):
            self._log("ast_decompile_success", True, f"decompiled {len(result)} chars")
            instrumenter = Instrumenter()
            result = instrumenter.instrument(result)
            header = "-- Deobfuscated & Instrumented via AST pipeline\n\n"
            return header + result, 'ast_decompile_instrumented', 'AST decompilation with instrumentation'
        self._log("ast_decompile", False, "AST decompilation produced no meaningful output")
        fallback = _format_clean_vm(_substitute_e_calls(source, full_strings))
        if fallback and _looks_like_real_code(fallback):
            return fallback, 'regex_fallback', 'Regex-based string substitution'
        lines = [f"-- [{i}] {json.dumps(str(s))}" for i, s in enumerate(full_strings) if s]
        return '\n'.join(lines), 'wearedevs_decode', 'Decoded string table'

class DeobfEngine:
    def __init__(self):
        self.unluac_path = UNLUAC_LOCAL_PATH
        self._java_available = shutil.which('java') is not None
        self.trace = []
        self.unveiler = Unveiler(
            java_available=self._java_available,
            unluac_path=self.unluac_path,
            run_unluac_fn=self._run_unluac,
            run_lua_harness_fn=self._run_lua_harness
        )
        self.var_renamer = VarRenamer()
    def get_capabilities(self):
        return {
            'wearedevs_decode': True,
            'ast_decompile': HAS_LUAPARSER,
            'lua_harness': True,
            'unluac': self._java_available and os.path.isfile(self.unluac_path),
            'var_renamer': True,
            'instrumentation': True,
        }
    def _trace(self, stage, success, message):
        self.trace.append(DiagnosticEvent(stage=stage, success=success, message=message))
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
if not getreg then getreg = function() return {} end end
if not getupvalues then getupvalues = function() return {} end end
if not hookfunction then hookfunction = function(f, h) return h end end
if not checkcaller then checkcaller = function() return false end end
if not bit then _G.bit = _G.bit32 end
if not game then
game = {
GetService = function(self, svc)
local s = {}
setmetatable(s, {__index = function() return function() end end})
return s
end,
FindFirstChild = function() return nil end,
FindFirstChildOfClass = function() return nil end,
Players = {
LocalPlayer = {
Kick = function() end,
Character = {Head = {Position = {}}},
Name = "Player",
WaitForChild = function() return {} end,
GetMouse = function() return {X=0,Y=0} end
},
GetPlayers = function() return {} end
},
Workspace = {},
JobId = "00000000-0000-0000-0000-000000000000"
}
end
if not workspace then
workspace = {
GetChildren = function() return {} end,
FindFirstChild = function() return nil end,
FindFirstChildOfClass = function() return nil end,
CurrentCamera = {CFrame = {}, Position = {}},
}
end
if not Instance then
Instance = {new = function(cls) return {} end}
end
if not task then
task = {spawn = function(f) pcall(f) end, delay = function(_,f) pcall(f) end, wait = function() end}
end
if not typeof then typeof = type end
if not getgenv then getgenv = function() return _G end end
if debug then
if not debug.getinfo then debug.getinfo = function() return {what="Lua"} end end
end
if not Enum then Enum = {} end
if not Color3 then Color3 = {new=function() return {} end, fromRGB=function() return {} end} end
if not UDim2 then UDim2 = {new=function() return {} end} end
if not CFrame then CFrame = {new=function() return {} end, lookAt=function() return {} end} end
if not Vector2 then Vector2 = {new=function() return {} end} end
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
_G.bit32=bit32; _G.bit=bit32
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
                        stdout, _ = proc.communicate(timeout=120)
                        stdout = stdout.decode('latin-1', errors='replace')
                    except subprocess.TimeoutExpired:
                        try: os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        except: pass
                    proc.wait()
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
                if tag == 'print_output':
                    if decoded_data.strip():
                        candidates.append({'data': decoded_data, 'tag': tag})
                    continue
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
            r = subprocess.run(['java', '-jar', self.unluac_path, '--rawstring', tmp_path], capture_output=True, timeout=30)
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
    def _apply_var_renamer(self, code):
        try:
            return self.var_renamer.rename(code)
        except:
            return code
    def process(self, source, logger=None):
        self.trace = []
        result, method, diagnostic = self.unveiler.unveil(source)
        for entry in self.unveiler.trace:
            self._trace(entry['stage'], entry['success'], entry['message'])
        if result and method in ('ast_decompile_instrumented', 'lua_harness', 'regex_fallback'):
            result = self._apply_var_renamer(result)
        if logger:
            for entry in self.unveiler.trace:
                logger.add_trace(entry['stage'], entry['success'], entry['message'])
            logger.finish(result, method, diagnostic)
        return result, method, diagnostic, [vars(t) for t in self.trace]

job_store = {}
job_lock = threading.Lock()

def _save_jobs():
    try:
        completed_jobs = {k: v for k, v in job_store.items() if v.get('status') != 'processing'}
        with open(JOB_STORAGE_FILE, 'w') as f:
            json.dump(completed_jobs, f)
    except:
        pass

def _load_jobs():
    try:
        if os.path.exists(JOB_STORAGE_FILE):
            with open(JOB_STORAGE_FILE, 'r') as f:
                loaded = json.load(f)
                job_store.update(loaded)
    except:
        pass

def _cleanup_old_jobs():
    while True:
        try:
            time.sleep(3600)
            current_time = time.time()
            with job_lock:
                to_delete = [job_id for job_id, job in job_store.items() if current_time - job.get('created', 0) > 86400]
                for job_id in to_delete:
                    del job_store[job_id]
            _save_jobs()
        except:
            pass

_load_jobs()
cleanup_thread = threading.Thread(target=_cleanup_old_jobs, daemon=True)
cleanup_thread.start()

def _run_job(job_id, source):
    engine = DeobfEngine()
    logger = JobLogger()
    logger.start_job(job_id, engine.get_capabilities())
    try:
        result, method, diagnostic, trace = engine.process(source, logger)
        with job_lock:
            job_store[job_id] = {
                'status': 'complete', 'result': result, 'detected': method,
                'diagnostic': diagnostic, 'trace': trace,
                'result_length': len(result) if result else 0,
                'created': job_store.get(job_id, {}).get('created', time.time()),
                'log_json': logger.to_json()
            }
        _save_jobs()
    except Exception as e:
        logger.add_error(str(e), e)
        logger.finish()
        with job_lock:
            job_store[job_id] = {
                'status': 'error', 'error': str(e),
                'traceback': traceback.format_exc()[:4000],
                'created': job_store.get(job_id, {}).get('created', time.time()),
                'log_json': logger.to_json()
            }
        _save_jobs()

def submit_job(source):
    job_id = str(uuid.uuid4())
    with job_lock:
        job_store[job_id] = {'status': 'processing', 'created': time.time()}
    _save_jobs()
    threading.Thread(target=_run_job, args=(job_id, source), daemon=True).start()
    return job_id

def get_job(job_id):
    with job_lock:
        _load_jobs()
        return job_store.get(job_id)
