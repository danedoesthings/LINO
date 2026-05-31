import os, re, shutil, subprocess, tempfile, base64, urllib.request, hashlib, json, sys, io, math, time, uuid, threading, contextlib, resource, signal, traceback, zlib, binascii
from collections import defaultdict, Counter, deque
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any, Set

try:
    import luaparser.astnodes as _astnodes
    from luaparser import ast as lua_ast
    from luaparser.astnodes import (
        Chunk, Block, If, While, Assign, LocalAssign, Name, Number, String,
        Index, AddOp, SubOp, MultOp, FloatDivOp, FloorDivOp, ModOp, ExpoOp,
        LessThanOp, GreaterThanOp, LessOrEqThanOp, GreaterOrEqThanOp,
        EqToOp, NotEqToOp, UMinusOp, ULNotOp, BinaryOp, UnaryOp,
    )
    HAS_LUAPARSER = True
except ImportError:
    HAS_LUAPARSER = False

from env_logger import JobLogger
from var_renamer import VarRenamer

UNLUAC_JAR_URL = "https://github.com/scratchminer/unluac/releases/download/v2023.03.22/unluac.jar"
UNLUAC_LOCAL_PATH = os.environ.get('UNLUAC_PATH') or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'unluac.jar')

LUA_KEYWORDS = {
    'function','local','end','return','if','then','else','elseif',
    'for','while','do','repeat','until','not','and','or',
    'nil','true','false','in','break','print','require',
    'pcall','xpcall','loadstring','load','pairs','ipairs',
    'setmetatable','getmetatable','rawset','rawget','tostring','tonumber',
    'table','string','math','coroutine','debug','io','os',
    'unpack','select','type','assert','error','next','rawequal',
}

JOB_STORAGE_DIR = '/data'
JOB_STORAGE_FILE = os.path.join(JOB_STORAGE_DIR, 'deobf_jobs.json')
os.makedirs(JOB_STORAGE_DIR, exist_ok=True)

@contextlib.contextmanager
def _suppress_stderr():
    old = sys.stderr
    sys.stderr = io.StringIO()
    try:
        yield
    finally:
        sys.stderr = old

def _shannon_entropy(data):
    if not data:
        return 0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())

def _is_lua_bytecode(raw):
    return isinstance(raw, (bytes, bytearray)) and raw[:4] == b'\x1bLua'

def _is_probably_text(data):
    if not data:
        return False
    raw = data.encode('latin-1', errors='ignore') if isinstance(data, str) else data
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

def _escape_lua_string(s):
    return json.dumps(s)

def _looks_like_real_code(text):
    if not text or len(text) < 20:
        return False
    lines = text.splitlines()
    keywords = {'function','while','for','if','repeat','print','local','return'}
    count = sum(1 for line in lines if any(kw in line for kw in keywords))
    return count >= 1

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
    bits, bit_count = 0, 0
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
            raw_bytes = _custom_b64_decode(s, alphabet)
            if raw_bytes and len(raw_bytes) >= 1:
                for enc in ('utf-8', 'latin-1'):
                    try:
                        text = raw_bytes.decode(enc, errors='replace')
                        if text and _is_probably_text(text):
                            decoded.append(text)
                            break
                    except Exception:
                        pass
                else:
                    decoded.append(s)
                continue
        except Exception:
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
        if inner is None:
            return None
        expr = expr[:m.start()] + str(inner) + expr[m.end():]
        expr = clean_doubles(expr)
    while True:
        m = re.search(r'(-?\d+)([\*/%])(-?\d+)', expr)
        if not m:
            break
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        if op == '*':
            res = a * b
        elif op == '/' and b != 0:
            res = a // b
        elif op == '%' and b != 0:
            res = a % b
        else:
            return None
        expr = expr[:m.start()] + str(res) + expr[m.end():]
        expr = clean_doubles(expr)
    tokens = re.findall(r'[+-]?\d+', expr)
    if tokens:
        try:
            return sum(int(t) for t in tokens)
        except Exception:
            pass
    try:
        return int(expr)
    except Exception:
        return None

def global_fold_math_regex(code):
    def repl(m):
        res = safe_eval_int(m.group(0))
        return str(res) if res is not None else m.group(0)
    for _ in range(8):
        prev = code
        code = re.sub(r'\(([^()a-zA-Z_"\']+)\)', lambda m: repl(m), code)
        code = re.sub(r'\b(-?\d+)\s*([+\-*/%])\s*(-?\d+)\b', repl, code)
        if code == prev:
            break
    return code

def _get_e_offset(source):
    patterns = [
        r'local\s+function\s+E\s*\(E\)\s*return\s+R\[E\s*\+\s*\(?\s*(-?\d+(?:[+\-]\d+)*)\s*\)?\]',
        r'\breturn\s+R\s*\[\s*E\s*\+\s*\(?\s*(-?\d+(?:[+\-]\d+)*)\s*\)?\s*\]',
    ]
    for pat in patterns:
        m = re.search(pat, source)
        if m:
            val = safe_eval_int(m.group(1))
            if val is not None:
                return val
    return None

def _substitute_e_calls(source, full_strings):
    source = global_fold_math_regex(source)
    offset = _get_e_offset(source)
    if offset is None:
        offset = 0
    call_pat = re.compile(r'\b(?:E|GetString)\s*\(\s*([^)]+?)\s*\)')

    def repl(m):
        inner = m.group(1).strip()
        n = safe_eval_int(inner)
        if n is None:
            return m.group(0)
        lua_idx = n + offset
        py_idx = lua_idx - 1
        if 0 <= py_idx < len(full_strings):
            val = full_strings[py_idx]
            if not val:
                return 'nil'
            return _escape_lua_string(str(val))
        return m.group(0)
    return call_pat.sub(repl, source)

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

if HAS_LUAPARSER:

    _OP_CLASS_TO_STR = {
        AddOp.__name__: '+',
        SubOp.__name__: '-',
        MultOp.__name__: '*',
        FloatDivOp.__name__: '/',
        FloorDivOp.__name__: '//',
        ModOp.__name__: '%',
        ExpoOp.__name__: '^',
        LessThanOp.__name__: '<',
        GreaterThanOp.__name__: '>',
        LessOrEqThanOp.__name__: '<=',
        GreaterOrEqThanOp.__name__: '>=',
        EqToOp.__name__: '==',
        NotEqToOp.__name__: '~=',
    }

    def _get_op_str(node):
        return _OP_CLASS_TO_STR.get(type(node).__name__)

    def _eval_binary_op(node):
        if not (isinstance(node.left, Number) and isinstance(node.right, Number)):
            return None
        op = _get_op_str(node)
        if op is None:
            return None
        try:
            left_val = float(node.left.n)
            right_val = float(node.right.n)
            if op == '+':
                result = left_val + right_val
            elif op == '-':
                result = left_val - right_val
            elif op == '*':
                result = left_val * right_val
            elif op == '/' and right_val != 0:
                result = left_val / right_val
            elif op == '//' and right_val != 0:
                result = left_val // right_val
            elif op == '%' and right_val != 0:
                result = left_val % right_val
            elif op == '^':
                result = left_val ** right_val
            else:
                return None
            int_result = int(result) if result == int(result) else result
            return Number(int_result)
        except Exception:
            return None

    class RobustASTConstantFolder:
        def visit(self, node):
            if node is None:
                return None
            if isinstance(node, BinaryOp):
                node.left = self.visit(node.left)
                node.right = self.visit(node.right)
                folded = _eval_binary_op(node)
                if folded is not None:
                    return folded
                return node
            if isinstance(node, UMinusOp):
                node.operand = self.visit(node.operand)
                if isinstance(node.operand, Number):
                    try:
                        val = -float(node.operand.n)
                        return Number(int(val) if val == int(val) else val)
                    except Exception:
                        pass
                return node
            self._visit_children(node)
            return node

        def _visit_children(self, node):
            for attr in vars(node):
                child = getattr(node, attr, None)
                if child is None:
                    continue
                if isinstance(child, list):
                    for i, item in enumerate(child):
                        if hasattr(item, '__class__') and item.__class__.__module__.startswith('luaparser'):
                            child[i] = self.visit(item)
                elif hasattr(child, '__class__') and child.__class__.__module__.startswith('luaparser'):
                    setattr(node, attr, self.visit(child))

    class ASTTableResolver:
        def __init__(self, strings):
            self.strings = strings

        def visit(self, node):
            if node is None:
                return None
            if isinstance(node, Index):
                node.value = self.visit(node.value)
                node.idx = self.visit(node.idx)
                is_r = (isinstance(node.value, Name) and
                        node.value.id in ('R', 'EncryptedStrings'))
                if is_r and isinstance(node.idx, Number):
                    idx = int(node.idx.n)
                    if 1 <= idx <= len(self.strings):
                        val = self.strings[idx - 1]
                        if isinstance(val, str) and _is_readable_identifier(val):
                            safe = _escape_lua_string(val)
                            return String(safe.encode(), val)
                        elif val:
                            safe = _escape_lua_string(str(val))
                            return String(safe.encode(), str(val))
                return node
            self._visit_children(node)
            return node

        def _visit_children(self, node):
            for attr in vars(node):
                child = getattr(node, attr, None)
                if child is None:
                    continue
                if isinstance(child, list):
                    for i, item in enumerate(child):
                        if hasattr(item, '__class__') and item.__class__.__module__.startswith('luaparser'):
                            child[i] = self.visit(item)
                elif hasattr(child, '__class__') and child.__class__.__module__.startswith('luaparser'):
                    setattr(node, attr, self.visit(child))

    class BinaryTreeUnflattener:
        def __init__(self, while_node, state_var_name):
            self.while_node = while_node
            self.state_var = state_var_name
            self.state_map: Dict[int, Any] = {}

        def _extract_candidate_states(self, source_code):
            return {int(n) for n in re.findall(r'-?\d+', source_code)}

        def _is_state_assign(self, stmt):
            if isinstance(stmt, (Assign, LocalAssign)):
                for target in stmt.targets:
                    if isinstance(target, Name) and target.id == self.state_var:
                        return True
            return False

        def _find_next_state(self, block):
            if not isinstance(block, Block):
                return None
            for stmt in block.body:
                if isinstance(stmt, (Assign, LocalAssign)):
                    for i, target in enumerate(stmt.targets):
                        if isinstance(target, Name) and target.id == self.state_var:
                            if i < len(stmt.values) and isinstance(stmt.values[i], Number):
                                return int(stmt.values[i].n)
            return None

        def _evaluate_path(self, node, state_value):
            if node is None:
                return None
            if isinstance(node, Block):
                for stmt in node.body:
                    if isinstance(stmt, If):
                        result = self._evaluate_path(stmt, state_value)
                        if result is not None:
                            return result
                return node
            if isinstance(node, If):
                test = node.test
                op = _get_op_str(test) if isinstance(test, BinaryOp) else None
                if op and isinstance(test, BinaryOp):
                    left = test.left
                    right = test.right
                    if isinstance(left, Name) and left.id == self.state_var:
                        if isinstance(right, Number):
                            rval = int(right.n)
                            cond = {
                                '<': state_value < rval,
                                '<=': state_value <= rval,
                                '>': state_value > rval,
                                '>=': state_value >= rval,
                                '==': state_value == rval,
                                '~=': state_value != rval,
                            }.get(op)
                            if cond is None:
                                return None
                            branch = node.body if cond else node.orelse
                            return self._evaluate_path(branch, state_value)
                return node
            return None

        def _build_state_map(self, source_code):
            for state in self._extract_candidate_states(source_code):
                leaf = self._evaluate_path(self.while_node.body, state)
                if leaf is not None and isinstance(leaf, Block) and leaf.body:
                    self.state_map[state] = leaf

        def reconstruct(self, initial_state, raw_body_source):
            self._build_state_map(raw_body_source)
            out_stmts = []
            current = initial_state
            visited: Set[int] = set()
            while current is not None and current not in visited:
                visited.add(current)
                if current not in self.state_map:
                    break
                leaf = self.state_map[current]
                for stmt in leaf.body:
                    if not self._is_state_assign(stmt):
                        out_stmts.append(stmt)
                current = self._find_next_state(leaf)
            return Chunk(Block(out_stmts))

def _format_clean_vm(code):
    code = re.sub(r'(?<![=<>~])\b(end)\b', r'\n\1\n', code)
    code = re.sub(r'\b(local\s+(?:function\b)?)', r'\n\1', code)
    code = re.sub(r'\b(return)\b', r'\n\1 ', code)
    code = re.sub(r'\b(if\s)', r'\n\1', code)
    code = re.sub(r'\b(else)\b(?!\s*if)', r'\nelse\n', code)
    code = re.sub(r'\b(elseif)\b', r'\nelseif', code)
    code = re.sub(r'\b(while\s)', r'\nwhile ', code)
    code = re.sub(r'\b(for\s)', r'\nfor ', code)
    code = re.sub(r'\b(do)\b', r'\ndo\n', code)
    code = re.sub(r'\}\s*\{', '}, {', code)
    code = re.sub(r'\s*--\s*\d{4,}\b', '', code)
    lines = code.split('\n')
    indent = 0
    out = []
    _OPEN_WORDS = {'then', 'do', 'else', 'elseif'}
    _CLOSE_WORDS = {'end', 'else', 'elseif', 'until'}
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        first = line.split()[0] if line.split() else ''
        first_kw = re.sub(r'[^a-zA-Z0-9_]', '', first)
        if first_kw in _CLOSE_WORDS:
            indent = max(0, indent - 1)
        out.append('    ' * indent + line)
        stripped = re.sub(r'"[^"]*"', '""', line)
        stripped = re.sub(r'--.*', '', stripped)
        opens = len(re.findall(r'\b(?:function|then|do)\b', stripped))
        closes = len(re.findall(r'\bend\b', stripped))
        if first_kw in ('else', 'elseif'):
            indent += 1
        elif opens > closes:
            indent += (opens - closes)
        elif closes > opens:
            indent = max(0, indent - (closes - opens))
    return '\n'.join(out)

class ASTDecompiler:
    def __init__(self, source, full_strings):
        self.source = source
        self.strings = full_strings

    def _is_virtual_machine(self, source):
        inner = source
        m = re.search(r'while\s+\w+\s+do', source)
        if m:
            inner = source[m.start():]
        vm_indicators = [
            r'while\s+\w+\s+do\s+if\s+\w+\s*<\s*\d+\s+then',
            r'if\s+\w+\s*<\s*-?\d+\s+then',
            r'\w+\[\w+\]\s*=\s*\w+\[\w+\]\s*[+\-]\s*\d+',
        ]
        hits = sum(1 for ind in vm_indicators if re.search(ind, inner))
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
        except Exception:
            return _format_clean_vm(prepared)
        folder = RobustASTConstantFolder()
        tree = folder.visit(tree)
        resolver = ASTTableResolver(self.strings)
        tree = resolver.visit(tree)
        if is_vm:
            tree = self._unflatten_vm(tree, prepared)
        try:
            final_code = lua_ast.to_lua_source(tree)
        except Exception:
            final_code = _format_clean_vm(prepared)
        if is_vm:
            return '-- [VM DETECTED] Devirtualized via control-flow unflattening\n\n' + _format_clean_vm(final_code)
        return final_code

    def _unflatten_vm(self, tree, raw_source):
        while_node = None
        state_var = None

        def _find_while(node):
            nonlocal while_node, state_var
            if node is None:
                return
            if isinstance(node, While):
                if isinstance(node.test, Name):
                    while_node = node
                    state_var = node.test.id
                    return
            for attr in vars(node):
                child = getattr(node, attr, None)
                if child is None:
                    continue
                if isinstance(child, list):
                    for item in child:
                        if hasattr(item, '__class__') and item.__class__.__module__.startswith('luaparser'):
                            _find_while(item)
                elif hasattr(child, '__class__') and child.__class__.__module__.startswith('luaparser'):
                    _find_while(child)

        _find_while(tree)
        if while_node is None or state_var is None:
            return tree
        unflat = BinaryTreeUnflattener(while_node, state_var)
        candidates = {int(n) for n in re.findall(r'-?\d+', raw_source)}
        if not candidates:
            return tree
        entry = min(candidates)
        return unflat.reconstruct(entry, raw_source)

class Instrumenter:

    _RENAME_HINTS = [
        (r'\bHttpService\b', 'httpService'),
        (r'\brequestAsync\b', 'httpResponse'),
        (r'\bLocalPlayer\b', 'localPlayer'),
        (r'\bCharacter\b', 'character'),
        (r'\bHumanoid\b', 'humanoid'),
        (r'\bloadstring\b', 'loadedFunc'),
        (r'\bload\b(?!\w)', 'loadedFunc'),
        (r'\bpcall\b', 'protectedCall'),
        (r'\bsetmetatable\b', 'setMeta'),
        (r'\bgetmetatable\b', 'getMeta'),
        (r'\brawset\b', 'rawSet'),
        (r'\brawget\b', 'rawGet'),
        (r'\bFireServer\b', 'fireServer'),
        (r'\bFireClient\b', 'fireClient'),
        (r'\bInvokeServer\b', 'invokeServer'),
        (r'\bFindFirstChild\b', 'findChild'),
        (r'\bWaitForChild\b', 'waitChild'),
        (r'\bGetService\b', 'getService'),
    ]

    _ENV_PROXY = r'''
    local _origEnv = getfenv and getfenv() or _ENV
    local _loggedEnv = setmetatable({}, {
        __index = function(_t, k)
            local v = _origEnv[k]
            print(string.format("[ENV READ]  %s -> %s", tostring(k), tostring(v)))
            if k == "HttpService" or k == "request" or k == "RequestAsync" then
                print("  [RENAME HINT] httpResponse / httpService")
            elseif k == "LocalPlayer" or k == "Character" or k == "Humanoid" then
                print("  [RENAME HINT] localPlayer / character / humanoid")
            elseif k == "loadstring" or k == "load" then
                print("  [RENAME HINT] loadedFunc")
            elseif k == "pcall" or k == "xpcall" then
                print("  [RENAME HINT] protectedCall")
            elseif k == "setmetatable" then
                print("  [RENAME HINT] setMeta")
            elseif type(v) == "function" then
                print("  [RENAME HINT] funcRef_" .. tostring(k))
            elseif type(v) == "table" then
                print("  [RENAME HINT] tableRef_" .. tostring(k))
            end
            if k == "HttpService" then
                return setmetatable({}, {
                    __index = function(_, method)
                        print("[NET INTERCEPT] HttpService." .. tostring(method) .. " called")
                        return function(...) print("[NET ARGS]", ...) end
                    end
                })
            end
            if k == "loadstring" or k == "load" then
                return function(code, ...)
                    print("[LOADSTRING INTERCEPT] len=" .. tostring(type(code)=="string" and #code or "?"))
                    if type(code) == "string" and #code > 0 then
                        print(string.sub(code, 1, 200))
                    end
                    return _origEnv[k](code, ...)
                end
            end
            return v
        end,
        __newindex = function(_t, k, v)
            print(string.format("[ENV WRITE] %s = %s", tostring(k), tostring(v)))
            _origEnv[k] = v
        end,
        __pairs = function(_t) return pairs(_origEnv) end,
    })
    if getfenv then setfenv(1, _loggedEnv) else _ENV = _loggedEnv end
    local _realSetMeta = setmetatable
    setmetatable = function(tbl, mt)
        if mt then
            local _origIndex = mt.__index
            local _origNewIndex = mt.__newindex
            if _origIndex then
                mt.__index = function(t, k)
                    local v = type(_origIndex)=="function" and _origIndex(t,k) or _origIndex[k]
                    print(string.format("[META __index]  key=%s  val=%s", tostring(k), tostring(v)))
                    return v
                end
            end
            if _origNewIndex then
                mt.__newindex = function(t, k, v)
                    print(string.format("[META __newindex]  key=%s  val=%s", tostring(k), tostring(v)))
                    if type(_origNewIndex) == "function" then _origNewIndex(t, k, v)
                    else rawset(t, k, v) end
                end
            end
        end
        return _realSetMeta(tbl, mt)
    end
'''

    def _safe_strip_comments(self, code):
        lines = code.split('\n')
        cleaned = []
        for line in lines:
            line = re.sub(r'\s*--\s*-?\d{4,}\s*$', '', line)
            cleaned.append(line)
        return '\n'.join(cleaned)

    def instrument(self, code):
        code = global_fold_math_regex(code)
        code = self._safe_strip_comments(code)
        lines = code.split('\n')
        output = []
        inserted_env = False
        inserted_hook = False
        state_var = self._detect_state_var(code)
        i = 0
        while i < len(lines):
            line = lines[i].rstrip()
            if not inserted_env:
                if re.match(r'^[ \t]*(local\s+)?function\b|^return\s*\(?\s*function', line):
                    output.append(line)
                    for proxy_line in self._ENV_PROXY.split('\n'):
                        output.append(proxy_line)
                    inserted_env = True
                    i += 1
                    continue
            if not inserted_hook and state_var:
                if re.search(r'\bwhile\s+' + re.escape(state_var) + r'\s+do\b', line):
                    output.append(line)
                    output.append(f'        print(string.format("[HOOK OP] StateId=%d PC=%d", {state_var}, (_hookPC or 0)))')
                    output.append(f'        _hookPC = (_hookPC or 0) + 1')
                    inserted_hook = True
                    i += 1
                    continue
            output.append(self._annotate_line(line))
            i += 1
        code = '\n'.join(output)
        code = self._apply_renames(code)
        return self._beautify(code)

    def _detect_state_var(self, code):
        m = re.search(r'while\s+(\w+)\s+do', code)
        return m.group(1) if m else None

    def _annotate_line(self, line):
        hints = []
        for pattern, hint in self._RENAME_HINTS:
            if re.search(pattern, line):
                hints.append(hint)
        if hints and '--' not in line:
            unique = list(dict.fromkeys(hints))[:3]
            line = line + '  -- [RENAME HINT] ' + ', '.join(unique)
        return line

    def _apply_renames(self, code):
        renames = {
            r'\bR\b': 'EncryptedStrings',
            r'\bE\b(?!\w)': 'GetString',
            r'\bl\b': 'stateId',
            r'\bQ\b': 'VirtualStack',
            r'\bI\b': 'InstructionTable',
            r'\bw\b': 'AllocSlot',
            r'\bM\b': 'PackArgs',
            r'\bY\b': 'CallEnv',
            r'\bN\b': 'AlphabetMap',
            r'\bh\b': 'charFunc',
            r'\bJ\b': 'FuncWrap',
            r'\bS\b': 'ShuffleTable',
            r'\bT\b': 'TokenMap',
            r'\bO\b(?!\w)': 'CleanupRef',
            r'\bg\b': 'helperG',
        }
        for pat, repl in renames.items():
            code = re.sub(pat, repl, code)
        return code

    def _beautify(self, code):
        code = re.sub(r';', '\n', code)
        code = re.sub(r'\n{3,}', '\n\n', code)
        lines = code.split('\n')
        indent = 0
        out = []
        _OPENERS = frozenset(['then', 'do', 'else', 'elseif', 'repeat'])
        _CLOSERS = frozenset(['end', 'else', 'elseif', 'until'])
        _FUNC_PAT = re.compile(r'\bfunction\b')
        for raw in lines:
            line = raw.strip()
            if not line:
                out.append('')
                continue
            safe = re.sub(r'"[^"]*"', '""', line)
            safe = re.sub(r"'[^']*'", "''", safe)
            safe = re.sub(r'--.*', '', safe)
            first_tok = (safe.split() or [''])[0].rstrip('(')
            if first_tok in _CLOSERS:
                indent = max(0, indent - 1)
            out.append('    ' * indent + line)
            func_opens = len(_FUNC_PAT.findall(safe))
            kw_opens = sum(1 for kw in _OPENERS if re.search(r'\b' + kw + r'\b', safe))
            kw_closes = len(re.findall(r'\bend\b', safe))
            opens = func_opens + kw_opens
            closes = kw_closes
            if first_tok in ('else', 'elseif'):
                indent += 1
            else:
                delta = opens - closes
                indent = max(0, indent + delta)
        return '\n'.join(out)

class Unveiler:
    def __init__(self, java_available, unluac_path, run_unluac_fn, run_lua_harness_fn):
        self.java_available = java_available
        self.unluac_path = unluac_path
        self._run_unluac = run_unluac_fn
        self._run_lua_harness = run_lua_harness_fn
        self.trace: List[Dict] = []

    def _log(self, stage, success, message):
        self.trace.append({'stage': stage, 'success': success,
                           'message': message, 'timestamp': time.time()})

    def unveil(self, source):
        self.trace = []
        full_strings = _decode_full_r_table(source)
        if not full_strings:
            self._log('decode', False, 'could not decode R table')
            return '', 'unable', 'String decode failed'
        self._log('decode', True, f'decoded {len(full_strings)} strings')
        self._log('harness', True, 'executing harness with Roblox stubs')
        harness_result = self._run_lua_harness(source)
        if harness_result and _looks_like_real_code(harness_result):
            self._log('harness_success', True, f'captured {len(harness_result)} chars')
            return harness_result, 'lua_harness', 'Harness captured original source'
        self._log('ast_decompile', True, 'attempting AST decompilation')
        decompiler = ASTDecompiler(source, full_strings)
        result = decompiler.decompile()
        if result and _looks_like_real_code(result):
            self._log('ast_decompile_success', True, f'decompiled {len(result)} chars')
            instrumenter = Instrumenter()
            result = instrumenter.instrument(result)
            header = '-- Deobfuscated & Instrumented via AST pipeline\n\n'
            return header + result, 'ast_decompile_instrumented', 'AST decompilation with instrumentation'
        self._log('ast_decompile', False, 'AST decompilation produced no meaningful output')
        fallback = _format_clean_vm(_substitute_e_calls(source, full_strings))
        if fallback and _looks_like_real_code(fallback):
            return fallback, 'regex_fallback', 'Regex-based string substitution'
        lines = [f'-- [{i}] {json.dumps(str(s))}' for i, s in enumerate(full_strings) if s]
        return '\n'.join(lines), 'wearedevs_decode', 'Decoded string table'

class DeobfEngine:
    def __init__(self):
        self.unluac_path = UNLUAC_LOCAL_PATH
        self._java_available = shutil.which('java') is not None
        self.trace: List[DiagnosticEvent] = []
        self.unveiler = Unveiler(
            java_available=self._java_available,
            unluac_path=self.unluac_path,
            run_unluac_fn=self._run_unluac,
            run_lua_harness_fn=self._run_lua_harness,
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
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_CPU, (60, 65))
            resource.setrlimit(resource.RLIMIT_NPROC, (50, 50))
            resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        except Exception:
            pass

    _HARNESS_TEMPLATE = r'''
local captures = {}
local hook_stats = {}
local CALL_DEPTH = 0
local MAX_DEPTH  = 25
local b64chars   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

local function b64encode(data)
    local result, padding = {}, ""
    for i = 1, #data, 3 do
        local a, b, c = data:byte(i, i+2)
        b = b or 0; c = c or 0
        local n = a*65536 + b*256 + c
        local c1,c2,c3,c4 = math.floor(n/262144)%64,math.floor(n/4096)%64,math.floor(n/64)%64,n%64
        table.insert(result, b64chars:sub(c1+1,c1+1))
        table.insert(result, b64chars:sub(c2+1,c2+1))
        if i+1>#data then padding="=="; break end
        table.insert(result, b64chars:sub(c3+1,c3+1))
        if i+2>#data then padding="="; break end
        table.insert(result, b64chars:sub(c4+1,c4+1))
    end
    return table.concat(result)..padding
end

local real_insert = table.insert
local function save(tag, data)
    if type(data)~="string" then return end
    if #data < 20 then return end
    if CALL_DEPTH > MAX_DEPTH then return end
    CALL_DEPTH = CALL_DEPTH + 1
    real_insert(captures, {tag=tag, data=b64encode(data), raw_length=#data})
    CALL_DEPTH = CALL_DEPTH - 1
end

local real_loadstring = loadstring
local real_load = load or loadstring
local INSIDE_LOAD = false
_G.loadstring = function(code, ...)
    if not INSIDE_LOAD then INSIDE_LOAD=true; save("loadstring",code); INSIDE_LOAD=false end
    return real_loadstring(code, ...)
end
if load then
    _G.load = function(code, ...)
        if not INSIDE_LOAD then INSIDE_LOAD=true; save("load",tostring(code)); INSIDE_LOAD=false end
        return real_load(code, ...)
    end
end

local real_char = string.char
string.char = function(...)
    local out = real_char(...)
    if #out > 40 then save("string_char", out) end
    return out
end

local real_concat = table.concat
table.concat = function(t, sep, i, j)
    local out = real_concat(t, sep, i, j)
    if type(out)=="string" and #out>20 then save("concat", out) end
    return out
end
local real_insert_hook = table.insert
table.insert = function(t, v, ...)
    if type(v)=="string" and #v>20 then save("table_insert", v) end
    return real_insert_hook(t, v, ...)
end

local real_pcall = pcall
_G.pcall = function(fn, ...)
    if type(fn)=="function" and debug and debug.getinfo then
        local info = debug.getinfo(fn)
        if info and info.what=="Lua" then
            local ok, dumped = real_pcall(string.dump, fn)
            if ok and dumped and #dumped>50 then save("pcall_fn", dumped) end
        end
    end
    return real_pcall(fn, ...)
end

local print_lines = {}
local real_print = print
_G.print = function(...)
    local parts = {}
    for i=1,select('#',...) do parts[i]=tostring(select(i,...)) end
    table.insert(print_lines, table.concat(parts,"\t"))
end

os.execute = function() error("os.execute blocked") end
io.popen   = function() error("io.popen blocked") end

if not getfenv then
    getfenv = function(f)
        if f then
            local i=1
            while true do
                local name,value=debug.getupvalue(f,i)
                if not name then break end
                if name=="_ENV" then return value end
                i=i+1
            end
        end
        return _G
    end
end
if not newproxy then newproxy=function(m) local p={} if m then setmetatable(p,{}) end return p end end
if not unpack then unpack=table.unpack or function(t,i,j) j=j or #t;i=i or 1;if i>j then return end;return t[i],unpack(t,i+1,j) end end
if not getreg then getreg=function() return {} end end
if not getupvalues then getupvalues=function() return {} end end
if not hookfunction then hookfunction=function(f,h) return h end end
if not checkcaller then checkcaller=function() return false end end
if not bit then _G.bit=_G.bit32 end
if not game then
    local stub=setmetatable({},{__index=function() return function() return setmetatable({},{__index=function() return function() end end}) end end})
    game=stub
    game.Players={LocalPlayer={Kick=function()end,Character={Head={Position={}}},Name="Player",WaitForChild=function() return {} end,GetMouse=function() return {X=0,Y=0} end},GetPlayers=function() return {} end}
    game.Workspace={}
    game.JobId="00000000-0000-0000-0000-000000000000"
    game.GetService=function(self,svc) return setmetatable({},{__index=function(_,k) return function() end end}) end
end
if not workspace then workspace=setmetatable({},{__index=function() return function() end end}) end
if not Instance then Instance={new=function(cls) return {} end} end
if not task then task={spawn=function(f) pcall(f) end,delay=function(_,f) pcall(f) end,wait=function() end} end
if not typeof then typeof=type end
if not getgenv then getgenv=function() return _G end end
if not Enum then Enum={} end
if not Color3 then Color3={new=function() return {} end,fromRGB=function() return {} end} end
if not UDim2 then UDim2={new=function() return {} end} end
if not CFrame then CFrame={new=function() return {} end,lookAt=function() return {} end} end
if not Vector2 then Vector2={new=function() return {} end} end
if not Vector3 then Vector3={new=function() return {} end} end
if debug then if not debug.getinfo then debug.getinfo=function() return {what="Lua"} end end end

local bit32=bit32 or nil
if not bit32 then
    local function bxor(a,b) local r,m=0,1;while a>0 or b>0 do local ab,bb=a%2,b%2;if ab~=bb then r=r+m end;a=math.floor(a/2);b=math.floor(b/2);m=m*2 end;return r end
    local function band(a,b) local r,m=0,1;while a>0 and b>0 do if a%2+b%2==2 then r=r+m end;a=math.floor(a/2);b=math.floor(b/2);m=m*2 end;return r end
    local function bor(a,b)  local r,m=0,1;while a>0 or b>0 do if a%2+b%2>0 then r=r+m end;a=math.floor(a/2);b=math.floor(b/2);m=m*2 end;return r end
    bit32={bxor=bxor,band=band,bor=bor,lshift=function(v,n) return math.floor(v*(2^n))%4294967296 end,rshift=function(v,n) return math.floor(v/(2^n)) end}
    bit32.arshift=bit32.rshift
end
_G.bit32=bit32; _G.bit=bit32

local f, err = loadfile("__SRCFILE__")
if not f then
    real_print("ERR:COMPILE:"..tostring(err))
else
    local ok, result = pcall(f)
    collectgarbage("collect")
    pcall(function()
        for k,v in pairs(_G) do
            if type(v)=="string" and #v>20 then save("env_"..tostring(k),v) end
        end
    end)
    if ok and type(result)=="function" and string.dump then
        local bc=string.dump(result)
        if bc and #bc>50 then save("function_return",bc) end
    end
    for _,cap in ipairs(captures) do real_print("CAP:"..cap.tag..":"..cap.data) end
    if #print_lines>0 then real_print("CAP:print_output:"..b64encode(table.concat(print_lines,"\n"))) end
    if #captures==0 and #print_lines==0 then
        if not ok then real_print("ERR:RUNTIME:"..tostring(result))
        else real_print("ERR:NO_OUTPUT") end
    end
end
'''

    def _run_lua_harness(self, source):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as src_tmp:
            src_tmp.write(source)
            src_path = src_tmp.name
        harness = self._HARNESS_TEMPLATE.replace('__SRCFILE__', src_path)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as tmp:
            tmp.write(harness)
            tmp_path = tmp.name
        captures = []
        try:
            for lua_bin in ('lua5.1', 'lua5.2', 'lua'):
                try:
                    proc = subprocess.Popen(
                        [lua_bin, tmp_path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        preexec_fn=self._set_process_limits,
                        start_new_session=True,
                    )
                    try:
                        stdout, _ = proc.communicate(timeout=120)
                        stdout = stdout.decode('latin-1', errors='replace')
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        except Exception:
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
        if not captures:
            return None
        candidates = []
        for cap in captures:
            tag, _, data = cap.partition(':')
            try:
                decoded = base64.b64decode(data).decode('latin-1', errors='replace')
            except Exception:
                decoded = data
            if tag == 'print_output':
                if decoded.strip():
                    candidates.append({'data': decoded, 'tag': tag})
                continue
            if not _is_probably_text(decoded):
                raw_check = decoded.encode('latin-1', errors='ignore')
                if _is_lua_bytecode(raw_check) and self._java_available:
                    try:
                        dec, _ = self._run_unluac(raw_check)
                        if dec:
                            decoded = dec
                    except Exception:
                        pass
                elif sum(1 for kw in LUA_KEYWORDS if kw in decoded) < 3:
                    continue
            candidates.append({'data': decoded, 'tag': tag})
        if candidates:
            return max(candidates, key=lambda x: len(x['data']))['data']
        return None

    def _run_unluac(self, bytecode):
        if not self._java_available:
            return None, 'no java'
        if not os.path.isfile(self.unluac_path):
            self._ensure_unluac_jar()
        if not os.path.isfile(self.unluac_path):
            return None, 'no unluac.jar'
        if bytecode[:4] != b'\x1bLua':
            return None, 'not lua bytecode'
        with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
            tmp.write(bytecode)
            tmp_path = tmp.name
        try:
            r = subprocess.run(
                ['java', '-jar', self.unluac_path, '--rawstring', tmp_path],
                capture_output=True, timeout=30)
            stdout = r.stdout.decode('latin-1', errors='replace')
            return (stdout, None) if r.returncode == 0 and stdout.strip() else (None, 'unluac failed')
        except subprocess.TimeoutExpired:
            return None, 'timeout'
        except Exception as e:
            return None, str(e)
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    def _ensure_unluac_jar(self):
        try:
            os.makedirs(os.path.dirname(self.unluac_path), exist_ok=True)
            urllib.request.urlretrieve(UNLUAC_JAR_URL, self.unluac_path)
        except Exception:
            pass

    def _apply_var_renamer(self, code):
        try:
            return self.var_renamer.rename(code)
        except Exception:
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

job_store: Dict[str, Any] = {}
job_lock = threading.Lock()

def _save_jobs():
    try:
        completed = {k: v for k, v in job_store.items() if v.get('status') != 'processing'}
        with open(JOB_STORAGE_FILE, 'w') as f:
            json.dump(completed, f)
    except Exception:
        pass

def _load_jobs():
    try:
        if os.path.exists(JOB_STORAGE_FILE):
            with open(JOB_STORAGE_FILE) as f:
                job_store.update(json.load(f))
    except Exception:
        pass

def _cleanup_old_jobs():
    while True:
        try:
            time.sleep(3600)
            now = time.time()
            with job_lock:
                old = [k for k, v in job_store.items() if now - v.get('created', 0) > 86400]
                for k in old:
                    del job_store[k]
            _save_jobs()
        except Exception:
            pass

_load_jobs()
_cleanup_thread = threading.Thread(target=_cleanup_old_jobs, daemon=True)
_cleanup_thread.start()

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
                'created': job_store.get(job_id, {}).get('created', time.time()),
                'log_json': logger.to_json(),
            }
        _save_jobs()
    except Exception as e:
        logger.add_error(str(e), e)
        logger.finish()
        with job_lock:
            job_store[job_id] = {
                'status': 'error',
                'error': str(e),
                'traceback': traceback.format_exc()[:4000],
                'created': job_store.get(job_id, {}).get('created', time.time()),
                'log_json': logger.to_json(),
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
