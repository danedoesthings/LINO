import re
import json
import math
from typing import Optional, List, Dict, Tuple, Any
from math_fold import safe_eval_int, fold_constants

class RobloxVMEmulator:
    def __init__(self, source: str, decoded_strings: List[str], offset: int = 0, getter_name: str = None):
        self.source = source
        self.strings = decoded_strings
        self.offset = offset
        self.getter_name = getter_name
        self.vm_var = None
        self.registers: Dict[str, Any] = {}
        self.memory: Dict[int, Any] = {}
        self.stack: List[Any] = []
        self.call_stack: List[Dict] = []
        self.output: List[str] = []
        self.instruction_count = 0
        self.max_instructions = 5000000
        self.debug = False
        self._bootstrap_environment()
        self._parse_source()

    def _log(self, msg: str):
        if self.debug:
            self.output.append(f"-- {msg}")

    def _bootstrap_environment(self):
        self.globals = {
            'print': self._native_print,
            'error': self._native_error,
            'pcall': self._native_pcall,
            'tostring': self._native_tostring,
            'tonumber': self._native_tonumber,
            'type': self._native_type,
            'select': self._native_select,
            'unpack': self._native_unpack,
            'setmetatable': self._native_setmetatable,
            'getmetatable': self._native_getmetatable,
            'rawget': self._native_rawget,
            'rawset': self._native_rawset,
            'rawequal': self._native_rawequal,
            'next': self._native_next,
            'pairs': self._native_pairs,
            'ipairs': self._native_ipairs,
            'assert': self._native_assert,
            'loadstring': self._native_loadstring,
            'load': self._native_loadstring,
            'getfenv': self._native_getfenv,
            'setfenv': self._native_setfenv,
            'newproxy': self._native_newproxy,
            'math': {
                'floor': math.floor,
                'random': self._native_math_random,
                'huge': float('inf'),
            },
            'string': {
                'char': self._native_string_char,
                'byte': self._native_string_byte,
                'sub': self._native_string_sub,
                'gsub': self._native_string_gsub,
                'len': self._native_string_len,
                'gmatch': self._native_string_gmatch,
                'rep': self._native_string_rep,
            },
            'table': {
                'concat': self._native_table_concat,
                'insert': self._native_table_insert,
                'remove': self._native_table_remove,
                'unpack': self._native_unpack,
            },
            'bit32': {
                'bxor': lambda a, b: a ^ b,
                'band': lambda a, b: a & b,
                'bor': lambda a, b: a | b,
                'lshift': lambda v, n: (v << n) & 0xFFFFFFFF,
                'rshift': lambda v, n: (v >> n) & 0xFFFFFFFF,
                'arshift': lambda v, n: (v >> n) if v >= 0 else ~(~v >> n),
                'bnot': lambda a: ~a & 0xFFFFFFFF,
            },
            'coroutine': {
                'wrap': lambda f: f,
                'create': lambda f: f,
                'resume': lambda co, *args: (True, co(*args) if callable(co) else None),
                'yield': lambda: None,
            },
            'tick': lambda: 0,
            'time': lambda: 0,
            'wait': lambda n=None: None,
            'spawn': lambda f: f() if callable(f) else None,
            'delay': lambda t, f: f() if callable(f) else None,
            'game': self._make_spy('game'),
            'workspace': self._make_spy('workspace'),
            'script': self._make_spy('script'),
            '_G': {},
            '_ENV': {},
            '_VERSION': 'Luau',
        }
        self.globals['_G'] = self.globals
        self.globals['_ENV'] = self.globals
        self.globals['bit'] = self.globals['bit32']

    def _make_spy(self, name: str) -> dict:
        def make_proxy(n):
            p = {}
            def index_handler(k):
                if k == 'Parent':
                    return None
                return make_proxy(f"{n}.{k}")
            def call_handler(*args):
                return make_proxy(f"{n}(...)")
            def newindex_handler(k, v):
                if isinstance(v, str) and len(v) > 3:
                    self.output.append(v)
            return {
                '__index': index_handler,
                '__call': call_handler,
                '__newindex': newindex_handler,
                '__tostring': lambda: n,
                '__len': lambda: 0,
                '__add': lambda a, b: 0,
                '__sub': lambda a, b: 0,
                '__mul': lambda a, b: 0,
                '__div': lambda a, b: 0,
                '__eq': lambda a, b: True,
                '__lt': lambda a, b: False,
                '__le': lambda a, b: False,
            }
        return make_proxy(name)

    def _native_print(self, *args):
        parts = [str(a) for a in args]
        line = '\t'.join(parts)
        self.output.append(line)

    def _native_error(self, msg, level=0):
        raise Exception(f"[VM Error] {msg}")

    def _native_pcall(self, fn, *args):
        try:
            result = fn(*args) if callable(fn) else fn
            return True, result
        except Exception as e:
            return False, str(e)

    def _native_tostring(self, v):
        if v is None:
            return 'nil'
        if isinstance(v, bool):
            return 'true' if v else 'false'
        if isinstance(v, (int, float)):
            if v == int(v) and not (isinstance(v, float) and math.isinf(v)):
                return str(int(v))
            return str(v)
        if isinstance(v, dict) and '__tostring' in v:
            return v['__tostring']()
        return str(v)

    def _native_tonumber(self, v, base=10):
        try:
            if isinstance(v, str):
                return int(v, base)
            return float(v)
        except:
            return None

    def _native_type(self, v):
        if v is None:
            return 'nil'
        if isinstance(v, bool):
            return 'boolean'
        if isinstance(v, (int, float)):
            return 'number'
        if isinstance(v, str):
            return 'string'
        if isinstance(v, (list, tuple)):
            return 'table'
        if callable(v):
            return 'function'
        if isinstance(v, dict):
            return 'table'
        return 'userdata'

    def _native_select(self, n, *args):
        if n == '#':
            return len(args)
        return args[n-1:] if n > 0 else args[n:]

    def _native_unpack(self, t, i=1, j=None):
        if isinstance(t, (list, tuple)):
            if j is None:
                j = len(t)
            return tuple(t[i-1:j])
        if isinstance(t, dict):
            keys = sorted([k for k in t.keys() if isinstance(k, int)], key=int)
            if j is None:
                j = max(keys) if keys else 0
            result = [t.get(k) for k in range(i, j+1)]
            return tuple(result)
        return ()

    def _native_setmetatable(self, t, mt):
        if isinstance(t, dict):
            if mt is not None:
                for key in mt:
                    t[key] = mt[key]
        return t

    def _native_getmetatable(self, t):
        if isinstance(t, dict):
            meta_keys = ['__index', '__newindex', '__call', '__tostring', '__len',
                         '__add', '__sub', '__mul', '__div', '__eq', '__lt', '__le',
                         '__gc', '__metatable', '__type']
            mt = {}
            for k in meta_keys:
                if k in t:
                    mt[k] = t[k]
            return mt if mt else None
        return None

    def _native_rawget(self, t, k):
        if isinstance(t, (list, tuple)):
            try:
                return t[k-1]
            except:
                return None
        if isinstance(t, dict):
            return t.get(k)
        if isinstance(t, str):
            try:
                return t[k-1]
            except:
                return None
        return None

    def _native_rawset(self, t, k, v):
        if isinstance(t, dict):
            t[k] = v
        return t

    def _native_rawequal(self, a, b):
        return a == b

    def _native_next(self, t, k=None):
        if isinstance(t, dict):
            keys = list(t.keys())
            if k is None:
                return keys[0] if keys else None, t.get(keys[0]) if keys else None
            try:
                idx = keys.index(k)
                if idx + 1 < len(keys):
                    return keys[idx+1], t.get(keys[idx+1])
            except ValueError:
                pass
        return None, None

    def _native_pairs(self, t):
        if isinstance(t, dict):
            keys = list(t.keys())
            def iterator(state, prev):
                try:
                    idx = state.index(prev) if prev is not None else -1
                    if idx + 1 < len(state):
                        k = state[idx+1]
                        return k, t.get(k)
                except ValueError:
                    pass
                return None
            return iterator, keys, None
        return lambda: None, {}, None

    def _native_ipairs(self, t):
        if isinstance(t, (list, tuple)):
            i = 0
            def iterator():
                nonlocal i
                i += 1
                if i <= len(t):
                    return i, t[i-1]
                return None
            return iterator
        return lambda: None

    def _native_assert(self, v, msg='assertion failed!'):
        if not v:
            self._native_error(msg)

    def _native_loadstring(self, src, chunkname=None):
        self.output.append(f"[Payload captured: {len(src)} bytes]")
        self.output.append(src)
        return lambda: None, None

    def _native_getfenv(self, lvl=None):
        return self.globals

    def _native_setfenv(self, fn, env):
        return fn

    def _native_newproxy(self, addmeta=False):
        return {}

    def _native_math_random(self, a=None, b=None):
        if a is None:
            return 0.5
        if b is None:
            return a % 65536
        return a + ((b - a) // 2)

    def _native_string_char(self, *codes):
        return ''.join(chr(c % 256) for c in codes)

    def _native_string_byte(self, s, i=1, j=None):
        if not s:
            return None
        if j is None:
            j = i
        return tuple(ord(c) for c in s[i-1:j])

    def _native_string_sub(self, s, i, j=None):
        if not s:
            return ''
        if j is None:
            j = len(s)
        return s[i-1:j]

    def _native_string_gsub(self, s, pattern, repl, n=None):
        if not s:
            return '', 0
        count = 0
        def repl_fn(m):
            nonlocal count
            count += 1
            if isinstance(repl, str):
                return repl
            if callable(repl):
                return str(repl(m))
            return str(repl)
        result = re.sub(pattern, repl_fn, s, count=n or 0)
        return result, count

    def _native_string_len(self, s):
        return len(s) if s else 0

    def _native_string_gmatch(self, s, pattern):
        def iterator():
            for m in re.finditer(pattern, s):
                yield m.group(0)
        return iterator()

    def _native_string_rep(self, s, n):
        return s * max(0, int(n))

    def _native_table_concat(self, t, sep='', i=1, j=None):
        if isinstance(t, (list, tuple)):
            if j is None:
                j = len(t)
            parts = [str(x) for x in t[i-1:j]]
            result = sep.join(parts)
            if len(result) > 5:
                self.output.append(result)
            return result
        return ''

    def _native_table_insert(self, t, pos, value=None):
        if isinstance(t, list):
            if value is None:
                t.append(pos)
            else:
                t.insert(pos-1, value)
        return t

    def _native_table_remove(self, t, pos=None):
        if isinstance(t, list):
            if pos is None:
                return t.pop()
            return t.pop(pos-1)
        return None

    def _parse_source(self):
        self._detect_getter()
        self._resolve_getter_calls()

    def _detect_getter(self):
        if self.getter_name and self.offset:
            return
        folded = fold_constants(self.source)
        patterns = [
            r'local\s+function\s+(\w+)\s*\(\s*\1\s*\)\s*return\s+R\s*\[\s*\1\s*\+\s*\(?(-?\d+)\)?\s*\]',
            r'local\s+function\s+(\w+)\s*\(\s*\1\s*\)\s*return\s+R\s*\[\s*\1\s*\+\s*(-?\d+)\s*\]',
        ]
        for p in patterns:
            m = re.search(p, folded)
            if m:
                self.getter_name = m.group(1)
                self.offset = int(m.group(2))
                return

    def _resolve_getter_calls(self):
        if not self.getter_name:
            return
        def repl(m):
            expr = m.group(1).strip()
            n = safe_eval_int(expr)
            if n is not None:
                idx = n + self.offset
                if 1 <= idx <= len(self.strings):
                    s = self.strings[idx - 1]
                    if s:
                        return json.dumps(s)
            return m.group(0)
        pattern = rf'{re.escape(self.getter_name)}\s*\(\s*([^)]+?)\s*\)'
        self.source = re.sub(pattern, repl, self.source)

    def execute(self) -> str:
        self._log("VM execution starting")
        self._log(f"Decoded strings: {len(self.strings)}")
        self._log(f"VM variable: {self.vm_var}")
        self._execute_main_chunk()
        if self.output:
            return '\n'.join(self.output)
        return '-- [VM] No output produced'

    def _execute_main_chunk(self):
        try:
            exec(self.source, self.globals)
        except Exception as e:
            self.output.append(f"-- [VM Error] {e}")

    def get_output(self) -> str:
        return '\n'.join(self.output) if self.output else '-- [VM] No output'
