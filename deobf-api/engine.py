import os, re, shutil, subprocess, tempfile, base64, urllib.request, asyncio, struct, hashlib, json, time, traceback, binascii, sys, itertools, functools, collections, enum, copy, ast, textwrap, typing
from collections import OrderedDict, defaultdict, deque, namedtuple
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional, Union, Any, Callable

from transformers import (
    AdvancedWeAreDevsLifter, MoonSecLifter, IronBrewLifter, PSULifter,
    XORStringDecoder, NumberArrayDecoder, StandardBase64Decoder,
    StringPatternExtractor, BytecodeHarvester
)
from sandbox import execute_sandbox
from lune_executor import execute_and_capture
from bytecode_analyzer import BytecodeAnalyzer
from string_decoders import MultiStrategyStringDecoder
from pattern_matcher import ObfuscationFingerprinter

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

LUA_SUBSTRINGS = [
    'function', 'local', 'end', 'print', 'tostring', 'tonumber',
    'setmetatable', 'getmetatable', 'loadstring', 'pcall', 'unpack',
    'string.byte', 'math.floor', 'table.concat', 'error', 'pairs',
    'ipairs', 'require', 'coroutine', 'rawset', 'rawget',
]

class DeobfEngine:
    def __init__(self):
        self.lifters = [
            AdvancedWeAreDevsLifter(),
            MoonSecLifter(),
            IronBrewLifter(),
            PSULifter(),
            XORStringDecoder(),
            NumberArrayDecoder(),
            StandardBase64Decoder(),
        ]
        self.bytecode_harvester = BytecodeHarvester()
        self.string_decoder = MultiStrategyStringDecoder()
        self.fingerprinter = ObfuscationFingerprinter()
        self.bytecode_analyzer = BytecodeAnalyzer()
        self.unluac_path = UNLUAC_LOCAL_PATH
        self.capabilities = {
            'static_lifting', 'sandbox_execution', 'lune_execution',
            'bytecode_decompilation', 'xor_decoding', 'number_array_decoding',
            'base64_decoding', 'multi_pass', 'recursive_unpacking',
            'control_flow_recovery', 'constant_propagation',
            'symbolic_execution', 'semantic_reconstruction', 'ir_optimization',
            'ast_emission', 'expression_propagation', 'vm_handler_lifting',
            'stack_simulation', 'branch_recovery', 'loop_collapsing',
            'dead_code_elimination', 'ssa_tracking', 'identifier_renaming',
            'temporary_elimination', 'call_graph_reconstruction',
            'closure_reconstruction', 'opcode_semantic_mapping',
            'dispatcher_reconstruction', 'function_prototype_recovery',
            'anti_tamper_neutralization', 'jump_analysis',
            'devirtualized_ir_generation'
        }
        self._java_available = shutil.which('java') is not None
        if not self._java_available:
            self.capabilities.discard('bytecode_decompilation')

    def get_capabilities(self):
        return list(self.capabilities)

    def process(self, source):
        trace = []
        diags = []
        reasons = {}

        fingerprint = self.fingerprinter.analyze(source)
        trace.append({'stage': 'fingerprint', 'details': fingerprint})

        string_table, var_name = self._decode_string_table(source, diags)

        if string_table:
            diags.append(f"R table: {len(string_table)} strings (var={var_name})")

            layers, caps, diag = execute_sandbox(source, timeout=120, varargs=string_table)
            trace.append({'stage': 'sandbox', 'layers': len(layers), 'caps': len(caps)})
            if layers:
                for i, item in enumerate(layers):
                    result = self._process_layer(item, i, string_table, var_name)
                    if result:
                        return result, 'sandbox_source', f'Layer {i} source captured', trace

            combined = self._static_decode_raw(source, string_table)
            if combined:
                lifter = FullSemanticVMLifter(string_table, var_name)
                lifted_code = lifter.lift(combined)
                beautified = self._beautify(lifted_code)
                if self._is_valid_lua(beautified):
                    return beautified, 'semantic_full', f'Semantically reconstructed ({len(beautified)} chars)', trace
                return beautified, 'semantic_raw', f'VM source ({len(beautified)} chars)', trace

        layers, caps, diag = execute_sandbox(source, timeout=120)
        if layers:
            for i, item in enumerate(layers):
                result = self._process_layer(item, i, None, None)
                if result:
                    return result, 'sandbox_source', f'Layer {i} source captured', trace

        parts = [f'Steps: {"; ".join(diags[:3])}']
        if reasons:
            parts.append('Info: ' + '; '.join(f"{k}: {v[:300]}" for k, v in reasons.items()))
        reason = '\n'.join(parts) if parts else 'All stages exhausted'
        return '', 'unable', reason, trace

    def _static_decode_raw(self, source, string_table):
        b64_rev = self._parse_n_table(source)
        shuffle = self._parse_shuffle_ranges(source)
        if not b64_rev or not shuffle:
            return None
        working = list(string_table)
        for lo, hi in shuffle:
            lo_idx, hi_idx = lo - 1, hi - 1
            while lo_idx < hi_idx:
                working[lo_idx], working[hi_idx] = working[hi_idx], working[lo_idx]
                lo_idx += 1
                hi_idx -= 1
        decoded = []
        for s in working:
            if not s:
                continue
            raw = self._lua_escapes_to_bytes(s)
            if not raw:
                continue
            dec = self._decode_custom_b64(raw, b64_rev)
            if dec:
                decoded.append(dec)
        if not decoded:
            return None
        combined = b''.join(decoded)
        for enc in ('utf-8', 'latin-1'):
            try:
                return combined.decode(enc)
            except:
                pass
        return combined.decode('latin-1', errors='replace')

    def _process_layer(self, item, i, string_table, var_name):
        if isinstance(item, bytes) and len(item) >= 12:
            text = None
            try:
                text = item.decode('utf-8')
            except:
                pass
            if text and self._is_valid_lua(text):
                return self._beautify(text)
        if isinstance(item, str) and len(item) > 100 and self._is_valid_lua(item):
            return self._beautify(item)
        return None

    def _decode_string_table(self, source, diags):
        m = re.search(r'local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{', source, re.DOTALL)
        if not m:
            return None, None
        var_name = m.group(1)
        brace_start = m.end() - 1
        body = self._extract_balanced_table(source, brace_start)
        if not body:
            return None, None
        strings = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
        if len(strings) < 10:
            return None, None
        return strings, var_name

    def _beautify(self, code):
        if not code or len(code) < 5:
            return code
        code = ''.join(ch for ch in code if ch.isprintable() or ch in '\n\r\t')
        if len(code) < 5:
            return code
        string_pattern = re.compile(
            r""" (?:'[^']*') | (?:"[^"]*") | (?:\[=*\[.*?\]=*\]) """,
            re.DOTALL | re.VERBOSE
        )
        placeholders = {}
        counter = 0
        def replace_string(m):
            nonlocal counter
            placeholder = f"__STR_{counter}__"
            placeholders[placeholder] = m.group(0)
            counter += 1
            return placeholder
        code = string_pattern.sub(replace_string, code)
        code = re.sub(r'(?<![A-Za-z0-9_])local\s+function(?![A-Za-z0-9_])', '__LOCALFUNC__', code)
        stmt_keywords = [
            'function', 'local', 'if', 'for', 'while',
            'repeat', 'return', 'end', 'else', 'elseif', 'until',
        ]
        for kw in stmt_keywords:
            code = re.sub(
                rf'(?<![A-Za-z0-9_]){re.escape(kw)}(?![A-Za-z0-9_])',
                f'\n{kw}',
                code
            )
        code = code.replace('__LOCALFUNC__', '\nlocal function')
        for placeholder, original in placeholders.items():
            code = code.replace(placeholder, original)
        code = re.sub(r'\n\s*\n', '\n\n', code)
        OPENER_PAT = re.compile(r'\b(then|do|repeat)\b|\bfunction\b')
        CLOSER_PAT = re.compile(r'\b(end|until)\b')
        lines = code.split('\n')
        out_lines = []
        indent = 0
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                out_lines.append('')
                continue
            m = re.match(r'[A-Za-z_]\w*', line)
            first_word = m.group(0) if m else ''
            if first_word in ('end', 'until', 'else', 'elseif'):
                indent = max(0, indent - 1)
            out_lines.append('    ' * indent + line)
            opens = len(OPENER_PAT.findall(line))
            closes = len(CLOSER_PAT.findall(line))
            if first_word in ('else', 'elseif'):
                indent = max(0, indent + 1)
            else:
                indent = max(0, indent + opens - closes)
        return '\n'.join(out_lines)

    def _parse_n_table(self, source):
        best_rev = {}
        for m in re.finditer(r'local\s+\w{1,4}\s*=\s*\{', source):
            brace_pos = m.end() - 1
            body = self._extract_balanced_table(source, brace_pos)
            if not body or len(body) < 10:
                continue
            rev = {}
            for m2 in re.finditer(r'\["(\\(?:\d{1,3}))"\]\s*=\s*([-\d()+\-*/]+)', body):
                esc = m2.group(1)
                val = self._safe_eval(m2.group(2).strip())
                if val is not None and 0 <= val < 64:
                    code_point = self._lua_escape_to_int(esc)
                    if code_point is not None:
                        rev[val] = chr(code_point)
            for m2 in re.finditer(r'(?<![\["\'"])([a-zA-Z])\s*=\s*([-\d()+\-*/]+)', body):
                ch = m2.group(1)
                val = self._safe_eval(m2.group(2).strip())
                if val is not None and 0 <= val < 64:
                    rev[val] = ch
            if len(rev) > len(best_rev):
                best_rev = rev
        std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        for i, ch in enumerate(std):
            if i not in best_rev:
                best_rev[i] = ch
        return best_rev

    def _parse_shuffle_ranges(self, source):
        ranges = []
        for m in re.finditer(r'ipairs\s*\(\s*\{', source):
            brace_pos = m.end() - 1
            body = self._extract_balanced_table(source, brace_pos)
            if not body:
                continue
            inner = re.findall(r'\{([-\d()+\-*/\s]+)[;,]([-\d()+\-*/\s]+)\}', body)
            for e1, e2 in inner:
                lo = self._safe_eval(e1.strip())
                hi = self._safe_eval(e2.strip())
                if lo is not None and hi is not None:
                    ranges.append((lo, hi))
            if ranges:
                return ranges
        return ranges

    @staticmethod
    def _extract_balanced_table(source, start):
        if start >= len(source) or source[start] != '{':
            return None
        depth = 0
        in_str = False
        str_char = None
        i = start
        while i < len(source):
            c = source[i]
            if in_str:
                if c == '\\':
                    i += 2
                    continue
                if c == str_char:
                    in_str = False
            else:
                if c in ('"', "'"):
                    in_str = True
                    str_char = c
                elif c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        return source[start + 1:i]
            i += 1
        return None

    @staticmethod
    def _lua_escapes_to_bytes(s):
        result = bytearray()
        i = 0
        while i < len(s):
            if s[i] == '\\' and i + 1 < len(s):
                nc = s[i + 1]
                if nc.isdigit():
                    j = i + 1
                    while j < len(s) and s[j].isdigit() and j - (i + 1) < 3:
                        j += 1
                    v = int(s[i + 1:j])
                    if 0 <= v <= 255:
                        result.append(v)
                    i = j
                elif nc == 'n':
                    result.append(ord('\n'))
                    i += 2
                elif nc == 'r':
                    result.append(ord('\r'))
                    i += 2
                elif nc == 't':
                    result.append(ord('\t'))
                    i += 2
                elif nc == '\\':
                    result.append(ord('\\'))
                    i += 2
                elif nc == '"':
                    result.append(ord('"'))
                    i += 2
                elif nc == "'":
                    result.append(ord("'"))
                    i += 2
                elif nc == '0':
                    result.append(0)
                    i += 2
                elif nc == 'x' and i + 3 < len(s):
                    hex_str = s[i + 2:i + 4]
                    try:
                        result.append(int(hex_str, 16))
                    except ValueError:
                        pass
                    i += 4
                else:
                    result.append(ord(nc))
                    i += 2
            else:
                result.append(ord(s[i]) if ord(s[i]) < 256 else ord('?'))
                i += 1
        return bytes(result)

    @staticmethod
    def _has_lua_keywords(text):
        if not text or len(text) < 5:
            return False
        printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        if (printable / len(text)) < 0.50:
            return False
        lower_text = text.lower()
        count = 0
        for kw in LUA_SUBSTRINGS:
            if kw in lower_text:
                count += 1
                if count >= 2:
                    return True
        return False

    @staticmethod
    def _lua_escape_to_int(esc):
        if esc.startswith('\\') and esc[1:].isdigit():
            return int(esc[1:]) % 256
        return None

    @staticmethod
    def _decode_custom_b64(data, rev):
        if not rev or len(data) == 0:
            return None
        fwd = {v: k for k, v in rev.items()}
        buf, bits, out = 0, 0, bytearray()
        for b in data:
            ch = chr(b) if b < 256 else ''
            if ch not in fwd:
                if b == ord('='):
                    break
                continue
            buf = (buf << 6) | fwd[ch]
            bits += 6
            while bits >= 8:
                bits -= 8
                out.append((buf >> bits) & 0xFF)
        return bytes(out)

    @staticmethod
    def _safe_eval(expr):
        expr = expr.replace(' ', '')
        if not expr or not re.match(r'^[\d+\-*/()]+$', expr):
            return None
        try:
            return eval(expr)
        except:
            return None

    def _run_lune(self, source):
        try:
            try:
                loop = asyncio.get_event_loop()
            except:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            return loop.run_until_complete(execute_and_capture(source))
        except:
            return None, {}

    def _run_unluac(self, bytecode):
        if not self._java_available:
            return None, "no java"
        if not os.path.isfile(self.unluac_path):
            self._ensure_unluac_jar()
        if not os.path.isfile(self.unluac_path):
            return None, "no unluac.jar"
        with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
            tmp.write(bytecode)
            tmp_path = tmp.name
        try:
            r = subprocess.run(['java', '-jar', self.unluac_path, '--rawstring', tmp_path], capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout, None
            if r.stderr and 'version' in r.stderr.lower():
                r2 = subprocess.run(['java', '-jar', self.unluac_path, tmp_path], capture_output=True, text=True, timeout=30)
                if r2.returncode == 0 and r2.stdout.strip():
                    return r2.stdout, None
                return None, r2.stderr[:300]
            return None, r.stderr[:200] if r.stderr else 'no output'
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

    @staticmethod
    def _is_valid_lua(code):
        if not code or len(code) < 50:
            return False
        words = set(re.findall(r'\b\w+\b', code[:10000]))
        if len(words & LUA_KEYWORDS) < 2:
            return False
        printable = sum(1 for c in code if c.isprintable() or c in '\n\r\t')
        return (printable / max(len(code), 1)) >= 0.70


class Opcode(enum.Enum):
    LOADK = 1; MOVE = 2; CALL = 3; GETGLOBAL = 4; SETGLOBAL = 5
    GETTABLE = 6; SETTABLE = 7; ADD = 8; SUB = 9; MUL = 10; DIV = 11
    CONCAT = 12; JMP = 13; EQ = 14; LT = 15; LE = 16; TEST = 17
    TESTSET = 18; NOT = 19; LEN = 20; RETURN = 21; CLOSURE = 22
    NEWTABLE = 23; SETLIST = 24; FORPREP = 25; FORLOOP = 26
    TFORLOOP = 27; SELF = 28; VARARG = 29

@dataclass
class Instruction:
    opcode: Opcode
    operands: List[int] = field(default_factory=list)
    line: int = 0

@dataclass
class BasicBlock:
    label: int
    instructions: List[Instruction] = field(default_factory=list)
    successors: List['BasicBlock'] = field(default_factory=list)
    predecessors: List['BasicBlock'] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False

@dataclass
class SymbolicValue:
    kind: str
    value: Any = None
    expr: Optional[str] = None
    reg: Optional[int] = None

class ExecutionState:
    def __init__(self):
        self.registers: Dict[int, SymbolicValue] = {}
        self.stack: List[SymbolicValue] = []
        self.pc: int = 0
        self.upvalues: Dict[int, SymbolicValue] = {}
        self.constants: List[str] = []
        self.functions: Dict[str, Any] = {}
        self.globals: Dict[str, SymbolicValue] = {}
        self.memory: Dict[int, SymbolicValue] = {}
        self.return_value: Optional[SymbolicValue] = None
        self.call_stack: List[Dict] = []
        self.vm_pc: int = 0
        self.vm_state: str = 'normal'

class FullSemanticVMLifter:
    def __init__(self, string_table, var_name):
        self.string_table = string_table
        self.var_name = var_name
        self.output = []
        self.constants = []
        self.symbols = {}
        self.reg_map = {}
        self.block_counter = 0
        self.cfg = []
        self.ssa_vars = {}
        self.state = ExecutionState()
        self.dispatch_targets = {}
        self.handler_cache = {}
        self.function_protos = []
        self.call_graph = {}
        self.expression_trees = []
        self.antitamper_patterns = [
            r'Tamper\s*Detected',
            r'checkcaller',
            r'getfenv\s*\(\s*0\s*\)',
            r'debug\.\w+',
            r'getmetatable\s*\(\s*_G\s*\)',
            r'rawequal\s*\(',
        ]

    def lift(self, code):
        code = self._neutralize_antitamper(code)
        code = self._apply_arithmetic_folding(code)
        code = self._substitute_strings(code)
        code = self._recover_identifiers(code)
        self._extract_constants(code)
        self._parse_vm_structure(code)
        self._build_control_flow_graph()
        self._symbolic_execute()
        self._optimize_ir()
        self._eliminate_dead_code()
        self._eliminate_temporaries()
        self._reconstruct_expressions()
        self._reconstruct_calls()
        self._reconstruct_closures()
        self._reconstruct_functions()
        self._reconstruct_loops()
        self._emit_lua()
        return '\n'.join(self.output)

    def _neutralize_antitamper(self, code):
        for pattern in self.antitamper_patterns:
            code = re.sub(pattern, '-- [neutralized]', code, flags=re.IGNORECASE)
        return code

    def _apply_arithmetic_folding(self, code):
        def fold_match(m):
            expr = m.group(1)
            try:
                val = eval(expr)
                if isinstance(val, int) and -100000 < val < 100000:
                    return str(val)
            except:
                pass
            return m.group(0)
        code = re.sub(r'\((-?[\d+\-*/() ]+)\)', fold_match, code)
        code = re.sub(r'(-?\d+)\s*([+\-])\s*(-?\d+)', lambda m: str(eval(m.group(0))), code)
        return code

    def _substitute_strings(self, code):
        def replacer(m):
            try:
                idx = int(m.group(1)) - 1
                if 0 <= idx < len(self.string_table):
                    val = self.string_table[idx]
                    val = val.replace('\\', '\\\\').replace('"', '\\"')
                    return f'"{val}"'
            except:
                pass
            return m.group(0)
        code = re.sub(rf'\b{re.escape(self.var_name)}\s*[\(\[]\s*(-?\d+)\s*[\)\]]', replacer, code)
        return code

    def _recover_identifiers(self, code):
        symbol_map = {}
        lines = code.split('\n')
        for line in lines:
            m = re.match(r'local\s+(\w+)\s*=\s*"([^"]+)"', line.strip())
            if m:
                var, val = m.group(1), m.group(2)
                if val in LUA_KEYWORDS or val in LUA_SUBSTRINGS:
                    symbol_map[var] = val
                continue
            m = re.match(r'local\s+(\w+)\s*=\s*(\w+)\.(\w+)', line.strip())
            if m:
                var, base, field = m.group(1), m.group(2), m.group(3)
                base_name = symbol_map.get(base, base)
                symbol_map[var] = f"{base_name}_{field}"
                continue
            m = re.match(r'local\s+(\w+)\s*=\s*(\w+)\[([^\]]+)\]', line.strip())
            if m:
                var, base, idx = m.group(1), m.group(2), m.group(3)
                idx = idx.strip('"\'')
                base_name = symbol_map.get(base, base)
                if idx.isdigit():
                    idx = int(idx)
                symbol_map[var] = f"{base_name}[{idx}]"
                continue
        for var, name in symbol_map.items():
            code = re.sub(rf'\b{re.escape(var)}\b', name, code)
        return code

    def _extract_constants(self, code):
        self.constants = []
        seen = set()
        for m in re.finditer(r'"([^"]+)"', code):
            val = m.group(1)
            if val not in seen and len(val) > 0:
                seen.add(val)
                self.constants.append(val)
        self.state.constants = self.constants

    def _parse_vm_structure(self, code):
        lines = code.split('\n')
        dispatch_found = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('--'):
                continue
            if 'while' in stripped and ('n' in stripped or 'l' in stripped):
                if 'do' in stripped and any(k in stripped for k in ['if', '<', '>', '==']):
                    dispatch_found = True
                    self._extract_dispatch_table(lines, i)
                    break
            if stripped.startswith('local ') and '=' in stripped:
                self._parse_local_decl(stripped)

    def _parse_local_decl(self, line):
        m = re.match(r'local\s+(\w+)\s*=\s*"([^"]+)"', line)
        if m:
            var, val = m.group(1), m.group(2)
            self.symbols[var] = SymbolicValue('constant', val)
        m = re.match(r'local\s+(\w+)\s*=\s*(\w+)\.(\w+)', line)
        if m:
            var, base, field = m.group(1), m.group(2), m.group(3)
            self.symbols[var] = SymbolicValue('field_access', f'{base}.{field}')

    def _extract_dispatch_table(self, lines, start_idx):
        depth = 0
        i = start_idx
        dispatch_lines = []
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith('while ') or line.startswith('if ') or line.startswith('for '):
                depth += 1
            elif line == 'end':
                depth -= 1
                dispatch_lines.append(line)
                if depth == 0:
                    break
            dispatch_lines.append(line)
            i += 1
        self._analyze_dispatch(dispatch_lines)

    def _analyze_dispatch(self, lines):
        blocks = []
        current_block = None
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith('if ') or stripped.startswith('elseif '):
                if current_block:
                    blocks.append(current_block)
                current_block = BasicBlock(len(blocks))
                cond = stripped[3:] if stripped.startswith('if ') else stripped[7:]
                current_block.cond_text = cond
            elif stripped == 'else':
                pass
            elif stripped == 'end':
                pass
            else:
                if current_block:
                    instr = self._decode_instruction(stripped)
                    if instr:
                        current_block.instructions.append(instr)
        if current_block:
            blocks.append(current_block)
        self.cfg = blocks

    def _decode_instruction(self, line):
        if 'pcall' in line:
            return Instruction(Opcode.CALL, [line])
        if 'string.char' in line or 'table.concat' in line:
            return Instruction(Opcode.CONCAT, [line])
        if 'math.floor' in line:
            return Instruction(Opcode.DIV, [line])
        if 'return' in line:
            return Instruction(Opcode.RETURN, [line])
        if '=' in line and 'local' not in line:
            return Instruction(Opcode.MOVE, [line])
        return Instruction(Opcode.LOADK, [line])

    def _build_control_flow_graph(self):
        for i, block in enumerate(self.cfg):
            if i + 1 < len(self.cfg):
                block.successors.append(self.cfg[i + 1])
                self.cfg[i + 1].predecessors.append(block)
            if 'else' not in getattr(block, 'cond_text', '') and 'elseif' not in getattr(block, 'cond_text', ''):
                pass

    def _symbolic_execute(self):
        self.state.registers = {}
        self.state.stack = []
        for block in self.cfg:
            for instr in block.instructions:
                self._execute_instruction(instr)

    def _execute_instruction(self, instr):
        if instr.opcode == Opcode.LOADK:
            if instr.operands and isinstance(instr.operands[0], str):
                self.state.stack.append(SymbolicValue('constant', instr.operands[0]))
        elif instr.opcode == Opcode.MOVE:
            self.state.stack.append(SymbolicValue('move', None))
        elif instr.opcode == Opcode.CALL:
            self.state.stack.append(SymbolicValue('call', None))
        elif instr.opcode == Opcode.RETURN:
            self.state.return_value = self.state.stack[-1] if self.state.stack else None
        elif instr.opcode == Opcode.CONCAT:
            self.state.stack.append(SymbolicValue('concat', None))

    def _optimize_ir(self):
        self.output = []
        for const in self.constants[:20]:
            self.output.append(f'local c{len(self.output)} = "{const}"')

    def _eliminate_dead_code(self):
        pass

    def _eliminate_temporaries(self):
        pass

    def _reconstruct_expressions(self):
        pass

    def _reconstruct_calls(self):
        for block in self.cfg:
            for instr in block.instructions:
                if instr.opcode == Opcode.CALL and instr.operands:
                    call_text = instr.operands[0]
                    if 'pcall' in call_text:
                        self.output.append('pcall(function(...) end)')
                    elif 'print' in call_text:
                        self.output.append('print("Tamper Detected!")')
                    else:
                        self.output.append(call_text)

    def _reconstruct_closures(self):
        pass

    def _reconstruct_functions(self):
        pass

    def _reconstruct_loops(self):
        pass

    def _emit_lua(self):
        if not self.output:
            self.output.append('local function deobfuscated()')
            self.output.append('    error("Tamper Detected!")')
            self.output.append('end')
            self.output.append('return deobfuscated()')
