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


@dataclass
class VMInstruction:
    opcode: int
    operands: List[Union[int, str]] = field(default_factory=list)
    handler_code: str = ""
    action: str = "UNKNOWN"

@dataclass 
class SymbolicValue:
    kind: str
    value: Any = None
    expr: str = ""
    const_idx: int = -1
    reg_name: str = ""

class FullSemanticVMLifter:
    def __init__(self, string_table, var_name):
        self.string_table = string_table
        self.var_name = var_name
        self.constants = []
        self.vm_instructions = []
        self.vm_table_var = ""
        self.vm_pc_var = ""
        self.vm_opcode_var = ""
        self.vm_dispatch_block = ""
        self.opcode_map = {}
        self.symbolic_stack = []
        self.symbolic_regs = {}
        self.symbolic_upvals = {}
        self.symbolic_globals = {}
        self.ir_statements = []
        self.function_protos = []
        self.temp_counter = 0
        self.current_function = None
        self.label_counter = 0
        self.function_registry = {}

    def lift(self, vm_code):
        code = self._neutralize_antitamper(vm_code)
        code = self._apply_arithmetic_folding(code)
        code = self._substitute_strings(code)
        code = self._recover_identifiers(code)

        self._extract_vm_components(code)
        if not self.vm_instructions or not self.opcode_map:
            return self._emit_fallback(code)

        self._symbolic_execute()
        self._reconstruct_expressions()
        self._reconstruct_calls()
        self._reconstruct_functions()
        self._reconstruct_loops()
        self._eliminate_dead_code()
        self._eliminate_temporaries()
        return self._emit_lua()

    def _neutralize_antitamper(self, code):
        for pattern in [
            r'if\s+not\s+pcall\s*\(\s*function\s*\(\)[^)]*end\s*\)\s*then\s*error\s*\(\s*"[^"]*"[^)]*\)\s*end',
            r'error\s*\(\s*"[^"]*Tamper[^"]*"[^)]*\)',
            r'checkcaller\s*\(\s*\)',
            r'getfenv\s*\(\s*0\s*\)\s*==\s*getfenv\s*\(\s*\)',
            r'getmetatable\s*\(\s*_G\s*\)\s*==\s*nil',
            r'rawequal\s*\(\s*getfenv\s*\(\s*\)',
        ]:
            code = re.sub(pattern, 'true', code, flags=re.IGNORECASE)
        code = re.sub(r'error\s*\(\s*"[^"]*Tamper\s*Detected[^"]*"[^)]*\)', 'do return end', code)
        return code

    def _apply_arithmetic_folding(self, code):
        def fold_match(m):
            expr = m.group(1)
            try:
                val = eval(expr)
                if isinstance(val, (int, float)) and -100000 < val < 100000:
                    if isinstance(val, float) and val == int(val):
                        return str(int(val))
                    return str(val)
            except:
                pass
            return m.group(0)
        code = re.sub(r'\(\s*(-?[\d+\-*/.() ]+)\s*\)', fold_match, code)
        code = re.sub(r'(-?\d+(?:\.\d+)?)\s*([+\-])\s*(-?\d+(?:\.\d+)?)', lambda m: str(eval(m.group(0))), code)
        return code

    def _substitute_strings(self, code):
        def replacer(m):
            try:
                idx = int(m.group(1)) - 1
                if 0 <= idx < len(self.string_table):
                    val = self.string_table[idx]
                    val = val.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
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
                if val in LUA_KEYWORDS or any(kw in val for kw in LUA_SUBSTRINGS):
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

    def _extract_vm_components(self, code):
        table_match = re.search(r'local\s+(\w+)\s*=\s*\{((?:\s*[^,{}]+(?:,|$))*)\}', code, re.DOTALL)
        if not table_match:
            table_match = re.search(r'(\w+)\s*=\s*\{((?:\s*[^,{}]+(?:,|$))*)\}', code, re.DOTALL)
        if table_match:
            self.vm_table_var = table_match.group(1)
            body = table_match.group(2)
            self._parse_vm_instruction_table(body)

        dispatch_match = re.search(
            r'(local\s+(\w+)\s*=\s*(\w+)\[(\w+)\][^\n]*\n(?:\s*[^\n]*\n)*?\s*end\s*end)',
            code, re.DOTALL
        )
        if dispatch_match:
            self.vm_dispatch_block = dispatch_match.group(1)
            self._parse_dispatch_block()

    def _parse_vm_instruction_table(self, body):
        entries = []
        for tok in re.finditer(r'(-?\d+(?:\.\d+)?|"[^"]*"|\'[^\']*\')', body):
            val = tok.group(1)
            if val.startswith('"') or val.startswith("'"):
                entries.append(val[1:-1])
            else:
                try:
                    entries.append(int(val))
                except ValueError:
                    try:
                        entries.append(float(val))
                    except ValueError:
                        entries.append(val)
        if len(entries) > 20:
            self.vm_instructions = entries

    def _parse_dispatch_block(self):
        pc_match = re.search(r'local\s+(\w+)\s*=\s*(\w+)\[(\w+)\]', self.vm_dispatch_block)
        if pc_match:
            self.vm_opcode_var = pc_match.group(1)
            self.vm_table_var = pc_match.group(2)
            self.vm_pc_var = pc_match.group(3)

        for match in re.finditer(
            r'(?:else)?if\s+' + re.escape(self.vm_opcode_var) + r'\s*==\s*(\d+)\s+then\s+(.*?)(?=\s*(?:elseif|else|end\b))',
            self.vm_dispatch_block, re.DOTALL
        ):
            opcode = int(match.group(1))
            handler = match.group(2)
            self.opcode_map[opcode] = self._classify_handler(handler)

    def _classify_handler(self, handler_code):
        classification = {'action': 'UNKNOWN', 'handler': handler_code}

        if re.search(r'R\s*\[[^\]]+\]\s*\[[^\]]+\]', handler_code):
            classification['action'] = 'GETTABLE'
        elif re.search(r'R\s*\[', handler_code):
            classification['action'] = 'LOADK'
            idx_match = re.search(r'R\s*\[([^\]]+)\]', handler_code)
            if idx_match:
                classification['index_expr'] = idx_match.group(1)
        elif re.search(r'_G\s*\[[^\]]+\]\s*=', handler_code):
            classification['action'] = 'SETGLOBAL'
            name_match = re.search(r'_G\s*\[([^\]]+)\]', handler_code)
            if name_match:
                classification['name_expr'] = name_match.group(1)
        elif re.search(r'=\s*_G\s*\[', handler_code):
            classification['action'] = 'GETGLOBAL'
            name_match = re.search(r'_G\s*\[([^\]]+)\]', handler_code)
            if name_match:
                classification['name_expr'] = name_match.group(1)
        elif re.search(r'pcall\s*\(', handler_code):
            classification['action'] = 'PCALL'
            func_match = re.search(r'pcall\s*\(([^,)]+)', handler_code)
            if func_match:
                classification['func_expr'] = func_match.group(1)
        elif re.search(r'loadstring\s*\(', handler_code):
            classification['action'] = 'LOADSTRING'
        elif re.search(r'string\.char\s*\(', handler_code):
            classification['action'] = 'STRCHAR'
        elif re.search(r'table\.concat\s*\(', handler_code):
            classification['action'] = 'TABLECONCAT'
        elif re.search(r'math\.floor\s*\(', handler_code):
            classification['action'] = 'MATHFLOOR'
        elif re.search(r'return\b', handler_code):
            classification['action'] = 'RETURN'
        elif re.search(r'=\s*function\s*\(', handler_code):
            classification['action'] = 'CLOSURE'
        elif re.search(r'=\s*\{', handler_code):
            classification['action'] = 'NEWTABLE'
        elif re.search(r'\[[^\]]+\]\s*=', handler_code) and '_G' not in handler_code:
            classification['action'] = 'SETTABLE'
        elif re.search(r'for\s+\w+\s*=', handler_code):
            classification['action'] = 'FORLOOP'
        elif re.search(r'if\s+', handler_code):
            classification['action'] = 'CONDJUMP'
        elif '+' in handler_code or '-' in handler_code or '*' in handler_code or '/' in handler_code:
            classification['action'] = 'ARITH'
        elif '..' in handler_code:
            classification['action'] = 'CONCAT'
        elif '=' in handler_code and 'local' not in handler_code:
            classification['action'] = 'MOVE'
        elif re.search(r'\w+\s*\(', handler_code):
            classification['action'] = 'CALL'
            func_match = re.search(r'(\w+)\s*\(', handler_code)
            if func_match:
                classification['func_name'] = func_match.group(1)

        return classification

    def _symbolic_execute(self):
        pc = 0
        instructions = self.vm_instructions
        instruction_limit = len(instructions)

        while pc < instruction_limit and len(self.ir_statements) < 10000:
            op = instructions[pc]
            pc += 1

            if not isinstance(op, int) or op not in self.opcode_map:
                continue

            handler = self.opcode_map[op]
            action = handler['action']

            if action == 'LOADK':
                if pc < instruction_limit:
                    const_idx = instructions[pc]
                    pc += 1
                    if isinstance(const_idx, int) and 0 <= const_idx - 1 < len(self.string_table):
                        val = self.string_table[const_idx - 1]
                        self.symbolic_stack.append(SymbolicValue('const', val, f'"{val}"', const_idx))
                    else:
                        self.symbolic_stack.append(SymbolicValue('unknown', const_idx, str(const_idx)))

            elif action == 'GETGLOBAL':
                name_expr = handler.get('name_expr', '')
                self.symbolic_stack.append(SymbolicValue('global', name_expr, f'_G[{name_expr}]'))

            elif action == 'SETGLOBAL':
                name_expr = handler.get('name_expr', '')
                val = self.symbolic_stack.pop() if self.symbolic_stack else SymbolicValue('nil', None, 'nil')
                self.ir_statements.append(f'_G[{name_expr}] = {val.expr}')

            elif action == 'GETTABLE':
                key = self.symbolic_stack.pop() if self.symbolic_stack else SymbolicValue('nil', None, 'nil')
                tbl = self.symbolic_stack.pop() if self.symbolic_stack else SymbolicValue('nil', None, 'nil')
                self.symbolic_stack.append(SymbolicValue('gettable', None, f'{tbl.expr}[{key.expr}]'))

            elif action == 'SETTABLE':
                val = self.symbolic_stack.pop() if self.symbolic_stack else SymbolicValue('nil', None, 'nil')
                key = self.symbolic_stack.pop() if self.symbolic_stack else SymbolicValue('nil', None, 'nil')
                tbl = self.symbolic_stack.pop() if self.symbolic_stack else SymbolicValue('nil', None, 'nil')
                self.ir_statements.append(f'{tbl.expr}[{key.expr}] = {val.expr}')

            elif action == 'CALL':
                func_name = handler.get('func_name', 'unknown')
                args = []
                for _ in range(min(3, len(self.symbolic_stack))):
                    args.insert(0, self.symbolic_stack.pop().expr)
                args_str = ', '.join(args)
                self.ir_statements.append(f'{func_name}({args_str})')
                self.symbolic_stack.append(SymbolicValue('call_result', None, f'{func_name}_result'))

            elif action == 'PCALL':
                func_expr = handler.get('func_expr', 'function() end')
                args = []
                for _ in range(min(2, len(self.symbolic_stack))):
                    args.insert(0, self.symbolic_stack.pop().expr)
                args_str = ', '.join(args)
                self.ir_statements.append(f'pcall({func_expr}, {args_str})')

            elif action == 'RETURN':
                ret_vals = []
                while self.symbolic_stack:
                    ret_vals.insert(0, self.symbolic_stack.pop().expr)
                ret_str = ', '.join(ret_vals) if ret_vals else ''
                self.ir_statements.append(f'return {ret_str}')

            elif action == 'MOVE':
                if self.symbolic_stack:
                    val = self.symbolic_stack.pop()
                    dest = self.symbolic_stack.pop() if self.symbolic_stack else SymbolicValue('temp', None, f'temp_{self.temp_counter}')
                    self.ir_statements.append(f'{dest.expr} = {val.expr}')
                    self.symbolic_stack.append(val)

            elif action == 'ARITH':
                b = self.symbolic_stack.pop() if self.symbolic_stack else SymbolicValue('nil', None, 'nil')
                a = self.symbolic_stack.pop() if self.symbolic_stack else SymbolicValue('nil', None, 'nil')
                result = SymbolicValue('arith', None, f'({a.expr} + {b.expr})')
                self.symbolic_stack.append(result)

            elif action == 'CONCAT':
                b = self.symbolic_stack.pop() if self.symbolic_stack else SymbolicValue('nil', None, '""')
                a = self.symbolic_stack.pop() if self.symbolic_stack else SymbolicValue('nil', None, '""')
                result = SymbolicValue('concat', None, f'({a.expr} .. {b.expr})')
                self.symbolic_stack.append(result)

            elif action == 'CLOSURE':
                func_body = handler.get('handler', '')
                func_name = f'func_{len(self.function_protos)}'
                self.function_protos.append({'name': func_name, 'body': func_body})
                self.symbolic_stack.append(SymbolicValue('function', None, func_name))

            elif action == 'NEWTABLE':
                self.symbolic_stack.append(SymbolicValue('table', None, '{}'))

            elif action == 'LOADSTRING':
                code_val = self.symbolic_stack.pop() if self.symbolic_stack else SymbolicValue('const', '', '""')
                self.ir_statements.append(f'loadstring({code_val.expr})()')

            elif action == 'STRCHAR':
                args = []
                while self.symbolic_stack and isinstance(self.symbolic_stack[-1].value, int):
                    args.insert(0, str(self.symbolic_stack.pop().value))
                char_str = f'string.char({", ".join(args)})'
                self.symbolic_stack.append(SymbolicValue('expr', None, char_str))

            elif action == 'TABLECONCAT':
                tbl = self.symbolic_stack.pop() if self.symbolic_stack else SymbolicValue('table', None, '{}')
                sep = self.symbolic_stack.pop() if self.symbolic_stack else SymbolicValue('const', ' ', '" "')
                self.symbolic_stack.append(SymbolicValue('concat', None, f'table.concat({tbl.expr}, {sep.expr})'))

            elif action == 'MATHFLOOR':
                val = self.symbolic_stack.pop() if self.symbolic_stack else SymbolicValue('nil', None, '0')
                self.symbolic_stack.append(SymbolicValue('expr', None, f'math.floor({val.expr})'))

            elif action == 'FORLOOP':
                self.ir_statements.append('for i = 1, 1 do')
                self.ir_statements.append('end')

            elif action == 'CONDJUMP':
                cond = self.symbolic_stack.pop() if self.symbolic_stack else SymbolicValue('nil', None, 'false')
                self.ir_statements.append(f'if {cond.expr} then')

            else:
                pass

    def _reconstruct_expressions(self):
        reconstructed = []
        for stmt in self.ir_statements:
            stmt = re.sub(r'temp_\d+', lambda m: f'v{self.temp_counter}', stmt)
            self.temp_counter += 1
            stmt = re.sub(r'"([^"]*)"', lambda m: f'"{m.group(1)}"', stmt)
            reconstructed.append(stmt)
        self.ir_statements = reconstructed

    def _reconstruct_calls(self):
        call_pattern = re.compile(r'(\w+)_result')
        def replace_call_result(m):
            return f'{m.group(1)}()'
        self.ir_statements = [call_pattern.sub(replace_call_result, s) for s in self.ir_statements]

    def _reconstruct_functions(self):
        for proto in self.function_protos:
            self.ir_statements.append(f'local function {proto["name"]}()')
            self.ir_statements.append('end')

    def _reconstruct_loops(self):
        pass

    def _eliminate_dead_code(self):
        filtered = []
        for stmt in self.ir_statements:
            if 'nil = nil' in stmt:
                continue
            if stmt.strip() in ('do', 'then') and not filtered:
                continue
            filtered.append(stmt)
        self.ir_statements = filtered

    def _eliminate_temporaries(self):
        cleaned = []
        for stmt in self.ir_statements:
            if re.match(r'^v\d+\s*=\s*v\d+$', stmt.strip()):
                continue
            cleaned.append(stmt)
        self.ir_statements = cleaned

    def _emit_lua(self):
        if not self.ir_statements:
            return self._emit_fallback("")
        lines = []
        indent = 0
        for stmt in self.ir_statements:
            stmt = stmt.strip()
            if not stmt:
                lines.append('')
                continue
            if any(stmt.startswith(kw) for kw in ('end', 'until', 'else', 'elseif')):
                indent = max(0, indent - 1)
            lines.append('    ' * indent + stmt)
            if any(kw in stmt for kw in ('function ', 'if ', 'for ', 'while ', 'repeat', 'do')):
                indent += 1
        return '\n'.join(lines)

    def _emit_fallback(self, code):
        if self.ir_statements:
            return '\n'.join(self.ir_statements)
        return 'local function deobfuscated()\n    error("VM lifting incomplete - manual review required")\nend\nreturn deobfuscated()'
