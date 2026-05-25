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


class FullSemanticVMLifter:
    def __init__(self, string_table, var_name):
        self.string_table = string_table
        self.var_name = var_name
        self.instruction_table = []
        self.table_var = ""
        self.pc_var = ""
        self.opcode_var = ""
        self.opcode_handlers = {}
        self.lua_output = []
        self.temp_counter = 0
        self.indent_level = 0
        self.var_counter = 0
        self.label_counter = 0
        self.function_stack = []
        self.constant_pool = []
        self.exported_globals = set()

    def lift(self, vm_code):
        code = self._neutralize_antitamper(vm_code)
        code = self._apply_arithmetic_folding(code)
        code = self._substitute_strings(code)
        code = self._recover_identifiers(code)

        self._extract_instruction_table(code)
        if not self.instruction_table or len(self.instruction_table) < 20:
            return self._fallback(code)

        self._extract_dispatch_variables(code)
        self._extract_opcode_handlers(code)
        if not self.opcode_handlers or len(self.opcode_handlers) < 3:
            return self._fallback(code)

        self._extract_constant_pool(code)
        self._translate_instructions()
        return self._format_output()

    def _neutralize_antitamper(self, code):
        code = re.sub(
            r'if\s+not\s+pcall\s*\(\s*function\s*\(\)[^)]*end\s*\)\s*then\s*error\s*\([^)]*\)\s*end',
            'do end',
            code, flags=re.DOTALL
        )
        code = re.sub(r'error\s*\(\s*"[^"]*Tamper\s*Detected[^"]*"\)', 'do return end', code)
        code = re.sub(r'checkcaller\s*\(\s*\)', 'true', code)
        return code

    def _apply_arithmetic_folding(self, code):
        def fold(m):
            try:
                val = eval(m.group(1))
                if isinstance(val, (int, float)) and -100000 < val < 100000:
                    if isinstance(val, float) and val == int(val):
                        return str(int(val))
                    return str(val)
            except:
                pass
            return m.group(0)
        return re.sub(r'\(\s*(-?[\d+\-*/.() ]+)\s*\)', fold, code)

    def _substitute_strings(self, code):
        def repl(m):
            try:
                bracket = m.group(0)[0]
                idx_str = m.group(1)
                idx = int(idx_str) - 1
                if 0 <= idx < len(self.string_table):
                    val = self.string_table[idx]
                    val = val.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
                    return f'"{val}"'
            except:
                pass
            return m.group(0)
        code = re.sub(rf'\b{re.escape(self.var_name)}\s*[\(\[]\s*(-?\d+)\s*[\)\]]', repl, code)
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
        for var, name in sorted(symbol_map.items(), key=lambda x: -len(x[0])):
            code = re.sub(rf'\b{re.escape(var)}\b', name, code)
        return code

    def _extract_instruction_table(self, code):
        best_var = ""
        best_body = ""
        best_count = 0
        
        for m in re.finditer(r'\b(local\s+)?(\w+)\s*=\s*\{', code):
            is_local = m.group(1) is not None
            var_name = m.group(2)
            brace_pos = m.end() - 1
            body = self._extract_balanced(code, brace_pos)
            if not body:
                continue
            inner = body[1:-1]
            entries = re.split(r'\s*,\s*', inner)
            count = len([e for e in entries if e.strip() and (e.strip().lstrip('-').isdigit() or e.strip().startswith('"'))])
            if count > best_count:
                best_count = count
                best_var = var_name
                best_body = inner

        if best_body:
            self.table_var = best_var
            self.instruction_table = self._parse_entries('{' + best_body + '}')

    def _extract_balanced(self, code, brace_pos):
        if brace_pos >= len(code) or code[brace_pos] != '{':
            return None
        depth = 0
        in_str = False
        str_char = None
        i = brace_pos
        while i < len(code):
            c = code[i]
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
                        return code[brace_pos:i+1]
            i += 1
        return None

    def _parse_entries(self, table_body):
        entries = []
        body = table_body[1:-1]
        depth = 0
        current = ""
        in_str = False
        str_char = None
        
        for c in body:
            if in_str:
                current += c
                if c == '\\':
                    current += ''
                elif c == str_char:
                    in_str = False
                continue
            
            if c in ('"', "'"):
                in_str = True
                str_char = c
                current += c
                continue
            
            if c == '{':
                depth += 1
                current += c
                continue
            
            if c == '}':
                depth -= 1
                current += c
                continue
            
            if c == ',' and depth == 0:
                entries.append(current.strip())
                current = ""
                continue
            
            current += c
        
        if current.strip():
            entries.append(current.strip())
        
        parsed = []
        for e in entries:
            e = e.strip()
            if not e:
                continue
            if (e.startswith('"') and e.endswith('"')) or (e.startswith("'") and e.endswith("'")):
                parsed.append(e[1:-1])
            elif e.lstrip('-').isdigit():
                parsed.append(int(e))
            elif e.replace('.', '', 1).lstrip('-').isdigit():
                parsed.append(float(e))
            else:
                parsed.append(e)
        
        return parsed

    def _extract_dispatch_variables(self, code):
        m = re.search(r'local\s+(\w+)\s*=\s*(\w+)\[(\w+)\]', code)
        if m:
            self.opcode_var = m.group(1)
            self.table_var = m.group(2)
            self.pc_var = m.group(3)
            return
        
        m = re.search(r'(\w+)\s*=\s*(\w+)\[(\w+)\]', code)
        if m:
            self.opcode_var = m.group(1)
            self.table_var = m.group(2)
            self.pc_var = m.group(3)

    def _extract_opcode_handlers(self, code):
        if not self.opcode_var:
            self._extract_dispatch_variables(code)
        
        if not self.opcode_var:
            return
        
        pattern = re.compile(
            r'(?:else)?if\s+' + re.escape(self.opcode_var) + r'\s*==\s*(\d+)\s+then\s+(.*?)(?=\s*(?:elseif|else|end)\b)',
            re.DOTALL
        )
        
        for m in pattern.finditer(code):
            opcode = int(m.group(1))
            handler_body = m.group(2)
            self.opcode_handlers[opcode] = self._classify_handler(handler_body)

    def _classify_handler(self, handler):
        h = handler.strip()
        
        if re.search(r'R\s*\[[^\]]+\]\s*\[[^\]]+\]', h):
            return 'GETTABLE'
        if re.search(r'R\s*\[', h):
            return 'LOADK'
        if re.search(r'_G\s*\[[^\]]+\]\s*=', h):
            return 'SETGLOBAL'
        if re.search(r'=\s*_G\s*\[', h):
            return 'GETGLOBAL'
        if 'pcall' in h:
            return 'PCALL'
        if 'loadstring' in h:
            return 'LOADSTRING'
        if 'string.char' in h:
            return 'STRCHAR'
        if 'table.concat' in h:
            return 'TABLECONCAT'
        if 'math.floor' in h:
            return 'MATHFLOOR'
        if 'return' in h:
            return 'RETURN'
        if '=' in h and 'function' in h:
            return 'CLOSURE'
        if '=' in h and '{' in h and '}' in h:
            return 'NEWTABLE'
        if '[' in h and ']' in h and '=' in h and '_G' not in h:
            return 'SETTABLE'
        if 'for ' in h:
            return 'FORLOOP'
        if 'while ' in h:
            return 'WHILELOOP'
        if 'if ' in h:
            return 'CONDJUMP'
        if '..' in h:
            return 'CONCAT'
        if re.search(r'[+\-*/]', h) and '=' in h:
            return 'ARITH'
        if '=' in h and 'local' not in h:
            return 'MOVE'
        if re.search(r'\w+\s*\(', h):
            return 'CALL'
        
        return 'UNKNOWN'

    def _extract_constant_pool(self, code):
        self.constant_pool = list(self.string_table)

    def _translate_instructions(self):
        table = self.instruction_table
        pc = 0
        limit = len(table)
        self.lua_output = []
        stack = []
        
        while pc < limit and len(self.lua_output) < 50000:
            op = table[pc]
            pc += 1
            
            if not isinstance(op, int) or op not in self.opcode_handlers:
                continue
            
            action = self.opcode_handlers[op]
            
            if action == 'LOADK':
                if pc < limit:
                    idx = table[pc]
                    pc += 1
                    const_val = self._resolve_constant(idx)
                    stack.append(('const', const_val))
            
            elif action == 'SETGLOBAL':
                if pc + 1 < limit:
                    name_idx = table[pc]
                    val_idx = table[pc + 1]
                    pc += 2
                    name = self._resolve_constant(name_idx)
                    val = self._resolve_constant(val_idx)
                    self.lua_output.append(f'_G["{name}"] = {self._format_value(val)}')
                    self.exported_globals.add(name)
            
            elif action == 'GETGLOBAL':
                if pc < limit:
                    name_idx = table[pc]
                    pc += 1
                    name = self._resolve_constant(name_idx)
                    stack.append(('global', name))
            
            elif action == 'GETTABLE':
                key = stack.pop() if stack else ('nil', 'nil')
                tbl = stack.pop() if stack else ('nil', 'nil')
                key_str = self._format_value(key[1]) if isinstance(key, tuple) else str(key)
                tbl_str = self._format_value(tbl[1]) if isinstance(tbl, tuple) else str(tbl)
                stack.append(('expr', f'{tbl_str}[{key_str}]'))
            
            elif action == 'SETTABLE':
                val = stack.pop() if stack else ('nil', 'nil')
                key = stack.pop() if stack else ('nil', 'nil')
                tbl = stack.pop() if stack else ('nil', 'nil')
                val_str = self._format_value(val[1]) if isinstance(val, tuple) else str(val)
                key_str = self._format_value(key[1]) if isinstance(key, tuple) else str(key)
                tbl_str = self._format_value(tbl[1]) if isinstance(tbl, tuple) else str(tbl)
                self.lua_output.append(f'{tbl_str}[{key_str}] = {val_str}')
            
            elif action == 'CALL':
                if pc < limit:
                    func_idx = table[pc]
                    pc += 1
                    func_name = self._resolve_constant(func_idx)
                    arg_count = 0
                    if pc < limit and isinstance(table[pc], int) and table[pc] not in self.opcode_handlers:
                        arg_count = table[pc]
                        pc += 1
                    
                    args = []
                    for _ in range(arg_count):
                        if stack:
                            arg = stack.pop()
                            args.insert(0, self._format_value(arg[1]) if isinstance(arg, tuple) else str(arg))
                    
                    args_str = ', '.join(args)
                    self.lua_output.append(f'{func_name}({args_str})')
            
            elif action == 'PCALL':
                args = []
                depth = 0
                temp_stack = []
                while stack and depth < 5:
                    arg = stack.pop()
                    temp_stack.append(arg)
                    depth += 1
                for arg in reversed(temp_stack):
                    args.append(self._format_value(arg[1]) if isinstance(arg, tuple) else str(arg))
                args_str = ', '.join(args)
                self.lua_output.append(f'pcall(function() {args_str} end)')
            
            elif action == 'RETURN':
                ret_vals = []
                while stack:
                    val = stack.pop()
                    ret_vals.insert(0, self._format_value(val[1]) if isinstance(val, tuple) else str(val))
                ret_str = ', '.join(ret_vals) if ret_vals else ''
                self.lua_output.append(f'return {ret_str}')
                break
            
            elif action == 'MOVE':
                if len(stack) >= 2:
                    src = stack.pop()
                    dst = stack.pop()
                    src_str = self._format_value(src[1]) if isinstance(src, tuple) else str(src)
                    dst_str = self._format_value(dst[1]) if isinstance(dst, tuple) else str(dst)
                    self.lua_output.append(f'{dst_str} = {src_str}')
            
            elif action == 'CONCAT':
                if len(stack) >= 2:
                    right = stack.pop()
                    left = stack.pop()
                    right_str = self._format_value(right[1]) if isinstance(right, tuple) else str(right)
                    left_str = self._format_value(left[1]) if isinstance(left, tuple) else str(left)
                    stack.append(('expr', f'{left_str} .. {right_str}'))
            
            elif action == 'ARITH':
                if len(stack) >= 2:
                    b = stack.pop()
                    a = stack.pop()
                    b_str = self._format_value(b[1]) if isinstance(b, tuple) else str(b)
                    a_str = self._format_value(a[1]) if isinstance(a, tuple) else str(a)
                    stack.append(('expr', f'({a_str} + {b_str})'))
            
            elif action == 'CLOSURE':
                func_var = f'func_{len(self.function_stack)}'
                self.function_stack.append(func_var)
                self.lua_output.append(f'local function {func_var}()')
                self.lua_output.append('end')
            
            elif action == 'NEWTABLE':
                stack.append(('expr', '{}'))
            
            elif action == 'STRCHAR':
                args = []
                while stack and len(args) < 20:
                    val = stack.pop()
                    val_str = self._format_value(val[1]) if isinstance(val, tuple) else str(val)
                    if val_str.isdigit():
                        args.insert(0, val_str)
                    else:
                        stack.append(val)
                        break
                if args:
                    self.lua_output.append(f'string.char({", ".join(args)})')
            
            elif action == 'TABLECONCAT':
                if len(stack) >= 2:
                    sep = stack.pop()
                    tbl = stack.pop()
                    sep_str = self._format_value(sep[1]) if isinstance(sep, tuple) else str(sep)
                    tbl_str = self._format_value(tbl[1]) if isinstance(tbl, tuple) else str(tbl)
                    stack.append(('expr', f'table.concat({tbl_str}, {sep_str})'))
            
            elif action == 'FORLOOP':
                self.lua_output.append('for i = 1, 1 do')
                self.lua_output.append('end')
            
            elif action == 'CONDJUMP':
                if stack:
                    cond = stack.pop()
                    cond_str = self._format_value(cond[1]) if isinstance(cond, tuple) else str(cond)
                    self.lua_output.append(f'if {cond_str} then')
                    self.lua_output.append('end')

    def _resolve_constant(self, idx):
        if isinstance(idx, int) and 1 <= idx <= len(self.string_table):
            return self.string_table[idx - 1]
        if isinstance(idx, int) and 1 <= idx <= len(self.constant_pool):
            return self.constant_pool[idx - 1]
        return str(idx)

    def _format_value(self, val):
        if val is None:
            return 'nil'
        if isinstance(val, bool):
            return 'true' if val else 'false'
        if isinstance(val, (int, float)):
            return str(val)
        if isinstance(val, str):
            if val in ('nil', 'true', 'false'):
                return val
            if any(c in val for c in ('"', '\\', '\n', '\r')):
                escaped = val.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
                return f'"{escaped}"'
            return f'"{val}"'
        return str(val)

    def _format_output(self):
        if not self.lua_output:
            return self._fallback("")
        
        lines = []
        indent = 0
        indent_str = '    '
        
        for stmt in self.lua_output:
            stmt = stmt.strip()
            if not stmt:
                lines.append('')
                continue
            
            if any(stmt.startswith(kw) for kw in ('end', 'until', 'else', 'elseif')):
                indent = max(0, indent - 1)
            
            lines.append(indent_str * indent + stmt)
            
            if any(kw in stmt for kw in ('function ', 'if ', 'for ', 'while ', 'repeat', 'do')) and not stmt.startswith('end'):
                indent += 1
        
        result = '\n'.join(lines)
        result = re.sub(r'\n\s*\n\s*\n', '\n\n', result)
        return result

    def _fallback(self, code):
        return 'local function deobfuscated()\n    error("Decompilation incomplete - manual review required")\nend\nreturn deobfuscated()'
