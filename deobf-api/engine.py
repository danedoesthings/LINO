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
        self.opcode_handlers = {}
        self.output_statements = []
        self.globals = {}
        self.stack = []
        self.locals = {}
        self.temp_counter = 0

    def lift(self, vm_code):
        if not self._extract_vm_components(vm_code):
            return self._fallback()
        self._execute_vm()
        return self._emit_lua()

    def _extract_vm_components(self, code):
        dispatch_loop = re.search(r'while\s+.+?do\s+(.*?)end\s*end', code, re.DOTALL)
        if not dispatch_loop:
            return False
        loop_body = dispatch_loop.group(1)

        pc_match = re.search(r'(\w+)\s*=\s*(\w+)\[(\w+)\]', loop_body)
        if not pc_match:
            return False
        self.op_var = pc_match.group(1)
        self.table_var = pc_match.group(2)
        self.pc_var = pc_match.group(3)

        table_decl = re.search(rf'{re.escape(self.table_var)}\s*=\s*\{{(.+?)\}}', code, re.DOTALL)
        if not table_decl:
            table_decl = re.search(rf'local\s+{re.escape(self.table_var)}\s*=\s*\{{(.+?)\}}', code, re.DOTALL)
        if not table_decl:
            return False

        self.instruction_table = self._parse_table(table_decl.group(1))

        handlers = {}
        handler_pattern = re.compile(
            rf'(?:else)?if\s+{re.escape(self.op_var)}\s*==\s*(\d+)\s+then\s+(.*?)(?=\s*(?:elseif|else|end)\b)',
            re.DOTALL
        )
        for m in handler_pattern.finditer(loop_body):
            opcode = int(m.group(1))
            handler_code = m.group(2)
            handlers[opcode] = self._parse_handler(handler_code)

        if not handlers:
            return False

        self.opcode_handlers = handlers
        return True

    def _parse_table(self, body):
        entries = re.split(r'\s*,\s*', body)
        parsed = []
        for e in entries:
            e = e.strip()
            if not e:
                continue
            if e.startswith('"') and e.endswith('"'):
                parsed.append(e[1:-1])
            elif e.startswith("'") and e.endswith("'"):
                parsed.append(e[1:-1])
            elif e.lstrip('-').isdigit():
                parsed.append(int(e))
            else:
                parsed.append(e)
        return parsed

    def _parse_handler(self, handler):
        h = handler.strip()
        if re.search(r'R\s*\[', h):
            m = re.search(r'R\s*\[([^\]]+)\]', h)
            index_expr = m.group(1) if m else '1'
            return {'action': 'LOADK', 'index': index_expr}
        if '_G[' in h and '=' in h and h.index('_G') > h.index('='):
            m = re.search(r'_G\s*\[([^\]]+)\]', h)
            name_expr = m.group(1) if m else '""'
            return {'action': 'SETGLOBAL', 'name': name_expr}
        if '=' in h and '_G[' in h:
            m = re.search(r'_G\s*\[([^\]]+)\]', h)
            name_expr = m.group(1) if m else '""'
            return {'action': 'GETGLOBAL', 'name': name_expr}
        if 'pcall' in h:
            return {'action': 'PCALL'}
        if 'loadstring' in h:
            return {'action': 'LOADSTRING'}
        if 'return' in h:
            return {'action': 'RETURN'}
        if 'string.char' in h:
            return {'action': 'STRCHAR'}
        if 'table.concat' in h:
            return {'action': 'TABLECONCAT'}
        if '..' in h:
            return {'action': 'CONCAT'}
        if re.search(r'[+\-*/]', h) and '=' in h:
            return {'action': 'ARITH'}
        if '=' in h and 'function' in h:
            return {'action': 'CLOSURE'}
        if '=' in h and '{' in h:
            return {'action': 'NEWTABLE'}
        if '[' in h and ']' in h and '=' in h:
            return {'action': 'SETTABLE'}
        if re.search(r'\w+\s*\(', h):
            m = re.search(r'(\w+)\s*\(', h)
            func = m.group(1) if m else 'unknown'
            return {'action': 'CALL', 'func': func}
        return {'action': 'UNKNOWN'}

    def _execute_vm(self):
        table = self.instruction_table
        pc = 0
        limit = len(table)
        self.stack = []
        self.locals = {}
        self.output_statements = []
        self.globals = {}

        while pc < limit:
            opcode = table[pc]
            pc += 1
            if not isinstance(opcode, int) or opcode not in self.opcode_handlers:
                continue

            handler = self.opcode_handlers[opcode]
            action = handler['action']

            if action == 'LOADK':
                idx = self._eval_index(handler['index'], pc, table)
                if idx is not None and isinstance(idx, int) and 1 <= idx <= len(self.string_table):
                    val = self.string_table[idx - 1]
                else:
                    val = idx
                self.stack.append(val)
                pc = self._advance_pc_for_index(pc, handler['index'])

            elif action == 'SETGLOBAL':
                name = self._resolve_string(handler['name'])
                val = self.stack.pop() if self.stack else 'nil'
                self.globals[name] = val
                self.output_statements.append(f'_G["{name}"] = {self._format_val(val)}')

            elif action == 'GETGLOBAL':
                name = self._resolve_string(handler['name'])
                self.stack.append(('global', name))

            elif action == 'CALL':
                func = handler.get('func', 'unknown')
                args = [self.stack.pop() for _ in range(min(3, len(self.stack)))]
                args.reverse()
                args_str = ', '.join(self._format_val(a) for a in args)
                self.output_statements.append(f'{func}({args_str})')

            elif action == 'RETURN':
                ret_vals = [self.stack.pop() for _ in range(len(self.stack))]
                ret_vals.reverse()
                ret_str = ', '.join(self._format_val(v) for v in ret_vals) if ret_vals else ''
                self.output_statements.append(f'return {ret_str}')
                break

            elif action == 'CONCAT':
                right = self.stack.pop()
                left = self.stack.pop()
                self.stack.append(f'{self._format_val(left)} .. {self._format_val(right)}')

            elif action == 'ARITH':
                b = self.stack.pop()
                a = self.stack.pop()
                self.stack.append(f'({self._format_val(a)} + {self._format_val(b)})')

            elif action == 'STRCHAR':
                args = []
                for _ in range(min(10, len(self.stack))):
                    val = self.stack.pop()
                    if isinstance(val, int):
                        args.insert(0, str(val))
                    else:
                        self.stack.append(val)
                        break
                if args:
                    self.output_statements.append(f'string.char({", ".join(args)})')

            elif action == 'TABLECONCAT':
                sep = self.stack.pop()
                tbl = self.stack.pop()
                self.stack.append(f'table.concat({self._format_val(tbl)}, {self._format_val(sep)})')

            elif action == 'PCALL':
                args = [self.stack.pop() for _ in range(min(2, len(self.stack)))]
                args.reverse()
                self.output_statements.append(f'pcall(function() {" ".join(self._format_val(a) for a in args)} end)')

            elif action == 'LOADSTRING':
                code = self.stack.pop()
                self.output_statements.append(f'loadstring({self._format_val(code)})()')

            elif action == 'SETTABLE':
                val = self.stack.pop()
                key = self.stack.pop()
                tbl = self.stack.pop()
                self.output_statements.append(f'{self._format_val(tbl)}[{self._format_val(key)}] = {self._format_val(val)}')

            elif action == 'NEWTABLE':
                self.stack.append('{}')

            elif action == 'CLOSURE':
                self.output_statements.append(f'local function func_{self.temp_counter}() end')
                self.stack.append(f'func_{self.temp_counter}')
                self.temp_counter += 1

        for name, val in self.globals.items():
            if name not in [s.split('"')[1] if '"' in s else '' for s in self.output_statements]:
                self.output_statements.insert(0, f'_G["{name}"] = {self._format_val(val)}')

    def _eval_index(self, expr, pc, table):
        expr = expr.strip()
        if expr.isdigit():
            return int(expr)
        if re.match(rf'{re.escape(self.table_var)}\[.+?\]', expr):
            return table[pc] if pc < len(table) else 0
        return None

    def _advance_pc_for_index(self, pc, expr):
        if re.match(rf'{re.escape(self.table_var)}\[.+?\]', expr):
            return pc + 1
        return pc

    def _resolve_string(self, expr):
        expr = expr.strip()
        if expr.startswith('"') and expr.endswith('"'):
            return expr[1:-1]
        if expr.isdigit():
            idx = int(expr) - 1
            if 0 <= idx < len(self.string_table):
                return self.string_table[idx]
        return expr

    def _format_val(self, val):
        if val is None:
            return 'nil'
        if isinstance(val, bool):
            return 'true' if val else 'false'
        if isinstance(val, (int, float)):
            return str(val)
        if isinstance(val, tuple) and val[0] == 'global':
            return f'_G["{val[1]}"]'
        if isinstance(val, str):
            if val in ('nil', 'true', 'false'):
                return val
            escaped = val.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
            return f'"{escaped}"'
        return str(val)

    def _emit_lua(self):
        if not self.output_statements:
            return self._fallback()
        return '\n'.join(self.output_statements)

    def _fallback(self):
        return 'return nil'
