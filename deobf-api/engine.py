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
from roblox_executor import execute_via_roblox
from errors import LinoError
from diagnostics import (
    diagnostic_parse, validate_lua, parse_lua_error,
    extract_error_context, auto_fix_lua, confidence_score,
    save_crash_snapshot, log_structured_error, pipeline_validate_stage,
    detect_bad_patterns
)

try:
    from luaparser import ast as lua_ast
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

LUA_SUBSTRINGS = [
    'function', 'local', 'end', 'print', 'tostring', 'tonumber',
    'setmetatable', 'getmetatable', 'loadstring', 'pcall', 'unpack',
    'string.byte', 'math.floor', 'table.concat', 'error', 'pairs',
    'ipairs', 'require', 'coroutine', 'rawset', 'rawget',
]

BAD_PATTERNS = [
    r'\d+\s+end',
    r'\.\.\s*\.\.',
    r',\s*,',
    r'function\s+end',
    r'if\s+then\s+end',
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
            'devirtualized_ir_generation', 'roblox_execution',
            'layered_diagnostics', 'staged_validation', 'transformer_isolation',
            'confidence_scoring', 'auto_recovery', 'crash_snapshots',
            'token_level_diagnostics', 'ast_verification'
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
        stage = "init"

        try:
            fingerprint = self.fingerprinter.analyze(source)
            trace.append({'stage': 'fingerprint', 'details': fingerprint})
            stage = "fingerprint"

            string_table, var_name = self._decode_string_table(source, diags)
            stage = "decode_string_table"

            if string_table:
                diags.append(f"R table: {len(string_table)} strings (var={var_name})")

                roblox_result, roblox_error = self._try_roblox_exec(source, string_table)
                if roblox_result:
                    trace.append({'stage': 'roblox', 'success': True})
                    stage = "roblox_exec"
                    pipeline_validate_stage(roblox_result, stage)
                    validated = self._beautify(roblox_result)
                    return validated, 'roblox_execution', 'Deobfuscated via Roblox execution', trace
                elif roblox_error:
                    trace.append({'stage': 'roblox', 'error': roblox_error})

                layers, caps, diag = execute_sandbox(source, timeout=120, varargs=string_table)
                trace.append({'stage': 'sandbox', 'layers': len(layers), 'caps': len(caps)})
                if layers:
                    stage = "sandbox"
                    for i, item in enumerate(layers):
                        result = self._process_layer(item, i, string_table, var_name)
                        if result:
                            pipeline_validate_stage(result, f"sandbox_layer_{i}")
                            validated = self._beautify(result)
                            return validated, 'sandbox_source', f'Layer {i} source captured', trace

                combined = self._static_decode_raw(source, string_table)
                if combined:
                    stage = "static_decode"
                    pipeline_validate_stage(combined, stage)
                    lifter = FullSemanticVMLifter(string_table, var_name)
                    lifted_code = lifter.lift(combined)
                    stage = "semantic_lift"
                    pipeline_validate_stage(lifted_code, stage)
                    validated = self._validate_and_repair(lifted_code)
                    beautified = self._beautify(validated)
                    return beautified, 'semantic_full', f'Semantically reconstructed ({len(beautified)} chars)', trace

            layers, caps, diag = execute_sandbox(source, timeout=120)
            if layers:
                stage = "sandbox_fallback"
                for i, item in enumerate(layers):
                    result = self._process_layer(item, i, None, None)
                    if result:
                        pipeline_validate_stage(result, f"sandbox_fallback_layer_{i}")
                        validated = self._beautify(result)
                        return validated, 'sandbox_source', f'Layer {i} source captured', trace

        except LinoError as e:
            log_structured_error(e)
            return self._handle_diagnostic_failure(e, stage)

        parts = [f'Steps: {"; ".join(diags[:3])}']
        if reasons:
            parts.append('Info: ' + '; '.join(f"{k}: {v[:300]}" for k, v in reasons.items()))
        reason = '\n'.join(parts) if parts else 'All stages exhausted'
        return '', 'unable', reason, trace

    def _handle_diagnostic_failure(self, lino_err, stage):
        repaired = auto_fix_lua(lino_err.code_snippet) if lino_err.code_snippet else ""
        if repaired:
            try:
                pipeline_validate_stage(repaired, f"recovery_{stage}")
                return self._beautify(repaired), 'recovered', f"Recovered from {stage} failure", []
            except:
                pass
        error_data = lino_err.to_dict()
        return f"-- Decompilation failed at stage {stage}\n-- {json.dumps(error_data)}", 'error', lino_err.message, []

    def _validate_and_repair(self, code):
        if not code or len(code) < 50:
            return code
        if self._is_valid_lua(code):
            return self._beautify(code)
        repaired = self._normalize_lua(code)
        if self._is_valid_lua(repaired):
            return self._beautify(repaired)
        return self._beautify(code)

    def _normalize_lua(self, code):
        code = code.replace('\r\n', '\n').replace('\r', '\n')
        code = re.sub(r'\n\s*\n', '\n\n', code)
        code = re.sub(r'(\d+)\s+end', r'\1\nend', code)
        code = re.sub(r'(\d+)\s+then', r'\1\nthen', code)
        code = re.sub(r'(\d+)\s+else', r'\1\nelse', code)
        code = re.sub(r'(\d+)\s+elseif', r'\1\nelseif', code)
        code = re.sub(r'(\d+)\s+do', r'\1\ndo', code)
        code = re.sub(r',\s*,', ',', code)
        code = re.sub(r'\.\s*\.', '..', code)
        code = re.sub(r'\bif\s*\n\s*then\b', 'if true then', code)
        code = re.sub(r'\bfunction\s+end\b', 'function dummy() end', code)
        code = re.sub(r'(\w+)\s*\(\s*\)\s*\(\s*\)', r'\1()()', code)
        code = re.sub(r'\n\s*return\s*\n', '\nreturn ', code)
        code = re.sub(r'\n\s*local\s+function\s*\n', '\nlocal function ', code)
        lines = code.split('\n')
        cleaned = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                cleaned.append('')
                continue
            cleaned.append(stripped)
        return '\n'.join(cleaned)

    @staticmethod
    def _is_valid_lua(code):
        if not code or len(code) < 50:
            return False
        if HAS_LUAPARSER:
            try:
                lua_ast.parse(code)
                return True
            except Exception:
                pass
        words = set(re.findall(r'\b\w+\b', code[:10000]))
        if len(words & LUA_KEYWORDS) < 2:
            return False
        printable = sum(1 for c in code if c.isprintable() or c in '\n\r\t')
        if (printable / max(len(code), 1)) < 0.70:
            return False
        for pat in BAD_PATTERNS:
            if re.search(pat, code):
                return False
        return True

    def _static_decode_raw(self, source, string_table):
        try:
            return self._static_decode_raw_inner(source, string_table)
        except Exception as e:
            save_crash_snapshot("static_decode", source, "", e)
            raise LinoError(
                stage="static_decode",
                message=str(e),
                original_exception=e,
                confidence=confidence_score(source)
            )

    def _static_decode_raw_inner(self, source, string_table):
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

    def _try_roblox_exec(self, source, string_table=None):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result, error = loop.run_until_complete(
                execute_via_roblox(source, string_table)
            )
            loop.close()
        except Exception as e:
            return None, str(e)

        if error:
            return None, error

        if isinstance(result, list):
            combined = self._static_decode_raw(source, result)
            if combined:
                return combined, None
            return None, "Static decode failed on Roblox table"

        return result, None


@dataclass
class BasicBlock:
    id: int
    start_pc: int
    end_pc: int
    instructions: List[Any] = field(default_factory=list)
    successors: List['BasicBlock'] = field(default_factory=list)
    predecessors: List['BasicBlock'] = field(default_factory=list)

@dataclass
class SymbolicExpr:
    kind: str
    value: Any = None
    left: Optional['SymbolicExpr'] = None
    right: Optional['SymbolicExpr'] = None
    args: List['SymbolicExpr'] = field(default_factory=list)
    reg: str = ""

class FullSemanticVMLifter:
    def __init__(self, string_table, var_name):
        self.string_table = string_table
        self.var_name = var_name
        self.inst_table = []
        self.handlers = {}
        self.cfg_blocks = []
        self.ssa_count = 0
        self.output = []

    def lift(self, vm_code):
        code = self._neutralize(vm_code)
        code = self._fold_arithmetic(code)
        code = self._subst_strings(code)

        if not self._extract_any_table(code):
            return vm_code
        if not self._extract_any_handlers(code):
            return vm_code

        self._build_cfg()
        self._symbolic_execute()
        self._optimize_ir()
        if not self.output:
            return vm_code
        return self._emit_lua()

    def _neutralize(self, code):
        code = re.sub(r'if\s+not\s+pcall\s*\(\s*function\s*\(\)[^)]*end\s*\)\s*then\s*error\s*\([^)]*\)\s*end', '', code, flags=re.DOTALL)
        code = re.sub(r'error\s*\(\s*"[^"]*Tamper\s*Detected[^"]*"\)', '', code)
        code = re.sub(r'checkcaller\s*\(\s*\)', 'true', code)
        return code

    def _fold_arithmetic(self, code):
        def fold(m):
            try:
                val = eval(m.group(1))
                if isinstance(val, (int, float)) and -1000000 < val < 1000000:
                    if isinstance(val, float) and val == int(val):
                        return str(int(val))
                    return str(val)
            except:
                pass
            return m.group(0)
        return re.sub(r'\(\s*(-?[\d+\-*/.() ]+)\s*\)', fold, code)

    def _subst_strings(self, code):
        def repl(m):
            try:
                idx = int(m.group(1)) - 1
                if 0 <= idx < len(self.string_table):
                    return f'"{self.string_table[idx]}"'
            except:
                pass
            return m.group(0)
        return re.sub(rf'\b{re.escape(self.var_name)}\s*[\(\[]\s*(-?\d+)\s*[\)\]]', repl, code)

    def _extract_any_table(self, code):
        all_tables = []
        for m in re.finditer(r'\{', code):
            body = self._balanced(code, m.start())
            if not body:
                continue
            inner = body[1:-1]
            entries = [e.strip() for e in re.split(r'\s*,\s*', inner) if e.strip()]
            nums = sum(1 for e in entries if e.lstrip('-').isdigit())
            strs = sum(1 for e in entries if e.startswith('"') or e.startswith("'"))
            if nums + strs >= 10:
                all_tables.append((nums + strs, body))
        if not all_tables:
            return False
        all_tables.sort(key=lambda x: -x[0])
        _, best = all_tables[0]
        self.inst_table = self._parse_entries(best)
        return len(self.inst_table) >= 5

    def _balanced(self, code, start):
        if start >= len(code) or code[start] != '{':
            return None
        depth = 0
        instr = False
        sc = None
        i = start
        while i < len(code):
            c = code[i]
            if instr:
                if c == '\\':
                    i += 2
                    continue
                if c == sc:
                    instr = False
            else:
                if c in ('"', "'"):
                    instr = True
                    sc = c
                elif c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        return code[start:i+1]
            i += 1
        return None

    def _parse_entries(self, body):
        inner = body[1:-1]
        entries = [e.strip() for e in re.split(r'\s*,\s*', inner) if e.strip()]
        parsed = []
        for e in entries:
            if (e.startswith('"') and e.endswith('"')) or (e.startswith("'") and e.endswith("'")):
                parsed.append(e[1:-1])
            elif e.lstrip('-').isdigit():
                parsed.append(int(e))
            elif e.replace('.', '', 1).lstrip('-').isdigit():
                parsed.append(float(e))
            else:
                parsed.append(e)
        return parsed

    def _extract_any_handlers(self, code):
        while_blocks = re.findall(r'while\s+.+?do\s+(.*?)end', code, re.DOTALL)
        for block in while_blocks:
            handlers = {}
            for m in re.finditer(r'if\s+(\w+)\s*==\s*(\d+)\s+then\s+(.*?)(?=\s*(?:elseif|else|end)\b)', block, re.DOTALL):
                try:
                    opc = int(m.group(2))
                    handlers[opc] = self._classify(m.group(3))
                except:
                    continue
            if len(handlers) >= 2:
                self.handlers = handlers
                return True
        handlers = {}
        for m in re.finditer(r'if\s+(\w+)\s*==\s*(\d+)\s+then\s+(.*?)(?=\s*(?:elseif|else|end)\b)', code, re.DOTALL):
            try:
                opc = int(m.group(2))
                handlers[opc] = self._classify(m.group(3))
            except:
                continue
        if len(handlers) >= 2:
            self.handlers = handlers
            return True
        return False

    def _classify(self, h):
        h = h.strip()
        if re.search(r'R\s*\[', h):
            return 'LOADK'
        if '_G[' in h and '=' in h and h.index('_G') > h.index('='):
            return 'SETGLOBAL'
        if '=' in h and '_G[' in h:
            return 'GETGLOBAL'
        if 'pcall' in h:
            return 'PCALL'
        if 'loadstring' in h:
            return 'LOADSTRING'
        if 'return' in h:
            return 'RETURN'
        if 'string.char' in h:
            return 'STRCHAR'
        if 'table.concat' in h:
            return 'TABLECONCAT'
        if '..' in h:
            return 'CONCAT'
        if re.search(r'[+\-*/]', h) and '=' in h:
            return 'ARITH'
        if '=' in h and 'function' in h:
            return 'CLOSURE'
        if '=' in h and '{' in h:
            return 'NEWTABLE'
        if '[' in h and ']' in h and '=' in h:
            return 'SETTABLE'
        if re.search(r'\w+\s*\(', h):
            return 'CALL'
        return 'UNKNOWN'

    def _build_cfg(self):
        pc = 0
        blocks = []
        current = []
        block_start = 0
        limit = len(self.inst_table)
        while pc < limit:
            op = self.inst_table[pc]
            if isinstance(op, int) and op in self.handlers:
                action = self.handlers[op]
                if action in ('RETURN', 'LOADSTRING'):
                    if current:
                        blocks.append(BasicBlock(len(blocks), block_start, pc-1, list(current)))
                    blocks.append(BasicBlock(len(blocks), pc, pc, [op]))
                    block_start = pc+1
                    current = []
                else:
                    current.append(op)
            else:
                current.append(op)
            pc += 1
        if current:
            blocks.append(BasicBlock(len(blocks), block_start, limit-1, current))
        for i, blk in enumerate(blocks):
            if i+1 < len(blocks):
                blk.successors.append(blocks[i+1])
                blocks[i+1].predecessors.append(blk)
        self.cfg_blocks = blocks

    def _symbolic_execute(self):
        state = {'stack': [], 'regs': {}, 'upvals': {}, 'globals': {}}
        self.ssa_count = 0
        self.output.clear()
        for block in self.cfg_blocks:
            pc = block.start_pc
            while pc <= block.end_pc and pc < len(self.inst_table):
                op = self.inst_table[pc]
                if isinstance(op, int) and op in self.handlers:
                    action = self.handlers[op]
                    if action == 'LOADK':
                        idx = self._operand(pc)
                        val = self._const(idx)
                        self._push(state, val)
                        pc = self._skip(pc)
                    elif action == 'SETGLOBAL':
                        name = self._name(pc)
                        val = self._pop(state)
                        self.output.append(f'_G["{name}"] = {self._fmt(val)}')
                        state['globals'][name] = val
                    elif action == 'GETGLOBAL':
                        name = self._name(pc)
                        self._push(state, SymbolicExpr('global', value=name))
                    elif action == 'CALL':
                        func = self._func(pc)
                        args = [self._pop(state) for _ in range(min(3, len(state['stack'])))]
                        args.reverse()
                        args_str = ', '.join(self._fmt(a) for a in args)
                        self.output.append(f'{func}({args_str})')
                    elif action == 'RETURN':
                        rets = [self._pop(state) for _ in range(len(state['stack']))]
                        rets.reverse()
                        self.output.append(f'return {", ".join(self._fmt(r) for r in rets)}')
                        return
                    elif action == 'CONCAT':
                        r = self._pop(state)
                        l = self._pop(state)
                        self._push(state, SymbolicExpr('concat', left=l, right=r))
                    elif action == 'ARITH':
                        r = self._pop(state)
                        l = self._pop(state)
                        self._push(state, SymbolicExpr('arith', left=l, right=r))
                    elif action == 'STRCHAR':
                        args = []
                        while state['stack'] and isinstance(state['stack'][-1].value, int):
                            args.insert(0, self._pop(state))
                        if args:
                            self.output.append(f'string.char({", ".join(self._fmt(a) for a in args)})')
                    elif action == 'TABLECONCAT':
                        sep = self._pop(state)
                        tbl = self._pop(state)
                        self._push(state, SymbolicExpr('call', value='table.concat', args=[tbl, sep]))
                    elif action == 'NEWTABLE':
                        self._push(state, SymbolicExpr('table'))
                    elif action == 'CLOSURE':
                        name = f'f_{len(state["regs"])}'
                        self._push(state, SymbolicExpr('closure', value=name))
                        self.output.append(f'local function {name}() end')
                pc += 1

    def _push(self, state, expr):
        reg = f'%{self.ssa_count}'
        self.ssa_count += 1
        expr.reg = reg
        state['stack'].append(expr)

    def _pop(self, state):
        return state['stack'].pop() if state['stack'] else SymbolicExpr('nil')

    def _const(self, idx):
        if isinstance(idx, int) and 1 <= idx <= len(self.string_table):
            return SymbolicExpr('const', value=self.string_table[idx-1])
        return SymbolicExpr('unknown', value=idx)

    def _operand(self, pc):
        return self.inst_table[pc+1] if pc+1 < len(self.inst_table) else 0

    def _skip(self, pc):
        return pc+1

    def _name(self, pc):
        val = self.inst_table[pc+1] if pc+1 < len(self.inst_table) else ""
        if isinstance(val, int) and 1 <= val <= len(self.string_table):
            return self.string_table[val-1]
        return str(val)

    def _func(self, pc):
        val = self.inst_table[pc+1] if pc+1 < len(self.inst_table) else "unknown"
        if isinstance(val, int) and 1 <= val <= len(self.string_table):
            return self.string_table[val-1]
        return str(val)

    def _fmt(self, expr):
        if expr.kind == 'const':
            if isinstance(expr.value, str):
                escaped = expr.value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
                return f'"{escaped}"'
            return str(expr.value)
        if expr.kind == 'global':
            return f'_G["{expr.value}"]'
        if expr.kind == 'concat':
            return f'({self._fmt(expr.left)} .. {self._fmt(expr.right)})'
        if expr.kind == 'arith':
            return f'({self._fmt(expr.left)} + {self._fmt(expr.right)})'
        if expr.kind == 'call':
            args_str = ', '.join(self._fmt(a) for a in expr.args)
            return f'{expr.value}({args_str})'
        if expr.kind == 'table':
            return '{}'
        if expr.kind == 'closure':
            return expr.value
        return 'nil'

    def _optimize_ir(self):
        cleaned = []
        for stmt in self.output:
            if 'nil = nil' in stmt or stmt.strip() == 'return' or stmt.strip() == 'return nil':
                continue
            cleaned.append(stmt)
        self.output = cleaned

    def _emit_lua(self):
        if not self.output:
            return 'return nil'
        return '\n'.join(self.output)
