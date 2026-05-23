import os, re, shutil, subprocess, tempfile, base64, urllib.request, asyncio, struct, hashlib, json, time, traceback, binascii, sys
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
            'control_flow_recovery', 'constant_propagation'
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
        input_size = len(source.encode('utf-8', errors='replace'))
        input_lines = len(source.splitlines())

        fingerprint = self.fingerprinter.analyze(source)
        trace.append({'stage': 'fingerprint', 'details': fingerprint, 'input_size': input_size, 'input_lines': input_lines})

        try:
            wearedevs_bc = self._extract_wearedevs_bytecode(source, diags)
            trace.append({'stage': 'wearedevs_extractor', 'bytecode_found': wearedevs_bc is not None})
            if wearedevs_bc:
                dc, err = self._run_unluac(wearedevs_bc)
                if dc and self._is_valid_lua(dc):
                    return self._beautify(dc), 'wearedevs_unluac', f'Decompiled ({len(dc)} chars)', trace
                if err:
                    reasons['wearedevs_unluac'] = err
                return base64.b64encode(wearedevs_bc).decode('ascii'), 'bytecode', f'Bytecode ({len(wearedevs_bc)}B). unluac: {err}', trace
        except Exception as e:
            diags.append(f"WeAreDevs crashed: {str(e)}")
            trace.append({'stage': 'wearedevs_extractor_error', 'error': str(e)})

        try:
            result = self._try_rapid_string_decode(source, trace)
            if result:
                bc = self._extract_bytecode(result)
                if bc:
                    dc, err = self._run_unluac(bc)
                    if dc and self._is_valid_lua(dc):
                        return self._beautify(dc), 'rapid_decode_unluac', f'Rapid decode ({len(dc)} chars)', trace
                    if err: reasons['rapid_decode_unluac'] = err
        except Exception as e:
            diags.append(f"Rapid decode crashed: {str(e)}")

        for lifter in self.lifters:
            lifter_name = lifter.__class__.__name__
            try:
                decoded_chunks = lifter.lift(source)
                if decoded_chunks:
                    chunk_no_bc = 0
                    for chunk in decoded_chunks:
                        if isinstance(chunk, bytes):
                            bc = self.bytecode_harvester.extract(chunk)
                            if bc:
                                dc, err = self._run_unluac(bc)
                                if dc and self._is_valid_lua(dc):
                                    return self._beautify(dc), f'{lifter_name}_unluac', f'{lifter_name} ({len(dc)} chars)', trace
                                if err: reasons[f'{lifter_name}_unluac'] = err
                            else:
                                chunk_no_bc += 1
                        elif isinstance(chunk, str):
                            nested_bc = self._extract_bytecode(chunk)
                            if nested_bc:
                                dc, err = self._run_unluac(nested_bc)
                                if dc and self._is_valid_lua(dc):
                                    return self._beautify(dc), f'{lifter_name}_nested_unluac', f'{lifter_name} nested ({len(dc)} chars)', trace
                                if err: reasons[f'{lifter_name}_nested_unluac'] = err
                            if self._is_valid_lua(chunk) and len(chunk) > 200:
                                rec_result, rec_type, rec_diag, rec_trace = self.process(chunk)
                                if rec_result and rec_type != 'unable':
                                    return rec_result, f'recursive_{rec_type}', f'Recursive: {rec_diag}', trace + rec_trace
                            else:
                                chunk_no_bc += 1
                    diags.append(f"{lifter_name}: {len(decoded_chunks)} chunks, {chunk_no_bc} no bc")
            except Exception as e:
                diags.append(f"{lifter_name} crashed: {str(e)}")

        try:
            all_strings = self.string_decoder.decode_all(source)
            if all_strings:
                combined = '\n'.join(all_strings)
                if len(combined) > 200 and self._is_valid_lua(combined):
                    return self._beautify(combined), 'string_decode', f'String decode ({len(combined)} chars)', trace
        except Exception as e:
            diags.append(f"String decoder crashed: {str(e)}")

        try:
            layers, caps, diag = execute_sandbox(source, timeout=120)
            trace.append({'stage': 'sandbox', 'layers': len(layers)})
            if diag: reasons['sandbox'] = diag[:150]
            if layers:
                diags.append(f"sandbox: {len(layers)} layers")
            for i, item in enumerate(layers):
                if isinstance(item, bytes) and len(item) >= 12:
                    bc = self.bytecode_harvester.extract(item)
                    if bc:
                        dc, err = self._run_unluac(bc)
                        if dc and self._is_valid_lua(dc):
                            return self._beautify(dc), 'sandbox_unluac', f'Sandbox layer {i} ({len(dc)} chars)', trace
                if isinstance(item, str) and len(item) > 100 and self._is_valid_lua(item):
                    return self._beautify(item), 'sandbox_capture', f'Layer {i} source ({len(item)} chars)', trace
        except Exception as e:
            diags.append(f"Sandbox crashed: {str(e)}")

        try:
            lune_data, lune_info = self._run_lune(source)
            trace.append({'stage': 'lune'})
            if lune_data:
                if isinstance(lune_data, bytes) and len(lune_data) >= 12:
                    bc = self.bytecode_harvester.extract(lune_data)
                    if bc:
                        dc, err = self._run_unluac(bc)
                        if dc and self._is_valid_lua(dc):
                            return self._beautify(dc), 'lune_unluac', f'Lune ({len(dc)} chars)', trace
        except Exception:
            pass

        try:
            raw_bytecode = self.bytecode_harvester.deep_scan(source)
            if raw_bytecode:
                dc, err = self._run_unluac(raw_bytecode)
                if dc and self._is_valid_lua(dc):
                    return self._beautify(dc), 'deep_scan_unluac', f'Deep scan ({len(dc)} chars)', trace
                if err: reasons['deep_scan_unluac'] = err
                return base64.b64encode(raw_bytecode).decode('ascii'), 'bytecode', f'Raw bc ({len(raw_bytecode)}B)', trace
        except Exception:
            pass

        parts = [f'Steps: {"; ".join(diags[:3])}']
        if reasons:
            parts.append('Errors: ' + '; '.join(f"{k}: {v[:60]}" for k, v in reasons.items()))
        reason = '\n'.join(parts)
        return '', 'unable', reason, trace

    def _extract_wearedevs_bytecode(self, source, diags):
        m = re.search(r'local R=\{([^}]+)\}', source)
        if not m:
            diags.append("no string table")
            return None
        table_body = m.group(1)
        strings = re.findall(r'"((?:[^"\\]|\\.)*)"', table_body)
        if len(strings) < 10:
            diags.append(f"only {len(strings)} strings")
            return None
        original_table = []
        for s in strings:
            decoded = self._decode_wearedevs_string(s)
            original_table.append(decoded if decoded else b'')
        empty_count = sum(1 for d in original_table if len(d)==0)
        b64_reverse = self._extract_custom_b64_reverse(source)
        shuffle_pairs = self._extract_shuffle_pairs(source)

        def apply_shuffles(table, pairs):
            working = list(table)
            for lo, hi in pairs:
                lo_idx, hi_idx = lo - 1, hi - 1
                while lo_idx < hi_idx:
                    working[lo_idx], working[hi_idx] = working[hi_idx], working[lo_idx]
                    lo_idx += 1
                    hi_idx -= 1
            return working

        def decode_and_find(table):
            decoded_chunks = []
            for chunk in table:
                if len(chunk) == 0:
                    continue
                decoded = self._decode_custom_b64(chunk, b64_reverse)
                if decoded:
                    decoded_chunks.append(decoded)
            if not decoded_chunks:
                return None
            combined = b''.join(decoded_chunks)
            bc = self.bytecode_harvester.extract(combined)
            if bc:
                return bc
            return None

        # Try normal order
        working = apply_shuffles(original_table, shuffle_pairs)
        bc = decode_and_find(working)
        if bc:
            diags.append(f"OK {len(bc)}B bc, {len(strings)} strs")
            return bc

        # Try reversed shuffle order
        reversed_pairs = list(reversed(shuffle_pairs))
        working = apply_shuffles(original_table, reversed_pairs)
        bc = decode_and_find(working)
        if bc:
            diags.append(f"OK {len(bc)}B bc (reversed shuffles)")
            return bc

        # If still no bc, report hex preview
        combined = b''.join([self._decode_custom_b64(c, b64_reverse) or b'' for c in working if len(c)>0])
        hex_preview = binascii.hexlify(combined[:16]).decode() if combined else 'empty'
        diags.append(f"no bc sig: {hex_preview} ({len(strings)} strs, {len(b64_reverse)} b64map, {len(shuffle_pairs)} shuff)")
        return None

    def _extract_custom_b64_reverse(self, source):
        m = re.search(r'local N=\{([^}]+)\}', source)
        if not m:
            return {}
        body = m.group(1)
        reverse = {}
        for key_match in re.finditer(r'\["(\\.)"\]\s*=\s*([-\d()+\-*/]+)', body):
            key_str = key_match.group(1)
            val_expr = key_match.group(2)
            val = self._safe_eval(val_expr.strip())
            if val is not None and 0 <= val < 64:
                key_char = self._decode_wearedevs_string(key_str)
                if key_char:
                    reverse[val] = key_char.decode('latin-1')
        for key_match in re.finditer(r'(?<![\["\'])([a-zA-Z])\s*=\s*([-\d()+\-*/]+)', body):
            key_str = key_match.group(1)
            val_expr = key_match.group(2)
            val = self._safe_eval(val_expr.strip())
            if val is not None and 0 <= val < 64:
                reverse[val] = key_str
        std_b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        for i, ch in enumerate(std_b64):
            if i not in reverse:
                reverse[i] = ch
        return reverse

    def _decode_custom_b64(self, data, reverse_map):
        if not reverse_map or len(data) == 0:
            return None
        forward = {v: k for k, v in reverse_map.items()}
        bit_buf = 0
        bits = 0
        out = bytearray()
        for byte_val in data:
            char = chr(byte_val) if byte_val < 256 else ''
            if char not in forward:
                if byte_val == ord('='):
                    break
                continue
            val = forward[char]
            bit_buf = (bit_buf << 6) | val
            bits += 6
            while bits >= 8:
                bits -= 8
                out.append((bit_buf >> bits) & 0xFF)
        return bytes(out)

    def _extract_shuffle_pairs(self, source):
        m = re.search(r'for\s+\w+,\w+\s+in\s+ipairs\s*\(\s*(\{.+?\})\s*\)', source)
        if not m:
            return []
        outer = m.group(1)
        inner_tables = re.findall(r'\{([-\d()+\-*/\s]+)[;,]([-\d()+\-*/\s]+)\}', outer)
        ranges = []
        for expr1, expr2 in inner_tables:
            lo = self._safe_eval(expr1.strip())
            hi = self._safe_eval(expr2.strip())
            if lo is not None and hi is not None:
                ranges.append((lo, hi))
        return ranges

    @staticmethod
    def _safe_eval(expr):
        expr = expr.replace(' ', '')
        if not expr:
            return None
        if not re.match(r'^[\d+\-*/()]+$', expr):
            return None
        try:
            return eval(expr)
        except Exception:
            return None

    @staticmethod
    def _decode_wearedevs_string(s):
        result = bytearray()
        i = 0
        while i < len(s):
            if s[i] == '\\' and i + 1 < len(s) and s[i+1].isdigit():
                j = i + 1
                while j < len(s) and s[j].isdigit() and j - i < 4:
                    j += 1
                try:
                    val = int(s[i+1:j])
                    if 0 <= val <= 255:
                        result.append(val)
                except ValueError:
                    pass
                i = j
            else:
                i += 1
        return bytes(result)

    def _try_rapid_string_decode(self, source, trace):
        patterns = [
            r'local\s+\w+\s*=\s*\{([^}]+)\}',
            r'local\s+\w+\s*=\s*\{\s*([^\}]{50,})\s*\}',
            r'=\s*\{\s*("[^"]{50,}"[,\s]*)+',
        ]
        for pat in patterns:
            matches = re.findall(pat, source, re.DOTALL)
            if matches:
                trace.append({'stage': 'rapid_decode_pattern', 'pattern': pat, 'matches': len(matches)})
                return source
        return None

    def _extract_bytecode(self, data):
        if isinstance(data, bytes):
            return self.bytecode_harvester.extract(data)
        if isinstance(data, str):
            if len(data) >= 12 and data[:4] == '\x1bLua' and len(data) > 12:
                return data.encode('latin-1')
            return self.bytecode_harvester.extract(data.encode('latin-1'))
        return None

    def _extract_bytecode_from_sandbox_output(self, item):
        start = item.find('SANDBOX_OUTPUT_START')
        end = item.find('SANDBOX_OUTPUT_END', start)
        if start == -1 or end == -1:
            return None
        block = item[start + len('SANDBOX_OUTPUT_START'):end]
        patterns = [
            r'"((?:\\\d{1,3}){12,}[^"]*)"',
            r"'((?:\\\d{1,3}){12,}[^']*)'",
            r'"([\x00-\xff]{12,})"',
            r'\[==?\[(.*?)\]==?\]',
        ]
        for pat in patterns:
            for m in re.finditer(pat, block, re.DOTALL):
                raw = m.group(1)
                decoded = self._decode_escaped_bytes(raw)
                if decoded and len(decoded) >= 12:
                    bc = self.bytecode_harvester.extract(decoded)
                    if bc:
                        return bc
        return None

    @staticmethod
    def _decode_escaped_bytes(s):
        try:
            result = bytearray()
            i = 0
            while i < len(s):
                if s[i] == '\\' and i + 1 < len(s):
                    if s[i+1] == '\\':
                        result.append(ord('\\'))
                        i += 2
                        continue
                    j = i + 1
                    while j < len(s) and s[j].isdigit():
                        j += 1
                    if j > i + 1:
                        val = int(s[i+1:j])
                        if 0 <= val <= 255:
                            result.append(val)
                        i = j
                    else:
                        escape_map = {'n': 10, 'r': 13, 't': 9, '0': 0, 'a': 7, 'b': 8, 'f': 12, 'v': 11}
                        result.append(escape_map.get(s[i+1], ord(s[i+1])))
                        i += 2
                else:
                    result.append(ord(s[i]))
                    i += 1
            return bytes(result)
        except Exception:
            return None

    def _run_lune(self, source):
        try:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_closed():
                    raise RuntimeError
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            return loop.run_until_complete(execute_and_capture(source))
        except Exception as e:
            return None, {'error': f'lune_execution_failed: {str(e)}'}

    def _run_unluac(self, bytecode):
        if not self._java_available:
            return None, "java not installed"
        if not os.path.isfile(self.unluac_path):
            self._ensure_unluac_jar()
        if not os.path.isfile(self.unluac_path):
            return None, "unluac.jar missing"
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
                tmp.write(bytecode)
                tmp_path = tmp.name
            result = subprocess.run(
                ['java', '-jar', self.unluac_path, '--rawstring', tmp_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout, None
            if result.stderr and 'version' in result.stderr.lower():
                result2 = subprocess.run(
                    ['java', '-jar', self.unluac_path, tmp_path],
                    capture_output=True, text=True, timeout=30
                )
                if result2.returncode == 0 and result2.stdout.strip():
                    return result2.stdout, None
                return None, f"unluac error: {result2.stderr[:300]}"
            return None, f"unluac exit {result.returncode}: {result.stderr[:200]}" if result.stderr else f'unluac exit {result.returncode}'
        except subprocess.TimeoutExpired:
            return None, "unluac timeout (30s)"
        except Exception as e:
            return None, f"unluac exception: {str(e)}"
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try: os.unlink(tmp_path)
                except OSError: pass

    def _ensure_unluac_jar(self):
        try:
            jar_dir = os.path.dirname(self.unluac_path)
            if jar_dir:
                os.makedirs(jar_dir, exist_ok=True)
            urllib.request.urlretrieve(UNLUAC_JAR_URL, self.unluac_path)
        except Exception:
            pass

    @staticmethod
    def _is_valid_lua(code):
        if not code or len(code) < 50:
            return False
        lines = code.split('\n')
        if len(lines) > 5:
            proxy_pattern = re.compile(r'^\s*[\w.]+ = [A-Z]\w+$')
            proxy_lines = sum(1 for line in lines if proxy_pattern.match(line.strip()))
            if proxy_lines > len(lines) * 0.4:
                return False
        words = set(re.findall(r'\b\w+\b', code[:10000]))
        keyword_count = len(words & LUA_KEYWORDS)
        if keyword_count < 5:
            return False
        has_function = 'function' in words and 'end' in words
        has_local = 'local' in words
        if not (has_function or has_local):
            return False
        printable = sum(1 for c in code if c.isprintable() or c in '\n\r\t')
        return (printable / max(len(code), 1)) >= 0.70

    def _beautify(self, code):
        try:
            from luaparser import ast as lua_ast
            return lua_ast.to_lua_source(lua_ast.parse(code))
        except Exception:
            out, ind = [], 0
            openers = ('if ', 'if(', 'for ', 'for(', 'while ', 'while(', 'function ', 'local function ', 'do', 'repeat')
            closers = ('end', 'else', 'elseif', 'until')
            for raw in code.split('\n'):
                line = raw.strip()
                if not line:
                    out.append('')
                    continue
                if any(line.startswith(w) for w in closers):
                    ind = max(0, ind - 1)
                out.append('    ' * ind + line)
                if any(line.startswith(w) for w in openers) and not line.rstrip().endswith('end'):
                    ind += 1
            return '\n'.join(out)
