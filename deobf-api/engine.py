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

    @staticmethod
    def _log(msg):
        ts = time.strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{ts}] {msg}", file=sys.stderr, flush=True)

    def process(self, source):
        self._log("process: start")
        trace = []
        diags = []
        reasons = {}
        input_size = len(source.encode('utf-8', errors='replace'))
        input_lines = len(source.splitlines())

        try:
            fingerprint = self.fingerprinter.analyze(source)
            trace.append({'stage': 'fingerprint', 'details': fingerprint, 'input_size': input_size, 'input_lines': input_lines})
            self._log(f"fingerprint: {fingerprint.get('estimated_type','?')}")
        except Exception as e:
            self._log(f"fingerprint error: {e}")
            trace.append({'stage': 'fingerprint', 'error': str(e)})

        # -- WeAreDevs specific extractor ---------------------------------
        try:
            self._log("trying wearedevs extractor")
            wearedevs_bc = self._extract_wearedevs_bytecode(source, diags)
            if wearedevs_bc:
                trace.append({'stage': 'wearedevs_extractor', 'bytecode_size': len(wearedevs_bc)})
                self._log(f"wearedevs bytecode {len(wearedevs_bc)} bytes")
                dc, err = self._run_unluac(wearedevs_bc)
                if dc and self._is_valid_lua(dc):
                    self._log("wearedevs unluac success")
                    return self._beautify(dc), 'wearedevs_unluac', f'WeAreDevs extracted ({len(dc)} chars)', trace
                if err:
                    reasons['wearedevs_unluac'] = err
                    self._log(f"wearedevs unluac fail: {err[:200]}")
                return base64.b64encode(wearedevs_bc).decode('ascii'), 'bytecode', f'WeAreDevs bytecode ({len(wearedevs_bc)}B). unluac: {err}', trace
        except Exception as e:
            self._log(f"wearedevs extractor crash: {e}")
            diags.append(f"wearedevs extractor crashed: {str(e)}")
            reasons['wearedevs_extractor'] = traceback.format_exc()

        # -- Rapid string decode -------------------------------------------
        try:
            result = self._try_rapid_string_decode(source, trace)
            if result:
                bc = self._extract_bytecode(result)
                if bc:
                    dc, err = self._run_unluac(bc)
                    if dc and self._is_valid_lua(dc):
                        return self._beautify(dc), 'rapid_decode_unluac', f'Rapid string decode ({len(dc)} chars)', trace
                    if err: reasons['rapid_decode_unluac'] = err
        except Exception as e:
            self._log(f"rapid decode error: {e}")

        # -- Lifters --------------------------------------------------------
        for lifter in self.lifters:
            lifter_name = lifter.__class__.__name__
            try:
                self._log(f"lifter {lifter_name}")
                decoded_chunks = lifter.lift(source)
                if hasattr(lifter, 'get_diag'):
                    lifter_diag = lifter.get_diag()
                    if lifter_diag:
                        diags.append(f"{lifter_name} found: {lifter_diag}")
                if decoded_chunks:
                    chunk_no_bc = 0
                    chunk_bytes = 0
                    chunk_strs = 0
                    for chunk in decoded_chunks:
                        if isinstance(chunk, bytes):
                            chunk_bytes += 1
                            bc = self.bytecode_harvester.extract(chunk)
                            if bc:
                                dc, err = self._run_unluac(bc)
                                if dc and self._is_valid_lua(dc):
                                    return self._beautify(dc), f'{lifter_name}_unluac', f'{lifter_name} bytecode decompiled ({len(dc)} chars)', trace
                                if err: reasons[f'{lifter_name}_unluac'] = err
                            else:
                                chunk_no_bc += 1
                        elif isinstance(chunk, str):
                            chunk_strs += 1
                            nested_bc = self._extract_bytecode(chunk)
                            if nested_bc:
                                dc, err = self._run_unluac(nested_bc)
                                if dc and self._is_valid_lua(dc):
                                    return self._beautify(dc), f'{lifter_name}_nested_unluac', f'{lifter_name} nested bytecode ({len(dc)} chars)', trace
                                if err: reasons[f'{lifter_name}_nested_unluac'] = err
                            if self._is_valid_lua(chunk) and len(chunk) > 200:
                                rec_result, rec_type, rec_diag, rec_trace = self.process(chunk)
                                if rec_result and rec_type != 'unable':
                                    return rec_result, f'recursive_{rec_type}', f'Recursive {lifter_name}: {rec_diag}', trace + rec_trace
                                if self._is_valid_lua(chunk):
                                    return self._beautify(chunk), f'{lifter_name}_source', f'{lifter_name} source ({len(chunk)} chars)', trace
                            else:
                                chunk_no_bc += 1
                    summary = f"{lifter_name}: {len(decoded_chunks)} chunks ({chunk_bytes}B/{chunk_strs}S), {chunk_no_bc} no bc"
                    diags.append(summary)
                    trace.append({'stage': f'lifter_{lifter_name}', 'total_chunks': len(decoded_chunks), 'bytes': chunk_bytes, 'strs': chunk_strs, 'no_bc': chunk_no_bc})
            except Exception as e:
                self._log(f"lifter {lifter_name} crash: {e}")
                reasons[f'{lifter_name}_error'] = str(e)
                diags.append(f"{lifter_name} crashed: {str(e)[:200]}")

        # -- String decoder --------------------------------------------------
        try:
            all_strings = self.string_decoder.decode_all(source)
            if all_strings:
                trace.append({'stage': 'string_decoder', 'count': len(all_strings)})
                combined = '\n'.join(all_strings)
                if len(combined) > 200 and self._is_valid_lua(combined):
                    return self._beautify(combined), 'string_decode', f'Strings combined ({len(combined)} chars)', trace
                for i, s in enumerate(all_strings):
                    bc = self._extract_bytecode(s)
                    if bc:
                        dc, err = self._run_unluac(bc)
                        if dc and self._is_valid_lua(dc):
                            return self._beautify(dc), 'string_decode_unluac', f'String {i} + unluac ({len(dc)} chars)', trace
                        if err: reasons[f'string_decode_unluac_{i}'] = err
        except Exception as e:
            self._log(f"string_decoder error: {e}")

        # -- Sandbox --------------------------------------------------------
        try:
            self._log("sandbox execution")
            layers, caps, diag = execute_sandbox(source, timeout=120)
            trace.append({'stage': 'sandbox', 'layers': len(layers), 'caps': len(caps), 'diag': diag[:300] if diag else ''})
            if diag: reasons['sandbox'] = diag
            if layers:
                diags.append(f"sandbox: {len(layers)} layers, {len(caps)} caps")
            for i, item in enumerate(layers):
                if isinstance(item, bytes) and len(item) >= 12:
                    bc = self.bytecode_harvester.extract(item)
                    if bc:
                        dc, err = self._run_unluac(bc)
                        if dc and self._is_valid_lua(dc):
                            return self._beautify(dc), 'sandbox_unluac', f'Layer {i} bytecode decompiled ({len(dc)} chars)', trace
                        if err: reasons[f'sandbox_unluac_layer_{i}'] = err
                if isinstance(item, str):
                    bc = self._extract_bytecode(item)
                    if bc:
                        dc, err = self._run_unluac(bc)
                        if dc and self._is_valid_lua(dc):
                            return self._beautify(dc), 'sandbox_unluac', f'Layer {i} string bytecode ({len(dc)} chars)', trace
                        if err: reasons[f'sandbox_unluac_str_{i}'] = err
                    if 'SANDBOX_OUTPUT_START' in item:
                        bc2 = self._extract_bytecode_from_sandbox_output(item)
                        if bc2:
                            dc, err = self._run_unluac(bc2)
                            if dc and self._is_valid_lua(dc):
                                return self._beautify(dc), 'sandbox_scan', f'State scan bytecode ({len(dc)} chars)', trace
                            if err: reasons['sandbox_scan'] = err
                    if len(item) > 100 and self._is_valid_lua(item):
                        return self._beautify(item), 'sandbox_capture', f'Layer {i} source ({len(item)} chars)', trace
            all_text = [c for c in caps if isinstance(c, str) and len(c) > 20]
            if all_text:
                combined = '\n'.join(all_text)
                if len(combined) > 200 and self._is_valid_lua(combined):
                    return self._beautify(combined), 'sandbox_strings', f'Captured {len(all_text)} strings ({len(combined)} chars)', trace
        except Exception as e:
            self._log(f"sandbox error: {e}")
            diags.append(f"sandbox crash: {str(e)}")

        # -- Lune -----------------------------------------------------------
        try:
            lune_data, lune_info = self._run_lune(source)
            trace.append({'stage': 'lune', 'info': lune_info})
            if lune_info.get('error'):
                reasons['lune'] = lune_info['error']
            if lune_data:
                if isinstance(lune_data, bytes) and len(lune_data) >= 12:
                    bc = self.bytecode_harvester.extract(lune_data)
                    if bc:
                        dc, err = self._run_unluac(bc)
                        if dc and self._is_valid_lua(dc):
                            return self._beautify(dc), 'lune_unluac', f'Lune bytecode ({len(dc)} chars)', trace
                        if err: reasons['lune_unluac'] = err
                try:
                    text = lune_data.decode('utf-8', errors='replace')
                    if self._is_valid_lua(text):
                        return self._beautify(text), 'lune_capture', f'Lune source ({len(text)} chars)', trace
                except Exception:
                    pass
        except Exception as e:
            self._log(f"lune error: {e}")

        # -- Deep scan -------------------------------------------------------
        try:
            raw_bytecode = self.bytecode_harvester.deep_scan(source)
            if raw_bytecode:
                bc_hex = binascii.hexlify(raw_bytecode[:32]).decode()
                trace.append({'stage': 'deep_scan', 'bytecode_found': True, 'size': len(raw_bytecode), 'preview': bc_hex})
                dc, err = self._run_unluac(raw_bytecode)
                if dc and self._is_valid_lua(dc):
                    return self._beautify(dc), 'deep_scan_unluac', f'Deep scan bytecode ({len(dc)} chars)', trace
                if err: reasons['deep_scan_unluac'] = err
                return base64.b64encode(raw_bytecode).decode('ascii'), 'bytecode', f'Raw bytecode ({len(raw_bytecode)}B). unluac: {err}', trace
        except Exception as e:
            self._log(f"deep scan error: {e}")

        if reasons:
            reason = '; '.join(f"{k}: {v[:100]}" for k, v in reasons.items())
        elif diag:
            reason = diag
        else:
            reason = f'All stages exhausted ({len(trace)} steps)'
        self._log(f"process: failure - {reason}")
        return '', 'unable', reason, trace

    def _extract_wearedevs_bytecode(self, source, diags):
        self._log("_extract_wearedevs_bytecode: searching")
        m = re.search(r'local R=\{([^}]+)\}', source)
        if not m:
            diags.append("WeAreDevs: no string table")
            self._log("no string table found")
            return None
        table_body = m.group(1)
        strings = re.findall(r'"((?:[^"\\]|\\.)*)"', table_body)
        if len(strings) < 10:
            diags.append(f"WeAreDevs: only {len(strings)} strings")
            self._log(f"only {len(strings)} strings")
            return None
        diags.append(f"WeAreDevs: found {len(strings)} strings")
        self._log(f"found {len(strings)} strings")
        decoded_strings = []
        for s in strings:
            try:
                dec = self._decode_wearedevs_string(s)
                if dec:
                    decoded_strings.append(dec)
            except Exception as e:
                self._log(f"decode string error: {e}")
        if not decoded_strings:
            diags.append("WeAreDevs: no valid strings decoded")
            self._log("no valid strings decoded")
            return None
        diags.append(f"WeAreDevs: decoded {len(decoded_strings)} strings")
        self._log(f"decoded {len(decoded_strings)} strings")
        shuffle_match = re.search(r'for E,l in ipairs\((\{[^}]+\})\)', source)
        shuffle_pairs = []
        if shuffle_match:
            nums = re.findall(r'(-?\d+)', shuffle_match.group(1))
            for i in range(0, len(nums) - 1, 2):
                shuffle_pairs.append((int(nums[i]), int(nums[i+1])))
        diags.append(f"WeAreDevs: {len(shuffle_pairs)} shuffle pairs")
        working = list(decoded_strings)
        for a, b in shuffle_pairs:
            lo, hi = a - 1, b - 1
            if 0 <= lo < len(working) and 0 <= hi < len(working) and lo < hi:
                working[lo:hi+1] = reversed(working[lo:hi+1])
        combined = b''.join(working)
        diags.append(f"WeAreDevs: combined {len(combined)} bytes, hex prefix {binascii.hexlify(combined[:12]).decode()}")
        self._log(f"combined {len(combined)} bytes")
        bc = self.bytecode_harvester.extract(combined)
        if bc:
            self._log(f"bytecode extracted {len(bc)} bytes")
            return bc
        diags.append("WeAreDevs: no Lua signature in combined data")
        self._log("no Lua signature")
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
