import os, re, shutil, subprocess, tempfile, base64, urllib.request, asyncio, struct, hashlib, json, time
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

    def get_capabilities(self):
        return self.capabilities

    def process(self, source):
        trace = []
        fingerprint = self.fingerprinter.analyze(source)
        trace.append({'stage': 'fingerprint', 'findings': fingerprint})

        result = self._try_rapid_string_decode(source, trace)
        if result:
            bc = self._extract_bytecode(result)
            if bc:
                dc, err = self._run_unluac(bc)
                if dc and self._is_valid_lua(dc):
                    return self._beautify(dc), 'rapid_decode_unluac', 'Rapid string decode + unluac', trace

        for lifter in self.lifters:
            lifter_name = lifter.__class__.__name__
            try:
                decoded_chunks = lifter.lift(source)
                if decoded_chunks:
                    trace.append({'stage': f'lifter_{lifter_name}', 'chunks': len(decoded_chunks)})
                    for chunk in decoded_chunks:
                        if isinstance(chunk, bytes):
                            bc = self.bytecode_harvester.extract(chunk)
                            if bc:
                                dc, err = self._run_unluac(bc)
                                if dc and self._is_valid_lua(dc):
                                    return self._beautify(dc), f'{lifter_name}_unluac', f'Decompiled via {lifter_name}', trace
                                trace.append({'stage': f'{lifter_name}_bytecode', 'size': len(bc), 'unluac_error': err})
                        elif isinstance(chunk, str):
                            nested_bc = self._extract_bytecode(chunk)
                            if nested_bc:
                                dc, err = self._run_unluac(nested_bc)
                                if dc and self._is_valid_lua(dc):
                                    return self._beautify(dc), f'{lifter_name}_nested_unluac', f'Nested bytecode decompiled via {lifter_name}', trace
                            if self._is_valid_lua(chunk) and len(chunk) > 200:
                                rec_result, rec_type, rec_diag, rec_trace = self.process(chunk)
                                if rec_result and rec_type != 'unable':
                                    return rec_result, f'recursive_{rec_type}', f'Recursive: {rec_diag}', trace + rec_trace
                                if self._is_valid_lua(chunk):
                                    return self._beautify(chunk), f'{lifter_name}_source', f'Source recovered via {lifter_name}', trace
            except Exception as e:
                trace.append({'stage': f'lifter_{lifter_name}_error', 'error': str(e)})

        all_strings = self.string_decoder.decode_all(source)
        if all_strings:
            trace.append({'stage': 'string_decoder', 'count': len(all_strings)})
            combined = '\n'.join(all_strings)
            if len(combined) > 200 and self._is_valid_lua(combined):
                return self._beautify(combined), 'string_decode', 'Reconstructed from decoded strings', trace
            for s in all_strings:
                bc = self._extract_bytecode(s)
                if bc:
                    dc, err = self._run_unluac(bc)
                    if dc and self._is_valid_lua(dc):
                        return self._beautify(dc), 'string_decode_unluac', 'Bytecode from decoded strings + unluac', trace

        layers, caps, diag = execute_sandbox(source, timeout=120)
        trace.append({'stage': 'sandbox', 'layers': len(layers), 'caps': len(caps), 'diag': diag[:200] if diag else ''})
        if not layers and diag and ('attempt to index local' in diag or 'attempt to index a nil value' in diag):
            wrapped_source = self._wrap_varargs_source(source, diag)
            if wrapped_source:
                layers2, caps2, diag2 = execute_sandbox(wrapped_source, timeout=120)
                if layers2 or caps2:
                    layers.extend(layers2)
                    caps.extend(caps2)
                    diag = diag2 if diag2 else diag
                    trace.append({'stage': 'sandbox_retry_varargs', 'success': True})
                else:
                    trace.append({'stage': 'sandbox_retry_varargs', 'success': False, 'diag': diag2[:200] if diag2 else ''})

        for i, item in enumerate(layers):
            if isinstance(item, bytes) and len(item) >= 12:
                bc = self.bytecode_harvester.extract(item)
                if bc:
                    dc, err = self._run_unluac(bc)
                    if dc and self._is_valid_lua(dc):
                        return self._beautify(dc), 'sandbox_unluac', f'Layer {i} bytecode decompiled', trace
            if isinstance(item, str):
                bc = self._extract_bytecode(item)
                if bc:
                    dc, err = self._run_unluac(bc)
                    if dc and self._is_valid_lua(dc):
                        return self._beautify(dc), 'sandbox_unluac', f'Layer {i} string bytecode decompiled', trace
                if 'SANDBOX_OUTPUT_START' in item:
                    bc2 = self._extract_bytecode_from_sandbox_output(item)
                    if bc2:
                        dc, err = self._run_unluac(bc2)
                        if dc and self._is_valid_lua(dc):
                            return self._beautify(dc), 'sandbox_scan', 'State scan bytecode decompiled', trace
                if len(item) > 100 and self._is_valid_lua(item):
                    return self._beautify(item), 'sandbox_capture', f'Layer {i} source captured', trace

        all_text = [c for c in caps if isinstance(c, str) and len(c) > 20]
        if all_text:
            combined = '\n'.join(all_text)
            if len(combined) > 200 and self._is_valid_lua(combined):
                return self._beautify(combined), 'sandbox_strings', 'Captured strings reconstructed', trace

        lune_data, lune_info = self._run_lune(source)
        trace.append({'stage': 'lune', 'info': lune_info})
        if lune_data:
            if isinstance(lune_data, bytes) and len(lune_data) >= 12:
                bc = self.bytecode_harvester.extract(lune_data)
                if bc:
                    dc, err = self._run_unluac(bc)
                    if dc and self._is_valid_lua(dc):
                        return self._beautify(dc), 'lune_unluac', 'Lune bytecode decompiled', trace
            try:
                text = lune_data.decode('utf-8', errors='replace')
                if self._is_valid_lua(text):
                    return self._beautify(text), 'lune_capture', 'Source captured via Lune', trace
            except Exception:
                pass

        raw_bytecode = self.bytecode_harvester.deep_scan(source)
        if raw_bytecode:
            trace.append({'stage': 'deep_scan', 'bytecode_found': True, 'size': len(raw_bytecode)})
            dc, err = self._run_unluac(raw_bytecode)
            if dc and self._is_valid_lua(dc):
                return self._beautify(dc), 'deep_scan_unluac', 'Deep scan bytecode decompiled', trace
            return base64.b64encode(raw_bytecode).decode('ascii'), 'bytecode', f'Raw bytecode ({len(raw_bytecode)}B). unluac: {err}', trace

        reason = diag or 'All strategies exhausted'
        return '', 'unable', reason, trace

    def _try_rapid_string_decode(self, source, trace):
        patterns = [
            r'local\s+\w+\s*=\s*\{([^}]+)\}',
            r'local\s+\w+\s*=\s*\{\s*([^\}]{50,})\s*\}',
            r'=\s*\{\s*("[^"]{50,}"[,\s]*)+',
        ]
        for pat in patterns:
            matches = re.findall(pat, source, re.DOTALL)
            if matches:
                trace.append({'stage': 'rapid_decode_pattern', 'matches': len(matches)})
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
        except Exception:
            return None, {'error': 'lune_execution_failed'}

    def _run_unluac(self, bytecode):
        if not os.path.isfile(self.unluac_path):
            self._ensure_unluac_jar()
        if not os.path.isfile(self.unluac_path):
            return None, "unluac.jar not found"
        java_bin = shutil.which('java')
        if not java_bin:
            return None, "java not found"
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
                tmp.write(bytecode)
                tmp_path = tmp.name
            result = subprocess.run(
                [java_bin, '-jar', self.unluac_path, '--rawstring', tmp_path],
                capture_output=True, text=True, timeout=45
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout, None
            if result.stderr and 'version' in result.stderr.lower():
                result2 = subprocess.run(
                    [java_bin, '-jar', self.unluac_path, tmp_path],
                    capture_output=True, text=True, timeout=45
                )
                if result2.returncode == 0 and result2.stdout.strip():
                    return result2.stdout, None
                return None, result2.stderr[:300]
            return None, result.stderr[:300] if result.stderr else 'no output'
        except subprocess.TimeoutExpired:
            return None, "timeout"
        except Exception as e:
            return None, str(e)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

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

    def _wrap_varargs_source(self, source, error_msg):
        match = re.search(r"local '(\w+)'", error_msg)
        if not match:
            match = re.search(r"local (\w+) ", error_msg)
        if not match:
            return None
        varname = match.group(1)
        proxy_table_line = f'local {varname} = setmetatable({{}}, {{ __index = function(t, k) if type(k) == "number" then return "" else return rawget(t, k) or "" end end, __newindex = function() end, __call = function() return "" end, __tostring = function() return "" end, __len = function() return 100 end }})'
        pattern = re.compile(rf'local\s+{varname}\s*=\s*\.\.\.', re.DOTALL)
        modified = pattern.sub(proxy_table_line, source, count=1)
        if modified != source:
            return modified
        return None
