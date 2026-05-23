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

        fingerprint = self.fingerprinter.analyze(source)
        trace.append({'stage': 'fingerprint', 'details': fingerprint})

        # Decode the string table to pass as varargs to sandbox
        string_table = self._decode_string_table(source, diags)
        if string_table:
            diags.append(f"decoded {len(string_table)} strings for sandbox")
            layers, caps, diag = execute_sandbox(source, timeout=120, varargs=string_table)
        else:
            layers, caps, diag = execute_sandbox(source, timeout=120)

        trace.append({'stage': 'sandbox', 'layers': len(layers), 'caps': len(caps)})
        if diag:
            reasons['sandbox'] = diag[:300]

        if layers:
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
                            return self._beautify(dc), 'sandbox_unluac', f'Layer {i} bytecode decompiled', trace
                    if len(item) > 100 and self._is_valid_lua(item):
                        return self._beautify(item), 'sandbox_capture', f'Layer {i} source captured', trace

        all_text = [c for c in caps if isinstance(c, str) and len(c) > 20]
        if all_text:
            combined = '\n'.join(all_text)
            if len(combined) > 200 and self._is_valid_lua(combined):
                return self._beautify(combined), 'sandbox_strings', 'Captured strings reconstructed', trace

        # Fallback: try other lifters and decoders
        for lifter in self.lifters:
            try:
                decoded_chunks = lifter.lift(source)
                if decoded_chunks:
                    for chunk in decoded_chunks:
                        if isinstance(chunk, bytes):
                            bc = self.bytecode_harvester.extract(chunk)
                            if bc:
                                dc, err = self._run_unluac(bc)
                                if dc and self._is_valid_lua(dc):
                                    return self._beautify(dc), 'lifter_unluac', 'Lifter bytecode decompiled', trace
                        elif isinstance(chunk, str) and self._is_valid_lua(chunk) and len(chunk) > 200:
                            return self._beautify(chunk), 'lifter_source', 'Lifter source recovered', trace
            except Exception:
                pass

        try:
            all_strings = self.string_decoder.decode_all(source)
            if all_strings:
                combined = '\n'.join(all_strings)
                if len(combined) > 200 and self._is_valid_lua(combined):
                    return self._beautify(combined), 'string_decode', 'String decode', trace
        except Exception:
            pass

        lune_data, lune_info = self._run_lune(source)
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
                    return self._beautify(text), 'lune_capture', 'Lune source', trace
            except Exception:
                pass

        raw_bytecode = self.bytecode_harvester.deep_scan(source)
        if raw_bytecode:
            dc, err = self._run_unluac(raw_bytecode)
            if dc and self._is_valid_lua(dc):
                return self._beautify(dc), 'deep_scan_unluac', 'Deep scan bytecode decompiled', trace

        parts = [f'Steps: {"; ".join(diags[:3])}']
        if reasons:
            parts.append('Info: ' + '; '.join(f"{k}: {v[:100]}" for k, v in reasons.items()))
        reason = '\n'.join(parts)
        return '', 'unable', reason, trace

    def _decode_string_table(self, source, diags):
        m = re.search(r'local R=\{([^}]+)\}', source)
        if not m:
            return None
        table_body = m.group(1)
        strings = re.findall(r'"((?:[^"\\]|\\.)*)"', table_body)
        if len(strings) < 10:
            return None
        return strings

    def _extract_bytecode(self, data):
        if isinstance(data, bytes):
            return self.bytecode_harvester.extract(data)
        if isinstance(data, str):
            if len(data) >= 12 and data[:4] == '\x1bLua' and len(data) > 12:
                return data.encode('latin-1')
            return self.bytecode_harvester.extract(data.encode('latin-1'))
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
