import os, re, shutil, subprocess, tempfile, base64, urllib.request, asyncio, struct, hashlib, json, time, traceback, binascii, sys
from transformers import (
    AdvancedWeAreDevsLifter, MoonSecLifter, IronBrewLifter, PSULifter,
    XORStringDecoder, NumberArrayDecoder, StandardBase64Decoder,
    StringPatternExtractor, BytecodeHarvester
)
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

        # ========== Static WeAreDevs extraction ==========
        try:
            bc = self._static_wearedevs_extract(source, diags)
            if bc:
                trace.append({'stage': 'static_extract', 'bytecode_size': len(bc)})
                dc, err = self._run_unluac(bc)
                if dc and self._is_valid_lua(dc):
                    return self._beautify(dc), 'static_unluac', f'Static extraction + unluac ({len(dc)} chars)', trace
                if err:
                    reasons['static_unluac'] = err
                return base64.b64encode(bc).decode('ascii'), 'bytecode', f'Bytecode ({len(bc)}B). unluac: {err}', trace
        except Exception as e:
            diags.append(f"Static extraction crashed: {str(e)}")
            trace.append({'stage': 'static_extract_error', 'error': str(e)})

        # Fall back to other lifters
        for lifter in self.lifters:
            lifter_name = lifter.__class__.__name__
            try:
                decoded_chunks = lifter.lift(source)
                if decoded_chunks:
                    for chunk in decoded_chunks:
                        if isinstance(chunk, bytes):
                            bc = self.bytecode_harvester.extract(chunk)
                            if bc:
                                dc, err = self._run_unluac(bc)
                                if dc and self._is_valid_lua(dc):
                                    return self._beautify(dc), f'{lifter_name}_unluac', f'{lifter_name} bytecode decompiled', trace
                        elif isinstance(chunk, str) and self._is_valid_lua(chunk) and len(chunk) > 200:
                            return self._beautify(chunk), f'{lifter_name}_source', f'{lifter_name} source recovered', trace
            except Exception as e:
                diags.append(f"{lifter_name} crashed: {str(e)}")

        # Lune
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
            except:
                pass

        # Deep scan
        raw_bytecode = self.bytecode_harvester.deep_scan(source)
        if raw_bytecode:
            dc, err = self._run_unluac(raw_bytecode)
            if dc and self._is_valid_lua(dc):
                return self._beautify(dc), 'deep_scan_unluac', 'Deep scan bytecode decompiled', trace

        parts = [f'Steps: {"; ".join(diags[:3])}']
        if reasons:
            parts.append('Info: ' + '; '.join(f"{k}: {v[:300]}" for k, v in reasons.items()))
        reason = '\n'.join(parts) if parts else 'All stages exhausted'
        return '', 'unable', reason, trace

    # ------------------------------------------------------------------------
    #  Static WeAreDevs extractor
    # ------------------------------------------------------------------------
    def _static_wearedevs_extract(self, source, diags):
        # 1. Extract the R table (hardcoded strings)
        m = re.search(r'local R=\{([^}]+)\}', source)
        if not m:
            diags.append("no R table found")
            return None
        table_body = m.group(1)
        strings = re.findall(r'"((?:[^"\\]|\\.)*)"', table_body)
        if len(strings) < 10:
            diags.append(f"only {len(strings)} strings in R")
            return None
        diags.append(f"R table: {len(strings)} strings")

        # 2. Extract the N table (custom base64 map)
        b64_reverse = self._parse_n_table(source, diags)
        diags.append(f"N table: {len(b64_reverse)} entries")

        # 3. Extract shuffle ranges
        shuffle_pairs = self._parse_shuffle_ranges(source)
        diags.append(f"shuffle ranges: {shuffle_pairs}")

        # 4. Apply shuffle to strings (they are already in order; shuffle reverses ranges)
        working = list(strings)
        for lo, hi in shuffle_pairs:
            lo_idx = lo - 1
            hi_idx = hi - 1
            while lo_idx < hi_idx:
                working[lo_idx], working[hi_idx] = working[hi_idx], working[lo_idx]
                lo_idx += 1
                hi_idx -= 1

        # 5. Decode each string through custom base64
        decoded_chunks = []
        for s in working:
            if not s:
                continue
            # Convert Lua escapes to raw bytes (the string is like "\076\049\117...")
            raw_bytes = self._lua_escapes_to_bytes(s)
            if not raw_bytes:
                continue
            # Decode the raw bytes as custom base64
            decoded = self._decode_custom_b64(raw_bytes, b64_reverse)
            if decoded:
                decoded_chunks.append(decoded)

        if not decoded_chunks:
            diags.append("no chunks survived base64 decode")
            return None
        diags.append(f"decoded {len(decoded_chunks)} chunks")

        # 6. Concatenate and find bytecode
        combined = b''.join(decoded_chunks)
        diags.append(f"combined {len(combined)} bytes, hex: {binascii.hexlify(combined[:16]).decode()}")
        bc = self.bytecode_harvester.extract(combined)
        if bc:
            diags.append(f"bytecode found: {len(bc)} bytes")
            return bc
        diags.append("no bytecode signature in combined data")
        return None

    def _parse_n_table(self, source, diags):
        """Parse the N table and return a reverse map: value -> character."""
        m = re.search(r'local N=\{([^}]+)\}', source)
        if not m:
            return {}
        body = m.group(1)
        reverse = {}

        # String keys: ["\055"]=value  (backslash + up to 3 digits)
        for key_match in re.finditer(r'\["(\\(?:\d{1,3}))"\]\s*=\s*([-\d()+\-*/]+)', body):
            key_str = key_match.group(1)
            val_expr = key_match.group(2)
            val = self._safe_eval(val_expr.strip())
            if val is not None and 0 <= val < 64:
                # key_str is like "\055" → character with code 55
                char_code = self._lua_escape_to_int(key_str)
                if char_code is not None:
                    reverse[val] = chr(char_code)

        # Identifier keys: M=value, V=value, etc.
        for key_match in re.finditer(r'(?<![\["\'])([a-zA-Z])\s*=\s*([-\d()+\-*/]+)', body):
            key_str = key_match.group(1)
            val_expr = key_match.group(2)
            val = self._safe_eval(val_expr.strip())
            if val is not None and 0 <= val < 64:
                reverse[val] = key_str

        # Fill any gaps with standard base64
        std_b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        for i, ch in enumerate(std_b64):
            if i not in reverse:
                reverse[i] = ch

        return reverse

    def _parse_shuffle_ranges(self, source):
        """Parse the shuffle loop to get (start, end) pairs."""
        m = re.search(r'for\s+\w+,\w+\s+in\s+ipairs\s*\(\s*(\{.+?\})\s*\)', source)
        if not m:
            return []
        outer = m.group(1)
        # Inner tables: {expr; expr} or {expr, expr}
        inner = re.findall(r'\{([-\d()+\-*/\s]+)[;,]([-\d()+\-*/\s]+)\}', outer)
        ranges = []
        for e1, e2 in inner:
            lo = self._safe_eval(e1.strip())
            hi = self._safe_eval(e2.strip())
            if lo is not None and hi is not None:
                ranges.append((lo, hi))
        return ranges

    @staticmethod
    def _lua_escapes_to_bytes(s):
        """Convert a Lua string literal like \076\049\117... to raw bytes."""
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

    @staticmethod
    def _lua_escape_to_int(esc):
        """Convert a Lua escape like \055 to an integer."""
        if esc.startswith('\\') and esc[1:].isdigit():
            return int(esc[1:]) % 256
        return None

    @staticmethod
    def _decode_custom_b64(data, reverse_map):
        """Decode bytes using the custom base64 reverse map (value -> char)."""
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

    @staticmethod
    def _safe_eval(expr):
        expr = expr.replace(' ', '')
        if not expr:
            return None
        if not re.match(r'^[\d+\-*/()]+$', expr):
            return None
        try:
            return eval(expr)
        except:
            return None

    # ------------------------------------------------------------------------
    #  Fallback methods (unchanged)
    # ------------------------------------------------------------------------
    def _extract_bytecode(self, data):
        if isinstance(data, bytes):
            return self.bytecode_harvester.extract(data)
        if isinstance(data, str):
            if len(data) >= 12 and data[:4] == '\x1bLua':
                return data.encode('latin-1')
            return self.bytecode_harvester.extract(data.encode('latin-1'))
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
            return None, "unluac timeout"
        except Exception as e:
            return None, str(e)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except:
                    pass

    def _ensure_unluac_jar(self):
        try:
            jar_dir = os.path.dirname(self.unluac_path)
            if jar_dir:
                os.makedirs(jar_dir, exist_ok=True)
            urllib.request.urlretrieve(UNLUAC_JAR_URL, self.unluac_path)
        except:
            pass

    @staticmethod
    def _is_valid_lua(code):
        if not code or len(code) < 50:
            return False
        lines = code.split('\n')
        if len(lines) > 5:
            proxy_pattern = re.compile(r'^\s*[\w.]+ = [A-Z]\w+$')
            if sum(1 for l in lines if proxy_pattern.match(l.strip())) > len(lines) * 0.4:
                return False
        words = set(re.findall(r'\b\w+\b', code[:10000]))
        if len(words & LUA_KEYWORDS) < 5:
            return False
        if not ('function' in words and 'end' in words or 'local' in words):
            return False
        printable = sum(1 for c in code if c.isprintable() or c in '\n\r\t')
        return (printable / max(len(code), 1)) >= 0.70

    def _beautify(self, code):
        try:
            from luaparser import ast
            return ast.to_lua_source(ast.parse(code))
        except:
            out, ind = [], 0
            for raw in code.split('\n'):
                line = raw.strip()
                if not line:
                    out.append('')
                    continue
                if any(line.startswith(w) for w in ('end', 'else', 'elseif', 'until')):
                    ind = max(0, ind - 1)
                out.append('    ' * ind + line)
                if any(line.startswith(w) for w in ('if ', 'for ', 'while ', 'function ', 'local function ', 'do', 'repeat')) and not line.rstrip().endswith('end'):
                    ind += 1
            return '\n'.join(out)
