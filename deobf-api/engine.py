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

        string_table, var_name = self._decode_string_table(source, diags)

        layers, caps, diag = execute_sandbox(source, timeout=120, varargs=string_table if string_table else None)
        trace.append({'stage': 'sandbox', 'layers': len(layers), 'caps': len(caps)})
        if diag:
            reasons['sandbox'] = self._sanitize_diag(diag[:2000])

        if layers:
            for i, item in enumerate(layers):
                result = self._process_layer(item, i, string_table, var_name)
                if result:
                    return result, 'sandbox_source', f'Layer {i} source captured', trace

        if string_table and not layers:
            result = self._static_wearedevs_extract(source, diags, string_table, var_name)
            if result:
                if isinstance(result, bytes):
                    dc, err = self._run_unluac(result)
                    if dc and self._is_valid_lua(dc):
                        return self._beautify(dc), 'static_unluac', f'Static decompile ({len(dc)} chars)', trace
                    return base64.b64encode(result).decode('ascii'), 'bytecode', f'Bytecode ({len(result)}B)', trace
                else:
                    beautified = self._beautify(result)
                    if string_table and var_name:
                        beautified = self._substitute_strings(beautified, string_table, var_name)
                    return beautified, 'static_source', f'Static source ({len(result)} chars)', trace

        for lifter in self.lifters:
            try:
                chunks = lifter.lift(source)
                if chunks:
                    for chunk in chunks:
                        if isinstance(chunk, bytes):
                            bc = self.bytecode_harvester.extract(chunk)
                            if bc:
                                dc, err = self._run_unluac(bc)
                                if dc and self._is_valid_lua(dc):
                                    return self._beautify(dc), 'lifter_unluac', f'Lifter ({len(dc)} chars)', trace
                        elif isinstance(chunk, str) and len(chunk) > 5 and self._is_likely_lua(chunk):
                            return self._beautify(chunk), 'lifter_source', f'Lifter source ({len(chunk)} chars)', trace
            except:
                pass

        lune_data, _ = self._run_lune(source)
        if lune_data and isinstance(lune_data, bytes) and len(lune_data) >= 12:
            bc = self.bytecode_harvester.extract(lune_data)
            if bc:
                dc, err = self._run_unluac(bc)
                if dc and self._is_valid_lua(dc):
                    return self._beautify(dc), 'lune_unluac', f'Lune ({len(dc)} chars)', trace

        raw_bc = self.bytecode_harvester.deep_scan(source)
        if raw_bc:
            dc, err = self._run_unluac(raw_bc)
            if dc and self._is_valid_lua(dc):
                return self._beautify(dc), 'deep_scan_unluac', f'Deep scan ({len(dc)} chars)', trace

        parts = [f'Steps: {"; ".join(diags[:3])}']
        if reasons:
            parts.append('Info: ' + '; '.join(f"{k}: {v[:300]}" for k, v in reasons.items()))
        reason = '\n'.join(parts) if parts else 'All stages exhausted'
        return '', 'unable', reason, trace

    def _sanitize_diag(self, text):
        return ''.join(c for c in text if c.isprintable() or c in '\n\t')

    def _process_layer(self, item, i, string_table, var_name):
        if isinstance(item, bytes) and len(item) >= 12:
            text = None
            try:
                text = item.decode('utf-8')
            except:
                pass
            if text and self._is_valid_lua(text):
                beautified = self._beautify(text)
                if string_table and var_name:
                    beautified = self._substitute_strings(beautified, string_table, var_name)
                return beautified
            bc = self.bytecode_harvester.extract(item)
            if bc:
                dc, err = self._run_unluac(bc)
                if dc and self._is_valid_lua(dc):
                    beautified = self._beautify(dc)
                    if string_table and var_name:
                        beautified = self._substitute_strings(beautified, string_table, var_name)
                    return beautified
        if isinstance(item, str) and len(item) > 100 and self._is_valid_lua(item):
            beautified = self._beautify(item)
            if string_table and var_name:
                beautified = self._substitute_strings(beautified, string_table, var_name)
            return beautified
        return None

    def _substitute_strings(self, code, string_table, var_name='R'):
        if not string_table or not code:
            return code

        def replacer(m):
            try:
                idx = int(m.group(1)) - 1
                if 0 <= idx < len(string_table):
                    val = string_table[idx]
                    val = val.replace('\\', '\\\\').replace('"', '\\"')
                    return f'"{val}"'
            except:
                pass
            return m.group(0)

        code = re.sub(rf'\b{re.escape(var_name)}\s*[\(\[]\s*(-?\d+)\s*[\)\]]', replacer, code)
        return code

    def _decode_string_table(self, source, diags):
        m = re.search(r'local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{([^}]+)\}', source, re.DOTALL)
        if not m:
            assignments = re.findall(r'([A-Za-z_][A-Za-z0-9_]*)\[(\d+)\]\s*=\s*"((?:[^"\\]|\\.)*)"', source)
            if len(assignments) >= 10:
                var_names = set(a[0] for a in assignments)
                if len(var_names) == 1:
                    var_name = var_names.pop()
                    max_idx = max(int(a[1]) for a in assignments)
                    strings = [''] * (max_idx + 1)
                    for vn, idx_str, val in assignments:
                        if vn == var_name:
                            strings[int(idx_str)] = val
                    return strings, var_name
            return None, None
        var_name = m.group(1)
        body = m.group(2)
        strings = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
        if len(strings) < 10:
            return None, None
        return strings, var_name

    def _static_wearedevs_extract(self, source, diags, string_table=None, var_name=None):
        m = re.search(r'local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{([^}]+)\}', source, re.DOTALL)
        if not m:
            diags.append("no R table")
            return None
        strings = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(2))
        if len(strings) < 10:
            diags.append(f"R table too small ({len(strings)})")
            return None

        b64_rev = self._parse_n_table(source)
        shuffle = self._parse_shuffle_ranges(source)
        diags.append(f"R={len(strings)} N={len(b64_rev)} shuff={len(shuffle)}")

        def try_decode(pairs, label):
            working = list(strings)
            for lo, hi in pairs:
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

            bc = self.bytecode_harvester.extract(combined)
            if bc:
                diags.append(f"bc ({len(bc)}B) [{label}]")
                return bc

            for enc in ('utf-8', 'latin-1'):
                try:
                    text = combined.decode(enc)
                    if self._is_likely_lua(text):
                        diags.append(f"source ({len(text)} chars) [{label}]")
                        if string_table and var_name:
                            text = self._substitute_strings(text, string_table, var_name)
                        return text
                except:
                    pass

            diags.append(f"no bc/source [{label}]")
            return None

        result = try_decode(shuffle, "orig")
        if result:
            return result
        result = try_decode(list(reversed(shuffle)), "rev")
        if result:
            return result
        return None

    @staticmethod
    def _is_likely_lua(text):
        if not text or len(text) < 5:
            return False
        printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        if (printable / len(text)) < 0.70:
            return False
        lower_text = text.lower()
        for kw in LUA_SUBSTRINGS:
            if kw in lower_text:
                return True
        return False

    def _beautify(self, code):
        if not code or len(code) < 5:
            return code

        stylua = shutil.which('stylua')
        if stylua:
            try:
                r = subprocess.run(
                    [stylua, '--indent-type', 'Spaces', '--indent-width', '4', '--line-endings', 'Unix', '-'],
                    input=code, capture_output=True, text=True, timeout=10
                )
                if r.returncode == 0 and r.stdout.strip():
                    return r.stdout
            except:
                pass

        try:
            from luaparser import ast
            return ast.to_lua_source(ast.parse(code))
        except:
            pass

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

        code = re.sub(r'(?<!\blocal )\bfunction\b', '\nfunction', code)
        for kw in ['local', 'if', 'for', 'while', 'repeat', 'return', 'do', 'end',
                    'else', 'elseif', 'until', 'then']:
            if kw == 'function':
                continue
            code = re.sub(rf'\b{kw}\b', f'\n{kw}', code)

        for placeholder, original in placeholders.items():
            code = code.replace(placeholder, original)

        code = re.sub(r'\n\s*\n', '\n\n', code)

        lines = code.split('\n')
        out_lines = []
        indent = 0

        open_kw = {'function', 'if', 'for', 'while', 'repeat', 'do', 'then'}
        close_kw = {'end', 'until', 'else', 'elseif'}

        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                out_lines.append('')
                continue

            first_word = line.split()[0] if line.split() else ''
            if first_word in close_kw:
                indent = max(0, indent - 1)

            out_lines.append('    ' * indent + line)

            opens = len(re.findall(
                r'\b(function|if|for|while|repeat|do|then)\b', line))
            closes = len(re.findall(r'\b(end|until)\b', line))
            indent += opens - closes
            if first_word in ('else', 'elseif'):
                indent += 1

            indent = max(0, indent)

        return '\n'.join(out_lines)

    def _parse_n_table(self, source):
        m = re.search(r'local N=\{([^}]+)\}', source)
        if not m:
            return {}
        body = m.group(1)
        rev = {}
        for m2 in re.finditer(r'\["(\\(?:\d{1,3}))"\]\s*=\s*([-\d()+\-*/]+)', body):
            esc = m2.group(1)
            val = self._safe_eval(m2.group(2).strip())
            if val is not None and 0 <= val < 64:
                code = self._lua_escape_to_int(esc)
                if code is not None:
                    rev[val] = chr(code)
        for m2 in re.finditer(r'(?<![\["\'])([a-zA-Z])\s*=\s*([-\d()+\-*/]+)', body):
            ch = m2.group(1)
            val = self._safe_eval(m2.group(2).strip())
            if val is not None and 0 <= val < 64:
                rev[val] = ch
        std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        for i, ch in enumerate(std):
            if i not in rev:
                rev[i] = ch
        return rev

    def _parse_shuffle_ranges(self, source):
        m = re.search(r'for\s+\w+,\w+\s+in\s+ipairs\s*\(\s*(\{.+?\})\s*\)', source)
        if not m:
            return []
        outer = m.group(1)
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
        result = bytearray()
        i = 0
        while i < len(s):
            if s[i] == '\\' and i + 1 < len(s) and s[i + 1].isdigit():
                j = i + 1
                while j < len(s) and s[j].isdigit() and j - i < 4:
                    j += 1
                try:
                    v = int(s[i + 1:j])
                    if 0 <= v <= 255:
                        result.append(v)
                except:
                    pass
                i = j
            else:
                i += 1
        return bytes(result)

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
        lines = code.split('\n')
        if len(lines) > 5:
            proxy_pattern = re.compile(r'^\s*[\w.]+ = [A-Z]\w+$')
            if sum(1 for l in lines if proxy_pattern.match(l.strip())) > len(lines) * 0.4:
                return False
        words = set(re.findall(r'\b\w+\b', code[:10000]))
        threshold = max(2, min(5, len(code) // 500))
        if len(words & LUA_KEYWORDS) < threshold:
            return False
        if not ('function' in words and 'end' in words or 'local' in words):
            return False
        printable = sum(1 for c in code if c.isprintable() or c in '\n\r\t')
        return (printable / max(len(code), 1)) >= 0.70
