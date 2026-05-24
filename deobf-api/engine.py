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

        result = self._static_wearedevs_extract(source, diags)
        if result:
            if isinstance(result, bytes):
                trace.append({'stage': 'static_extract', 'bytecode_size': len(result)})
                dc, err = self._run_unluac(result)
                if dc and self._is_valid_lua(dc):
                    return self._beautify(dc), 'static_unluac', f'Decompiled ({len(dc)} chars)', trace
                if err:
                    reasons['unluac'] = err
                return base64.b64encode(result).decode('ascii'), 'bytecode', f'Bytecode ({len(result)}B)', trace
            else:
                return self._beautify(result), 'static_source', f'Source recovered ({len(result)} chars)', trace

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

    def _static_wearedevs_extract(self, source, diags):
        m = re.search(r'local R=\{([^}]+)\}', source)
        if not m:
            diags.append("no R table")
            return None
        strings = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))
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
                if not s: continue
                raw = self._lua_escapes_to_bytes(s)
                if not raw: continue
                dec = self._decode_custom_b64(raw, b64_rev)
                if dec: decoded.append(dec)
            if not decoded:
                return None
            combined = b''.join(decoded)
            hex_pre = binascii.hexlify(combined[:16]).decode()

            bc = self.bytecode_harvester.extract(combined)
            if bc:
                diags.append(f"bc ({len(bc)}B) [{label}]")
                return bc

            for enc in ('utf-8', 'latin-1'):
                try:
                    text = combined.decode(enc)
                    if self._is_likely_lua(text):
                        diags.append(f"source ({len(text)} chars) [{label}]")
                        return text
                except:
                    pass

            diags.append(f"no bc/source [{label}] hex={hex_pre}")
            return None

        result = try_decode(shuffle, "orig")
        if result: return result
        result = try_decode(list(reversed(shuffle)), "rev")
        if result: return result
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

    # --------------- Beautification for minified Lua ---------------
    def _beautify(self, code):
        # First, try luaparser
        try:
            from luaparser import ast
            return ast.to_lua_source(ast.parse(code))
        except:
            pass

        # Clean non-printable garbage (keep printable ASCII, newline, tab)
        cleaned = []
        for ch in code:
            if ch.isprintable() or ch in '\n\r\t':
                cleaned.append(ch)
        code = ''.join(cleaned)

        # If empty or tiny, return as-is
        if len(code) < 5:
            return code

        # Token-based formatting for minified Lua
        # Insert a newline before common keywords
        keywords = r'\b(function|local|if|for|while|repeat|return|end|else|elseif|until|do|then)\b'
        # Add newline before each keyword
        code = re.sub(keywords, r'\n\1', code)

        # Insert space after commas and semicolons
        code = re.sub(r',([^\s])', r', \1', code)
        code = re.sub(r';([^\s])', r'; \1', code)

        # Insert space around operators if adjacent to identifiers
        code = re.sub(r'(\w)([=+\-*/<>])', r'\1 \2', code)
        code = re.sub(r'([=+\-*/<>])(\w)', r'\1 \2', code)

        # Indent based on keywords
        lines = code.split('\n')
        out = []
        indent = 0
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            # Decrease indent for closing keywords
            if any(stripped.startswith(w) for w in ('end', 'else', 'elseif', 'until')):
                indent = max(0, indent - 1)
            out.append('    ' * indent + stripped)
            # Increase indent for opening keywords
            if any(stripped.startswith(w) for w in ('function', 'local function', 'if', 'for', 'while', 'repeat', 'do')):
                indent += 1
        return '\n'.join(out)

    # --------------- Parsing helpers (unchanged) ---------------
    def _parse_n_table(self, source):
        m = re.search(r'local N=\{([^}]+)\}', source)
        if not m: return {}
        body = m.group(1)
        rev = {}
        for m2 in re.finditer(r'\["(\\(?:\d{1,3}))"\]\s*=\s*([-\d()+\-*/]+)', body):
            esc = m2.group(1)
            val = self._safe_eval(m2.group(2).strip())
            if val is not None and 0 <= val < 64:
                code = self._lua_escape_to_int(esc)
                if code is not None: rev[val] = chr(code)
        for m2 in re.finditer(r'(?<![\["\'])([a-zA-Z])\s*=\s*([-\d()+\-*/]+)', body):
            ch = m2.group(1)
            val = self._safe_eval(m2.group(2).strip())
            if val is not None and 0 <= val < 64: rev[val] = ch
        std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        for i, ch in enumerate(std):
            if i not in rev: rev[i] = ch
        return rev

    def _parse_shuffle_ranges(self, source):
        m = re.search(r'for\s+\w+,\w+\s+in\s+ipairs\s*\(\s*(\{.+?\})\s*\)', source)
        if not m: return []
        outer = m.group(1)
        inner = re.findall(r'\{([-\d()+\-*/\s]+)[;,]([-\d()+\-*/\s]+)\}', outer)
        ranges = []
        for e1, e2 in inner:
            lo = self._safe_eval(e1.strip())
            hi = self._safe_eval(e2.strip())
            if lo is not None and hi is not None: ranges.append((lo, hi))
        return ranges

    @staticmethod
    def _lua_escapes_to_bytes(s):
        result = bytearray()
        i = 0
        while i < len(s):
            if s[i] == '\\' and i+1 < len(s) and s[i+1].isdigit():
                j = i+1
                while j < len(s) and s[j].isdigit() and j-i < 4: j += 1
                try:
                    v = int(s[i+1:j])
                    if 0 <= v <= 255: result.append(v)
                except: pass
                i = j
            else: i += 1
        return bytes(result)

    @staticmethod
    def _lua_escape_to_int(esc):
        if esc.startswith('\\') and esc[1:].isdigit():
            return int(esc[1:]) % 256
        return None

    @staticmethod
    def _decode_custom_b64(data, rev):
        if not rev or len(data)==0: return None
        fwd = {v:k for k,v in rev.items()}
        buf, bits, out = 0, 0, bytearray()
        for b in data:
            ch = chr(b) if b < 256 else ''
            if ch not in fwd:
                if b == ord('='): break
                continue
            buf = (buf << 6) | fwd[ch]
            bits += 6
            while bits >= 8:
                bits -= 8
                out.append((buf >> bits) & 0xFF)
        return bytes(out)

    @staticmethod
    def _safe_eval(expr):
        expr = expr.replace(' ','')
        if not expr or not re.match(r'^[\d+\-*/()]+$', expr): return None
        try: return eval(expr)
        except: return None

    def _run_lune(self, source):
        try:
            try: loop = asyncio.get_event_loop()
            except: loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
            return loop.run_until_complete(execute_and_capture(source))
        except: return None, {}

    def _run_unluac(self, bytecode):
        if not self._java_available: return None, "no java"
        if not os.path.isfile(self.unluac_path): self._ensure_unluac_jar()
        if not os.path.isfile(self.unluac_path): return None, "no unluac.jar"
        with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
            tmp.write(bytecode)
            tmp_path = tmp.name
        try:
            r = subprocess.run(['java','-jar',self.unluac_path,'--rawstring',tmp_path], capture_output=True, text=True, timeout=30)
            if r.returncode==0 and r.stdout.strip(): return r.stdout, None
            if r.stderr and 'version' in r.stderr.lower():
                r2 = subprocess.run(['java','-jar',self.unluac_path,tmp_path], capture_output=True, text=True, timeout=30)
                if r2.returncode==0 and r2.stdout.strip(): return r2.stdout, None
                return None, r2.stderr[:300]
            return None, r.stderr[:200] if r.stderr else 'no output'
        except subprocess.TimeoutExpired: return None, "timeout"
        except Exception as e: return None, str(e)
        finally:
            if os.path.exists(tmp_path):
                try: os.unlink(tmp_path)
                except: pass

    def _ensure_unluac_jar(self):
        try:
            os.makedirs(os.path.dirname(self.unluac_path), exist_ok=True)
            urllib.request.urlretrieve(UNLUAC_JAR_URL, self.unluac_path)
        except: pass

    @staticmethod
    def _is_valid_lua(code):
        if not code or len(code) < 50: return False
        words = set(re.findall(r'\b\w+\b', code[:10000]))
        if len(words & LUA_KEYWORDS) < 5: return False
        if not ('function' in words and 'end' in words or 'local' in words): return False
        printable = sum(1 for c in code if c.isprintable() or c in '\n\r\t')
        return (printable / max(len(code),1)) >= 0.70
