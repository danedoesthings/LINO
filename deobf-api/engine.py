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

        if string_table:
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

            safe_for_sandbox = all(
                all(c.isprintable() or c in '\n\r\t\\' for c in s)
                for s in string_table
            )
            if safe_for_sandbox:
                layers, caps, diag = execute_sandbox(source, timeout=120, varargs=string_table)
                trace.append({'stage': 'sandbox', 'layers': len(layers), 'caps': len(caps)})
                if diag:
                    reasons['sandbox'] = self._sanitize_diag(diag[:2000])
                if layers:
                    for i, item in enumerate(layers):
                        result = self._process_layer(item, i, string_table, var_name)
                        if result:
                            return result, 'sandbox_source', f'Layer {i} source captured', trace
        else:
            layers, caps, diag = execute_sandbox(source, timeout=120)
            trace.append({'stage': 'sandbox', 'layers': len(layers)})
            if layers:
                for i, item in enumerate(layers):
                    result = self._process_layer(item, i, None, None)
                    if result:
                        return result, 'sandbox_source', f'Layer {i} source captured', trace

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
                        elif isinstance(chunk, str) and len(chunk) > 5 and self._has_lua_keywords(chunk):
                            return self._beautify(chunk), 'lifter_source', f'Lifter source ({len(chunk)} chars)', trace
            except:
                pass

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

    # FIX 1: Use a balanced-brace extractor instead of [^}]+ regex,
    # which failed entirely on string tables containing nested table values.
    @staticmethod
    def _extract_balanced_table(source, start):
        """Extract the body of a Lua table starting at the '{' at position start."""
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

    def _decode_string_table(self, source, diags):
        # FIX 1 (continued): Use _extract_balanced_table instead of [^}]+
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

    def _static_wearedevs_extract(self, source, diags, string_table=None, var_name=None):
        # FIX 1 (continued): Same balanced-table fix here
        m = re.search(r'local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{', source, re.DOTALL)
        if not m:
            return None
        brace_start = m.end() - 1
        body = self._extract_balanced_table(source, brace_start)
        if not body:
            return None
        strings = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
        if len(strings) < 10:
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
                return bc

            for enc in ('utf-8', 'latin-1'):
                try:
                    text = combined.decode(enc)
                    if self._has_lua_keywords(text):
                        if string_table and var_name:
                            text = self._substitute_strings(text, string_table, var_name)
                        return text
                except:
                    pass
            return None

        result = try_decode(shuffle, "orig")
        if result:
            return result
        result = try_decode(list(reversed(shuffle)), "rev")
        if result:
            return result
        return None

    @staticmethod
    def _has_lua_keywords(text):
        if not text or len(text) < 5:
            return False
        printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        if (printable / len(text)) < 0.50:
            return False
        lower_text = text.lower()
        # FIX 2: Threshold raised from 1 to 2 — a single keyword match
        # caused binary garbage to pass as valid Lua. Require at least 2
        # distinct keyword matches before treating the content as Lua source.
        count = 0
        for kw in LUA_SUBSTRINGS:
            if kw in lower_text:
                count += 1
                if count >= 2:
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

        code = ''.join(ch for ch in code if ch.isprintable() or ch in '\n\r\t')
        if len(code) < 5:
            return code

        # Protect string literals so keyword regex doesn't mangle their contents
        string_pattern = re.compile(
            r"""(?:'[^']*')|(?:"[^"]*")|(?:\[=*\[.*?\]=*\])""",
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

        # FIX 3: 'then' and 'do' are NOT given their own lines.
        # The original code naively newlined ALL keywords including 'then' and
        # 'do', which tore control-structure headers apart (e.g. "if x\nthen").
        # Only true statement-starters and block-enders go on their own lines.
        # 'then' and 'do' must remain on the same line as their opener so the
        # indentation counter can correctly associate them with the opener.
        stmt_keywords = [
            'function', 'local', 'if', 'for', 'while',
            'repeat', 'return', 'end', 'else', 'elseif', 'until',
        ]
        # Protect 'local function' so the 'local' split doesn't orphan 'function'
        code = re.sub(r'(?<![A-Za-z0-9_])local\s+function(?![A-Za-z0-9_])', '__LOCALFUNC__', code)
        for kw in stmt_keywords:
            code = re.sub(
                rf'(?<![A-Za-z0-9_]){re.escape(kw)}(?![A-Za-z0-9_])',
                f'\n{kw}',
                code
            )
        code = code.replace('__LOCALFUNC__', '\nlocal function')

        # Restore string literals before indentation pass
        for placeholder, original in placeholders.items():
            code = code.replace(placeholder, original)

        code = re.sub(r'\n\s*\n', '\n\n', code)

        # FIX 4: Correct indentation counting.
        # The original code counted every occurrence of 'function', 'if', 'for',
        # 'while', 'repeat', 'do', 'then' as block openers — so "if x then"
        # counted as +2 when it should be +1. The correct rule:
        #
        #   Block openers (indent increases AFTER the line):
        #     'then', 'do', 'function', 'repeat'
        #   Block closers (indent decreases BEFORE the line):
        #     'end', 'until'
        #   Mid-block markers (decrease before, increase after):
        #     'else', 'elseif'
        #
        # 'if', 'for', 'while' are NOT openers by themselves — their companion
        # 'then'/'do' on the same line is what opens the block.
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

    # FIX 5: _parse_n_table no longer requires the variable to be named exactly
    # 'N'. The original hardcoded `local N=` regex silently returned an empty
    # map for any obfuscator that used a different variable name, causing every
    # subsequent base64 decode to use the standard alphabet (almost always wrong).
    # Now all short-named local tables are scanned and the one that contains
    # base64-map-like entries (>= 30 mapped values) is used.
    def _parse_n_table(self, source):
        best_rev = {}
        for m in re.finditer(r'local\s+\w{1,4}\s*=\s*\{([^}]{10,})\}', source):
            body = m.group(1)
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
        # Fill any missing positions with standard base64 alphabet
        std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        for i, ch in enumerate(std):
            if i not in best_rev:
                best_rev[i] = ch
        return best_rev

    # FIX 6: _parse_shuffle_ranges had two problems:
    #   (a) The outer regex used non-greedy .+? inside braces, stopping too early
    #       on any obfuscated code with nested constructs.
    #   (b) It required two loop variables (\w+,\w+) but many loops use a
    #       single variable or underscore (_,v style).
    # The fix uses a simpler, more targeted pattern that reliably captures the
    # numeric pair arrays regardless of loop variable naming.
    def _parse_shuffle_ranges(self, source):
        ranges = []
        # Pattern: ipairs({...}) where the table contains numeric pair sub-tables
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

    # FIX 7: _lua_escapes_to_bytes previously only handled \NNN decimal escapes
    # and silently discarded all other escape sequences (\n, \t, \\, \", \x, etc.).
    # Any string containing those escapes would produce truncated or wrong bytes,
    # causing the base64 decode to fail or produce garbage. All standard Lua
    # escape sequences are now handled correctly.
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
