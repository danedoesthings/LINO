import re
import base64
import logging

log = logging.getLogger(__name__)

STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _eval_arithmetic(expr):
    """Safely evaluate arithmetic expressions in alphaMap values."""
    expr = re.sub(r'\s+', '', str(expr))
    while True:
        old = expr
        expr = expr.replace('--', '+').replace('+-', '-').replace('-+', '-').replace('++', '+')
        if old == expr:
            break
    while '(' in expr:
        m = re.search(r'\(([^()]+)\)', expr)
        if not m:
            break
        inner = _eval_arithmetic(m.group(1))
        if inner is None:
            return None
        expr = expr[:m.start()] + str(inner) + expr[m.end():]
        while True:
            old = expr
            expr = expr.replace('--', '+').replace('+-', '-').replace('-+', '-').replace('++', '+')
            if old == expr:
                break
    while True:
        m = re.search(r'(-?\d+)\s*([*/%])\s*(-?\d+)', expr)
        if not m:
            break
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        if op == '*':
            res = a * b
        elif op == '/' and b != 0:
            res = int(a / b)
        elif op == '%' and b != 0:
            res = a % b
        else:
            return None
        expr = expr[:m.start()] + str(res) + expr[m.end():]
    tokens = re.findall(r'[+-]?\d+', expr)
    if tokens:
        try:
            return sum(int(t) for t in tokens)
        except ValueError:
            pass
    try:
        return int(expr)
    except ValueError:
        return None


def _decode_decimal_escapes(s):
    """Decode Lua 5.1 decimal escape sequences like \\049 -> '1'."""
    result = []
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s) and s[i + 1] in '0123456789':
            j = i + 1
            digits = ''
            while j < len(s) and len(digits) < 3 and s[j] in '0123456789':
                digits += s[j]
                j += 1
            if digits:
                try:
                    code = int(digits)
                    if 0 <= code <= 255:
                        result.append(chr(code))
                        i = j
                        continue
                except:
                    pass
        result.append(s[i])
        i += 1
    return ''.join(result)


def _balance_braces(source, start_idx):
    depth = 1
    i = start_idx + 1
    while i < len(source) and depth > 0:
        if source[i] == '{':
            depth += 1
        elif source[i] == '}':
            depth -= 1
        i += 1
    return i if depth == 0 else -1


class WeAreDevsDecoder:
    """
    Dedicated decoder for WeAreDevs v1.x obfuscated scripts.
    Handles:
    - Decimal escape sequences in string table (\\ddd)
    - Decimal escape sequences in alphaMap keys (["\\ddd"] = N)
    - Multi-character alphaMap keys (VM variable names)
    - Nested-brace shuffle tables
    - Lua-style swap shuffle (converging pointers)
    """

    def __init__(self, source):
        self.source = source
        self.strings = []
        self.alphabet = {}  # char -> base64_index
        self.shuffle_ops = []
        self.ok = False

    def _extract_strings(self):
        """Extract the EncStr string table with decimal escape decoding."""
        m = re.search(r'local\s+EncStr\s*=\s*\{', self.source)
        if not m:
            # Fallback: find any table with 5+ strings near the top
            m = re.search(r'local\s+\w+\s*=\s*\{', self.source)
        if not m:
            return False
        start = m.end() - 1
        end = _balance_braces(self.source, start)
        if end == -1:
            return False
        body = self.source[start + 1:end - 1]
        raw = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
        if not raw or len(raw) < 3:
            return False
        self.strings = [_decode_decimal_escapes(s) for s in raw]
        return True

    def _extract_alphabet(self):
        """
        Extract alphaMap including:
        - Single char keys: V = 615891+-615871
        - Decimal escape keys: ["\\055"] = 135105-135089
        - Multi-char keys: packArgs = 685299-685257
        """
        # Find alphaMap specifically, or any table with arithmetic assignments
        m = re.search(r'local\s+alphaMap\s*=\s*\{', self.source)
        if not m:
            # Try broader pattern but be careful not to match the whole source
            m = re.search(r'local\s+\w+\s*=\s*\{[^}]{10,500}?\d+\s*[-+]\s*\d+[^}]{0,500}?\}', self.source)
        if not m:
            return False

        start = m.end() - 1
        end = _balance_braces(self.source, start)
        if end == -1:
            return False
        body = self.source[start + 1:end - 1]

        # Only process if body is reasonable size (alphaMap should be < 2000 chars)
        if len(body) > 3000:
            return False

        # Split by comma and semicolon separators
        parts = re.split(r'[,;]', body)

        for part in parts:
            part = part.strip()
            if not part or '=' not in part:
                continue

            # Find first = not inside parentheses
            eq_pos = part.find('=')
            key = part[:eq_pos].strip()
            val_str = part[eq_pos + 1:].strip()

            val = _eval_arithmetic(val_str)
            if val is None or not (0 <= val <= 63):
                continue

            decoded_key = None

            # Check for ["\\ddd"] or ['\\ddd']
            m_esc = re.match(r'\["(\\\d+)"\]', key)
            if m_esc:
                try:
                    code = int(m_esc.group(1)[1:])
                    if 0 <= code <= 255:
                        decoded_key = chr(code)
                except:
                    pass

            if not decoded_key:
                m_esc2 = re.match(r"\['(\\\d+)'\]", key)
                if m_esc2:
                    try:
                        code = int(m_esc2.group(1)[1:])
                        if 0 <= code <= 255:
                            decoded_key = chr(code)
                    except:
                        pass

            # Check for quoted char
            if not decoded_key:
                m_quote = re.match(r'"([A-Za-z0-9+/?])"', key)
                if m_quote:
                    decoded_key = m_quote.group(1)

            if not decoded_key:
                m_quote2 = re.match(r"'([A-Za-z0-9+/?])'", key)
                if m_quote2:
                    decoded_key = m_quote2.group(1)

            # Single unquoted char
            if not decoded_key:
                if re.match(r'^[A-Za-z0-9+/?]$', key):
                    decoded_key = key

            # Multi-char word
            if not decoded_key:
                if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', key) and len(key) > 1:
                    decoded_key = key

            if decoded_key:
                self.alphabet[decoded_key] = val

        return len(self.alphabet) > 0

    def _extract_shuffle(self):
        """Extract shuffle ops from nested-brace ipairs table."""
        ipairs_positions = [m.start() for m in re.finditer(r'ipairs', self.source)]
        for pos in ipairs_positions:
            brace_match = re.search(r'\(\s*\{', self.source[pos:pos + 200])
            if not brace_match:
                continue
            start = pos + brace_match.end() - 1
            end = _balance_braces(self.source, start)
            if end == -1:
                continue
            body = self.source[start + 1:end - 1]
            for pair_match in re.finditer(r'\{([^}]+)\}', body):
                pair_str = pair_match.group(1)
                parts = re.split(r'[;,]', pair_str)
                resolved = [_eval_arithmetic(p.strip()) for p in parts if p.strip()]
                resolved = [n for n in resolved if n is not None]
                if len(resolved) == 2:
                    a, b = resolved
                    if a < b:
                        self.shuffle_ops.append((a, b))
            if self.shuffle_ops:
                break

    def _apply_shuffle(self):
        """Apply Lua-style swap shuffle (converging pointers)."""
        arr = list(self.strings)
        for a, b in self.shuffle_ops:
            lo, hi = a - 1, b - 1  # Convert to 0-indexed
            while lo < hi:
                if 0 <= lo < len(arr) and 0 <= hi < len(arr):
                    arr[lo], arr[hi] = arr[hi], arr[lo]
                lo += 1
                hi -= 1
        self.strings = arr

    def _build_full_alphabet(self):
        """Build complete 64-char alphabet from extracted entries."""
        single_chars = {k: v for k, v in self.alphabet.items() if len(k) == 1}

        if len(single_chars) < 5:
            return None

        chars = [''] * 64
        used_chars = set()
        for ch, idx in single_chars.items():
            chars[idx] = ch
            used_chars.add(ch)

        # Fill missing positions from standard base64
        for i in range(64):
            if not chars[i]:
                for c in STD_ALPHABET:
                    if c not in used_chars:
                        chars[i] = c
                        used_chars.add(c)
                        break

        return ''.join(chars)

    def _decode_with_alphabet(self):
        """Decode strings using the alphaMap."""
        full_alphabet = self._build_full_alphabet()
        if not full_alphabet:
            return self._try_multi_char_decode()

        # Build reverse: encoded_char -> standard_base64_char
        rev = {c: STD_ALPHABET[i] for i, c in enumerate(full_alphabet)}

        decoded = []
        for s in self.strings:
            translated = []
            valid = True
            for c in s:
                if c == '=':
                    translated.append('=')
                elif c in rev:
                    translated.append(rev[c])
                else:
                    # Char not in alphabet - try standard base64 as fallback
                    if c in STD_ALPHABET:
                        translated.append(c)
                    else:
                        valid = False
                        break
            if not valid:
                continue
            t = ''.join(translated)
            pad = (4 - len(t) % 4) % 4
            t += '=' * pad
            try:
                b = base64.b64decode(t)
                text = b.decode('utf-8', errors='replace')
                decoded.append(text)
            except Exception:
                pass
        return decoded

    def _try_multi_char_decode(self):
        """When alphabet is multi-char only, return strings as-is for VM processing."""
        return self.strings

    def _is_lua_source(self, s):
        if len(s) < 20:
            return False
        keywords = ['function', 'local', 'end', 'return', 'if', 'then', 'else', 'while', 'for', 'do']
        count = sum(1 for kw in keywords if kw in s)
        return count >= 2

    def decode(self):
        """Main entry point. Returns decoded Lua source or None."""
        if not self._extract_strings():
            log.debug("WeAreDevs: Failed to extract string table")
            return None
        if not self._extract_alphabet():
            log.debug("WeAreDevs: Failed to extract alphabet")
            return None
        self._extract_shuffle()
        if self.shuffle_ops:
            self._apply_shuffle()

        decoded = self._decode_with_alphabet()

        # Return first valid Lua source
        for s in decoded:
            if self._is_lua_source(s):
                return s

        # Fallback: return longest decoded string if it looks like code
        best = max(decoded, key=len, default='')
        if best and len(best) > 50:
            return best

        # Last resort: return raw string dump for manual analysis
        return '\n'.join(self.strings) if self.strings else None
