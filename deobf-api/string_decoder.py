"""
String table extraction and decoding for Prometheus/WeAreDevs obfuscated Lua.
"""

import re
import base64
import logging

log = logging.getLogger('deobf-api')


def decode_octal_escapes(s: str) -> str:
    """Decode octal escape sequences like \\123 to actual characters."""
    result = []
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            if s[i + 1] == '\\':
                result.append('\\')
                i += 2
                continue
            octal = ''
            j = i + 1
            while j < len(s) and len(octal) < 3 and s[j] in '01234567':
                octal += s[j]
                j += 1
            if octal:
                try:
                    result.append(chr(int(octal, 8)))
                    i = j
                    continue
                except (ValueError, OverflowError):
                    pass
            # Not a valid octal escape, keep the backslash
            result.append(s[i])
            i += 1
        else:
            result.append(s[i])
            i += 1
    return ''.join(result)


def decode_unicode_escapes(s: str) -> str:
    """Decode unicode escape sequences like \\u0041 to actual characters."""
    def replace_hex(match):
        try:
            code = int(match.group(1), 16)
            if code <= 0x10FFFF:
                return chr(code)
            return match.group(0)
        except (ValueError, OverflowError):
            return match.group(0)
    return re.sub(r'\\u([0-9a-fA-F]{4})', replace_hex, s)


def decode_hex_escapes(s: str) -> str:
    """Decode hex escape sequences like \\x41 to actual characters."""
    def replace_hex(match):
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)
    return re.sub(r'\\x([0-9a-fA-F]{2})', replace_hex, s)


def eval_arithmetic(expr: str):
    """Safely evaluate simple arithmetic expressions for alphabet indices."""
    expr = re.sub(r'\s+', '', str(expr))
    expr = re.sub(r'--[^\n]*', '', expr)
    if not expr:
        return None
    if expr.isdigit() or (expr[0] == '-' and expr[1:].isdigit()):
        return int(expr)
    try:
        allowed_names = {"abs": abs, "min": min, "max": max}
        return eval(expr, {"__builtins__": {}}, allowed_names)
    except Exception:
        return None


def extract_alphabet_from_n_table(source: str):
    """Extract the custom base64 alphabet from the N/alphaMap table."""
    patterns = [
        r'local\s+N\s*=\s*\{([^}]+)\}',
        r'local\s+alphaMap\s*=\s*\{([^}]+)\}',
        r'\bN\s*=\s*\{([^}]+)\}',
        r'\balphaMap\s*=\s*\{([^}]+)\}',
        r'local\s+(\w+)\s*=\s*\{\s*(?:\[?["\']?([A-Za-z0-9+/?])["\']?\]?\s*=\s*\d+\s*,?\s*){20,}\}',
    ]

    for pattern in patterns:
        match = re.search(pattern, source, re.DOTALL)
        if match:
            body = match.group(1)
            chars = [''] * 64

            # Pattern: ["char"] = index or char = index
            for m in re.finditer(r'\[\s*["\']([^"\']+)["\']\s*\]\s*=\s*([^,;\n}]+)', body):
                key_char = m.group(1)
                expr = m.group(2)
                val = eval_arithmetic(expr)
                if val is not None and 0 <= val <= 63 and len(key_char) == 1:
                    chars[int(val)] = key_char

            # Pattern: char = index (unquoted key)
            for m in re.finditer(r'([A-Za-z0-9+/])\s*=\s*([^,;\n}]+)', body):
                key_char = m.group(1)
                expr = m.group(2)
                val = eval_arithmetic(expr)
                if val is not None and 0 <= val <= 63:
                    chars[int(val)] = key_char

            # Pattern: [index] = "char"
            for m in re.finditer(r'\[\s*(\d+)\s*\]\s*=\s*["\']([^"\']+)["\']', body):
                idx = int(m.group(1))
                char = m.group(2)
                if 0 <= idx <= 63 and len(char) == 1:
                    chars[idx] = char

            # Pattern: [arith_expr] = "char"
            for m in re.finditer(r'\[\s*([^\]]+)\s*\]\s*=\s*["\']([^"\']+)["\']', body):
                expr = m.group(1)
                char = m.group(2)
                val = eval_arithmetic(expr)
                if val is not None and 0 <= val <= 63 and len(char) == 1:
                    chars[int(val)] = char

            if any(chars):
                # Fill missing positions with standard alphabet characters not yet used
                std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                used = set(c for c in chars if c)
                for i in range(64):
                    if not chars[i]:
                        for c in std:
                            if c not in used:
                                chars[i] = c
                                used.add(c)
                                break
                return ''.join(chars)

    return None


def extract_strings(source: str):
    """Extract the encrypted string table (EncStr/R) from obfuscated Lua."""
    patterns = [
        r'local\s+EncStr\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
        r'local\s+R\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
        r'\bEncStr\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
        r'\bR\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
    ]

    for pattern in patterns:
        match = re.search(pattern, source, re.DOTALL)
        if match:
            body = match.group(1)
            # Extract all double-quoted strings, handling escaped quotes
            strings = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
            if strings and len(strings) >= 2:
                return strings

    return []


def extract_shuffle_ops(source: str):
    """Extract shuffle/reversal operations from ipairs patterns."""
    ops = []
    patterns = [
        r'ipairs\s*\(\s*\{([^}]+)\}\s*\)',
        r'for\s+\w+\s*,\s*\w+\s+in\s+ipairs\s*\(\s*\{([^}]+)\}\s*\)',
    ]

    for pattern in patterns:
        match = re.search(pattern, source)
        if match:
            body = match.group(1)
            # Find pairs like {1, 100}, {2, 99}
            for pair in re.finditer(r'\{(\d+)\s*,\s*(\d+)\}', body):
                try:
                    a = int(pair.group(1))
                    b = int(pair.group(2))
                    if a < b:
                        ops.append((a, b))
                except ValueError:
                    pass
            if ops:
                break

    return ops


def apply_shuffle(strings, ops):
    """Apply reversal operations to the string table."""
    result = list(strings)
    for a, b in ops:
        lo, hi = a - 1, b - 1
        if 0 <= lo < hi < len(result):
            # Reverse the range [lo, hi]
            result[lo:hi + 1] = reversed(result[lo:hi + 1])
    return result


def custom_b64_decode(s, alphabet):
    """Decode a custom base64 string using the provided alphabet."""
    if not alphabet or len(alphabet) != 64:
        return None

    rev = {}
    for i, c in enumerate(alphabet):
        rev[c] = i

    # Validate input characters
    for c in s.rstrip('='):
        if c not in rev:
            return None

    # Translate to standard base64 alphabet
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    translated = []
    for c in s:
        if c != '=':
            translated.append(std[rev[c]])
        else:
            translated.append('=')

    translated_str = ''.join(translated)

    # Add padding if needed
    padding = (4 - len(translated_str) % 4) % 4
    if padding:
        translated_str += '=' * padding

    try:
        return base64.b64decode(translated_str)
    except Exception:
        return None


def is_printable(s: str) -> bool:
    """Check if a string is mostly printable ASCII."""
    if not s:
        return False
    printable = 0
    for c in s:
        if 32 <= ord(c) <= 126 or c in '\n\r\t':
            printable += 1
    return printable / len(s) > 0.7


def is_lua_source(s: str) -> bool:
    """Check if a string looks like valid Lua source code."""
    if len(s) < 20 or not is_printable(s):
        return False
    keywords = ['function', 'local', 'return', 'print', 'if', 'then', 'else', 'end', 'while', 'for', 'do']
    count = 0
    for kw in keywords:
        if kw in s:
            count += 1
    return count >= 2


def get_string_table_offset(source: str) -> int:
    """Detect the offset used in string getter functions."""
    patterns = [
        r'return\s+(\w+)\s*\[\s*\w+\s*\+\s*(\d+)\s*\]',
        r'return\s+(\w+)\s*\[\s*\w+\s*-\s*(\d+)\s*\]',
        r'\+\s*(\d+)\s*\]',
    ]

    for pattern in patterns:
        match = re.search(pattern, source)
        if match:
            groups = match.groups()
            for g in groups:
                if g and g.isdigit():
                    return int(g)

    return 0


class StringTableDecoder:
    """Main decoder class for extracting and decoding obfuscated string tables."""

    def __init__(self, source: str):
        self.source = source
        self.strings = []
        self.alphabet = None
        self.offset = 0
        self.ok = False
        self._decode()

    def _decode(self):
        """Attempt to decode the string table."""
        raw = extract_strings(self.source)
        if not raw:
            return

        # Apply shuffle operations if found
        ops = extract_shuffle_ops(self.source)
        if ops:
            raw = apply_shuffle(raw, ops)

        # Extract custom alphabet
        self.alphabet = extract_alphabet_from_n_table(self.source)

        # Decode each string
        decoded = []
        for s in raw:
            if not s:
                decoded.append('')
                continue

            # Decode escape sequences
            s = decode_unicode_escapes(s)
            s = decode_hex_escapes(s)
            s = decode_octal_escapes(s)

            # Try custom base64 decode if we have an alphabet
            decoded_str = None
            if self.alphabet and len(s) >= 4:
                try:
                    b = custom_b64_decode(s, self.alphabet)
                    if b:
                        try:
                            text = b.decode('utf-8', errors='replace')
                            if is_lua_source(text):
                                decoded_str = text
                        except Exception:
                            pass
                except Exception:
                    pass

            # If not a valid Lua source, keep the original decoded string
            if decoded_str is None:
                if is_printable(s) and len(s) > 1:
                    decoded_str = s
                else:
                    decoded_str = ''

            decoded.append(decoded_str)

        self.strings = decoded
        self.offset = get_string_table_offset(self.source)
        self.ok = len([s for s in self.strings if s]) > 0

    def get_source(self):
        """Return the best candidate for Lua source code from decoded strings."""
        # First pass: find actual Lua source fragments
        for s in self.strings:
            if is_lua_source(s):
                return s

        # Second pass: concatenate printable strings that look like code fragments
        code_keywords = {'function', 'local', 'return', 'if', 'then', 'end', 'while', 'for'}
        fragments = []
        for s in self.strings:
            if is_printable(s) and len(s) > 5:
                # Check if it contains code-like content
                if any(kw in s for kw in code_keywords) or '(' in s or '=' in s:
                    fragments.append(s)

        if fragments:
            return '\n'.join(fragments)

        # Third pass: just return all printable strings
        printable = [s for s in self.strings if is_printable(s) and len(s) > 10]
        if printable:
            return '\n'.join(printable)

        return ''
