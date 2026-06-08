import re
import base64
import logging

log = logging.getLogger(__name__)

def decode_octal_escapes(s: str) -> str:
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
            result.append(s[i])
            i += 1
        else:
            result.append(s[i])
            i += 1
    return ''.join(result)

def decode_unicode_escapes(s: str) -> str:
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
    def replace_hex(match):
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)
    return re.sub(r'\\x([0-9a-fA-F]{2})', replace_hex, s)

def eval_arithmetic(expr: str):
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

def extract_alphabet_enhanced(source: str):
    """Find any 64-char alphabet mapping regardless of variable name."""
    chars = [''] * 64
    found = False

    # Named tables first
    named = [
        r'local\s+(?:N|alphaMap)\s*=\s*\{([^}]+)\}',
        r'\b(?:N|alphaMap)\s*=\s*\{([^}]+)\}',
    ]
    for pat in named:
        m = re.search(pat, source, re.DOTALL)
        if m:
            body = m.group(1)
            for ch, idx in re.findall(r'["\']([A-Za-z0-9+/?])["\']\s*=\s*(\d+)', body):
                v = int(idx)
                if 0 <= v < 64:
                    chars[v] = ch
                    found = True
            for idx, ch in re.findall(r'\[(\d+)\]\s*=\s*["\']([A-Za-z0-9+/?])["\']', body):
                v = int(idx)
                if 0 <= v < 64:
                    chars[v] = ch
                    found = True
            for ch, idx in re.findall(r'([A-Za-z0-9+/?])\s*=\s*(\d+)', body):
                v = int(idx)
                if 0 <= v < 64 and len(ch) == 1:
                    chars[v] = ch
                    found = True
            if found:
                break

    # Generic fallback: any table with 10+ char->index mappings
    if not found:
        gen = r'(?:local\s+)?(\w+)\s*=\s*\{((?:[^}]|\}(?=[,;]))*)\}'
        for m in re.finditer(gen, source, re.DOTALL):
            body = m.group(2)
            mappings = re.findall(r'["\']([A-Za-z0-9+/?])["\']\s*=\s*(\d+)', body)
            if len(mappings) >= 10:
                for ch, idx in mappings:
                    v = int(idx)
                    if 0 <= v < 64:
                        chars[v] = ch
                        found = True
                if found:
                    break

    if found:
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

def extract_strings_enhanced(source: str):
    """Find string tables by known name, then by content (any table with 5+ base64 strings)."""
    # Priority 1: known WeAreDevs names
    patterns = [
        r'local\s+EncStr\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
        r'local\s+R\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
        r'local\s+Y\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
        r'\bEncStr\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
        r'\bR\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
        r'\bY\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
    ]
    for pat in patterns:
        m = re.search(pat, source, re.DOTALL)
        if m:
            body = m.group(1)
            strings = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
            if strings and len(strings) >= 2:
                return strings, m.group(0)

    # Priority 2: generic detection
    best = None
    best_score = 0
    gen = r'(?:local\s+)?(\w+)\s*=\s*\{((?:[^}]|\}(?=[,;]))*)\}'
    for m in re.finditer(gen, source, re.DOTALL):
        body = m.group(2)
        strings = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
        score = sum(1 for s in strings if len(s) >= 4 and re.match(r'^[A-Za-z0-9+/=]+$', s))
        if score >= 5 and score > best_score:
            best_score = score
            best = strings
    if best:
        return best, None
    return [], None

def extract_shuffle_ops(source: str):
    ops = []
    patterns = [
        r'ipairs\s*\(\s*\{([^}]+)\}\s*\)',
        r'for\s+\w+\s*,\s*\w+\s+in\s+ipairs\s*\(\s*\{([^}]+)\}\s*\)',
    ]
    for pat in patterns:
        m = re.search(pat, source)
        if m:
            body = m.group(1)
            for pair in re.finditer(r'\{(\d+)\s*,\s*(\d+)\}', body):
                try:
                    a, b = int(pair.group(1)), int(pair.group(2))
                    if a < b:
                        ops.append((a, b))
                except ValueError:
                    pass
            if ops:
                break
    return ops

def apply_shuffle(strings, ops):
    result = list(strings)
    for a, b in ops:
        lo, hi = a - 1, b - 1
        if 0 <= lo < hi < len(result):
            result[lo:hi + 1] = reversed(result[lo:hi + 1])
    return result

def custom_b64_decode(s, alphabet):
    if not alphabet or len(alphabet) != 64:
        return None
    rev = {c: i for i, c in enumerate(alphabet)}
    clean = s.rstrip('=')
    for c in clean:
        if c not in rev:
            return None
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    translated = []
    for c in s:
        if c == '=':
            translated.append('=')
        else:
            translated.append(std[rev[c]])
    t = ''.join(translated)
    pad = (4 - len(t) % 4) % 4
    t += '=' * pad
    try:
        return base64.b64decode(t)
    except Exception:
        return None

def is_printable(s: str) -> bool:
    if not s:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) <= 126 or c in '\n\r\t')
    return printable / len(s) > 0.85

def is_lua_source(s: str) -> bool:
    if len(s) < 20 or not is_printable(s):
        return False
    keywords = ['function', 'local', 'return', 'print', 'if', 'then', 'else',
                'end', 'while', 'for', 'do', 'repeat', 'until']
    count = sum(1 for kw in keywords if kw in s)
    return count >= 2

def get_string_table_offset(source: str) -> int:
    patterns = [
        r'return\s+(\w+)\s*\[\s*\w+\s*\+\s*(\d+)\s*\]',
        r'return\s+(\w+)\s*\[\s*\w+\s*-\s*(\d+)\s*\]',
        r'\+\s*(\d+)\s*\]',
        r'\[\s*\w+\s*\+\s*(\d+)\s*\]',
    ]
    for pat in patterns:
        m = re.search(pat, source)
        if m:
            for g in m.groups():
                if g and g.isdigit():
                    return int(g)
    return 0

class StringTableDecoder:
    def __init__(self, source: str):
        self.source = source
        self.strings = []
        self.alphabet = None
        self.offset = 0
        self.ok = False
        self.raw_match = None
        self._decode()

    def _decode(self):
        raw, match = extract_strings_enhanced(self.source)
        if not raw:
            return
        self.raw_match = match
        ops = extract_shuffle_ops(self.source)
        if ops:
            raw = apply_shuffle(raw, ops)

        self.alphabet = extract_alphabet_enhanced(self.source)
        decoded = []

        for s in raw:
            if not s:
                decoded.append('')
                continue
            s = decode_unicode_escapes(s)
            s = decode_hex_escapes(s)
            s = decode_octal_escapes(s)

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

            if decoded_str is None:
                # Keep printable non-decoded strings as potential fragments
                if len(s) >= 10 and is_printable(s) and not s.startswith('local'):
                    decoded_str = s
                else:
                    decoded_str = ''

            decoded.append(decoded_str)

        self.strings = decoded
        self.offset = get_string_table_offset(self.source)
        self.ok = len([s for s in self.strings if s]) > 0

    def get_source(self) -> str:
        # First pass: full Lua source
        for s in self.strings:
            if is_lua_source(s):
                return s

        # Second pass: code fragments
        code_keywords = {'function', 'local', 'return', 'print', 'if', 'then',
                         'else', 'end', 'while', 'for', 'do', 'repeat', 'until'}
        fragments = []
        for s in self.strings:
            if not s or len(s) < 5:
                continue
            if is_printable(s) and any(kw in s for kw in code_keywords):
                if re.search(r'\s', s) or '(' in s or ')' in s or ',' in s or '\n' in s:
                    fragments.append(s)

        if fragments:
            return '\n\n'.join(fragments)

        return ''
