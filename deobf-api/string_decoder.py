import re
import base64

def decode_octal_escapes(s: str) -> str:
    result = []
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            if s[i+1] == '\\':
                result.append('\\')
                i += 2
                continue
            octal = ''
            j = i + 1
            while j < len(s) and len(octal) < 3 and s[j] in '01234567':
                octal += s[j]
                j += 1
            if octal:
                result.append(chr(int(octal, 8)))
                i = j
                continue
        result.append(s[i])
        i += 1
    return ''.join(result)

def decode_unicode_escapes(s: str) -> str:
    return re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), s)

def eval_arithmetic(expr: str):
    expr = re.sub(r'\s+', '', expr)
    try:
        return eval(expr, {"__builtins__": {}}, {})
    except:
        return None

def extract_alphabet_from_n_table(source: str):
    patterns = [
        r'local\s+N\s*=\s*\{([^}]+)\}',
        r'local\s+alphaMap\s*=\s*\{([^}]+)\}',
        r'N\s*=\s*\{([^}]+)\}',
    ]
    for pattern in patterns:
        m = re.search(pattern, source, re.DOTALL)
        if m:
            body = m.group(1)
            chars = [''] * 64
            for match in re.finditer(r'\["([^"]+)"\]\s*=\s*(\d+)(?:[+\-]\d+)*', body):
                c = match.group(1)
                if len(c) == 1:
                    idx = eval_arithmetic(match.group(2))
                    if idx is not None and 0 <= idx < 64:
                        chars[idx] = c
            for match in re.finditer(r'([A-Za-z0-9+/])\s*=\s*(\d+)(?:[+\-]\d+)*', body):
                c = match.group(1)
                idx = eval_arithmetic(match.group(2))
                if idx is not None and 0 <= idx < 64:
                    chars[idx] = c
            if any(chars):
                std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                for i in range(64):
                    if not chars[i]:
                        for x in std:
                            if x not in chars:
                                chars[i] = x
                                break
                return ''.join(chars)
    return None

def extract_strings(source: str):
    patterns = [
        r'local\s+EncStr\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
        r'local\s+R\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
    ]
    for pattern in patterns:
        m = re.search(pattern, source, re.DOTALL)
        if m:
            body = m.group(1)
            strings = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
            if strings:
                return strings
    return []

def extract_shuffle_ops(source: str):
    ops = []
    m = re.search(r'ipairs\s*\(\s*\{([^}]+)\}\s*\)', source)
    if m:
        for pair in re.finditer(r'\{(\d+)\s*,\s*(\d+)\}', m.group(1)):
            ops.append((int(pair.group(1)), int(pair.group(2))))
    return ops

def apply_shuffle(strings, ops):
    result = list(strings)
    for a, b in ops:
        lo, hi = a - 1, b - 1
        if 0 <= lo < hi < len(result):
            while lo < hi:
                result[lo], result[hi] = result[hi], result[lo]
                lo += 1
                hi -= 1
    return result

def custom_b64_decode(s, alphabet):
    if not alphabet or len(alphabet) != 64:
        return None
    rev = {c: i for i, c in enumerate(alphabet)}
    for c in s.rstrip('='):
        if c not in rev:
            return None
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    translated = ''.join(std[rev[c]] for c in s)
    padding = (4 - len(translated) % 4) % 4
    if padding:
        translated += '=' * padding
    try:
        return base64.b64decode(translated)
    except:
        return None

def is_lua_source(s):
    if len(s) < 20:
        return False
    keywords = ['function', 'local', 'return', 'print', 'if', 'then', 'else', 'end', 'while', 'for', 'do']
    return sum(1 for kw in keywords if kw in s) >= 2

def get_string_table_offset(source: str) -> int:
    patterns = [
        r'return\s+(\w+)\s*\[\s*\w+\s*\+\s*(\d+)\s*\]',
        r'return\s+(\w+)\s*\[\s*\w+\s*-\s*(\d+)\s*\]',
        r'\+\s*(\d+)\s*\]',
    ]
    for pattern in patterns:
        m = re.search(pattern, source)
        if m:
            groups = m.groups()
            if len(groups) >= 2:
                try:
                    return int(groups[1])
                except:
                    pass
            elif len(groups) >= 1:
                try:
                    return int(groups[0])
                except:
                    pass
    return 0

class StringTableDecoder:
    def __init__(self, source: str):
        self.source = source
        self.strings = []
        self.alphabet = None
        self.offset = 0
        self.ok = False
        self._decode()

    def _decode(self):
        raw = extract_strings(self.source)
        if not raw:
            return
        ops = extract_shuffle_ops(self.source)
        if ops:
            raw = apply_shuffle(raw, ops)
        self.alphabet = extract_alphabet_from_n_table(self.source)
        decoded = []
        for s in raw:
            s = decode_unicode_escapes(s)
            s = decode_octal_escapes(s)
            if self.alphabet and len(s) >= 4:
                b = custom_b64_decode(s, self.alphabet)
                if b:
                    try:
                        text = b.decode('utf-8', errors='replace')
                        if is_lua_source(text):
                            decoded.append(text)
                            continue
                    except:
                        pass
            decoded.append(s)
        self.strings = decoded
        self.offset = get_string_table_offset(self.source)
        self.ok = bool(self.strings)

    def get_source(self):
        for s in self.strings:
            if is_lua_source(s):
                return s
        return '\n'.join([s for s in self.strings if s])
