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
                try:
                    result.append(chr(int(octal, 8)))
                    i = j
                    continue
                except:
                    pass
        result.append(s[i])
        i += 1
    return ''.join(result)

def decode_unicode_escapes(s: str) -> str:
    def replace_hex(match):
        try:
            return chr(int(match.group(1), 16))
        except:
            return match.group(0)
    return re.sub(r'\\u([0-9a-fA-F]{4})', replace_hex, s)

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
    except:
        return None

def extract_alphabet_from_n_table(source: str):
    patterns = [
        r'local\s+N\s*=\s*\{([^}]+)\}',
        r'local\s+alphaMap\s*=\s*\{([^}]+)\}',
        r'N\s*=\s*\{([^}]+)\}',
        r'alphaMap\s*=\s*\{([^}]+)\}',
    ]
    for pattern in patterns:
        match = re.search(pattern, source, re.DOTALL)
        if match:
            body = match.group(1)
            chars = [''] * 64
            for m in re.finditer(r'\[\s*["\']([^"\']+)["\']\s*\]\s*=\s*([^,;\n}]+)', body):
                key_char = m.group(1)
                expr = m.group(2)
                val = eval_arithmetic(expr)
                if val is not None and 0 <= val <= 63 and len(key_char) == 1:
                    chars[val] = key_char
            for m in re.finditer(r'([A-Za-z0-9+/])\s*=\s*([^,;\n}]+)', body):
                key_char = m.group(1)
                expr = m.group(2)
                val = eval_arithmetic(expr)
                if val is not None and 0 <= val <= 63 and len(key_char) == 1:
                    chars[val] = key_char
            for m in re.finditer(r'\[\s*(\d+)\s*\]\s*=\s*["\']([^"\']+)["\']', body):
                idx = int(m.group(1))
                char = m.group(2)
                if 0 <= idx <= 63 and len(char) == 1:
                    chars[idx] = char
            if any(chars):
                std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                used = set(chars)
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
    patterns = [
        r'local\s+EncStr\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
        r'local\s+R\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
        r'EncStr\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
        r'R\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
    ]
    for pattern in patterns:
        match = re.search(pattern, source, re.DOTALL)
        if match:
            body = match.group(1)
            strings = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
            if strings and len(strings) >= 2:
                return strings
    return []

def extract_shuffle_ops(source: str):
    ops = []
    patterns = [
        r'ipairs\s*\(\s*\{([^}]+)\}\s*\)',
        r'for\s+\w+\s*,\s*\w+\s+in\s+ipairs\s*\(\s*\{([^}]+)\}\s*\)',
    ]
    for pattern in patterns:
        match = re.search(pattern, source)
        if match:
            for pair in re.finditer(r'\{(\d+)\s*,\s*(\d+)\}', match.group(1)):
                try:
                    a = int(pair.group(1))
                    b = int(pair.group(2))
                    ops.append((a, b))
                except:
                    pass
            if ops:
                break
    return ops

def apply_shuffle(strings, ops):
    result = list(strings)
    for a, b in ops:
        lo, hi = a - 1, b - 1
        if 0 <= lo < hi < len(result):
            result[lo], result[hi] = result[hi], result[lo]
            lo += 1
            hi -= 1
    return result

def custom_b64_decode(s, alphabet):
    if not alphabet or len(alphabet) != 64:
        return None
    rev = {}
    for i, c in enumerate(alphabet):
        rev[c] = i
    for c in s.rstrip('='):
        if c not in rev:
            return None
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    translated = []
    for c in s:
        if c != '=':
            translated.append(std[rev[c]])
        else:
            translated.append('=')
    translated_str = ''.join(translated)
    padding = (4 - len(translated_str) % 4) % 4
    if padding:
        translated_str += '=' * padding
    try:
        return base64.b64decode(translated_str)
    except:
        return None

def is_printable(s: str) -> bool:
    if not s:
        return False
    printable = 0
    for c in s:
        if 32 <= ord(c) <= 126 or c in '\n\r\t':
            printable += 1
    return printable / len(s) > 0.7

def is_lua_source(s: str) -> bool:
    if len(s) < 20 or not is_printable(s):
        return False
    keywords = ['function', 'local', 'return', 'print', 'if', 'then', 'else', 'end', 'while', 'for', 'do']
    count = 0
    for kw in keywords:
        if kw in s:
            count += 1
    return count >= 2

def get_string_table_offset(source: str) -> int:
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
            if not s:
                decoded.append('')
                continue
            s = decode_unicode_escapes(s)
            s = decode_octal_escapes(s)
            if self.alphabet and len(s) >= 4:
                try:
                    b = custom_b64_decode(s, self.alphabet)
                    if b:
                        try:
                            text = b.decode('utf-8', errors='replace')
                            if is_lua_source(text):
                                decoded.append(text)
                                continue
                        except:
                            pass
                except:
                    pass
            if is_printable(s) and len(s) > 5:
                decoded.append(s)
            else:
                decoded.append('')
        self.strings = decoded
        self.offset = get_string_table_offset(self.source)
        self.ok = len([s for s in self.strings if s]) > 0

    def get_source(self):
        for s in self.strings:
            if is_lua_source(s):
                return s
        printable = [s for s in self.strings if is_printable(s) and len(s) > 10]
        if printable:
            return '\n'.join(printable)
        return ''
