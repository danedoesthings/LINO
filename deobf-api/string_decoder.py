import re
import base64

def decode_octal(s):
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

def fix_unicode(s):
    return re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), s)

def eval_expr(expr):
    expr = re.sub(r'\s+', '', expr)
    try:
        return eval(expr, {"__builtins__": {}}, {})
    except:
        return None

def extract_alphabet(source):
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
                    idx = eval_expr(match.group(2))
                    if idx is not None and 0 <= idx < 64:
                        chars[idx] = c
            for match in re.finditer(r'([A-Za-z0-9+/])\s*=\s*(\d+)(?:[+\-]\d+)*', body):
                c = match.group(1)
                idx = eval_expr(match.group(2))
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

def extract_strings(source):
    patterns = [
        r'local\s+EncStr\s*=\s*\{([^}]+)\}',
        r'local\s+R\s*=\s*\{([^}]+)\}',
    ]
    for pattern in patterns:
        m = re.search(pattern, source, re.DOTALL)
        if m:
            return re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))
    return []

def extract_shuffle(source):
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

def is_lua(s):
    if len(s) < 20:
        return False
    keywords = ['function', 'local', 'return', 'print', 'if', 'then', 'else', 'end', 'while', 'for', 'do']
    return sum(1 for kw in keywords if kw in s) >= 2

class StringTableDecoder:
    def __init__(self, source):
        self.source = source
        self.strings = []
        self.alphabet = None
        self.ok = False
        
    def decode(self):
        raw = extract_strings(self.source)
        if not raw:
            return False
        
        ops = extract_shuffle(self.source)
        if ops:
            raw = apply_shuffle(raw, ops)
        
        self.alphabet = extract_alphabet(self.source)
        
        for s in raw:
            s = fix_unicode(s)
            s = decode_octal(s)
            if self.alphabet and len(s) >= 4:
                decoded = custom_b64_decode(s, self.alphabet)
                if decoded:
                    try:
                        text = decoded.decode('utf-8', errors='replace')
                        if is_lua(text):
                            self.strings.append(text)
                            continue
                    except:
                        pass
            if is_lua(s):
                self.strings.append(s)
            else:
                self.strings.append('')
        
        self.ok = bool(self.strings)
        return self.ok
    
    def get_source(self):
        for s in self.strings:
            if is_lua(s):
                return s
        return '\n'.join([s for s in self.strings if s])
