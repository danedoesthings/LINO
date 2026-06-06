import re
import base64 as _b64std
from typing import Optional, List, Tuple, Dict

def decode_raw_octal(s: str) -> str:
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

def fix_unicode_escapes(s: str) -> str:
    def replace_unicode(m):
        code = m.group(1)
        try:
            return chr(int(code, 16))
        except:
            return m.group(0)
    return re.sub(r'\\u([0-9a-fA-F]{4})', replace_unicode, s)

def eval_arithmetic(expr: str) -> Optional[int]:
    expr = expr.strip()
    expr = re.sub(r'--[^\n]*', '', expr)
    expr = re.sub(r'\s+', '', expr)
    if not expr:
        return None
    if expr.isdigit() or (expr[0] == '-' and expr[1:].isdigit()):
        return int(expr)
    if re.match(r'^[\d\s\+\-\*\/\%\(\)]+$', expr):
        try:
            val = eval(expr, {"__builtins__": {}}, {})
            if isinstance(val, (int, float)):
                return int(val)
        except:
            pass
    return None

def extract_alphabet_from_n_table(source: str) -> Optional[str]:
    patterns = [
        r'local\s+N\s*=\s*\{([^}]+)\}',
        r'local\s+alphaMap\s*=\s*\{([^}]+)\}',
        r'N\s*=\s*\{([^}]+)\}',
        r'alphaMap\s*=\s*\{([^}]+)\}',
    ]
    for pattern in patterns:
        m = re.search(pattern, source, re.DOTALL)
        if m:
            body = m.group(1)
            break
    else:
        return None
    
    alphabet_chars = [''] * 64
    for m in re.finditer(r'\["([^"]+)"\]\s*=\s*(\d+)(?:[+\-]\s*\d+)*', body):
        char = m.group(1)
        if len(char) == 1:
            val = eval_arithmetic(m.group(2))
            if val is not None and 0 <= val <= 63:
                alphabet_chars[val] = char
    for m in re.finditer(r'([A-Za-z0-9+/])\s*=\s*(\d+)(?:[+\-]\s*\d+)*', body):
        char = m.group(1)
        val = eval_arithmetic(m.group(2))
        if val is not None and 0 <= val <= 63:
            alphabet_chars[val] = char
    if any(alphabet_chars):
        std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        for i in range(64):
            if not alphabet_chars[i]:
                for c in std:
                    if c not in alphabet_chars:
                        alphabet_chars[i] = c
                        break
        return ''.join(alphabet_chars)
    return None

def extract_shuffle_ops(source: str) -> List[Tuple[int, int]]:
    ops = []
    m = re.search(r'ipairs\s*\(\s*\{([^}]+)\}\s*\)', source, re.DOTALL)
    if m:
        for pair in re.finditer(r'\{(\d+)\s*,\s*(\d+)\}', m.group(1)):
            ops.append((int(pair.group(1)), int(pair.group(2))))
    return ops

def apply_shuffle(strings: List[str], ops: List[Tuple[int, int]]) -> List[str]:
    result = list(strings)
    for a, b in ops:
        lo, hi = a - 1, b - 1
        if 0 <= lo < hi < len(result):
            while lo < hi:
                result[lo], result[hi] = result[hi], result[lo]
                lo += 1
                hi -= 1
    return result

def custom_b64_decode(s: str, alphabet: str) -> Optional[bytes]:
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
        return _b64std.b64decode(translated)
    except:
        return None

def extract_raw_strings(source: str) -> Optional[List[str]]:
    patterns = [
        r'local\s+EncStr\s*=\s*\{([^}]+)\}',
        r'local\s+R\s*=\s*\{([^}]+)\}',
    ]
    for pattern in patterns:
        m = re.search(pattern, source, re.DOTALL)
        if m:
            return re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))
    return None

def is_lua_source(s: str) -> bool:
    s = s.strip()
    if len(s) < 20:
        return False
    keywords = ['function', 'local', 'return', 'print', 'if', 'then', 'else', 'end', 'while', 'for', 'do']
    return sum(1 for kw in keywords if kw in s) >= 2


class StringTableDecoder:
    def __init__(self, source: str) -> None:
        self.source = source
        self.ok = False
        self.strings: List[str] = []
        self.alphabet: str = ''
        self.offset: int = 0
        self.diagnostics: Dict = {}
        self._decode()

    def _decode(self) -> None:
        raw = extract_raw_strings(self.source)
        if not raw:
            self.diagnostics['error'] = 'No string table found'
            return
        
        ops = extract_shuffle_ops(self.source)
        if ops:
            raw = apply_shuffle(raw, ops)
        
        self.alphabet = extract_alphabet_from_n_table(self.source)
        
        decoded = []
        for s in raw:
            s = fix_unicode_escapes(s)
            s = decode_raw_octal(s)
            
            if self.alphabet and len(s) >= 4:
                try:
                    b = custom_b64_decode(s, self.alphabet)
                    if b:
                        try:
                            t = b.decode('utf-8', errors='replace')
                            if is_lua_source(t):
                                decoded.append(t)
                                continue
                        except:
                            pass
                except:
                    pass
            decoded.append(s)
        
        self.strings = decoded
        self.ok = True
        self.diagnostics['count'] = len(self.strings)
        self.diagnostics['alphabet'] = self.alphabet[:20] + '...' if self.alphabet else 'none'
        
        for i, s in enumerate(self.strings):
            if s and is_lua_source(s):
                self.diagnostics['found_source'] = True
                break
