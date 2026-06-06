import re
import base64 as _b64std
from typing import Optional, List, Tuple, Dict
from math_fold import safe_eval_int, get_string_table_offset


def _decode_octal_string(s: str) -> str:
    result = []
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            if s[i+1] == '\\' and i + 2 < len(s) and s[i+2].isdigit():
                i += 1
            if i + 1 < len(s) and s[i+1].isdigit():
                j = i + 1
                while j < len(s) and s[j].isdigit() and j - i <= 3:
                    j += 1
                try:
                    octal_val = int(s[i+1:j], 8)
                    result.append(chr(octal_val % 256))
                    i = j
                    continue
                except ValueError:
                    pass
        result.append(s[i])
        i += 1
    return ''.join(result)


def _eval_arithmetic(expr: str) -> Optional[int]:
    expr = expr.strip()
    if re.match(r'^[\d\s\+\-\*\/\%\(\)]+$', expr):
        try:
            val = eval(expr, {"__builtins__": {}}, {})
            if isinstance(val, (int, float)):
                return int(val)
        except Exception:
            pass
    return None


def _extract_alphabet_from_n_table(source: str) -> Optional[str]:
    start_pos = None
    for m in re.finditer(r'(?:local\s+)?alphaMap\s*=\s*\{', source):
        start_pos = m.end() - 1
        break
    if start_pos is None:
        for m in re.finditer(r'(?:local\s+)?N\s*=\s*\{', source):
            start_pos = m.end() - 1
            break
    if start_pos is None:
        for m in re.finditer(r'local\s+(\w+)\s*=\s*\{', source):
            preview = source[m.end():m.end()+500]
            if re.search(r'\[\s*"\w+"\s*\]\s*=\s*\d+\s*[+\-]', preview):
                start_pos = m.end() - 1
                break
    if start_pos is None:
        return None

    depth = 0
    end_pos = start_pos
    i = start_pos
    in_string = False
    escape = False
    while i < len(source):
        c = source[i]
        if escape:
            escape = False
        elif c == '\\':
            escape = True
        elif c == '"' or c == "'":
            in_string = not in_string
        elif not in_string:
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    end_pos = i + 1
                    break
        i += 1

    if end_pos <= start_pos:
        return None

    body = source[start_pos:end_pos]
    alphabet_chars = [''] * 64
    filled = 0

    for m in re.finditer(r'\[\s*["\']([^"\']+)["\']\s*\]\s*=\s*([^,;\n}]+)', body):
        key_char = m.group(1)
        expr = m.group(2)
        val = _eval_arithmetic(expr)
        if val is not None and 0 <= val <= 63 and len(key_char) == 1:
            alphabet_chars[val] = key_char
            filled += 1

    for m in re.finditer(r'\[\s*(\d+)\s*\]\s*=\s*["\']([^"\']+)["\']', body):
        idx = int(m.group(1))
        char = m.group(2)
        if 0 <= idx <= 63 and len(char) == 1:
            alphabet_chars[idx] = char
            filled += 1

    for m in re.finditer(r'\b([A-Za-z0-9+/])\s*=\s*([^,;\n}]+)', body):
        key_char = m.group(1)
        expr = m.group(2)
        val = _eval_arithmetic(expr)
        if val is not None and 0 <= val <= 63 and len(key_char) == 1:
            alphabet_chars[val] = key_char
            filled += 1

    if filled >= 40:
        std_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        used_chars = set(c for c in alphabet_chars if c)
        for i in range(64):
            if not alphabet_chars[i]:
                for c in std_alphabet:
                    if c not in used_chars:
                        alphabet_chars[i] = c
                        used_chars.add(c)
                        break
        alphabet = ''.join(alphabet_chars)
        if len(alphabet) == 64:
            return alphabet
    return None


def _extract_shuffle_ops(source: str) -> List[Tuple[int, int]]:
    ops = []
    patterns = [
        r'ipairs\s*\(\s*\{\s*(\{(?:\s*\d+\s*,\s*\d+\s*\},?\s*)+\}\s*\)',
        r'for\s*[^,]+,\s*[^,]+,\s*[^}]+ipairs\s*\(\s*\{\s*(\{[^}]+\})\s*\}\)',
        r'ipairs\s*\(\s*(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})\s*\)',
    ]
    for pattern in patterns:
        m = re.search(pattern, source, re.DOTALL)
        if m:
            inner = m.group(1)
            for pair in re.finditer(r'\{(\d+)\s*,\s*(\d+)\}', inner):
                try:
                    a = int(pair.group(1))
                    b = int(pair.group(2))
                    ops.append((a, b))
                except ValueError:
                    pass
            if ops:
                break
    return ops


def _apply_shuffle(strings: List[str], ops: List[Tuple[int, int]]) -> List[str]:
    result = list(strings)
    for a, b in ops:
        lo, hi = a - 1, b - 1
        if 0 <= lo < len(result) and 0 <= hi < len(result) and lo < hi:
            while lo < hi:
                result[lo], result[hi] = result[hi], result[lo]
                lo += 1
                hi -= 1
    return result


def _custom_b64_decode(s: str, alphabet: str) -> Optional[bytes]:
    if len(alphabet) != 64:
        return None
    rev = {c: i for i, c in enumerate(alphabet)}
    for c in s.rstrip('='):
        if c not in rev:
            return None
    std_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    translated = ''.join(std_alphabet[rev[c]] for c in s.rstrip('='))
    translated += '=' * ((4 - len(translated) % 4) % 4)
    try:
        return _b64std.b64decode(translated)
    except Exception:
        return None


def _is_readable_string(s: str) -> bool:
    if not s:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) <= 126 or ord(c) in (9, 10, 13))
    return printable / max(len(s), 1) >= 0.80


def _extract_raw_octal_strings(source: str) -> Optional[List[str]]:
    patterns = [
        r'local\s+EncStr\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
        r'local\s+R\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
        r'=\s*\{\s*"\\\d+',
    ]
    for pattern in patterns:
        m = re.search(pattern, source, re.DOTALL)
        if not m:
            continue
        body = m.group(1) if m.groups() else m.group(0)
        raw = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
        if raw and len(raw) >= 4:
            return raw
    return None


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
        raw_strings = _extract_raw_octal_strings(self.source)
        if not raw_strings:
            self.diagnostics['error'] = 'string table not found in source'
            return

        self.diagnostics['raw_count'] = len(raw_strings)
        ops = _extract_shuffle_ops(self.source)
        self.diagnostics['shuffle_ops'] = ops
        shuffled = _apply_shuffle(raw_strings, ops)

        alpha = _extract_alphabet_from_n_table(self.source)
        if alpha:
            self.alphabet = alpha
            self.diagnostics['alphabet'] = alpha[:16] + '...'
        else:
            self.diagnostics['alphabet_warning'] = 'no alphabet found'

        decoded = []
        for s in shuffled:
            decoded.append(self._decode_entry(s))
        self.strings = decoded
        self.ok = True
        self.diagnostics['decoded_count'] = len(self.strings)
        self.offset = get_string_table_offset(self.source)
        self.diagnostics['offset'] = self.offset

    def _decode_entry(self, s: str) -> str:
        if not s:
            return ''
        if re.match(r'^(\\\d{1,3})+$', s) or '\\' in s:
            octal_decoded = _decode_octal_string(s)
            if self.alphabet:
                raw_bytes = _custom_b64_decode(octal_decoded, self.alphabet)
                if raw_bytes is not None:
                    for enc in ('utf-8', 'latin-1'):
                        try:
                            text = raw_bytes.decode(enc, errors='strict')
                            if _is_readable_string(text):
                                return text
                        except Exception:
                            pass
            if _is_readable_string(octal_decoded):
                return octal_decoded
            return s
        if self.alphabet:
            raw_bytes = _custom_b64_decode(s, self.alphabet)
            if raw_bytes is not None:
                for enc in ('utf-8', 'latin-1'):
                    try:
                        text = raw_bytes.decode(enc, errors='strict')
                        if _is_readable_string(text):
                            return text
                    except Exception:
                        pass
        if _is_readable_string(s):
            return s
        return s
