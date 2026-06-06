import re
import base64 as _b64std
from typing import Optional
from math_fold import safe_eval_int, fold_constants, get_string_table_offset


def _extract_balanced_braces(text: str, start: int) -> Optional[str]:
    if start >= len(text) or text[start] != '{':
        return None
    depth = 0
    i = start
    while i < len(text):
        c = text[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return text[start:i+1]
        elif c == '"':
            i += 1
            while i < len(text) and text[i] != '"':
                if text[i] == '\\':
                    i += 1
                i += 1
        elif c == "'":
            i += 1
            while i < len(text) and text[i] != "'":
                if text[i] == '\\':
                    i += 1
                i += 1
        i += 1
    return None


def _decode_octal_string(s: str) -> str:
    result = []
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            if s[i+1] == '\\' and i + 2 < len(s) and s[i+2].isdigit():
                i += 1
                j = i + 1
                while j < len(s) and s[j].isdigit() and j - i <= 3:
                    j += 1
                try:
                    result.append(chr(int(s[i+1:j]) % 256))
                    i = j
                    continue
                except ValueError:
                    pass
            elif s[i+1].isdigit():
                j = i + 1
                while j < len(s) and s[j].isdigit() and j - i <= 3:
                    j += 1
                try:
                    result.append(chr(int(s[i+1:j]) % 256))
                    i = j
                    continue
                except ValueError:
                    pass
        result.append(s[i])
        i += 1
    return ''.join(result)


_STANDARD_B64 = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')


def _extract_alphabet_from_numeric_table(source: str) -> Optional[str]:
    folded = fold_constants(source)
    for m in re.finditer(r'local\s+\w+\s*=\s*\{', folded):
        start = m.end() - 1
        body = _extract_balanced_braces(folded, start)
        if not body:
            continue
        entries: dict[str, int] = {}
        for m2 in re.finditer(r'\b([A-Za-z_])\s*=\s*(\d+)', body):
            key = m2.group(1)
            try:
                val = int(m2.group(2))
                if 0 <= val <= 63 and len(key) == 1:
                    entries[key] = val
            except Exception:
                pass
        for m2 in re.finditer(r'\["([^"]*)"\]\s*=\s*(\d+)', body):
            raw_key = m2.group(1)
            key = _decode_octal_string(raw_key) if '\\' in raw_key else raw_key
            try:
                val = int(m2.group(2))
                if 0 <= val <= 63 and len(key) == 1:
                    entries[key] = val
            except Exception:
                pass
        for m2 in re.finditer(r'\[(\d+)\]\s*=\s*(\d+)', body):
            key = m2.group(1)
            try:
                val = int(m2.group(2))
                if 0 <= val <= 63 and len(key) == 1:
                    entries[key] = val
            except Exception:
                pass
        if len(entries) < 50:
            continue
        rev: dict[int, str] = {}
        for k, v in entries.items():
            if len(k) == 1:
                rev[v] = k
        if len(rev) < 50:
            continue
        alphabet_chars = []
        for i in range(64):
            if i in rev:
                alphabet_chars.append(rev[i])
            else:
                alphabet_chars.append('')
        if len(alphabet_chars) != 64:
            continue
        missing_indices = [i for i, c in enumerate(alphabet_chars) if c == '']
        used_chars = set(c for c in alphabet_chars if c != '')
        if len(missing_indices) == 1:
            remaining = _STANDARD_B64 - used_chars
            if remaining:
                missing_char = remaining.pop()
                alphabet_chars[missing_indices[0]] = missing_char
        alphabet = ''.join(alphabet_chars)
        if len(alphabet) == 64 and len(set(alphabet)) >= 63:
            return alphabet
    return None


def _extract_shuffle_ops(source: str) -> list:
    ops = []
    m = re.search(r'ipairs\s*\(\s*\{(.*?)\}\s*\)', source, re.DOTALL)
    if not m:
        return ops
    inner = m.group(1)
    for pair in re.finditer(r'\{([^}]+)\}', inner):
        parts = re.split(r'[;,]', pair.group(1))
        if len(parts) >= 2:
            try:
                a = safe_eval_int(re.sub(r'\s+', '', parts[0]))
                b = safe_eval_int(re.sub(r'\s+', '', parts[1]))
                if a is not None and b is not None:
                    ops.append((a, b))
            except Exception:
                pass
    return ops


def _apply_shuffle(strings: list, ops: list) -> list:
    result = list(strings)
    for a, b in ops:
        lo, hi = a - 1, b - 1
        while lo < hi:
            if 0 <= lo < len(result) and 0 <= hi < len(result):
                result[lo], result[hi] = result[hi], result[lo]
            lo += 1
            hi -= 1
    return result


def _custom_b64_decode(s: str, alphabet: str) -> Optional[bytes]:
    if len(set(alphabet)) < 60:
        return None
    rev = {c: i for i, c in enumerate(alphabet)}
    bits = 0
    bit_count = 0
    out = bytearray()
    for c in s.rstrip('='):
        if c not in rev:
            return None
        bits = (bits << 6) | rev[c]
        bit_count += 6
        if bit_count >= 8:
            bit_count -= 8
            out.append((bits >> bit_count) & 0xFF)
    return bytes(out)


def _is_readable_string(s: str) -> bool:
    if not s:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) <= 126 or ord(c) in (9, 10, 13))
    return printable / max(len(s), 1) >= 0.80


def _is_identifier(s: str) -> bool:
    return bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', s))


_TABLE_PATTERNS = [
    re.compile(r'local\s+EncStr\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}', re.DOTALL),
    re.compile(r'local\s+R\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}', re.DOTALL),
    re.compile(r'\}=\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}', re.DOTALL),
    re.compile(r'local\s+\w{1,6}\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}', re.DOTALL),
]


def _extract_raw_octal_strings(source: str) -> Optional[list]:
    for pat in _TABLE_PATTERNS:
        m = pat.search(source)
        if not m:
            continue
        body = m.group(1)
        raw = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
        if raw and len(raw) >= 4:
            return raw
    return None


class StringTableDecoder:
    def __init__(self, source: str) -> None:
        self.source = source
        self.ok = False
        self.strings: list[str] = []
        self.alphabet: str = ''
        self.offset: int = 0
        self.diagnostics: dict = {}
        self._decode()

    def _decode(self) -> None:
        raw_strings = _extract_raw_octal_strings(self.source)
        if not raw_strings:
            self.diagnostics['error'] = 'string table not found in source'
            return

        self.diagnostics['raw_count'] = len(raw_strings)
        ops = _extract_shuffle_ops(self.source)
        self.diagnostics['shuffle_ops'] = len(ops)
        shuffled = _apply_shuffle(raw_strings, ops)

        alpha = _extract_alphabet_from_numeric_table(self.source)
        if alpha:
            self.alphabet = alpha
            self.diagnostics['alphabet'] = alpha[:10] + '...'

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
        if re.match(r'^(\\\d{1,3})+$', s):
            decoded = _decode_octal_string(s)
            if self.alphabet:
                raw_bytes = _custom_b64_decode(decoded, self.alphabet)
                if raw_bytes is not None:
                    for enc in ('utf-8', 'latin-1'):
                        try:
                            text = raw_bytes.decode(enc, errors='strict')
                            if _is_readable_string(text):
                                return text
                        except Exception:
                            pass
            if _is_readable_string(decoded):
                return decoded
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
        if _is_identifier(s):
            return s
        return s
