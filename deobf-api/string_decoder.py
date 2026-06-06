import re
from typing import Optional
from math_fold import safe_eval_int, fold_constants, get_string_table_offset

def _extract_alphabet_from_numeric_table(source: str) -> Optional[str]:
    for tbl_m in re.finditer(r'local\s+\w+\s*=\s*\{([^}]{300,})\}', source):
        body = tbl_m.group(1)
        entries: dict[str, int] = {}
        for m in re.finditer(r'\b([A-Za-z_])\s*=\s*([-\d+*()\s]{3,60}?)(?=[,;\}]|\Z)', body):
            key = m.group(1)
            try:
                val = safe_eval_int(m.group(2))
                if val is not None and 0 <= val <= 63:
                    entries[key] = val
            except Exception:
                pass
        for m in re.finditer(r'\["\\(\d{1,3})"\]\s*=\s*([-\d+*()\s]{3,60}?)(?=[,;\}]|\Z)', body):
            key = chr(int(m.group(1)))
            try:
                val = safe_eval_int(m.group(2))
                if val is not None and 0 <= val <= 63:
                    entries[key] = val
            except Exception:
                pass
        if len(entries) < 60:
            continue
        rev: dict[int, str] = {v: k for k, v in entries.items()}
        if len(rev) < 60:
            continue
        alphabet = ''.join(rev.get(i, '') for i in range(64))
        if len(alphabet) == 64 and len(set(alphabet)) == 64:
            return alphabet
    for m in re.finditer(r'["\']([A-Za-z0-9+/]{64})["\']', source):
        cand = m.group(1)
        if len(set(cand)) == 64:
            return cand
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

def _decode_octal_string(s: str) -> str:
    result = []
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s) and s[i+1].isdigit():
            j = i + 1
            while j < len(s) and s[j].isdigit() and j - i <= 4:
                j += 1
            try:
                code = int(s[i+1:j])
                result.append(chr(code % 256))
                i = j
                continue
            except ValueError:
                pass
        result.append(s[i])
        i += 1
    return ''.join(result)

def _decode_numeric_escapes(s: str) -> str:
    return re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1)) % 256), s)

def _is_readable_string(s: str) -> bool:
    if not s:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) <= 126 or ord(c) in (9, 10, 13))
    return printable / len(s) >= 0.80

def _extract_raw_octal_strings(source: str) -> Optional[list]:
    r_match = re.search(r'local\s+R\s*=\s*\{([^}]+)\}', source, re.DOTALL)
    if not r_match:
        r_match = re.search(r'\}=\{([^}]+)\}', source, re.DOTALL)
    if not r_match:
        return None
    body = r_match.group(1)
    raw = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
    if raw and len(raw) >= 4:
        return raw
    return None

_R_TABLE_PATTERNS = [
    re.compile(r'local\s+R\s*=\s*\{(.*?)\}(?=local\s+function|for\s+E)', re.DOTALL),
    re.compile(r'\{((?:\s*"[^"]*"\s*[;,]?\s*){10,})\}', re.DOTALL),
]

def _extract_raw_strings(source: str) -> Optional[list]:
    for pat in _R_TABLE_PATTERNS:
        m = pat.search(source)
        if m:
            body = m.group(1)
            raw = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
            if raw:
                return [_decode_numeric_escapes(s) for s in raw]
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
        raw_octal = _extract_raw_octal_strings(self.source)
        if not raw_octal:
            self.diagnostics['error'] = 'R table not found in source'
            return

        self.diagnostics['raw_count'] = len(raw_octal)
        ops = _extract_shuffle_ops(self.source)
        self.diagnostics['shuffle_ops'] = len(ops)

        alpha = _extract_alphabet_from_numeric_table(self.source)
        if alpha:
            self.alphabet = alpha
            self.diagnostics['alphabet'] = alpha[:10] + '...'
            shuffled = _apply_shuffle(raw_octal, ops)
            decoded = []
            for s in shuffled:
                decoded.append(self._decode_entry(s))
            self.strings = decoded
        else:
            self.diagnostics['note'] = 'no custom alphabet, using octal decode'
            shuffled = _apply_shuffle(raw_octal, ops)
            decoded = []
            for s in shuffled:
                decoded.append(_decode_octal_string(s))
            self.strings = decoded

        self.ok = True
        self.diagnostics['decoded_count'] = len(self.strings)
        self.offset = get_string_table_offset(self.source)
        self.diagnostics['offset'] = self.offset

    def _decode_entry(self, s: str) -> str:
        if not s:
            return ''
        if _is_readable_string(s):
            return s
        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', s):
            return s
        if re.match(r'^(\\\d{1,3})+$', s):
            return _decode_octal_string(s)
        raw_bytes = _custom_b64_decode(s, self.alphabet)
        if raw_bytes is not None:
            for enc in ('utf-8', 'latin-1'):
                try:
                    text = raw_bytes.decode(enc, errors='strict')
                    if _is_readable_string(text):
                        return text
                except Exception:
                    pass
        fallback = _decode_octal_string(s)
        if _is_readable_string(fallback):
            return fallback
        return s
