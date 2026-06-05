import re
from typing import Optional
from constants import is_readable_identifier, is_probably_text, escape_lua_string, decode_numeric_escapes
from math_fold import safe_eval_int, fold_constants, get_string_table_offset


def _extract_alphabet_from_numeric_table(source: str) -> Optional[str]:
    folded = fold_constants(source)
    for tbl_m in re.finditer(r'local\s+\w+\s*=\s*\{([^}]{300,})\}', folded):
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
    for m in re.finditer(r'["\']([A-Za-z0-9+/]{64})["\']', folded):
        cand = m.group(1)
        if len(set(cand)) == 64:
            return cand
    return None


def _extract_shuffle_ops(source: str) -> list[tuple[int, int]]:
    ops: list[tuple[int, int]] = []
    folded = fold_constants(source)
    m = re.search(r'ipairs\s*\(\s*\{(.*?)\}\s*\)', folded, re.DOTALL)
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


def _apply_shuffle(strings: list[str], ops: list[tuple[int, int]]) -> list[str]:
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
            continue
        bits = (bits << 6) | rev[c]
        bit_count += 6
        if bit_count >= 8:
            bit_count -= 8
            out.append((bits >> bit_count) & 0xFF)
    return bytes(out)


_R_TABLE_PATTERNS = [
    re.compile(r'local\s+R\s*=\s*\{(.*?)\}(?=local\s+function|for\s+E)', re.DOTALL),
    re.compile(r'\{((?:\s*"[^"]*"\s*[;,]?\s*){10,})\}', re.DOTALL),
]


def _extract_raw_strings(source: str) -> Optional[list[str]]:
    for pat in _R_TABLE_PATTERNS:
        m = pat.search(source)
        if m:
            body = m.group(1)
            raw = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
            if raw:
                return [decode_numeric_escapes(s) for s in raw]
    return None


_KEYED_TABLE_PATTERN = re.compile(
    r'local\s+\w+\s*=\s*\{((?:\s*\[\d+\]\s*=\s*"[^"]*"\s*[,;]?\s*){4,})\}',
    re.DOTALL,
)


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
        alpha = _extract_alphabet_from_numeric_table(self.source)
        if not alpha:
            raw = _extract_raw_strings(self.source)
            if raw is None:
                raw = self._extract_keyed_strings(self.source)
            if raw:
                self.strings = [decode_numeric_escapes(s) for s in raw]
                self.ok = True
                self.diagnostics['raw_count'] = len(raw)
                self.diagnostics['decoded_count'] = len(self.strings)
                self.diagnostics['note'] = 'alphabet not found, used raw strings'
                self.offset = get_string_table_offset(self.source)
                self.diagnostics['offset'] = self.offset
                return
            self.diagnostics['error'] = 'alphabet not found and no raw strings'
            return

        self.alphabet = alpha
        self.diagnostics['alphabet'] = alpha[:10] + '...'

        raw = _extract_raw_strings(self.source)
        if raw is None:
            raw = self._extract_keyed_strings(self.source)
        if raw is None:
            self.diagnostics['error'] = 'R table not found'
            return

        self.diagnostics['raw_count'] = len(raw)
        ops = _extract_shuffle_ops(self.source)
        self.diagnostics['shuffle_ops'] = len(ops)
        shuffled = _apply_shuffle(raw, ops)
        decoded: list[str] = []
        for s in shuffled:
            decoded.append(self._decode_entry(s))
        self.strings = decoded
        self.ok = True
        self.diagnostics['decoded_count'] = len(decoded)
        self.offset = get_string_table_offset(self.source)
        self.diagnostics['offset'] = self.offset

    @staticmethod
    def _extract_keyed_strings(source: str) -> Optional[list[str]]:
        m = _KEYED_TABLE_PATTERN.search(source)
        if not m:
            return None
        body = m.group(1)
        entries: dict[int, str] = {}
        for km in re.finditer(r'\[(\d+)\]\s*=\s*"((?:[^"\\]|\\.)*)"', body):
            entries[int(km.group(1))] = km.group(2)
        if not entries:
            return None
        max_key = max(entries.keys())
        return [entries.get(i, '') for i in range(1, max_key + 1)]

    def _decode_entry(self, s: str) -> str:
        if not s:
            return ''
        if is_readable_identifier(s):
            return s
        raw_bytes = _custom_b64_decode(s, self.alphabet)
        if raw_bytes:
            for enc in ('utf-8', 'latin-1'):
                try:
                    text = raw_bytes.decode(enc, errors='strict')
                    if is_probably_text(text):
                        return text
                except Exception:
                    pass
            try:
                return raw_bytes.decode('latin-1', errors='replace')
            except Exception:
                pass
        return s

    def resolve(self, lua_index: int) -> Optional[str]:
        py_index = lua_index + self.offset - 1
        if 0 <= py_index < len(self.strings):
            return self.strings[py_index]
        return None

    def summary(self) -> str:
        if not self.ok:
            return f"StringTableDecoder: FAILED - {self.diagnostics.get('error')}"
        sample = ', '.join(repr(s) for s in self.strings[:6] if s)
        return f"StringTableDecoder: OK count={len(self.strings)} offset={self.offset} sample=[{sample}]"
