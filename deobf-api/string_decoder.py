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


def _extract_alphabet_from_numeric_table(source: str) -> Optional[str]:
    """
    Extract the custom base-64 alphabet from the Prometheus N-table.

    Prometheus stores the alphabet as a Lua table that maps each base-64
    character to its 0-based index.  The entries may look like any of:
        A = 0       (letter key, no quotes)
        ["0"] = 52  (digit key, quoted)
        ["_"] = 62  (symbol key, quoted)

    We need ALL 64 entries to reconstruct the alphabet correctly.
    """
    folded = fold_constants(source)

    for m in re.finditer(r'local\s+\w+\s*=\s*\{', folded):
        start = m.end() - 1
        body = _extract_balanced_braces(folded, start)
        if not body:
            continue
        entries: dict = {}

        # Single-char letter/underscore keys without quotes  â  A = 5
        for m2 in re.finditer(r'\b([A-Za-z_])\s*=\s*(\d+)', body):
            try:
                val = int(m2.group(2))
                if 0 <= val <= 63:
                    entries[m2.group(1)] = val
            except Exception:
                pass

        # Any quoted single-char key  â  ["0"] = 52  or  ["+"] = 62
        for m2 in re.finditer(r'\["(.)"\]\s*=\s*(\d+)', body):
            try:
                val = int(m2.group(2))
                if 0 <= val <= 63:
                    entries[m2.group(1)] = val
            except Exception:
                pass

        # Bare digit key (no quotes)  â  0 = 52  (digits 0-9 in alphabet)
        for m2 in re.finditer(r'(?<!["\w])(\d)\s*=\s*(\d+)(?!\d)', body):
            key = m2.group(1)
            try:
                val = int(m2.group(2))
                if 0 <= val <= 63:
                    entries[key] = val
            except Exception:
                pass

        if len(entries) < 60:          # need at least 60 of 64 entries
            continue
        rev: dict[int, str] = {}
        for k, v in entries.items():
            if v not in rev:
                rev[v] = k
        if len(rev) < 60:
            continue
        alphabet = ''.join(rev.get(i, '') for i in range(64))
        if len(alphabet) >= 62 and len(set(alphabet)) >= 62:
            return alphabet

    # Fallback: explicit 64-char printable string literal anywhere in source
    for m in re.finditer(r'["\']([!-~]{64})["\']', source):
        cand = m.group(1)
        if len(set(cand)) == 64:
            return cand

    # Fallback: string.byte(alpha, â¦) call carries the alphabet as an argument
    for m in re.finditer(
        r'string\.byte\s*\(\s*["\']([!-~]{20,})["\']',
        source
    ):
        cand = m.group(1)
        if len(cand) >= 64 and len(set(cand[:64])) == 64:
            return cand[:64]

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


def _is_readable_string(s: str) -> bool:
    if not s:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) <= 126 or ord(c) in (9, 10, 13))
    return printable / max(len(s), 1) >= 0.80


def _is_identifier(s: str) -> bool:
    return bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', s))


# ââ String-table extraction: handles any variable name ââââââââââââââââââââââ

_TABLE_PATTERNS = [
    re.compile(r'local\s+R\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}', re.DOTALL),
    re.compile(r'\}=\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}', re.DOTALL),
    re.compile(r'local\s+EncStr\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}', re.DOTALL),
    # Any short (â¤6-char) local variable assigned a table of quoted strings
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
        raw_octal = _extract_raw_octal_strings(self.source)
        if not raw_octal:
            self.diagnostics['error'] = 'R table not found in source'
            return

        self.diagnostics['raw_count'] = len(raw_octal)
        ops = _extract_shuffle_ops(self.source)
        self.diagnostics['shuffle_ops'] = len(ops)
        shuffled = _apply_shuffle(raw_octal, ops)

        alpha = _extract_alphabet_from_numeric_table(self.source)
        if alpha:
            self.alphabet = alpha
            self.diagnostics['alphabet'] = alpha[:10] + '...'
        else:
            self.diagnostics['alphabet_warning'] = 'no custom alphabet found'

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
        # Pure numeric escapes  \65\66  (check before anything else)
        if re.match(r'^(\\\d{1,3})+$', s):
            decoded = _decode_octal_string(s)
            if _is_readable_string(decoded):
                return decoded
            return s
        # Custom-alphabet base64 -- try BEFORE identifier check.
        # Prometheus encodes "workspace" -> "d29ya3NwYWNl" which looks like
        # a valid identifier but is actually encoded. Always attempt decode
        # when an alphabet is available.
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
        # Standard base64 fallback (handles strings without custom alphabet)
        try:
            padded = s + '=' * (-len(s) % 4)
            text = _b64std.b64decode(padded).decode('utf-8', errors='strict')
            if _is_readable_string(text):
                return text
        except Exception:
            pass
        # Keep as-is (plain identifier or unrecognised encoding)
        return s
