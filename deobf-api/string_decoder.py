import re
import base64
import logging

log = logging.getLogger(__name__)

STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

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

def _balance_braces(source: str, start_idx: int) -> int:
    depth = 1
    i = start_idx + 1
    while i < len(source) and depth > 0:
        if source[i] == '{':
            depth += 1
        elif source[i] == '}':
            depth -= 1
        i += 1
    return i if depth == 0 else -1

def extract_alphabet_enhanced(source: str):
    # Strategy 1: 64-char string literal
    for m in re.finditer(r'["\']([A-Za-z0-9+/]{64})["\']', source):
        candidate = m.group(1)
        if len(set(candidate)) == 64:
            return candidate

    # Strategy 2: Named mapping tables
    chars = [''] * 64
    found = False

    for m in re.finditer(r'(?:local\s+)?(?:N|alphaMap|aMap|alphabet|charMap|map|\w+)\s*=\s*\{', source):
        end = _balance_braces(source, m.end() - 1)
        if end == -1:
            continue
        body = source[m.end():end - 1]

        valid_entries = 0
        temp_chars = [''] * 64

        # Pattern: "char" = index
        for ch, idx in re.findall(r'["\']([A-Za-z0-9+/?])["\']\s*=\s*([+-]?[\d()+\-*/]+)', body):
            v = eval_arithmetic(idx)
            if v is not None and 0 <= v < 64:
                temp_chars[v] = ch
                valid_entries += 1

        # Pattern: [index] = "char"
        for idx, ch in re.findall(r'\[([+-]?[\d()+\-*/]+)\]\s*=\s*["\']([A-Za-z0-9+/?])["\']', body):
            v = eval_arithmetic(idx)
            if v is not None and 0 <= v < 64:
                temp_chars[v] = ch
                valid_entries += 1

        # Pattern: char = index (unquoted, single char)
        for ch, idx in re.findall(r'\b([A-Za-z0-9+/?])\s*=\s*([+-]?[\d()+\-*/]+)', body):
            v = eval_arithmetic(idx)
            if v is not None and 0 <= v < 64:
                if not temp_chars[v]:
                    temp_chars[v] = ch
                    valid_entries += 1

        # Detect renamed alphabet (multi-char keys)
        multi_char_entries = 0
        for key, idx in re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([+-]?[\d()+\-*/]+)', body):
            if len(key) > 1:
                v = eval_arithmetic(idx)
                if v is not None and 0 <= v < 64:
                    multi_char_entries += 1

        if valid_entries >= 10:
            chars = temp_chars
            found = True
            break
        elif multi_char_entries >= 10:
            return "RENAMED"

    if found:
        used = set(c for c in chars if c)
        for i in range(64):
            if not chars[i]:
                for c in STD_ALPHABET:
                    if c not in used:
                        chars[i] = c
                        used.add(c)
                        break
        return ''.join(chars)

    return None

def extract_strings_enhanced(source: str):
    known_names = ['EncStr', 'R', 'Y', 'S', 'T', 'Str', 'Strings', 'Data', 'Pool', 'E']
    for name in known_names:
        for prefix in [rf'local\s+{re.escape(name)}', rf'\b{re.escape(name)}']:
            pat = re.compile(rf'{prefix}\s*=\s*(\{{)', re.DOTALL)
            for m in pat.finditer(source):
                start = m.end() - 1
                end = _balance_braces(source, start)
                if end == -1:
                    continue
                body = source[start + 1:end - 1]
                strings = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
                if strings and len(strings) >= 2:
                    return strings, source[m.start():end]

    best = None
    best_score = 0
    best_match = None

    for m in re.finditer(r'(?:local\s+)?(\w+)\s*=\s*(\{)', source):
        start = m.end() - 1
        end = _balance_braces(source, start)
        if end == -1:
            continue
        body = source[start + 1:end - 1]
        strings = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
        if not strings or len(strings) < 5:
            continue
        score = 0
        for s in strings:
            if len(s) >= 4 and re.match(r'^[A-Za-z0-9+/=]+$', s):
                score += 3
            elif len(s) >= 10:
                score += 1
        if score >= 5 and score > best_score:
            best_score = score
            best = strings
            best_match = source[m.start():end]

    if best:
        return best, best_match
    return [], None

def extract_shuffle_ops(source: str):
    ops = []
    patterns = [
        r'ipairs\s*\(\s*\{([^}]+)\}\s*\)',
        r'for\s+\w+\s*,\s+\w+\s+in\s+ipairs\s*\(\s*\{([^}]+)\}\s*\)',
    ]
    for pat in patterns:
        m = re.search(pat, source)
        if m:
            body = m.group(1)
            for pair in re.finditer(r'\{([+-]?\d+)\s*,\s*([+-]?\d+)\}', body):
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
    translated = []
    for c in s:
        if c == '=':
            translated.append('=')
        else:
            translated.append(STD_ALPHABET[rev[c]])
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
    keywords = ['function', 'local', 'return', 'print', 'if', 'then', 'else', 'end', 'while', 'for', 'do', 'repeat', 'until']
    count = sum(1 for kw in keywords if kw in s)
    return count >= 2

def get_string_table_offset(source: str) -> int:
    patterns = [
        r'local\s+function\s+\w+\s*\(\s*\w+\s*\)\s*return\s+\w+\s*\[\s*\w+\s*\+\s*(\d+)\s*\]',
        r'\breturn\s+\w+\s*\[\s*\w+\s*\+\s*(\d+)\s*\]',
        r'\[\s*\w+\s*\+\s*(\d+)\s*\]',
    ]
    for pat in patterns:
        m = re.search(pat, source)
        if m:
            for g in m.groups():
                if g and g.strip().isdigit():
                    val = int(g.strip())
                    if 0 <= val <= 1000:
                        return val
                if g:
                    val = eval_arithmetic(g.strip())
                    if val is not None and 0 <= val <= 1000:
                        return int(val)
    return 0

class StringTableDecoder:
    def __init__(self, source: str):
        self.source = source
        self.strings = []
        self.alphabet = None
        self.offset = 0
        self.ok = False
        self.raw_match = None
        self.alphabet_renamed = False
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

        if self.alphabet == "RENAMED":
            self.alphabet_renamed = True
            self.alphabet = None

        alphabet_to_try = self.alphabet if self.alphabet else STD_ALPHABET

        decoded = []
        for s in raw:
            if not s:
                decoded.append('')
                continue

            s = decode_unicode_escapes(s)
            s = decode_hex_escapes(s)
            s = decode_octal_escapes(s)

            decoded_str = None

            if len(s) >= 4 and re.match(r'^[A-Za-z0-9+/=]+$', s):
                try:
                    b = custom_b64_decode(s, alphabet_to_try)
                    if b:
                        try:
                            text = b.decode('utf-8', errors='strict')
                            if is_lua_source(text):
                                decoded_str = text
                        except UnicodeDecodeError:
                            pass
                        if decoded_str is None:
                            try:
                                text = b.decode('latin-1', errors='replace')
                                if is_lua_source(text):
                                    decoded_str = text
                            except Exception:
                                pass
                except Exception:
                    pass

            if decoded_str is None:
                if len(s) >= 5 and is_printable(s) and not s.startswith('local'):
                    decoded_str = s
                else:
                    decoded_str = ''

            decoded.append(decoded_str)

        self.strings = decoded
        self.offset = get_string_table_offset(self.source)
        self.ok = len([s for s in self.strings if s]) > 0

    def get_source(self) -> str:
        for s in self.strings:
            if is_lua_source(s):
                return s

        code_keywords = {'function', 'local', 'return', 'print', 'if', 'then', 'else', 'end', 'while', 'for', 'do', 'repeat', 'until'}
        fragments = []
        for s in self.strings:
            if not s or len(s) < 5:
                continue
            if is_printable(s) and any(kw in s for kw in code_keywords):
                if re.search(r'\s', s) or '(' in s or ')' in s or ',' in s or '\n' in s or '=' in s:
                    fragments.append(s)

        if fragments:
            result = '\n'.join(fragments)
            if len(result) > 50:
                return result

        return ''
