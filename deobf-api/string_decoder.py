import re
import base64 as _b64std
from typing import Optional, List, Tuple, Dict

def _decode_octal_string(s: str) -> str:
    """Convert octal escapes like \123 to characters (Lua-style)"""
    result = []
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            # Handle \\123 format
            if s[i+1] == '\\' and i + 2 < len(s) and s[i+2].isdigit():
                i += 1
            # Parse 1-3 octal digits
            if i + 1 < len(s) and s[i+1].isdigit():
                j = i + 1
                while j < len(s) and s[j].isdigit() and j - i <= 4:
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
    """Safely evaluate arithmetic expressions"""
    expr = expr.strip()
    # Remove Lua-specific comments
    expr = re.sub(r'--[^\n]*', '', expr)
    expr = re.sub(r'\s+', '', expr)
    
    if not expr:
        return None
    
    # Handle simple number
    if expr.isdigit() or (expr[0] == '-' and expr[1:].isdigit()):
        return int(expr)
    
    # Handle arithmetic
    if re.match(r'^[\d\s\+\-\*\/\%\(\)]+$', expr):
        try:
            val = eval(expr, {"__builtins__": {}}, {})
            if isinstance(val, (int, float)):
                return int(val)
        except:
            pass
    return None


def _extract_alphabet_from_n_table(source: str) -> Optional[str]:
    """Extract custom base64 alphabet from N-table/alphaMap"""
    
    # Try to find the table by scanning for patterns
    table_start = None
    table_body = None
    
    # Method 1: Look for local N = { pattern
    patterns = [
        r'(?:local\s+)?N\s*=\s*(\{)',
        r'(?:local\s+)?alphaMap\s*=\s*(\{)',
        r'(?:local\s+)?ALPHABET\s*=\s*(\{)',
        r'(?:local\s+)?__ALPHABET\s*=\s*(\{)',
    ]
    
    for pattern in patterns:
        m = re.search(pattern, source)
        if m:
            table_start = m.start(1)
            break
    
    if table_start is None:
        # Method 2: Find any table with arithmetic values
        for m in re.finditer(r'local\s+(\w+)\s*=\s*\{', source):
            # Look ahead for arithmetic patterns
            preview = source[m.end():min(m.end()+1000, len(source))]
            if re.search(r'\d+\s*[+\-]\s*\d+', preview):
                table_start = m.end()
                break
    
    if table_start is None:
        return None
    
    # Find matching closing brace with proper nesting
    depth = 1
    end_pos = table_start + 1
    in_string = False
    escape = False
    
    while end_pos < len(source) and depth > 0:
        c = source[end_pos]
        if escape:
            escape = False
        elif c == '\\':
            escape = True
        elif c in ('"', "'"):
            in_string = not in_string
        elif not in_string:
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
        end_pos += 1
    
    if depth != 0:
        return None
    
    table_body = source[table_start:end_pos]
    
    # Extract alphabet mapping
    alphabet_chars = [''] * 64
    filled = 0
    
    # Pattern 1: ["A"] = 65-64 (or any arithmetic)
    for m in re.finditer(r'\[\s*["\']([^"\']+)["\']\s*\]\s*=\s*([^,;\n}]+)', table_body):
        key_char = m.group(1)
        expr = m.group(2)
        val = _eval_arithmetic(expr)
        if val is not None and 0 <= val <= 63 and len(key_char) == 1:
            if not alphabet_chars[val]:
                alphabet_chars[val] = key_char
                filled += 1
    
    # Pattern 2: A = 0, B = 1 style
    for m in re.finditer(r'([A-Za-z0-9+/])\s*=\s*([^,;\n}]+)', table_body):
        key_char = m.group(1)
        expr = m.group(2)
        val = _eval_arithmetic(expr)
        if val is not None and 0 <= val <= 63 and len(key_char) == 1:
            if not alphabet_chars[val]:
                alphabet_chars[val] = key_char
                filled += 1
    
    # Pattern 3: [0] = 'A' style
    for m in re.finditer(r'\[\s*(\d+)\s*\]\s*=\s*["\']([^"\']+)["\']', table_body):
        idx = int(m.group(1))
        char = m.group(2)
        if 0 <= idx <= 63 and len(char) == 1 and not alphabet_chars[idx]:
            alphabet_chars[idx] = char
            filled += 1
    
    # If we have at least 40 characters, fill the rest with standard alphabet
    if filled >= 40:
        std_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        used = set(alphabet_chars)
        for i in range(64):
            if not alphabet_chars[i]:
                for c in std_alphabet:
                    if c not in used:
                        alphabet_chars[i] = c
                        used.add(c)
                        break
        
        alphabet = ''.join(alphabet_chars)
        if len(alphabet) == 64:
            return alphabet
    
    return None


def _extract_shuffle_ops(source: str) -> List[Tuple[int, int]]:
    """Extract shuffle operations from ipairs table"""
    ops = []
    
    # Look for shuffle table
    shuffle_patterns = [
        r'ipairs\s*\(\s*(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})\s*\)',
        r'local\s+\w+\s*=\s*(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})',
    ]
    
    table_content = None
    for pattern in shuffle_patterns:
        m = re.search(pattern, source, re.DOTALL)
        if m:
            table_content = m.group(1)
            break
    
    if table_content:
        # Extract pairs like {1,45}, {1,31}
        for pair in re.finditer(r'\{(\d+)\s*,\s*(\d+)\}', table_content):
            try:
                a = int(pair.group(1))
                b = int(pair.group(2))
                ops.append((a, b))
            except:
                pass
    
    return ops


def _apply_shuffle(strings: List[str], ops: List[Tuple[int, int]]) -> List[str]:
    """Apply shuffle operations to reorder strings"""
    result = list(strings)
    for a, b in ops:
        lo, hi = a - 1, b - 1
        if 0 <= lo < len(result) and 0 <= hi < len(result):
            # Reverse the segment
            while lo < hi:
                result[lo], result[hi] = result[hi], result[lo]
                lo += 1
                hi -= 1
    return result


def _custom_b64_decode(s: str, alphabet: str) -> Optional[bytes]:
    """Decode base64 with custom alphabet"""
    if not alphabet or len(alphabet) != 64:
        return None
    
    # Build reverse mapping
    rev = {c: i for i, c in enumerate(alphabet)}
    
    # Check if all characters are valid
    for c in s.rstrip('='):
        if c not in rev:
            return None
    
    # Translate to standard base64
    std_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    translated = ''.join(std_alphabet[rev[c]] for c in s)
    
    # Fix padding
    padding = (4 - len(translated) % 4) % 4
    if padding:
        translated += '=' * padding
    
    try:
        return _b64std.b64decode(translated)
    except:
        return None


def _is_readable_string(s: str) -> bool:
    """Check if string is mostly printable"""
    if not s:
        return False
    # Check if it contains Lua code patterns
    lua_patterns = ['function', 'local', 'return', 'print', 'if', 'then', 'else', 'end', 'while', 'for']
    if any(p in s for p in lua_patterns):
        return True
    # Check printable ratio
    printable = sum(1 for c in s if 32 <= ord(c) <= 126 or c in '\n\r\t')
    return printable / max(len(s), 1) >= 0.70


def _extract_raw_octal_strings(source: str) -> Optional[List[str]]:
    """Extract string table from source"""
    patterns = [
        r'local\s+EncStr\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
        r'local\s+R\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
        r'local\s+__STR__\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
    ]
    
    for pattern in patterns:
        m = re.search(pattern, source, re.DOTALL)
        if not m:
            continue
        
        body = m.group(1)
        # Find all quoted strings
        strings = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
        if len(strings) >= 2:
            return strings
    
    return None


def get_string_table_offset(source: str) -> int:
    """Extract offset value from getter function"""
    # Look for patterns like return R[idx + offset]
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
    def __init__(self, source: str) -> None:
        self.source = source
        self.ok = False
        self.strings: List[str] = []
        self.alphabet: str = ''
        self.offset: int = 0
        self.diagnostics: Dict = {}
        self._decode()

    def _decode(self) -> None:
        """Main decode entry point"""
        # Step 1: Extract raw strings
        raw_strings = _extract_raw_octal_strings(self.source)
        if not raw_strings:
            self.diagnostics['error'] = 'String table not found'
            return
        
        self.diagnostics['raw_count'] = len(raw_strings)
        
        # Step 2: Apply shuffle if present
        ops = _extract_shuffle_ops(self.source)
        if ops:
            self.diagnostics['shuffle_ops'] = ops
            shuffled = _apply_shuffle(raw_strings, ops)
        else:
            shuffled = raw_strings
        
        # Step 3: Extract custom alphabet
        self.alphabet = _extract_alphabet_from_n_table(self.source)
        if self.alphabet:
            self.diagnostics['alphabet'] = f"Found {len(self.alphabet)} chars"
        else:
            self.diagnostics['alphabet_warning'] = 'No custom alphabet, using standard'
            self.alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        
        # Step 4: Decode each string
        decoded_strings = []
        for s in shuffled:
            decoded = self._decode_string(s)
            if decoded and len(decoded) > 0:
                decoded_strings.append(decoded)
            else:
                decoded_strings.append(s)
        
        self.strings = decoded_strings
        self.offset = get_string_table_offset(self.source)
        self.diagnostics['offset'] = self.offset
        self.diagnostics['decoded_count'] = len([s for s in self.strings if s])
        self.ok = len(self.strings) > 0
        
        # Log what we got
        if self.strings:
            self.diagnostics['first_string'] = self.strings[0][:50] if self.strings[0] else 'empty'
            self.diagnostics['last_string'] = self.strings[-1][:50] if self.strings[-1] else 'empty'

    def _decode_string(self, s: str) -> str:
        """Decode a single string entry"""
        if not s:
            return ''
        
        # Handle octal-escaped strings
        if '\\' in s:
            # Decode octal escapes first
            try:
                decoded = _decode_octal_string(s)
            except:
                decoded = s
            
            # Try custom base64 decode
            if self.alphabet:
                try:
                    raw = _custom_b64_decode(decoded, self.alphabet)
                    if raw:
                        for enc in ['utf-8', 'latin-1']:
                            try:
                                text = raw.decode(enc)
                                if _is_readable_string(text):
                                    return text
                            except:
                                pass
                except:
                    pass
            
            if _is_readable_string(decoded):
                return decoded
            return s
        
        # Handle direct base64
        if self.alphabet and len(s) >= 4:
            try:
                raw = _custom_b64_decode(s, self.alphabet)
                if raw:
                    for enc in ['utf-8', 'latin-1']:
                        try:
                            text = raw.decode(enc)
                            if _is_readable_string(text):
                                return text
                        except:
                            pass
            except:
                pass
        
        return s if _is_readable_string(s) else ''
