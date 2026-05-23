import re, base64, struct, string, itertools
from collections import Counter

class BaseLifter:
    def _unescape_lua_string(self, s):
        result = []
        i = 0
        while i < len(s):
            if s[i] == '\\' and i + 1 < len(s):
                nc = s[i+1]
                if nc == 'n': result.append('\n')
                elif nc == 'r': result.append('\r')
                elif nc == 't': result.append('\t')
                elif nc == '\\': result.append('\\')
                elif nc == '"': result.append('"')
                elif nc == "'": result.append("'")
                elif nc == '0': result.append('\0')
                elif nc.isdigit():
                    j = i + 1
                    while j < len(s) and s[j].isdigit() and j - i <= 4:
                        j += 1
                    try:
                        code = int(s[i+1:j])
                        result.append(chr(code % 256))
                        i = j - 1
                    except ValueError:
                        result.append(s[i])
                else:
                    result.append(s[i])
                i += 2
            else:
                result.append(s[i])
                i += 1
        return ''.join(result)

class AdvancedWeAreDevsLifter(BaseLifter):
    def lift(self, source):
        results = []
        string_tables = self._find_all_string_tables(source)
        b64_maps = self._find_all_b64_maps(source)
        shuffle_sets = self._find_all_shuffle_sets(source)
        for str_table in string_tables:
            working = list(str_table)
            for shuf in shuffle_sets:
                working = self._apply_shuffle(working, shuf)
            for b64_map in b64_maps:
                for s in working:
                    decoded = self._decode_custom_b64(s, b64_map)
                    if decoded and len(decoded) > 4:
                        results.append(decoded)
        iife_tables = self._find_iife_inline_tables(source)
        for tbl in iife_tables:
            working = list(tbl)
            for shuf in shuffle_sets:
                working = self._apply_shuffle(working, shuf)
            for b64_map in b64_maps:
                for s in working:
                    decoded = self._decode_custom_b64(s, b64_map)
                    if decoded and len(decoded) > 4:
                        results.append(decoded)
        return results

    def _find_all_string_tables(self, source):
        tables = []
        for m in re.finditer(r'local\s+(\w+)\s*=\s*\{([^}]+)\}', source):
            body = m.group(2)
            strings = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
            if len(strings) >= 4:
                decoded = [self._unescape_lua_string(s) for s in strings]
                if any(len(s) > 20 for s in decoded):
                    tables.append(decoded)
        for m in re.finditer(r'(\w+)\s*=\s*\{([^}]+)\}', source):
            body = m.group(2)
            strings = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
            if len(strings) >= 4:
                decoded = [self._unescape_lua_string(s) for s in strings]
                if any(len(s) > 20 for s in decoded):
                    tables.append(decoded)
        return tables

    def _find_iife_inline_tables(self, source):
        tables = []
        for m in re.finditer(r'\(\s*function\s*\([^)]*\)\s*.*?end\s*\)\s*\(\s*(\{[^}]*\})\s*\)', source, re.DOTALL):
            table_body = m.group(1)
            strings = re.findall(r'"((?:[^"\\]|\\.)*)"', table_body)
            if len(strings) >= 4:
                decoded = [self._unescape_lua_string(s) for s in strings]
                if any(len(s) > 20 for s in decoded):
                    tables.append(decoded)
        for m in re.finditer(r'\(\s*function\s*\([^)]*\)\s*.*?end\s*\)\s*\(\s*(\{.*?\})\s*\)', source, re.DOTALL):
            table_raw = m.group(1)
            table_body = self._extract_balanced_braces(source, m.start(1))
            if table_body:
                strings = re.findall(r'"((?:[^"\\]|\\.)*)"', table_body)
                if len(strings) >= 4:
                    decoded = [self._unescape_lua_string(s) for s in strings]
                    if any(len(s) > 20 for s in decoded):
                        tables.append(decoded)
        return tables

    def _extract_balanced_braces(self, text, start):
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
            i += 1
        return None

    def _find_all_b64_maps(self, source):
        maps = []
        for m in re.finditer(r'local\s+\w+\s*=\s*\{([^}]{60,})\}', source):
            body = m.group(1)
            entries = re.findall(r'\[(\d+)\]\s*=\s*"(.+?)"', body)
            if not entries:
                entries = re.findall(r'"(.+?)"', body)
                if entries:
                    entries = [(str(i), entries[i]) for i in range(len(entries))]
            if len(entries) >= 62:
                cmap = {}
                for idx_str, val in entries:
                    try:
                        cmap[int(idx_str)] = val
                    except ValueError:
                        continue
                if len(cmap) >= 62:
                    maps.append(cmap)
        return maps

    def _find_all_shuffle_sets(self, source):
        sets = []
        for m in re.finditer(r'for\s+\w+\s*=\s*(\d+)\s*,\s*(\d+)\s*do\s+(\w+)\[(\w+)\]\s*=\s*(\w+)\[(\w+)\]', source):
            try:
                start = int(m.group(1))
                end = int(m.group(2))
                src_var = m.group(5)
                dst_var = m.group(3)
                pairs = []
                for assign in re.finditer(rf'{re.escape(src_var)}\[(\d+)\]\s*=\s*{re.escape(dst_var)}\[(\d+)\]', source):
                    a = int(assign.group(2))
                    b = int(assign.group(1))
                    pairs.append((a, b))
                if len(pairs) >= 2:
                    sets.append(pairs)
            except:
                pass
        for m in re.finditer(r'local\s+\w+\s*=\s*\{([\d,\s]+)\}', source):
            nums = re.findall(r'\d+', m.group(1))
            if len(nums) >= 4 and len(nums) % 2 == 0:
                pairs = []
                for i in range(0, len(nums), 2):
                    pairs.append((int(nums[i]), int(nums[i+1])))
                sets.append(pairs)
        return sets

    def _apply_shuffle(self, arr, pairs):
        result = list(arr)
        for a, b in pairs:
            lo, hi = a-1, b-1
            if 0 <= lo < len(result) and 0 <= hi < len(result) and lo < hi:
                result[lo:hi+1] = result[lo:hi+1][::-1]
        return result

    def _decode_custom_b64(self, encoded, cmap):
        if len(cmap) < 64:
            return None
        reverse_map = {}
        for k, v in cmap.items():
            if isinstance(v, str) and len(v) >= 1:
                reverse_map[v] = k
        if not reverse_map:
            return None
        bit_buf = 0
        bits = 0
        out = bytearray()
        for c in encoded:
            if c == '=':
                break
            if c not in reverse_map:
                continue
            val = reverse_map[c]
            bit_buf = (bit_buf << 6) | val
            bits += 6
            while bits >= 8:
                bits -= 8
                out.append((bit_buf >> bits) & 0xFF)
        return bytes(out)

class MoonSecLifter(BaseLifter):
    def lift(self, source):
        results = []
        b64_tables = self._find_moonsec_tables(source)
        for table in b64_tables:
            encoded_strings = self._extract_moonsec_strings(source)
            for enc in encoded_strings:
                decoded = self._decode_moonsec(enc, table)
                if decoded and len(decoded) > 4:
                    results.append(decoded)
        return results

    def _find_moonsec_tables(self, source):
        tables = []
        for m in re.finditer(r'local\s+(\w+)\s*=\s*\{([^}]{64,})\}', source):
            body = m.group(2)
            chars = re.findall(r'"(.+?)"', body)
            if len(chars) >= 62:
                tables.append(chars)
        return tables

    def _extract_moonsec_strings(self, source):
        strings = []
        for m in re.finditer(r'(\w+)\[(\d+)\]\s*=\s*"([^"]+)"', source):
            strings.append(m.group(3))
        for m in re.finditer(r'"((?:[A-Za-z0-9+/=]{40,}))"', source):
            candidate = m.group(1)
            if len(candidate) >= 40 and all(c in string.ascii_letters + string.digits + '+/=' for c in candidate):
                strings.append(candidate)
        return strings

    def _decode_moonsec(self, encoded, table):
        try:
            if len(table) < 64:
                table = list(table) + ['='] * (64 - len(table))
            reverse = {table[i]: i for i in range(64) if i < len(table)}
            bit_buf = 0
            bits = 0
            out = bytearray()
            for c in encoded:
                if c == '=':
                    break
                if c not in reverse:
                    continue
                bit_buf = (bit_buf << 6) | reverse[c]
                bits += 6
                if bits >= 8:
                    bits -= 8
                    out.append((bit_buf >> bits) & 0xFF)
            return bytes(out)
        except Exception:
            return None

class IronBrewLifter(BaseLifter):
    def lift(self, source):
        results = []
        xor_keys = self._find_xor_keys(source)
        encoded_chunks = self._find_encoded_chunks(source)
        for chunk in encoded_chunks:
            for key in xor_keys:
                decoded = self._xor_decode(chunk, key)
                if decoded:
                    results.append(decoded)
        return results

    def _find_xor_keys(self, source):
        keys = []
        for m in re.finditer(r'local\s+\w+\s*=\s*(\d+)', source):
            keys.append(int(m.group(1)))
        for m in re.finditer(r'string\.byte\("(\w+)"\)', source):
            keys.append(m.group(1).encode('latin-1')[0] if m.group(1) else 0)
        for m in re.finditer(r'\\\d{2,3}', source):
            val = int(m.group(0)[1:])
            if 1 <= val <= 255:
                keys.append(val)
        if not keys:
            keys = list(range(1, 256))
        return list(set(keys))[:50]

    def _find_encoded_chunks(self, source):
        chunks = []
        for m in re.finditer(r'\{([\d,\s]{20,})\}', source):
            nums = re.findall(r'\d+', m.group(1))
            if len(nums) >= 10:
                chunks.append(bytes([int(n) % 256 for n in nums]))
        patterns = [
            r'"((?:\\\d{1,3}){12,})"',
            r"'((?:\\\d{1,3}){12,})'",
        ]
        for pat in patterns:
            for m in re.finditer(pat, source):
                escaped = m.group(1)
                decoded = self._decode_escapes(escaped)
                if decoded and len(decoded) >= 12:
                    chunks.append(decoded)
        return chunks

    def _xor_decode(self, data, key):
        try:
            result = bytes([b ^ key for b in data])
            if result[:4] == b'\x1bLua':
                return result
            try:
                text = result.decode('utf-8', errors='replace')
                if any(kw in text for kw in ['function', 'local', 'end', 'loadstring']):
                    return text
            except Exception:
                pass
            return result
        except Exception:
            return None

    @staticmethod
    def _decode_escapes(s):
        result = bytearray()
        i = 0
        while i < len(s):
            if s[i] == '\\' and i + 1 < len(s):
                j = i + 1
                while j < len(s) and s[j].isdigit():
                    j += 1
                if j > i + 1:
                    result.append(int(s[i+1:j]) % 256)
                    i = j
                else:
                    i += 1
            else:
                i += 1
        return bytes(result)

class PSULifter(BaseLifter):
    def lift(self, source):
        results = []
        loadstring_calls = re.findall(r'loadstring\s*\(\s*([^)]+)\s*\)', source)
        for call in loadstring_calls:
            decoded = self._evaluate_expression(call, source)
            if decoded:
                results.append(decoded)
        pcall_load = re.findall(r'pcall\s*\(\s*loadstring\s*\(\s*([^)]+)\s*\)', source)
        for call in pcall_load:
            decoded = self._evaluate_expression(call, source)
            if decoded:
                results.append(decoded)
        return results

    def _evaluate_expression(self, expr, source):
        expr = expr.strip().strip('"').strip("'")
        func_match = re.search(r'(\w+)\s*\(', expr)
        if func_match:
            func_name = func_match.group(1)
            func_def = re.search(
                rf'local\s+function\s+{func_name}\s*\([^)]*\)\s*(.*?)\s*end',
                source, re.DOTALL
            )
            if func_def:
                return f'[{func_name} function body]'
        return None

class XORStringDecoder(BaseLifter):
    def lift(self, source):
        results = []
        encoded_arrays = re.findall(r'\{\s*([\d,\s]{30,})\s*\}', source)
        for arr_str in encoded_arrays:
            nums = [int(n.strip()) for n in arr_str.split(',') if n.strip().isdigit()]
            if len(nums) < 10:
                continue
            for key in range(1, 256):
                decoded = bytes([(n ^ key) % 256 for n in nums])
                try:
                    text = decoded.decode('utf-8', errors='replace')
                    if any(kw in text for kw in ['function', 'local', 'end', 'print']):
                        results.append(text)
                    elif decoded[:4] == b'\x1bLua':
                        results.append(decoded)
                except Exception:
                    pass
        return results

class NumberArrayDecoder(BaseLifter):
    def lift(self, source):
        results = []
        patterns = [
            r'string\.char\s*\(\s*([\d,\s]+)\s*\)',
            r'string\.char%(([\d,\s]+)%)',
        ]
        for pat in patterns:
            for m in re.finditer(pat, source):
                nums = [int(n.strip()) for n in m.group(1).split(',') if n.strip().isdigit()]
                if nums:
                    decoded = bytes(nums)
                    try:
                        text = decoded.decode('utf-8', errors='replace')
                        if len(text) > 5:
                            results.append(text)
                    except Exception:
                        results.append(decoded)
        return results

class StandardBase64Decoder(BaseLifter):
    def lift(self, source):
        results = []
        b64_pattern = r'"([A-Za-z0-9+/=]{40,})"'
        for m in re.finditer(b64_pattern, source):
            candidate = m.group(1)
            try:
                decoded = base64.b64decode(candidate)
                if decoded[:4] == b'\x1bLua':
                    results.append(decoded)
                try:
                    text = decoded.decode('utf-8', errors='replace')
                    if any(kw in text for kw in ['function', 'local', 'end']):
                        results.append(text)
                except Exception:
                    pass
            except Exception:
                pass
        return results

class StringPatternExtractor:
    @staticmethod
    def extract_all(source):
        patterns = {
            'double_quoted': r'"((?:[^"\\]|\\.)*)"',
            'single_quoted': r"'((?:[^'\\]|\\.)*)'",
            'long_bracket': r'\[=*\[(.*?)\]=*\]',
            'concat_chain': r'(\w+)\s*\.\.\s*(\w+)(?:\s*\.\.\s*(\w+))*',
        }
        results = []
        for name, pat in patterns.items():
            for m in re.finditer(pat, source, re.DOTALL):
                results.append(m.group(0))
        return results

class BytecodeHarvester:
    LUA_SIGNATURE = b'\x1bLua'
    LUA_VERSION_OFFSET = 4

    def extract(self, data):
        if not isinstance(data, bytes):
            data = data.encode('latin-1', errors='replace')
        idx = data.find(self.LUA_SIGNATURE)
        while idx != -1:
            if idx + 5 <= len(data):
                version = data[idx + self.LUA_VERSION_OFFSET]
                if version in (0x50, 0x51, 0x52, 0x53, 0x54):
                    end = self._find_bytecode_end(data, idx)
                    if end and end > idx:
                        return data[idx:end]
            idx = data.find(self.LUA_SIGNATURE, idx + 1)
        return None

    def deep_scan(self, source):
        if isinstance(source, str):
            data = source.encode('latin-1', errors='replace')
        else:
            data = source
        found = self.extract(data)
        if found:
            return found
        decoded_base64 = self._try_all_base64(data)
        if decoded_base64:
            return self.extract(decoded_base64)
        return None

    def _find_bytecode_end(self, data, start):
        try:
            if start + 12 > len(data):
                return None
            header_size = data[start + 5]
            if start + header_size + 1 > len(data):
                return None
            size_upvalues = data[start + 7]
            size_params = data[start + 11]
            ptr = start + header_size + 1
            if ptr >= len(data):
                return None
            size_code = struct.unpack('<I', data[ptr:ptr+4])[0]
            ptr += 4 + size_code * 4
            if ptr + 4 > len(data):
                return None
            size_constants = struct.unpack('<I', data[ptr:ptr+4])[0]
            ptr += 4
            for _ in range(size_constants):
                if ptr >= len(data):
                    return None
                const_type = data[ptr]
                ptr += 1
                if const_type == 4:
                    if ptr + 4 > len(data):
                        return None
                    str_len = struct.unpack('<I', data[ptr:ptr+4])[0]
                    ptr += 4 + str_len
                elif const_type == 3:
                    ptr += 8
                elif const_type == 1:
                    ptr += 1
            if ptr + 4 > len(data):
                return None
            size_protos = struct.unpack('<I', data[ptr:ptr+4])[0]
            ptr += 4
            for _ in range(size_protos):
                sub_end = self._find_bytecode_end(data, ptr)
                if sub_end:
                    ptr = sub_end
            return ptr
        except Exception:
            return len(data)

    @staticmethod
    def _try_all_base64(data):
        b64_chars = set(string.ascii_letters + string.digits + '+/=')
        candidates = re.findall(rb'[A-Za-z0-9+/=]{40,}', data)
        for candidate in candidates:
            try:
                decoded = base64.b64decode(candidate)
                if decoded[:4] == b'\x1bLua':
                    return decoded
            except Exception:
                continue
        return None
