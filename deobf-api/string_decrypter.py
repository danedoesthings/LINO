import re
import base64
import string
from typing import Optional, List

class StringDecrypter:
    def __init__(self):
        pass

    def decrypt_all(self, source: str) -> List[str]:
        results = []
        results.extend(self._decrypt_xor(source))
        results.extend(self._decrypt_base64(source))
        results.extend(self._decrypt_character_codes(source))
        results.extend(self._decrypt_byte_arrays(source))
        results.extend(self._decrypt_number_arrays(source))
        return results

    def _decrypt_xor(self, source: str) -> List[str]:
        results = []
        patterns = [
            r'local\s+\w+\s*=\s*(\d+)',
            r'string\.byte\("(\w+)"\)',
        ]
        xor_keys = []
        for pat in patterns:
            for m in re.finditer(pat, source):
                try:
                    key = int(m.group(1))
                    if 1 <= key <= 255:
                        xor_keys.append(key)
                except ValueError:
                    pass
        xor_keys = list(set(xor_keys))[:20]
        if not xor_keys:
            return results
        encoded_chunks = []
        for m in re.finditer(r'\{([\d,\s]{20,})\}', source):
            nums = re.findall(r'\d+', m.group(1))
            if len(nums) >= 10:
                encoded_chunks.append(bytes([int(n) % 256 for n in nums]))
        for m in re.finditer(r'"((?:\\\d{1,3}){12,})"', source):
            escaped = m.group(1)
            decoded = self._decode_octal_escapes(escaped)
            if decoded and len(decoded) >= 12:
                encoded_chunks.append(decoded)
        for chunk in encoded_chunks[:10]:
            for key in xor_keys:
                try:
                    decoded = bytes([b ^ key for b in chunk])
                    try:
                        text = decoded.decode('utf-8', errors='replace')
                        if self._is_likely_code(text):
                            results.append(text)
                    except:
                        pass
                except:
                    pass
        return results

    def _decrypt_base64(self, source: str) -> List[str]:
        results = []
        for m in re.finditer(r'"([A-Za-z0-9+/=]{40,})"', source):
            candidate = m.group(1)
            try:
                decoded = base64.b64decode(candidate)
                try:
                    text = decoded.decode('utf-8', errors='replace')
                    if self._is_likely_code(text):
                        results.append(text)
                except:
                    pass
            except:
                pass
        return results

    def _decrypt_character_codes(self, source: str) -> List[str]:
        results = []
        for m in re.finditer(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', source):
            nums = [int(n.strip()) for n in m.group(1).split(',') if n.strip().isdigit()]
            if len(nums) >= 4:
                decoded = bytes(nums)
                try:
                    text = decoded.decode('utf-8', errors='replace')
                    if self._is_likely_code(text):
                        results.append(text)
                except:
                    pass
        for m in re.finditer(r'table\.concat\s*\(\s*\{([^}]+)\}\s*\)', source):
            inner = m.group(1)
            chars = re.findall(r'string\.char\s*\(\s*(\d+)\s*\)', inner)
            if len(chars) >= 4:
                decoded = bytes([int(c) for c in chars])
                try:
                    text = decoded.decode('utf-8', errors='replace')
                    if self._is_likely_code(text):
                        results.append(text)
                except:
                    pass
        return results

    def _decrypt_byte_arrays(self, source: str) -> List[str]:
        results = []
        for m in re.finditer(r'string\.byte\s*\(\s*("[^"]+")\s*\)', source):
            s = m.group(1).strip('"')
            bytes_list = [str(ord(c)) for c in s]
            results.append(f"-- byte array: {', '.join(bytes_list)}")
        return results

    def _decrypt_number_arrays(self, source: str) -> List[str]:
        results = []
        for m in re.finditer(r'\{\s*([\d,\s]{30,})\s*\}', source):
            nums = [int(n.strip()) for n in m.group(1).split(',') if n.strip().isdigit()]
            if len(nums) >= 4:
                decoded = bytes(nums)
                try:
                    text = decoded.decode('utf-8', errors='replace')
                    if self._is_likely_code(text):
                        results.append(text)
                except:
                    pass
        return results

    def _decode_octal_escapes(self, s: str) -> Optional[bytes]:
        result = bytearray()
        i = 0
        while i < len(s):
            if s[i] == '\\' and i + 1 < len(s):
                j = i + 1
                while j < len(s) and s[j].isdigit():
                    j += 1
                if j > i + 1:
                    try:
                        result.append(int(s[i+1:j]) % 256)
                        i = j
                        continue
                    except ValueError:
                        pass
            i += 1
        return bytes(result) if len(result) > 0 else None

    def _is_likely_code(self, text: str) -> bool:
        if len(text) < 20:
            return False
        keywords = ['function', 'local', 'end', 'return', 'if', 'then', 'else', 'for', 'while', 'do', 'print', 'loadstring', 'require', 'game', 'workspace', 'http', 'pcall', 'error']
        found = sum(1 for kw in keywords if kw in text.lower())
        return found >= 2
