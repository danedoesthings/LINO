import re, base64, string, itertools
from collections import Counter

class MultiStrategyStringDecoder:
    def __init__(self):
        self.strategies = [
            self._decode_xor_bruteforce,
            self._decode_substitution,
            self._decode_caesar,
            self._decode_reverse_concat,
        ]

    def decode_all(self, source):
        results = []
        string_literals = re.findall(r'"((?:[^"\\]|\\.)*)"', source)
        string_literals += re.findall(r"'((?:[^'\\]|\\.)*)'", source)
        for s in string_literals:
            for strategy in self.strategies:
                decoded = strategy(s)
                if decoded and len(decoded) > 10:
                    results.append(decoded)
        return results

    def _decode_xor_bruteforce(self, s):
        try:
            raw = s.encode('latin-1', errors='replace')
            for key in range(1, 256):
                decoded = bytes([b ^ key for b in raw])
                try:
                    text = decoded.decode('utf-8', errors='replace')
                    if any(kw in text for kw in ['function', 'local', 'end', 'loadstring']):
                        return text
                except Exception:
                    pass
        except Exception:
            pass
        return None

    def _decode_substitution(self, s):
        freq = Counter(s)
        common_chars = [c for c, _ in freq.most_common(5)]
        return None

    def _decode_caesar(self, s):
        return None

    def _decode_reverse_concat(self, s):
        parts = s.split('..')
        if len(parts) > 1:
            return ''.join(parts)
        return None
