
import re
import json
from typing import Optional, List
from math_fold import safe_eval_int, fold_constants


class PrometheusDecoder:
    def __init__(self, source: str, decoder):
        self.source = source
        self.decoder = decoder
        self.strings = list(decoder.strings)
        self.offset = decoder.offset
        self.getter_name = None
        self.shuffle_pairs = []
        self._detect_getter()
        self._extract_shuffle_pairs()

    def _detect_getter(self):
        folded = fold_constants(self.source)
        patterns = [
            r'local\s+function\s+(\w+)\s*\(\s*\1\s*\)\s*return\s+R\s*\[\s*\1\s*\+\s*\(?(-?\d+)\)?\s*\]',
            r'local\s+function\s+(\w+)\s*\(\s*\1\s*\)\s*return\s+R\s*\[\s*\1\s*\+\s*(-?\d+)\s*\]',
        ]
        for p in patterns:
            m = re.search(p, folded)
            if m:
                self.getter_name = m.group(1)
                self.offset = int(m.group(2))
                return

    def _extract_shuffle_pairs(self):
        ipairs_match = re.search(r'ipairs\s*\(\s*\{([^}]+)\}\s*\)', self.source, re.DOTALL)
        if not ipairs_match:
            return
        body = ipairs_match.group(1)
        pairs = re.findall(r'\{([^}]+)\}', body)
        for pair_str in pairs:
            parts = re.split(r'[;,]', pair_str)
            resolved = []
            for part in parts:
                part = part.strip()
                if not part:
                    continue
                n = safe_eval_int(part)
                if n is not None:
                    resolved.append(n)
            if len(resolved) == 2:
                self.shuffle_pairs.append(tuple(resolved))

    def _apply_shuffle(self, arr: List[str]) -> List[str]:
        result = list(arr)
        for a, b in self.shuffle_pairs:
            lo, hi = a - 1, b - 1
            while lo < hi:
                if 0 <= lo < len(result) and 0 <= hi < len(result):
                    result[lo], result[hi] = result[hi], result[lo]
                lo += 1
                hi -= 1
        return result

    def decode(self) -> Optional[str]:
        if not self.strings or len(self.strings) < 4:
            return None

        if self.shuffle_pairs:
            payload = self._try_shuffled_assembly()
            if payload:
                return payload

        payload = self._try_keyword_ordered_assembly()
        if payload:
            return payload

        return None

    def _try_shuffled_assembly(self) -> Optional[str]:
        shuffled = self._apply_shuffle(self.strings)
        payload_keywords = {'print', 'function', 'local', 'return', 'loadstring', 'pcall', 'game', 'workspace', 'error'}

        for i, s in enumerate(shuffled):
            if s and s in payload_keywords:
                parts = []
                for j in range(i, len(shuffled)):
                    part = shuffled[j]
                    if part and self._is_source_fragment(part):
                        parts.append(part)
                if parts:
                    result = self._join_fragments(parts)
                    if len(result) > 10 and any(kw in result for kw in payload_keywords):
                        return result

        return None

    def _try_keyword_ordered_assembly(self) -> Optional[str]:
        payload_keywords = {'print', 'function', 'local', 'return', 'loadstring', 'pcall', 'game', 'workspace', 'error'}

        for kw in payload_keywords:
            if kw in self.strings:
                idx = self.strings.index(kw)
                parts = []
                for s in self.strings[idx:]:
                    if s and self._is_source_fragment(s):
                        parts.append(s)
                if parts:
                    result = self._join_fragments(parts)
                    if len(result) > 10 and any(kw in result for kw in payload_keywords):
                        return result
        return None

    def _is_source_fragment(self, s: str) -> bool:
        if len(s) == 0:
            return False
        if len(s) > 500:
            return False
        source_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.,;:!?()[]{}\'\"=+-*/<>@# \t\n\r')
        non_source = sum(1 for c in s if c not in source_chars)
        if non_source > len(s) * 0.1:
            return False
        return True

    def _join_fragments(self, parts: List[str]) -> str:
        result_parts = []
        for part in parts:
            if result_parts and self._needs_space_before(part):
                result_parts.append(' ')
            result_parts.append(part)
        return ''.join(result_parts)

    def _needs_space_before(self, part: str) -> bool:
        if not part:
            return False
        no_space_after = set('.,;:)]}\'\"')
        no_space_before = set('.,;:)]}\'\"')
        if part[0] in no_space_before:
            return False
        return True
