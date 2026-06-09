import re
import json
from typing import Optional, List
from string_decoder import is_lua_source, is_printable
from math_fold import safe_eval_int, fold_constants, get_getter_name_and_offset

class PrometheusDecoder:
    def __init__(self, source: str, decoder):
        self.source = source
        self.decoder = decoder
        self.strings = list(decoder.strings) if decoder else []
        self.offset = decoder.offset if decoder else 0
        self.getter_name = None
        self.table_name = None
        self.shuffle_pairs = []
        self._detect_getter()
        self._extract_shuffle_pairs()

    def _detect_getter(self):
        g, t, off = get_getter_name_and_offset(self.source)
        if g:
            self.getter_name = g
            self.table_name = t
            self.offset = off
            return

        folded = fold_constants(self.source)
        patterns = [
            r'local\s+function\s+(\w+)\s*\(\s*\w+\s*\)\s*return\s+R\s*\[\s*\w+\s*\+\s*\(?(-?\d+)\)?\s*\]',
            r'local\s+function\s+(\w+)\s*\(\s*\w+\s*\)\s*return\s+EncStr\s*\[\s*\w+\s*\+\s*\(?(-?\d+)\)?\s*\]',
            r'local\s+function\s+(\w+)\s*\(\s*\w+\s*\)\s*return\s+(\w+)\s*\[\s*\w+\s*\+\s*\(?(-?\d+)\)?\s*\]',
        ]
        for pat in patterns:
            m = re.search(pat, folded)
            if m:
                self.getter_name = m.group(1)
                if len(m.groups()) >= 3:
                    self.offset = int(m.group(3))
                    self.table_name = m.group(2)
                else:
                    self.offset = int(m.group(2))
                return

    def _extract_shuffle_pairs(self):
        m = re.search(r'ipairs\s*\(\s*\{([^}]+)\}\s*\)', self.source, re.DOTALL)
        if not m:
            return
        for pair_str in re.findall(r'\{([^}]+)\}', m.group(1)):
            parts = re.split(r'[;,]', pair_str)
            resolved = [safe_eval_int(p.strip()) for p in parts if p.strip()]
            resolved = [n for n in resolved if n is not None]
            if len(resolved) == 2:
                self.shuffle_pairs.append(tuple(resolved))

    def _apply_shuffle(self, arr: List[str]) -> List[str]:
        result = list(arr)
        for a, b in self.shuffle_pairs:
            lo, hi = a - 1, b - 1
            if 0 <= lo < hi < len(result):
                result[lo:hi + 1] = list(reversed(result[lo:hi + 1]))
        return result

    def decode(self) -> Optional[str]:
        if not self.strings or len(self.strings) < 4:
            return None

        payload = self._try_shuffled_assembly()
        if payload:
            return payload

        payload = self._try_keyword_ordered_assembly()
        if payload:
            return payload

        payload = self._try_getter_substitution()
        if payload:
            return payload

        return None

    def _try_shuffled_assembly(self) -> Optional[str]:
        if not self.shuffle_pairs:
            return None
        shuffled = self._apply_shuffle(self.strings)
        return self._assemble_from_list(shuffled)

    def _try_keyword_ordered_assembly(self) -> Optional[str]:
        return self._assemble_from_list(self.strings)

    def _assemble_from_list(self, strings: List[str]) -> Optional[str]:
        payload_keywords = {'print', 'function', 'local', 'return', 'loadstring', 'pcall', 'while', 'for', 'if', 'then', 'end'}

        for i, s in enumerate(strings):
            if s and s in payload_keywords:
                parts = [strings[j] for j in range(i, len(strings)) if strings[j] and self._is_source_fragment(strings[j])]
                if parts:
                    result = self._join_fragments(parts)
                    if len(result) > 15 and any(kw in result for kw in payload_keywords) and self._looks_like_lua_source(result):
                        return result

        all_parts = [s for s in strings if s and self._is_source_fragment(s)]
        if all_parts:
            result = self._join_fragments(all_parts)
            if self._looks_like_lua_source(result):
                return result

        return None

    def _is_source_fragment(self, s: str) -> bool:
        if not s or len(s) > 500:
            return False
        source_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.,;:!?()[]{}=+-*/%<>~ \n\r\t\'"')
        non_source = sum(1 for c in s if c not in source_chars)
        return non_source <= len(s) * 0.05

    def _join_fragments(self, parts: List[str]) -> str:
        result_parts = []
        for part in parts:
            if result_parts and part and part[0] not in set('.,;:)]}\'"'):
                if not result_parts[-1].endswith(' ') and not result_parts[-1].endswith('\n'):
                    result_parts.append(' ')
            result_parts.append(part)
        return ''.join(result_parts)

    def _looks_like_lua_source(self, code: str) -> bool:
        if len(code) < 20:
            return False
        keywords = ['function', 'local', 'end', 'return', 'if', 'then', 'else', 'for', 'while', 'do']
        found = sum(1 for kw in keywords if kw in code)
        return found >= 1 and ('=' in code or '(' in code)

    def _try_getter_substitution(self) -> Optional[str]:
        if not self.getter_name:
            return None

        getter = re.escape(self.getter_name)
        pattern = re.compile(rf'\b{getter}\s*\(\s*([0-9+\-*/%\s()]+?)\s*\)')
        strings = self.strings
        offset = self.offset

        def repl(m):
            idx = safe_eval_int(m.group(1).strip())
            if idx is None:
                return m.group(0)
            py_index = idx + offset - 1
            if 0 <= py_index < len(strings):
                s = strings[py_index]
                if s:
                    return json.dumps(s)
            return m.group(0)

        result = pattern.sub(repl, self.source)
        if result != self.source:
            result = self._strip_setup_block(result)
            if self._looks_like_lua_source(result):
                return result
        return None

    def _strip_setup_block(self, source: str) -> str:
        source = re.sub(r'local\s+\w+\s*=\s*\{(?:"[^"]*",?\s*)+\}\s*', '', source, count=1)
        source = re.sub(r'local\s+\w+\s*=\s*\{(?:\s*(?:\w+|\["."\])\s*=\s*\d+\s*,?\s*)+\}\s*', '', source, count=1)
        source = re.sub(r'for\s+\w+\s*,\s*\w+\s+in\s+ipairs\s*\(\s*\{[^}]+\}\s*\)\s*do.*?end\s*', '', source, count=1, flags=re.DOTALL)
        if self.getter_name:
            g = re.escape(self.getter_name)
            source = re.sub(rf'local\s+function\s+{g}\s*\([^)]*\).*?end\s*', '', source, count=1, flags=re.DOTALL)
        source = re.sub(r'^\s*\n+', '', source)
        source = re.sub(r'\n{3,}', '\n\n', source)
        return source.strip()
