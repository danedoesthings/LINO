import re
import json
from typing import Optional, List, Dict, Tuple
from math_fold import safe_eval_int, fold_constants
from string_decoder import StringTableDecoder


class LoadstringPayloadExtractor:
    def __init__(self, source: str, decoder: StringTableDecoder):
        self.source = source
        self.decoder = decoder
        self.strings = decoder.strings
        self.offset = decoder.offset
        self.getter_name = None
        self._detect_getter()

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

    def _resolve_getter(self, expr: str) -> Optional[str]:
        if not self.getter_name:
            return None
        n = safe_eval_int(expr)
        if n is None:
            return None
        idx = n + self.offset
        if 1 <= idx <= len(self.strings):
            s = self.strings[idx - 1]
            if s:
                return s
        return None

    def _resolve_r_access(self, index_str: str) -> Optional[str]:
        idx = safe_eval_int(index_str)
        if idx is None:
            return None
        if 1 <= idx <= len(self.strings):
            s = self.strings[idx - 1]
            if s:
                return s
        return None

    def extract(self) -> Optional[str]:
        handler_bodies = self._extract_handler_bodies()
        loadstring_handlers = self._find_loadstring_handlers(handler_bodies)
        if not loadstring_handlers:
            return None

        for handler_body in loadstring_handlers:
            payload = self._extract_from_handler(handler_body)
            if payload:
                return payload

        payload = self._try_concat_chain_global()
        if payload:
            return payload

        payload = self._try_table_concat_pattern()
        return payload

    def _extract_handler_bodies(self) -> List[str]:
        bodies = []
        for m in re.finditer(r'\[(\d+)\]\s*=\s*function\s*\([^)]*\)(.*?)end\s*[,;}]', self.source, re.DOTALL):
            bodies.append(m.group(2))
        return bodies

    def _find_loadstring_handlers(self, bodies: List[str]) -> List[str]:
        loadstring_bodies = []
        for body in bodies:
            if 'loadstring' in body or 'load' in body:
                loadstring_bodies.append(body)
        return loadstring_bodies

    def _extract_from_handler(self, body: str) -> Optional[str]:
        payload = self._extract_concat_from_body(body)
        if payload:
            return payload
        payload = self._extract_string_char_assembly(body)
        if payload:
            return payload
        payload = self._extract_table_concat_in_body(body)
        return payload

    def _extract_concat_from_body(self, body: str) -> Optional[str]:
        resolved_body = self._resolve_indices_in_body(body)
        concat_patterns = [
            r'local\s+(\w+)\s*=\s*(.+)',
            r'(\w+)\s*=\s*(.+)',
        ]
        for pat in concat_patterns:
            for m in re.finditer(pat, resolved_body):
                expr = m.group(2)
                if '..' in expr:
                    parts = [p.strip() for p in expr.split('..')]
                    resolved_parts = []
                    for part in parts:
                        val = self._evaluate_part(part)
                        if val is not None:
                            resolved_parts.append(val)
                        else:
                            break
                    else:
                        return ''.join(resolved_parts)

        direct_call = re.search(r'loadstring\s*\(\s*(.+?)\s*\)', resolved_body)
        if direct_call:
            arg = direct_call.group(1).strip()
            val = self._evaluate_part(arg)
            if val:
                return val
        return None

    def _evaluate_part(self, part: str) -> Optional[str]:
        part = part.strip()
        if part.startswith('"') and part.endswith('"'):
            return part[1:-1]
        if part.startswith("'") and part.endswith("'"):
            return part[1:-1]

        r_index = re.match(r'R\s*\[\s*(\d+)\s*\]', part)
        if r_index:
            return self._resolve_r_access(r_index.group(1))

        getter_call = re.match(rf'{re.escape(self.getter_name)}\s*\(\s*([^)]+)\s*\)', part) if self.getter_name else None
        if getter_call:
            return self._resolve_getter(getter_call.group(1))

        string_char = re.match(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', part)
        if string_char:
            nums = [int(n.strip()) for n in string_char.group(1).split(',') if n.strip().isdigit()]
            return ''.join(chr(n % 256) for n in nums)

        return None

    def _resolve_indices_in_body(self, body: str) -> str:
        def replace_getter(m):
            val = self._resolve_getter(m.group(1))
            if val:
                return json.dumps(val)
            return m.group(0)
        if self.getter_name:
            body = re.sub(rf'{re.escape(self.getter_name)}\s*\(\s*([^)]+)\s*\)', replace_getter, body)

        def replace_r(m):
            val = self._resolve_r_access(m.group(1))
            if val:
                return json.dumps(val)
            return m.group(0)
        body = re.sub(r'R\s*\[\s*(\d+)\s*\]', replace_r, body)
        return body

    def _extract_string_char_assembly(self, body: str) -> Optional[str]:
        char_calls = re.findall(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', body)
        if not char_calls:
            return None
        all_chars = []
        for call in char_calls:
            nums = [int(n.strip()) for n in call.split(',') if n.strip().isdigit()]
            all_chars.extend(nums)
        if all_chars:
            return ''.join(chr(n % 256) for n in all_chars)
        return None

    def _extract_table_concat_in_body(self, body: str) -> Optional[str]:
        concat_call = re.search(r'table\.concat\s*\(\s*(\w+)\s*\)', body)
        if not concat_call:
            return None
        table_var = concat_call.group(1)
        table_entries = self._collect_table_entries(body, table_var)
        if table_entries:
            return ''.join(table_entries)
        return None

    def _collect_table_entries(self, body: str, table_var: str) -> List[str]:
        entries = []
        pattern = re.compile(rf'{table_var}\s*\[(\d+)\]\s*=\s*(.+)')
        for m in pattern.finditer(body):
            val = self._evaluate_part(m.group(2))
            if val is not None:
                entries.append((int(m.group(1)), val))
        if not entries:
            insertion_pattern = re.compile(rf'table\.insert\s*\(\s*{table_var}\s*,\s*(.+?)\s*\)')
            for m in insertion_pattern.finditer(body):
                val = self._evaluate_part(m.group(1))
                if val is not None:
                    entries.append((len(entries) + 1, val))
        entries.sort(key=lambda x: x[0])
        return [e[1] for e in entries]

    def _try_concat_chain_global(self) -> Optional[str]:
        load_pos = self.source.find('loadstring(')
        if load_pos == -1:
            load_pos = self.source.find('loadstring (')
        if load_pos == -1:
            load_pos = self.source.find('load(')
        if load_pos == -1:
            return None

        window = self.source[max(0, load_pos - 2000):load_pos + 500]
        resolved = self._resolve_indices_in_body(window)
        concat_expr = re.search(r'(\w+(?:\s*\.\.\s*\w+)+)', resolved)
        if not concat_expr:
            concat_expr = re.search(r'(\w+\s*\.\.\s*.+)', resolved)
        if not concat_expr:
            return None

        expr = concat_expr.group(1)
        parts = re.split(r'\s*\.\.\s*', expr)
        resolved_parts = []
        for part in parts:
            part = part.strip()
            val = self._evaluate_part(part)
            if val is not None:
                resolved_parts.append(val)
            else:
                return None
        return ''.join(resolved_parts)

    def _try_table_concat_pattern(self) -> Optional[str]:
        concat_match = re.search(r'table\.concat\s*\(\s*(\w+)\s*\)', self.source)
        if not concat_match:
            return None
        table_var = concat_match.group(1)
        entries = self._collect_table_entries(self.source, table_var)
        if entries:
            return ''.join(entries)
        return None
