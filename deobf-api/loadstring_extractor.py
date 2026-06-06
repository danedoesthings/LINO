import re
import json
from typing import Optional, List, Dict, Tuple
from math_fold import safe_eval_int, fold_constants


class LoadstringPayloadExtractor:
    def __init__(self, source, decoder):
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

    def _resolve_getter(self, expr):
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

    def _resolve_r_access(self, index_str):
        idx = safe_eval_int(index_str)
        if idx is None:
            return None
        if 1 <= idx <= len(self.strings):
            s = self.strings[idx - 1]
            if s:
                return s
        return None

    def _resolve_indices(self, code):
        code = fold_constants(code)
        if self.getter_name:
            def repl(m):
                val = self._resolve_getter(m.group(1))
                return json.dumps(val) if val else m.group(0)
            code = re.sub(rf'{re.escape(self.getter_name)}\s*\(\s*([^)]+?)\s*\)', repl, code)
        def repl_r(m):
            val = self._resolve_r_access(m.group(1))
            return json.dumps(val) if val else m.group(0)
        code = re.sub(r'R\s*\[\s*(\d+)\s*\]', repl_r, code)
        return code

    def _evaluate_expression(self, expr):
        expr = expr.strip()
        if (expr.startswith('"') and expr.endswith('"')) or (expr.startswith("'") and expr.endswith("'")):
            return expr[1:-1]
        m = re.match(r'string\.char\s*\(([\d,\s]+)\)', expr)
        if m:
            nums = [int(n.strip()) for n in m.group(1).split(',') if n.strip().isdigit()]
            return ''.join(chr(n % 256) for n in nums)
        m = re.match(r'R\s*\[\s*(\d+)\s*\]', expr)
        if m:
            return self._resolve_r_access(m.group(1))
        if self.getter_name:
            m = re.match(rf'{re.escape(self.getter_name)}\s*\(\s*([^)]+?)\s*\)', expr)
            if m:
                return self._resolve_getter(m.group(1))
        return None

    def _decode_octal_string(self, s):
        octals = re.findall(r'\\(\d{1,3})', s)
        if not octals:
            return s
        return ''.join(chr(int(o) % 256) for o in octals)

    def extract(self):
        payload = self._try_direct_byte_array_assembly()
        if payload:
            return payload
        payload = self._try_handler_body_extraction()
        if payload:
            return payload
        payload = self._try_global_scan()
        return payload

    def _try_direct_byte_array_assembly(self):
        r_body = None
        for m in re.finditer(r'local\s+R\s*=\s*\{([^}]+)\}', self.source, re.DOTALL):
            r_body = m.group(1)
            break
        if not r_body:
            return None
        entries = re.findall(r'"((?:[^"\\]|\\.)*)"', r_body)
        if not entries or len(entries) < 4:
            return None
        decoded = [self._decode_octal_string(e) for e in entries]
        loadstring_idx = None
        known = {'loadstring','load','print','error','pcall','tostring','tonumber','assert','getfenv','setfenv'}
        for i, s in enumerate(decoded):
            if s in known:
                loadstring_idx = i
            if s == 'loadstring' or s == 'load':
                loadstring_idx = i
                break
        if loadstring_idx is None:
            return None
        payload_parts = []
        for i in range(loadstring_idx + 1, len(decoded)):
            s = decoded[i]
            if s and s not in known and not re.match(r'^[\w_]+$', s):
                payload_parts.append(s)
            elif s and s not in known:
                payload_parts.append(s)
        if not payload_parts:
            return None
        payload = ''.join(payload_parts)
        if len(payload) > 10:
            return payload
        return None

    def _try_handler_body_extraction(self):
        bodies = []
        for m in re.finditer(r'\[(\d+)\]\s*=\s*function\s*\([^)]*\)(.*?)end\s*[,;}]', self.source, re.DOTALL):
            bodies.append(m.group(2))
        if not bodies:
            return None
        for body in bodies:
            resolved = self._resolve_indices(body)
            concat = re.split(r'\s*\.\.\s*', resolved)
            if len(concat) >= 2:
                parts = []
                for p in concat:
                    v = self._evaluate_expression(p.strip())
                    if v is None:
                        break
                    parts.append(v)
                else:
                    result = ''.join(parts)
                    if len(result) > 10:
                        return result
            char_calls = re.findall(r'string\.char\s*\(([\d,\s]+)\)', resolved)
            if char_calls:
                all_bytes = []
                for c in char_calls:
                    nums = [int(n.strip()) for n in c.split(',') if n.strip().isdigit()]
                    all_bytes.extend(nums)
                if all_bytes:
                    return ''.join(chr(b % 256) for b in all_bytes)
            tc = re.search(r'table\.concat\s*\(\s*(\w+)\s*\)', resolved)
            if tc:
                var = tc.group(1)
                entries = {}
                for m in re.finditer(rf'{var}\[(\d+)\]\s*=\s*(.+)', resolved):
                    v = self._evaluate_expression(m.group(2).strip())
                    if v is not None:
                        entries[int(m.group(1))] = v
                if entries:
                    return ''.join(entries[k] for k in sorted(entries))
        return None

    def _try_global_scan(self):
        if 'loadstring(' not in self.source and 'load(' not in self.source:
            return None
        window = self.source
        resolved = self._resolve_indices(window)
        concat_candidates = re.findall(r'(\w+(?:\s*\.\.\s*\w+)+)', resolved)
        for cand in concat_candidates:
            parts = re.split(r'\s*\.\.\s*', cand)
            vals = []
            for p in parts:
                v = self._evaluate_expression(p.strip())
                if v is None:
                    break
                vals.append(v)
            else:
                result = ''.join(vals)
                if len(result) > 10:
                    return result
        tc = re.search(r'table\.concat\s*\(\s*(\w+)\s*\)', resolved)
        if tc:
            var = tc.group(1)
            entries = {}
            for m in re.finditer(rf'{var}\[(\d+)\]\s*=\s*(.+)', resolved):
                v = self._evaluate_expression(m.group(2).strip())
                if v is not None:
                    entries[int(m.group(1))] = v
            if entries:
                return ''.join(entries[k] for k in sorted(entries))
        return None
