import re
import json
from typing import Optional, List, Dict, Tuple, Set
from math_fold import safe_eval_int, fold_constants


class VirtualRegister:
    def __init__(self, name, value=None):
        self.name = name
        self.value = value

    def __repr__(self):
        if self.value is not None:
            return str(self.value)
        return self.name


class StringBuilderTracer:
    def __init__(self, source, decoded_strings, offset=0, getter_name=None):
        self.source = source
        self.strings = decoded_strings
        self.offset = offset
        self.getter_name = getter_name
        self.registers = {}
        self.tables = {}
        self.output = []
        self.max_steps = 5000
        self.step_count = 0
        self.vm_state_var = None
        self.state_handlers = {}
        self.handler_cache = {}

    def trace_loadstring_payload(self):
        self._detect_vm_structure()
        self._detect_getter()

        if not self.state_handlers:
            handler_bodies = self._extract_all_handler_bodies()
            for idx, body in enumerate(handler_bodies):
                self._analyze_handler_body(body, idx)

        loadstring_handlers = self._find_loadstring_handlers()
        if not loadstring_handlers:
            return None

        for handler in loadstring_handlers:
            payload = self._trace_handler(handler)
            if payload and len(payload) > 5:
                return payload

        return self._try_build_from_concat_chain()

    def _detect_vm_structure(self):
        m = re.search(r'while\s+(\w+)\s+do', self.source)
        if not m:
            return
        self.vm_state_var = m.group(1)

        handler_pattern = re.compile(
            r'\[(\d+)\]\s*=\s*function\s*\([^)]*\)(.*?)end\s*[,;}]',
            re.DOTALL
        )
        for m in handler_pattern.finditer(self.source):
            idx = int(m.group(1))
            body = m.group(2)
            self.state_handlers[idx] = body

    def _detect_getter(self):
        if self.getter_name and self.offset:
            return
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
            return self.strings[idx - 1]
        return None

    def _resolve_r_access(self, index_str):
        idx = safe_eval_int(index_str)
        if idx is None:
            return None
        if 1 <= idx <= len(self.strings):
            return self.strings[idx - 1]
        return None

    def _extract_all_handler_bodies(self):
        bodies = []
        for m in re.finditer(r'\[(\d+)\]\s*=\s*function\s*\([^)]*\)(.*?)end\s*[,;}]', self.source, re.DOTALL):
            bodies.append(m.group(2))
        return bodies

    def _analyze_handler_body(self, body, handler_id):
        pass

    def _find_loadstring_handlers(self):
        handlers = []
        for idx, body in self.state_handlers.items():
            if 'loadstring' in body or 'load' in body:
                handlers.append(body)
        if not handlers:
            all_bodies = self._extract_all_handler_bodies()
            for body in all_bodies:
                if 'loadstring' in body or 'load' in body:
                    handlers.append(body)
        return handlers

    def _trace_handler(self, body):
        resolved = self._resolve_indices_in_body(body)
        concat_exprs = re.findall(r'(?:local\s+\w+\s*=\s*)?(.+?(?:\s*\.\.\s*.+?)+)', resolved)
        for expr in concat_exprs:
            parts = [p.strip() for p in re.split(r'\s*\.\.\s*', expr)]
            result = []
            for part in parts:
                val = self._evaluate_part(part)
                if val is not None:
                    result.append(val)
                else:
                    break
            else:
                return ''.join(result)

        char_expr = self._extract_string_char_assembly(resolved)
        if char_expr:
            return char_expr

        table_concat = self._extract_table_concat_in_body(resolved, body)
        if table_concat:
            return table_concat

        return self._try_simple_loadstring_arg(resolved)

    def _resolve_indices_in_body(self, body):
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

    def _evaluate_part(self, part):
        part = part.strip()
        if part.startswith('"') and part.endswith('"'):
            return part[1:-1]
        if part.startswith("'") and part.endswith("'"):
            return part[1:-1]

        r_idx = re.match(r'R\s*\[\s*(\d+)\s*\]', part)
        if r_idx:
            return self._resolve_r_access(r_idx.group(1))

        if self.getter_name:
            getter = re.match(rf'{re.escape(self.getter_name)}\s*\(\s*([^)]+)\s*\)', part)
            if getter:
                return self._resolve_getter(getter.group(1))

        str_char = re.match(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', part)
        if str_char:
            nums = [int(n.strip()) for n in str_char.group(1).split(',') if n.strip().isdigit()]
            return ''.join(chr(n % 256) for n in nums)

        return None

    def _extract_string_char_assembly(self, body):
        chars = re.findall(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', body)
        if not chars:
            return None
        all_bytes = []
        for call in chars:
            nums = [int(n.strip()) for n in call.split(',') if n.strip().isdigit()]
            all_bytes.extend(nums)
        if all_bytes:
            return ''.join(chr(n % 256) for n in all_bytes)
        return None

    def _extract_table_concat_in_body(self, resolved_body, original_body):
        concat_call = re.search(r'table\.concat\s*\(\s*(\w+)\s*\)', resolved_body)
        if not concat_call:
            return None
        table_var = concat_call.group(1)
        entries = self._collect_table_entries(resolved_body, original_body, table_var)
        if entries:
            return ''.join(entries)
        return None

    def _collect_table_entries(self, resolved_body, original_body, table_var):
        entries = {}
        pattern = re.compile(rf'{table_var}\s*\[(\d+)\]\s*=\s*(.+)')
        for m in pattern.finditer(resolved_body):
            val = self._evaluate_part(m.group(2).strip())
            if val is not None:
                entries[int(m.group(1))] = val

        insert_pattern = re.compile(rf'table\.insert\s*\(\s*{table_var}\s*,\s*(.+?)\s*\)')
        next_idx = 1
        for m in insert_pattern.finditer(resolved_body):
            val = self._evaluate_part(m.group(1).strip())
            if val is not None:
                entries[next_idx] = val
                next_idx += 1

        if not entries:
            return None

        sorted_keys = sorted(entries.keys())
        return [entries[k] for k in sorted_keys]

    def _try_simple_loadstring_arg(self, resolved_body):
        call_match = re.search(r'loadstring\s*\(\s*(.+?)\s*\)', resolved_body)
        if call_match:
            arg = call_match.group(1).strip()
            val = self._evaluate_part(arg)
            if val:
                return val
        return None

    def _try_build_from_concat_chain(self):
        resolved = self._resolve_indices_in_body(self.source)
        for var in re.findall(r'local\s+(\w+)\s*=\s*', resolved):
            pattern = re.compile(rf'{var}\s*=\s*{var}\s*\.\.\s*(.+)')
            if pattern.search(resolved):
                return self._reconstruct_concat_chain(var, resolved)
        return None

    def _reconstruct_concat_chain(self, var, code):
        base_match = re.search(rf'local\s+{var}\s*=\s*(.+)', code)
        if not base_match:
            return None
        base_val = self._evaluate_part(base_match.group(1).strip())
        if base_val is None:
            return None

        parts = [base_val]
        append_pattern = re.compile(rf'{var}\s*=\s*{var}\s*\.\.\s*(.+)')
        for m in append_pattern.finditer(code):
            part = self._evaluate_part(m.group(1).strip())
            if part is not None:
                parts.append(part)
            else:
                return None

        return ''.join(parts)


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

    def extract(self):
        tracer = StringBuilderTracer(
            self.source, self.strings, self.offset, self.getter_name
        )
        payload = tracer.trace_loadstring_payload()
        if payload:
            return payload

        return self._extract_via_handler_bodies()

    def _extract_via_handler_bodies(self):
        handler_bodies = self._extract_handler_bodies()
        loadstring_handlers = self._find_loadstring_handlers(handler_bodies)
        if not loadstring_handlers:
            return None

        for body in loadstring_handlers:
            payload = self._extract_from_handler(body)
            if payload:
                return payload

        payload = self._try_concat_chain_global()
        if payload:
            return payload

        return self._try_table_concat_pattern()

    def _extract_handler_bodies(self):
        bodies = []
        for m in re.finditer(r'\[(\d+)\]\s*=\s*function\s*\([^)]*\)(.*?)end\s*[,;}]', self.source, re.DOTALL):
            bodies.append(m.group(2))
        return bodies

    def _find_loadstring_handlers(self, bodies):
        return [b for b in bodies if 'loadstring' in b or 'load' in b]

    def _extract_from_handler(self, body):
        resolved = self._resolve_indices_in_body(body)
        concat_parts = re.split(r'\s*\.\.\s*', resolved)
        if len(concat_parts) > 1:
            result = []
            for part in concat_parts:
                val = self._evaluate_part(part.strip())
                if val is not None:
                    result.append(val)
                else:
                    break
            else:
                return ''.join(result)

        char_assembly = self._extract_string_char_assembly(resolved)
        if char_assembly:
            return char_assembly

        return self._try_simple_loadstring_arg(resolved)

    def _resolve_indices_in_body(self, body):
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

    def _resolve_getter(self, expr):
        if not self.getter_name:
            return None
        n = safe_eval_int(expr)
        if n is None:
            return None
        idx = n + self.offset
        if 1 <= idx <= len(self.strings):
            return self.strings[idx - 1]
        return None

    def _resolve_r_access(self, index_str):
        idx = safe_eval_int(index_str)
        if idx is None:
            return None
        if 1 <= idx <= len(self.strings):
            return self.strings[idx - 1]
        return None

    def _evaluate_part(self, part):
        part = part.strip()
        if part.startswith('"') and part.endswith('"'):
            return part[1:-1]
        if part.startswith("'") and part.endswith("'"):
            return part[1:-1]

        r_idx = re.match(r'R\s*\[\s*(\d+)\s*\]', part)
        if r_idx:
            return self._resolve_r_access(r_idx.group(1))

        if self.getter_name:
            getter = re.match(rf'{re.escape(self.getter_name)}\s*\(\s*([^)]+)\s*\)', part)
            if getter:
                return self._resolve_getter(getter.group(1))

        str_char = re.match(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', part)
        if str_char:
            nums = [int(n.strip()) for n in str_char.group(1).split(',') if n.strip().isdigit()]
            return ''.join(chr(n % 256) for n in nums)

        return None

    def _extract_string_char_assembly(self, body):
        chars = re.findall(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', body)
        if not chars:
            return None
        all_bytes = []
        for call in chars:
            nums = [int(n.strip()) for n in call.split(',') if n.strip().isdigit()]
            all_bytes.extend(nums)
        if all_bytes:
            return ''.join(chr(n % 256) for n in all_bytes)
        return None

    def _try_simple_loadstring_arg(self, resolved_body):
        call_match = re.search(r'loadstring\s*\(\s*(.+?)\s*\)', resolved_body)
        if call_match:
            arg = call_match.group(1).strip()
            val = self._evaluate_part(arg)
            if val:
                return val
        return None

    def _try_concat_chain_global(self):
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
        result = []
        for part in parts:
            val = self._evaluate_part(part.strip())
            if val is not None:
                result.append(val)
            else:
                return None
        return ''.join(result)

    def _try_table_concat_pattern(self):
        concat_match = re.search(r'table\.concat\s*\(\s*(\w+)\s*\)', self.source)
        if not concat_match:
            return None
        table_var = concat_match.group(1)
        resolved = self._resolve_indices_in_body(self.source)
        entries = {}
        pattern = re.compile(rf'{table_var}\s*\[(\d+)\]\s*=\s*(.+)')
        for m in pattern.finditer(resolved):
            val = self._evaluate_part(m.group(2).strip())
            if val is not None:
                entries[int(m.group(1))] = val

        if not entries:
            return None
        return ''.join(entries[k] for k in sorted(entries.keys()))
