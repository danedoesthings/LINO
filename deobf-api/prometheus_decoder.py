import re
import json
from typing import Optional, List, Dict, Tuple
from math_fold import safe_eval_int, fold_constants


class PrometheusDecoder:
    def __init__(self, source: str, decoder):
        self.source = source
        self.decoder = decoder
        self.strings = decoder.strings
        self.offset = decoder.offset
        self.getter_name = None
        self.vm_var = None
        self.instruction_table = None
        self.state_handlers = {}
        self._detect_getter()
        self._extract_vm_structure()

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

    def _extract_vm_structure(self):
        m = re.search(r'while\s+(\w+)\s+do', self.source)
        if m:
            self.vm_var = m.group(1)

        handler_pattern = re.compile(
            r'\[(\d+)\]\s*=\s*function\s*\([^)]*\)(.*?)end\s*[,;}]',
            re.DOTALL
        )
        for m in handler_pattern.finditer(self.source):
            idx = int(m.group(1))
            body = m.group(2)
            self.state_handlers[idx] = body

        ipairs_match = re.search(r'ipairs\s*\(\s*\{([^}]+)\}\s*\)', self.source, re.DOTALL)
        if ipairs_match:
            body = ipairs_match.group(1)
            pairs = re.findall(r'\{([^}]+)\}', body)
            if pairs:
                self.instruction_table = []
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
                        self.instruction_table.append(tuple(resolved))

    def _resolve_getter(self, expr: str) -> Optional[str]:
        if not self.getter_name:
            return None
        n = safe_eval_int(expr)
        if n is None:
            return None
        idx = n + self.offset
        if 1 <= idx <= len(self.strings):
            return self.strings[idx - 1]
        return None

    def _resolve_indices(self, code: str) -> str:
        code = fold_constants(code)
        if self.getter_name:
            def repl(m):
                val = self._resolve_getter(m.group(1))
                return json.dumps(val) if val else m.group(0)
            code = re.sub(rf'{re.escape(self.getter_name)}\s*\(\s*([^)]+?)\s*\)', repl, code)
        return code

    def decode(self) -> Optional[str]:
        if not self.strings or len(self.strings) < 4:
            return None

        payload = self._try_instruction_table_decode()
        if payload:
            return payload

        payload = self._try_vm_handler_decode()
        if payload:
            return payload

        payload = self._try_direct_string_assembly()
        return payload

    def _try_instruction_table_decode(self) -> Optional[str]:
        if not self.instruction_table:
            return None

        decoded_ops = []
        for a, b in self.instruction_table:
            if isinstance(b, int) and 1 <= b <= len(self.strings):
                s = self.strings[b - 1]
                if s:
                    decoded_ops.append(s)
                else:
                    decoded_ops.append(f"[{b}]")
            elif a == 0:
                continue
            else:
                decoded_ops.append(f"<{a},{b}>")

        if not decoded_ops:
            return None

        result = ''.join(decoded_ops)
        if len(result) > 5 and ('function' in result or 'local' in result or 'print' in result):
            return result

        return None

    def _try_vm_handler_decode(self) -> Optional[str]:
        if not self.state_handlers:
            return None

        loadstring_handler = None
        for idx, body in self.state_handlers.items():
            resolved = self._resolve_indices(body)
            if 'loadstring' in resolved:
                loadstring_handler = resolved
                break

        if not loadstring_handler:
            for idx, body in self.state_handlers.items():
                resolved = self._resolve_indices(body)
                for name in ['loadstring', 'load', 'pcall']:
                    if f'"{name}"' in resolved or f"'{name}'" in resolved:
                        loadstring_handler = resolved
                        break
                if loadstring_handler:
                    break

        if not loadstring_handler:
            return None

        concat_parts = re.split(r'\s*\.\.\s*', loadstring_handler)
        if len(concat_parts) >= 2:
            result_parts = []
            for part in concat_parts:
                part = part.strip()
                if part.startswith('"') and part.endswith('"'):
                    result_parts.append(part[1:-1])
                elif part.startswith("'") and part.endswith("'"):
                    result_parts.append(part[1:-1])
                elif part.isidentifier():
                    result_parts.append(part)
                else:
                    break
            else:
                result = ''.join(result_parts)
                if len(result) > 5:
                    return result

        char_calls = re.findall(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', loadstring_handler)
        if char_calls:
            all_bytes = []
            for call in char_calls:
                nums = [int(n.strip()) for n in call.split(',') if n.strip().isdigit()]
                all_bytes.extend(nums)
            if all_bytes:
                return ''.join(chr(b % 256) for b in all_bytes)

        return None

    def _try_direct_string_assembly(self) -> Optional[str]:
        candidates = []
        for s in self.strings:
            if s and len(s) > 2:
                candidates.append(s)

        if not candidates:
            return None

        payload_keywords = ['print', 'function', 'local', 'return', 'end', 'then', 'else', 'for', 'while', 'do']
        for kw in payload_keywords:
            if kw in candidates:
                idx = candidates.index(kw)
                payload_parts = []
                for s in candidates[idx:]:
                    payload_parts.append(s)
                result = ''.join(payload_parts)
                if len(result) > 5:
                    return result

        return None
