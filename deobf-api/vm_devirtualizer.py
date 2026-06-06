import re
import json
from typing import Optional, List, Dict, Tuple
from math_fold import safe_eval_int, fold_constants


class VMDevirtualizer:
    def __init__(self, source: str, decoder):
        self.source = source
        self.decoder = decoder
        self.strings = decoder.strings
        self.offset = decoder.offset
        self.getter_name = None
        self.vm_var = None
        self.handlers = {}
        self.instructions = []
        self.output_lines = []

    def devirtualize(self) -> Optional[str]:
        self._detect_vm()
        if not self.vm_var:
            return None

        self._extract_handlers()
        if not self.handlers:
            return None

        self._trace_execution()
        if self.output_lines:
            result = '\n'.join(self.output_lines)
            if self._looks_like_real_code(result):
                return result

        return self._try_getter_substitution()

    def _detect_vm(self):
        m = re.search(r'while\s+(\w+)\s+do', self.source)
        if m:
            self.vm_var = m.group(1)

        folded = fold_constants(self.source)
        patterns = [
            r'local\s+function\s+(\w+)\s*\(\s*\w+\s*\)\s*return\s+R\s*\[\s*\w+\s*\+\s*\(?(-?\d+)\)?\s*\]',
            r'local\s+function\s+(\w+)\s*\(\s*\w+\s*\)\s*return\s+EncStr\s*\[\s*\w+\s*\+\s*\(?(-?\d+)\)?\s*\]',
        ]
        for p in patterns:
            m = re.search(p, folded)
            if m:
                self.getter_name = m.group(1)
                if not self.offset:
                    self.offset = int(m.group(2))
                return

    def _extract_handlers(self):
        handler_pattern = re.compile(
            r'\[(\d+)\]\s*=\s*function\s*\([^)]*\)(.*?)end\s*[,;}]',
            re.DOTALL
        )
        for m in handler_pattern.finditer(self.source):
            idx = int(m.group(1))
            body = m.group(2)
            self.handlers[idx] = body

        if not self.handlers:
            self._extract_inline_handlers()

    def _extract_inline_handlers(self):
        folded = fold_constants(self.source)
        if self.vm_var:
            pattern = re.compile(
                rf'if\s+{re.escape(self.vm_var)}\s*<\s*(-?\d+)\s+then\s*(.*?)(?=elseif|else|end)',
                re.DOTALL
            )
            idx = 0
            for m in pattern.finditer(folded):
                body = m.group(2)
                self.handlers[idx] = body
                idx += 1

    def _trace_execution(self):
        resolved = self._resolve_getter_calls(self.source)

        prints = re.findall(r'"print"\s*,\s*"([^"]*)"', resolved)
        if prints:
            for p in prints:
                self.output_lines.append(p)

        print_calls = re.findall(r'print\s*\(\s*"([^"]*)"\s*\)', resolved)
        if print_calls:
            for p in print_calls:
                self.output_lines.append(p)

        payloads = re.findall(r'\[Payload:\s*(\d+)\s*bytes\]', resolved)
        if payloads:
            for size in payloads:
                self.output_lines.append(f'[Payload captured: {size} bytes]')

        loads = re.findall(r'"loadstring"\s*,\s*"([^"]*)"', resolved)
        if loads:
            for ld in loads:
                if len(ld) > 10:
                    self.output_lines.append(ld)

        string_chars = self._extract_string_char_blocks(resolved)
        if string_chars:
            self.output_lines.append(string_chars)

    def _extract_string_char_blocks(self, source: str) -> Optional[str]:
        blocks = re.findall(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', source)
        if not blocks:
            return None
        all_bytes = []
        for block in blocks:
            nums = [int(n.strip()) for n in block.split(',') if n.strip().isdigit()]
            all_bytes.extend(nums)
        if all_bytes:
            return ''.join(chr(b % 256) for b in all_bytes)
        return None

    def _resolve_getter_calls(self, source: str) -> str:
        if not self.getter_name:
            return source
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

        return pattern.sub(repl, source)

    def _try_getter_substitution(self) -> Optional[str]:
        if not self.getter_name:
            return None
        result = self._resolve_getter_calls(self.source)
        if result == self.source:
            return None
        result = self._strip_vm_boilerplate(result)
        if self._looks_like_real_code(result):
            return result
        return None

    def _strip_vm_boilerplate(self, source: str) -> str:
        source = re.sub(
            r'local\s+\w+\s*=\s*\{(?:"[^"]*",?\s*)+\}\s*',
            '', source, count=1
        )
        source = re.sub(
            r'local\s+\w+\s*=\s*\{(?:\s*(?:\w+|\["."\])\s*=\s*\d+\s*,?\s*)+\}\s*',
            '', source, count=1
        )
        source = re.sub(
            r'for\s+\w+\s*,\s*\w+\s+in\s+ipairs\s*\(\s*\{[^}]+\}\s*\)'
            r'\s*do.*?end\s*',
            '', source, count=1, flags=re.DOTALL
        )
        if self.getter_name:
            g = re.escape(self.getter_name)
            source = re.sub(
                rf'local\s+function\s+{g}\s*\([^)]*\).*?end\s*',
                '', source, count=1, flags=re.DOTALL
            )
        if self.vm_var:
            v = re.escape(self.vm_var)
            source = re.sub(
                rf'while\s+{v}\s+do.*',
                '',
                source, flags=re.DOTALL
            )
        source = re.sub(r'^\s*\n+', '', source)
        source = re.sub(r'\n{3,}', '\n\n', source)
        return source.strip()

    def _looks_like_real_code(self, code: str) -> bool:
        if not code or len(code) < 10:
            return False
        vm_indicators = [
            'while vmState do', 'while l do if l<', 'instrTbl',
            'allocSlot', 'funcWrap', 'vmStack', 'callEnvA', 'callEnvB',
            'packArgs', 'cleanRef', 'return(function('
        ]
        hits = sum(1 for m in vm_indicators if m in code)
        if hits >= 1:
            return False
        keywords = ['print', 'function', 'local', 'return', 'if', 'then', 'else', 'for', 'while', 'do']
        found = sum(1 for kw in keywords if kw in code)
        return found >= 1 and ('=' in code or '(' in code)
