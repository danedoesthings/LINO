import re
from typing import Optional, Dict, List

class VMDevirtualizer:
    def __init__(self, source: str, decoder=None):
        self.source = source
        self.decoder = decoder
        self.strings = decoder.strings if decoder else []
        self.blocks: Dict[int, str] = {}
        self.pos_var = None
        self.start_pos = None

    def devirtualize(self) -> Optional[str]:
        result = self._extract_and_linearize()
        if result and len(result) > 10:
            return result
        result = self._try_trace_execution()
        if result and len(result) > 10:
            return result
        result = self._extract_string_payload()
        if result and len(result) > 10:
            return result
        return self._extract_visible_payload()

    def _extract_and_linearize(self) -> Optional[str]:
        # Pattern 1: return (function(pos_var, ...) ... end)(start_pos)
        vm_match = re.search(
            r'return\s*\(\s*function\s*\(\s*(\w+)\s*(?:,\s*\w+)*\s*\)(.*?)end\s*\)\s*\(\s*(\d+)\s*\)',
            self.source, re.DOTALL
        )
        if not vm_match:
            # Pattern 1b: return(function(...)...end)(...)
            vm_match = re.search(
                r'return\s*\(\s*function\s*\((.*?)\)(.*?)end\s*\)\s*\(',
                self.source, re.DOTALL
            )
            if vm_match:
                self.pos_var = re.search(r'(\w+)', vm_match.group(1)).group(1) if vm_match.group(1) else 'pos'
                body = vm_match.group(2)
                self.start_pos = 0
            else:
                # Pattern 2: function(pos_var) while pos_var do ... end
                vm_match = re.search(
                    r'function\s*\(\s*(\w+)\s*[^)]*\)\s*while\s+\1\s+do(.*?)end',
                    self.source, re.DOTALL
                )
                if vm_match:
                    self.pos_var = vm_match.group(1)
                    body = vm_match.group(2)
                    self.start_pos = 0
                else:
                    return None
        else:
            self.pos_var = vm_match.group(1)
            body = vm_match.group(2)
            try:
                self.start_pos = int(vm_match.group(3))
            except (ValueError, IndexError):
                self.start_pos = 0

        block_pattern = re.compile(
            rf'if\s+{re.escape(self.pos_var)}\s*==\s*(\d+)\s+then\s*(.*?)(?=elseif\s+{re.escape(self.pos_var)}\s*==|else\s|end\s)',
            re.DOTALL
        )
        for m in block_pattern.finditer(body):
            try:
                block_id = int(m.group(1))
                block_code = m.group(2).strip()
                block_code = re.sub(rf'{re.escape(self.pos_var)}\s*=\s*\d+\s*;?\s*', '', block_code)
                block_code = re.sub(r'break\s*;?\s*', '', block_code)
                if block_code and not self._is_dead_block(block_code):
                    self.blocks[block_id] = block_code
            except ValueError:
                continue

        if not self.blocks:
            return None

        sorted_ids = sorted(self.blocks.keys())
        entry_id = self.start_pos if self.start_pos is not None and self.start_pos in self.blocks else sorted_ids[0]
        ordered = self._order_by_execution_flow(entry_id, sorted_ids)
        if not ordered:
            ordered = sorted_ids

        lines = []
        for bid in ordered:
            code = self.blocks.get(bid, '')
            if code and not self._is_dead_block(code):
                lines.append(code)
        return '\n'.join(lines) if lines else None

    def _order_by_execution_flow(self, entry_id: int, all_ids: List[int]) -> List[int]:
        ordered = []
        visited = set()
        current = entry_id
        while current is not None and current not in visited and len(ordered) < len(all_ids) * 2:
            visited.add(current)
            ordered.append(current)
            if current in self.blocks:
                block = self.blocks[current]
                nxt = re.search(rf'{re.escape(self.pos_var)}\s*=\s*(\d+)', block)
                if nxt:
                    nxt_id = int(nxt.group(1))
                    if nxt_id in all_ids and nxt_id not in visited:
                        current = nxt_id
                        continue
            remaining = [bid for bid in all_ids if bid not in visited]
            current = remaining[0] if remaining else None
        return ordered

    def _is_dead_block(self, code: str) -> bool:
        dead = [
            r'while\s+true\s+do\s*end',
            r'while\s+true\s+do\s+\w+\s*=\s*\w+\s*;?\s*\w+\s*=\s*\w+\s*;?\s*\w+\(\)\s*;?\s*end',
            r'error\s*\(\s*"[^"]*[Tt]amper[^"]*"\s*\)',
            r'error\s*\(\s*"[^"]*[Dd]ebug[^"]*"\s*\)',
            r'error\s*\(\s*"[^"]*[Hh]ook[^"]*"\s*\)',
        ]
        return any(re.search(p, code) for p in dead)

    def _try_trace_execution(self) -> Optional[str]:
        dispatcher_match = re.search(
            r'while\s+(\w+)\s+do\s+if\s+\1\s*<\s*(-?\d+)\s+then',
            self.source, re.DOTALL
        )
        if not dispatcher_match:
            return None
        var = dispatcher_match.group(1)
        try:
            boundary = int(dispatcher_match.group(2))
        except ValueError:
            return None

        handlers = {}
        handler_pattern = re.compile(
            rf'if\s+{re.escape(var)}\s*<\s*(\d+)\s+then\s*(.*?)(?=elseif\s+{re.escape(var)}\s*<|<|else|end)',
            re.DOTALL
        )
        for m in handler_pattern.finditer(self.source):
            try:
                limit = int(m.group(1))
                body = m.group(2)
                state_assign = re.findall(rf'{re.escape(var)}\s*=\s*(-?\d+)', body)
                nxt = int(state_assign[-1]) if state_assign else None
                handlers[limit] = {'body': body.strip(), 'next': nxt}
            except (ValueError, IndexError):
                continue

        if not handlers:
            return None

        sorted_limits = sorted(handlers.keys())
        entry = sorted_limits[0]
        trace_lines = []
        visited = set()
        current = entry
        max_iter = 500
        iterations = 0
        while current is not None and current not in visited and iterations < max_iter:
            visited.add(current)
            iterations += 1
            info = handlers.get(current)
            if info and info['body'] and not self._is_dead_block(info['body']):
                trace_lines.append(info['body'])
            current = info['next'] if info else None

        return '\n'.join(trace_lines) if trace_lines else None

    def _extract_string_payload(self) -> Optional[str]:
        """If the VM uses loadstring on decoded strings, return the matching string."""
        if not self.strings:
            return None
        load_patterns = [
            r'loadstring\s*\(\s*\w+\s*\[.*?\]\s*\)',
            r'load\s*\(\s*\w+\s*\[.*?\]\s*\)',
            r'loadstring\s*\(\s*\w+\s*\(.*?\)\s*\)',
        ]
        for pat in load_patterns:
            if re.search(pat, self.source):
                for s in self.strings:
                    if s and len(s) > 50 and is_lua_source(s):
                        return s
        return None

    def _extract_visible_payload(self) -> Optional[str]:
        patterns = [
            r'print\s*\(\s*"([^"]*)"s*\)',
            r'loadstring\s*\(\s*"((?:[^"\\]|\\.)*)"\s*\)',
            r'load\s*\(\s*"((?:[^"\\]|\\.)*)"\s*\)',
        ]
        for pat in patterns:
            m = re.search(pat, self.source)
            if m:
                content = m.group(1)
                if len(content) > 10:
                    return content

        call_matches = re.findall(r'(loadstring|load)\s*\(\s*"((?:[^"\\]|\\.)*)"\s*\)', self.source)
        if call_matches:
            for _, payload in call_matches:
                try:
                    decoded = payload.encode('latin-1').decode('unicode_escape')
                    if len(decoded) > 10:
                        return decoded
                except Exception:
                    continue
        return None
