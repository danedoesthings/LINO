import re
from typing import Optional, List, Dict


class StateMachineLifter:
    def __init__(self, source: str, decoded_strings: list = None, offset: int = 0):
        self.source = source
        self.strings = decoded_strings if decoded_strings else []
        self.offset = offset
        self.vm_state_var: str = "vmState"
        self.entry_state: Optional[int] = None
        self.handlers: Dict[int, dict] = {}
        self.diagnostics: List[str] = []

    def lift(self) -> Optional[str]:
        self.diagnostics = []
        code = self._resolve_getstr(self.source)

        dispatcher = self._extract_dispatcher(code)
        if dispatcher is None:
            self.diagnostics.append("No 'while' dispatcher found")
            return None

        self.vm_state_var = dispatcher['var']
        body = dispatcher['body']

        self._extract_states(body)
        if not self.handlers:
            self.diagnostics.append("No states extracted from dispatcher")
            return None

        self.diagnostics.append(f"Extracted {len(self.handlers)} states, entry = {self.entry_state}")
        return self._emit_lua()

    def _resolve_getstr(self, code: str) -> str:
        offset_constant = self.offset
        if not offset_constant:
            m_offset = re.search(r'GetStr\s*\+\s*\(?\s*(\d+)\s*\)?', code)
            if m_offset:
                offset_constant = int(m_offset.group(1))
        def repl(m):
            try:
                n = int(m.group(1))
                idx = n + offset_constant - 1
                if 0 <= idx < len(self.strings):
                    s = self.strings[idx]
                    if s is not None:
                        escaped = s.replace('\\', '\\\\').replace('"', '\\"')
                        return f'"{escaped}"'
                return 'nil'
            except Exception:
                return m.group(0)
        code = re.sub(r'GetStr\s*\(\s*(-?\d+)\s*\)', repl, code)
        code = re.sub(r'GetStr\s*-\s*(-?\d+)', repl, code)
        return code

    def _extract_dispatcher(self, code: str) -> Optional[dict]:
        pattern = r'while\s+(\w+)\s+do\s*(.*?)\nend\s*\n'
        for m in re.finditer(pattern, code, re.DOTALL):
            var = m.group(1)
            inner = m.group(2)
            if re.search(r'if\s+' + re.escape(var) + r'\s*<\s*-?\d+\s+then', inner):
                return {'var': var, 'body': inner}
        return None

    def _extract_states(self, body: str) -> None:
        self._walk_ifs(body, [], "")

    def _walk_ifs(self, body: str, conditions: list, prefix: str) -> None:
        if_match = re.search(r'\bif\s+(\w+)\s*<\s*(-?\d+)\s+then\b', body)
        if not if_match:
            self._process_leaf(body, conditions)
            return

        boundary = int(if_match.group(2))
        var = if_match.group(1)
        true_cond = conditions + [f"{var} < {boundary}"]
        false_cond = conditions + [f"{var} >= {boundary}"]

        true_start = if_match.end()
        pos = true_start
        depth = 0
        while pos < len(body):
            if body.startswith('if ', pos):
                depth += 1
                pos += 3
            elif body.startswith('end', pos):
                if depth == 0:
                    break
                depth -= 1
                pos += 3
            elif body.startswith('else', pos) and depth == 0:
                else_pos = pos
                end_pos = body.find('end', else_pos + 4)
                if end_pos == -1:
                    end_pos = len(body)
                self._walk_ifs(body[true_start:else_pos], true_cond, prefix)
                self._walk_ifs(body[else_pos+4:end_pos], false_cond, prefix)
                return
            else:
                pos += 1
        end_pos = body.find('end', true_start)
        if end_pos == -1:
            end_pos = len(body)
        self._walk_ifs(body[true_start:end_pos], true_cond, prefix)
        self._walk_ifs(body[end_pos+3:], false_cond, prefix)

    def _process_leaf(self, body: str, conditions: list) -> None:
        assignments = re.findall(rf'\b{self.vm_state_var}\s*=\s*(-?\d+)', body)
        if not assignments:
            return
        state = int(assignments[-1])
        last_assign_pos = body.rfind(f'{self.vm_state_var} = {state}')
        if last_assign_pos == -1:
            return
        handler_code = body[:last_assign_pos].strip()
        handler_code = re.sub(r'\bend\b\s*$', '', handler_code).strip()

        if state not in self.handlers:
            self.handlers[state] = {
                'code': handler_code,
                'conditions': conditions,
            }
        if self.entry_state is None:
            self.entry_state = state

    def _emit_lua(self) -> str:
        lines = []
        lines.append("local state_handlers = {}")
        lines.append("")
        for state, info in sorted(self.handlers.items()):
            lines.append(f"state_handlers[{state}] = function()")
            code = info['code']
            if code:
                for cl in code.split('\n'):
                    cl = cl.strip()
                    if cl:
                        lines.append(f"  {cl}")
            next_state = self._find_next_state_in_code(info['code'])
            if next_state is None:
                next_state = "nil"
            lines.append(f"  return {next_state}")
            lines.append("end")
            lines.append("")
        lines.append(f"local {self.vm_state_var} = {self.entry_state}")
        lines.append(f"while {self.vm_state_var} do")
        lines.append(f"  local next_state = state_handlers[{self.vm_state_var}]()")
        lines.append(f"  if next_state then")
        lines.append(f"    {self.vm_state_var} = next_state")
        lines.append(f"  else")
        lines.append(f"    {self.vm_state_var} = nil")
        lines.append(f"  end")
        lines.append("end")
        return "\n".join(lines)

    def _find_next_state_in_code(self, code: str) -> Optional[int]:
        m = re.search(rf'{self.vm_state_var}\s*=\s*(-?\d+)', code)
        if m:
            return int(m.group(1))
        return None
