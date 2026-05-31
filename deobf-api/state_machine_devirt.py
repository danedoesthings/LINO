import re
from typing import Optional, Dict, List

class StateMachineLifter:
    def __init__(self, source: str, decoded_strings: list):
        self.source = source
        self.strings = decoded_strings
        self.state_var = "vmState"
        self.blocks: Dict[int, str] = {}
        self.transitions: Dict[int, Optional[int]] = {}
        self.entry_state: Optional[int] = None

    def lift(self) -> Optional[str]:
        self._find_state_var()
        if not self._parse_blocks():
            return None
        if not self._trace_states():
            return None
        return self._emit_linear_code()

    def _find_state_var(self):
        m = re.search(r'while\s+(\w+)\s+do', self.source)
        if m:
            self.state_var = m.group(1)

    def _parse_blocks(self) -> bool:
        pat = re.compile(
            rf'if\s+{re.escape(self.state_var)}\s*==\s*(-?\d+)\s*then\s*(.*?)'
            rf'(?=\n\s*(?:elseif|else|end)\b)',
            re.DOTALL,
        )
        matches = pat.findall(self.source)
        if not matches:
            pat2 = re.compile(
                rf'if\s+{re.escape(self.state_var)}\s*<\s*(-?\d+)\s*then\s*(.*?)'
                rf'(?=\n\s*(?:elseif|else|end)\b)',
                re.DOTALL,
            )
            matches = pat2.findall(self.source)

        for num_str, body in matches:
            state = int(num_str)
            self.blocks[state] = body

        return len(self.blocks) > 0

    def _trace_states(self) -> bool:
        for state in self.blocks:
            self.transitions[state] = self._find_next_state(state)

        positives = [s for s in self.transitions if s > 0]
        self.entry_state = min(positives) if positives else min(self.transitions)
        return self.entry_state is not None

    def _find_next_state(self, state: int) -> Optional[int]:
        block = self.blocks.get(state, "")
        m = re.search(
            rf'{re.escape(self.state_var)}\s*=\s*(-?\d+)', block
        )
        if m:
            return int(m.group(1))
        return None

    def _emit_linear_code(self) -> str:
        visited: set[int] = set()
        order: list[int] = []
        current = self.entry_state
        while current is not None and current not in visited:
            visited.add(current)
            order.append(current)
            current = self.transitions.get(current)

        output_lines = []
        for state in order:
            block = self.blocks[state]
            block = re.sub(
                rf'{re.escape(self.state_var)}\s*=\s*-?\d+\s*;?\s*', '', block
            )
            block = block.strip()
            if block:
                output_lines.append(block)

        return self._resolve_string_refs('\n'.join(output_lines))

    def _resolve_string_refs(self, code: str) -> str:
        def repl(m):
            n = int(m.group(1))
            if 1 <= n <= len(self.strings):
                s = self.strings[n - 1]
                if s:
                    return repr(s)
            return m.group(0)
        return re.sub(r'\bGetStr\s*\(\s*(\d+)\s*\)', repl, code)
