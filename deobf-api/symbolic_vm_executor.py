import re
from typing import Optional, List, Dict, Tuple


class SymbolicVMExecutor:
    def __init__(self, source: str, decoded_strings: List[str], offset: int = 0):
        self.source = source
        self.strings = decoded_strings
        self.offset = offset
        self.vm_state_var = "vmState"
        self.states: Dict[int, dict] = {}
        self.entry_state: Optional[int] = None
        self.registers: Dict[str, str] = {}
        self.output: List[str] = []

    def execute(self) -> Optional[str]:
        self._extract_states()
        if not self.states or self.entry_state is None:
            return None

        visited = set()
        self._execute_state(self.entry_state, visited)
        
        if self.output:
            return "\n".join(self.output)
        return None

    def _extract_states(self) -> None:
        lines = self.source.split('\n')
        in_while = False
        body_start = 0
        
        for i, line in enumerate(lines):
            if f'while {self.vm_state_var} do' in line:
                in_while = True
                body_start = i + 1
                break
        
        if not in_while:
            return

        self._parse_state_blocks(lines[body_start:])

    def _parse_state_blocks(self, lines: List[str]) -> None:
        current_state = None
        current_code = []
        
        for line in lines:
            state_match = re.search(rf'{self.vm_state_var}\s*=\s*(-?\d+)', line)
            if state_match:
                state = int(state_match.group(1))
                if current_state is None:
                    self.entry_state = state
                else:
                    if current_state not in self.states:
                        self.states[current_state] = {
                            'code': '\n'.join(current_code),
                            'next': state
                        }
                    else:
                        self.states[current_state]['code'] += '\n' + '\n'.join(current_code)
                        self.states[current_state]['next'] = state
                current_state = state
                current_code = []
            else:
                current_code.append(line)

        if current_state is not None and current_state not in self.states:
            self.states[current_state] = {
                'code': '\n'.join(current_code),
                'next': None
            }

    def _execute_state(self, state: int, visited: set) -> None:
        if state in visited or state not in self.states:
            return
        
        visited.add(state)
        info = self.states[state]
        code = info['code']
        
        self._process_state_code(code)
        
        next_state = info.get('next')
        if next_state is not None:
            self._execute_state(next_state, visited)

    def _process_state_code(self, code: str) -> None:
        str_match = re.search(r'instrTbl\s*\[\s*(\w+)\s*\]\s*=\s*"([^"]*)"', code)
        if str_match:
            reg = str_match.group(1)
            val = str_match.group(2)
            self.registers[reg] = val
            if val in ['print', 'pcall', 'tostring', 'tonumber', 'error', 'loadstring']:
                self.output.append(f"-- register {reg} = \"{val}\" (function)")
            else:
                self.output.append(f"local {reg} = \"{val}\"")

        encstr_match = re.search(r'EncStr\s*\[\s*"([^"]+)"\s*\]', code)
        if encstr_match:
            key = encstr_match.group(1)
            if key in self.strings:
                idx = self.strings.index(key) + 1
                self.output.append(f"-- EncStr[\"{key}\"] = R[{idx}]")

        call_match = re.search(r'\{\s*(\w+)\s*\(\s*(\w+)\s*\)\s*\}', code)
        if call_match:
            func = call_match.group(1)
            arg = call_match.group(2)
            arg_val = self.registers.get(arg, arg)
            self.output.append(f"-- {func}({arg_val})")

        move_match = re.search(r'instrTbl\s*\[\s*(\w+)\s*\]\s*=\s*instrTbl\s*\[\s*(\w+)\s*\]', code)
        if move_match:
            dest = move_match.group(1)
            src = move_match.group(2)
            if src in self.registers:
                self.registers[dest] = self.registers[src]
                self.output.append(f"local {dest} = {src}  -- {self.registers.get(dest, '?')}")
