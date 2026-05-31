import re
from typing import Optional, Dict, List, Tuple

class StateMachineLifter:
    def __init__(self, source: str, decoded_strings: list):
        self.source = source
        self.strings = decoded_strings
        self.state_var = "vmState"
        self.state_to_block: Dict[int, str] = {}
        self.transitions: Dict[int, any] = {}  # maps state_id to next_state info
        self.entry_state: Optional[int] = None

    def lift(self) -> Optional[str]:
        self._find_state_var()
        loop_body = self._get_loop_body()
        if not loop_body:
            return None
            
        # 1. Parse the nested binary tree structure into leaf blocks and path constraints
        blocks = self._parse_nested_tree(loop_body)
        if not blocks:
            return None
            
        # 2. Map actual state ID integers to their reachable basic blocks
        self._map_states_to_blocks(blocks, loop_body)
        if not self.state_to_block:
            return None
            
        # 3. Graph out the execution flow transitions
        self._analyze_transitions()
        self._find_entry_state()
        
        # 4. Synthesize straight-line linear Lua code
        return self._emit_linear_code()

    def _find_state_var(self):
        m = re.search(r'while\s+(\w+)\s+do', self.source)
        if m:
            self.state_var = m.group(1)

    def _get_loop_body(self) -> Optional[str]:
        pattern = rf'while\s+{re.escape(self.state_var)}\s+do\s*(.*?)\s*end\s*$'
        m = re.search(pattern, self.source, re.DOTALL | re.MULTILINE)
        if m:
            return m.group(1)
        pattern2 = rf'while\s+{re.escape(self.state_var)}\s+do\s*(.*?)\s*(?=end\s*(?:\n|\Z))'
        m2 = re.search(pattern2, self.source, re.DOTALL)
        if m2:
            return m2.group(1)
        return None

    def _parse_nested_tree(self, loop_body: str) -> List[Tuple[list, str]]:
        lines = loop_body.split('\n')
        stack = []
        blocks = []
        current_block_lines = []

        for line in lines:
            trimmed = line.strip()
            if not trimmed:
                continue

            if_match = re.match(rf'if\s+{re.escape(self.state_var)}\s*([<>==]+)\s*(-?\d+)\s*then', trimmed)
            elseif_match = re.match(rf'elseif\s+{re.escape(self.state_var)}\s*([<>==]+)\s*(-?\d+)\s*then', trimmed)

            if if_match:
                if current_block_lines:
                    blocks.append((list(stack), '\n'.join(current_block_lines)))
                    current_block_lines = []
                op, val = if_match.group(1), if_match.group(2)
                stack.append((op, int(val), False))
            elif elseif_match:
                if current_block_lines:
                    blocks.append((list(stack), '\n'.join(current_block_lines)))
                    current_block_lines = []
                op, val = elseif_match.group(1), elseif_match.group(2)
                if stack:
                    stack.pop()
                stack.append((op, int(val), False))
            elif trimmed == 'else':
                if current_block_lines:
                    blocks.append((list(stack), '\n'.join(current_block_lines)))
                    current_block_lines = []
                if stack:
                    op, val, is_else = stack.pop()
                    stack.append((op, val, True))
            elif trimmed == 'end':
                if current_block_lines:
                    blocks.append((list(stack), '\n'.join(current_block_lines)))
                    current_block_lines = []
                if stack:
                    stack.pop()
            else:
                current_block_lines.append(line)

        if current_block_lines:
            blocks.append((list(stack), '\n'.join(current_block_lines)))

        return blocks

    def _map_states_to_blocks(self, blocks: list, loop_body: str):
        all_ids = set()
        for num_str in re.findall(r'\b-?\d+\b', loop_body):
            all_ids.add(int(num_str))

        def satisfies(sid, constraints):
            for op, val, is_else in constraints:
                if op == '<': res = sid < val
                elif op == '>': res = sid > val
                elif op == '<=': res = sid <= val
                elif op == '>=': res = sid >= val
                elif op == '==': res = sid == val
                else: res = True
                if is_else:
                    res = not res
                if not res:
                    return False
            return True

        for constraints, block_code in blocks:
            clean_code = block_code.strip()
            if not clean_code or clean_code in ('else', 'end', 'then'):
                continue
            for sid in all_ids:
                if satisfies(sid, constraints):
                    self.state_to_block[sid] = clean_code

    def _analyze_transitions(self):
        for sid, block in self.state_to_block.items():
            # Match conditional transitions: vmState = condition and stateA or stateB
            cond_m = re.search(rf'\b{re.escape(self.state_var)}\s*=\s*(.*?)\s*\band\s*(-?\d+)(?:--\d+)?\s*\bor\s*(-?\d+)', block)
            if cond_m:
                cond, left, right = cond_m.group(1), int(cond_m.group(2)), int(cond_m.group(3))
                self.transitions[sid] = ('cond', cond, left, right)
                continue

            # Match basic linear transitions
            all_assigns = list(re.finditer(rf'\b{re.escape(self.state_var)}\s*=\s*(-?\d+)\b', block))
            if all_assigns:
                last_assign = all_assigns[-1]
                self.transitions[sid] = ('simple', int(last_assign.group(1)))
            else:
                self.transitions[sid] = ('terminal', None)

    def _find_entry_state(self):
        all_targets = set()
        for t_info in self.transitions.values():
            if t_info[0] == 'simple':
                all_targets.add(t_info[1])
            elif t_info[0] == 'cond':
                all_targets.add(t_info[2])
                all_targets.add(t_info[3])

        sources = set(self.state_to_block.keys())
        potential_entries = sources - all_targets
        
        if potential_entries:
            for pe in potential_entries:
                if "allocSlot" in self.state_to_block[pe]:
                    self.entry_state = pe
                    return
            self.entry_state = list(potential_entries)[0]
        else:
            for sid, block in self.state_to_block.items():
                if "allocSlot" in block:
                    self.entry_state = sid
                    return
            self.entry_state = min(self.state_to_block.keys()) if self.state_to_block else None

    def _emit_linear_code(self) -> str:
        visited = set()
        output_lines = []

        def trace(sid, indent_level=0):
            if sid in visited or sid not in self.state_to_block:
                return
            visited.add(sid)
            
            block = self.state_to_block[sid]
            # Strip out internal state variable updates entirely
            clean_block = re.sub(rf'\b{re.escape(self.state_var)}\s*=\s*.*?(?:\n|;|$)', '', block).strip()
            
            if clean_block:
                for line in clean_block.split('\n'):
                    output_lines.append("    " * indent_level + line)

            t_info = self.transitions.get(sid)
            if not t_info:
                return
                
            t_type = t_info[0]
            if t_type == 'simple':
                trace(t_info[1], indent_level)
            elif t_type == 'cond':
                cond, left_sid, right_sid = t_info[1], t_info[2], t_info[3]
                output_lines.append("    " * indent_level + f"if {cond} then")
                trace(left_sid, indent_level + 1)
                output_lines.append("    " * indent_level + "else")
                trace(right_sid, indent_level + 1)
                output_lines.append("    " * indent_level + "end")

        if self.entry_state is not None:
            trace(self.entry_state)
            
        # Append any unlinked dangling fragments safely at the end
        for sid in sorted(self.state_to_block.keys()):
            if sid not in visited:
                block = self.state_to_block[sid]
                clean_block = re.sub(rf'\b{re.escape(self.state_var)}\s*=\s*.*?(?:\n|;|$)', '', block).strip()
                if clean_block:
                    output_lines.append(clean_block)

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
