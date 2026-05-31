import re
from typing import Optional, Dict, List, Tuple, Any

class StateMachineLifter:
    def __init__(self, source: str, decoded_strings: list):
        self.source = source
        self.strings = decoded_strings
        self.state_var = "vmState"
        self.state_to_block: Dict[int, str] = {}
        self.transitions: Dict[int, Any] = {}
        self.entry_state: Optional[int] = None

    def lift(self) -> Optional[str]:
        self._find_state_var()
        loop_body = self._get_loop_body()
        if not loop_body:
            return None

        blocks = self._parse_nested_tree(loop_body)
        if not blocks:
            return None

        self._map_states_to_blocks(blocks, loop_body)
        if not self.state_to_block:
            return None

        self._analyze_transitions()
        self._find_entry_state()

        return self._emit_linear_code()

    def _find_state_var(self):
        m = re.search(r'while\s+(\w+)\s+do', self.source)
        if m:
            self.state_var = m.group(1)

    def _get_loop_body(self) -> Optional[str]:
        pattern = rf'while\s+{re.escape(self.state_var)}\s+do\s*(.*?)\s*end\s*(?:$|\n)'
        m = re.search(pattern, self.source, re.DOTALL)
        if m:
            return m.group(1)

        start = self.source.find(f'while {self.state_var} do')
        if start == -1:
            return None

        depth = 0
        i = start
        while i < len(self.source):
            if self.source[i:i+5] == 'while':
                depth += 1
                i += 5
            elif self.source[i:i+3] == 'end':
                depth -= 1
                if depth == 0:
                    body_start = self.source.find('do', start) + 2
                    return self.source[body_start:i]
                i += 3
            else:
                i += 1
        return None

    def _parse_nested_tree(self, loop_body: str) -> List[Tuple[List[Tuple[str, int, bool]], str]]:
        lines = loop_body.split('\n')
        stack: List[Tuple[str, int, bool]] = []
        blocks: List[Tuple[List[Tuple[str, int, bool]], str]] = []
        current_lines: List[str] = []
        
        # FIXED: Explicitly ignore internal scopes by tracking non-dispatcher if statement depths
        internal_if_depth = 0 

        for line in lines:
            trimmed = line.strip()
            if not trimmed:
                continue

            # Strict matches checking only the dispatcher value context mutations
            if_match = re.match(rf'^if\s+{re.escape(self.state_var)}\s*(<|<=|>|>=|==)\s*(-?\d+)\s*then', trimmed)
            elseif_match = re.match(rf'^elseif\s+{re.escape(self.state_var)}\s*(<|<=|>|>=|==)\s*(-?\d+)\s*then', trimmed)

            if if_match and internal_if_depth == 0:
                if current_lines:
                    blocks.append((list(stack), '\n'.join(current_lines)))
                    current_lines = []
                op, val = if_match.group(1), int(if_match.group(2))
                stack.append((op, val, False))
                
            elif elseif_match and internal_if_depth == 0:
                if current_lines:
                    blocks.append((list(stack), '\n'.join(current_lines)))
                    current_lines = []
                op, val = elseif_match.group(1), int(elseif_match.group(2))
                if stack:
                    prev_op, prev_val, _ = stack.pop()
                    stack.append((prev_op, prev_val, True))
                stack.append((op, val, False))
                
            elif trimmed == 'else':
                if internal_if_depth == 0:
                    if current_lines:
                        blocks.append((list(stack), '\n'.join(current_lines)))
                        current_lines = []
                    if stack:
                        op, val, _ = stack.pop()
                        stack.append((op, val, True))
                else:
                    current_lines.append(line)
                    
            elif trimmed == 'end':
                if internal_if_depth > 0:
                    # Closing an internal standard statement block, keep line
                    internal_if_depth -= 1
                    current_lines.append(line)
                else:
                    # Closing an outer dispatcher binary tree node structure path context
                    if current_lines:
                        blocks.append((list(stack), '\n'.join(current_lines)))
                        current_lines = []
                    if stack:
                        stack.pop()
            else:
                # Catch regular inline conditional flows that do NOT belong to the main state driver map
                if re.match(r'^if\s', trimmed) and not if_match:
                    internal_if_depth += 1
                current_lines.append(line)

        if current_lines:
            blocks.append((list(stack), '\n'.join(current_lines)))

        return blocks

    def _map_states_to_blocks(self, blocks: list, loop_body: str):
        all_ids = set()
        # Ensure we catch numbers used in arithmetic expansions cleanly
        for num_str in re.findall(r'-?\d+', loop_body):
            try:
                all_ids.add(int(num_str))
            except ValueError:
                pass

        def satisfies(sid: int, constraints: List[Tuple[str, int, bool]]) -> bool:
            for op, val, inverted in constraints:
                if op == '<': result = sid < val
                elif op == '<=': result = sid <= val
                elif op == '>': result = sid > val
                elif op == '>=': result = sid >= val
                elif op == '==': result = sid == val
                else: result = True
                
                if inverted:
                    result = not result
                if not result:
                    return False
            return True

        for constraints, block_code in blocks:
            clean_code = block_code.strip()
            if not clean_code or clean_code in ('else', 'end', 'then'):
                continue
            for sid in all_ids:
                if satisfies(sid, constraints):
                    existing = self.state_to_block.get(sid, '')
                    # Map code precisely to avoid duplicating segments across matched conditions
                    if len(clean_code) > len(existing):
                        self.state_to_block[sid] = clean_code

    def _analyze_transitions(self):
        for sid, block in self.state_to_block.items():
            cond_match = re.search(
                rf'{re.escape(self.state_var)}\s*=\s*(.+?)\s+and\s+(-?\d+)\s+or\s+(-?\d+)',
                block
            )
            if cond_match:
                self.transitions[sid] = ('cond', cond_match.group(1).strip(),
                                         int(cond_match.group(2)), int(cond_match.group(3)))
                continue

            assigns = list(re.finditer(rf'{re.escape(self.state_var)}\s*=\s*(-?\d+)', block))
            if assigns:
                self.transitions[sid] = ('simple', int(assigns[-1].group(1)))
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
                if 'allocSlot' in self.state_to_block.get(pe, ''):
                    self.entry_state = pe
                    return
            self.entry_state = list(potential_entries)[0]
        else:
            self.entry_state = min(self.state_to_block.keys()) if self.state_to_block else None

    def _emit_linear_code(self) -> str:
        visited: set[int] = set()
        output_lines: List[str] = []

        def trace(sid: int, indent: int = 0):
            if sid in visited or sid not in self.state_to_block:
                return
            visited.add(sid)

            block = self.state_to_block[sid]
            clean_block = re.sub(
                rf'[ \t]*{re.escape(self.state_var)}\s*=\s*[^;\n]+[;\n]?', '', block
            ).strip()

            if clean_block:
                for line in clean_block.split('\n'):
                    stripped = line.strip()
                    if stripped:
                        output_lines.append('    ' * indent + stripped)

            t_info = self.transitions.get(sid)
            if not t_info:
                return

            t_type = t_info[0]
            if t_type == 'simple':
                trace(t_info[1], indent)
            elif t_type == 'cond':
                cond, left_sid, right_sid = t_info[1], t_info[2], t_info[3]
                clean_cond = self._resolve_string_refs(cond)
                output_lines.append('    ' * indent + f'if {clean_cond} then')
                trace(left_sid, indent + 1)
                output_lines.append('    ' * indent + 'else')
                trace(right_sid, indent + 1)
                output_lines.append('    ' * indent + 'end')

        if self.entry_state is not None:
            trace(self.entry_state)

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
