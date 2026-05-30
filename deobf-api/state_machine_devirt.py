import re
import json
from collections import defaultdict, deque
from typing import List, Dict, Tuple, Optional, Set, Any

class StateMachineLifter:
    def __init__(self, source: str, decoded_strings: List[str]):
        self.source = source
        self.strings = decoded_strings
        self.state_handlers: Dict[int, Dict[str, Any]] = {}
        self.entry_state: Optional[int] = None
        self.register_state: Dict[int, str] = {}
        self.output_lines: List[str] = []
        self.indent_level: int = 0
        
    def lift(self) -> Optional[str]:
        if not self._extract_state_machine():
            return None
        self._simulate_states()
        if not self.output_lines:
            return None
        return self._format_output()
    
    def _extract_state_machine(self) -> bool:
        while_match = re.search(r'while\s+(\w+)\s+do\s+(.*?)end\s*(?:\)\s*\)|$)', self.source, re.DOTALL)
        if not while_match:
            return False
        
        state_var = while_match.group(1)
        body = while_match.group(2)
        
        if_pattern = r'if\s+' + state_var + r'\s*<\s*(\d+)\s+then\s*(.*?)(?:elseif\s+' + state_var + r'\s*<\s*(\d+)\s+then\s*(.*?))*?\s*else\s*(.*?)\s*end'
        
        matches = list(re.finditer(if_pattern, body, re.DOTALL))
        if not matches:
            return False
        
        for match in matches:
            state_num = int(match.group(1))
            handler_body = match.group(2).strip()
            self.state_handlers[state_num] = {
                'body': handler_body,
                'transitions': self._extract_transitions(handler_body, state_var)
            }
        
        if 0 not in self.state_handlers:
            for state_num in sorted(self.state_handlers.keys()):
                if state_num > 0:
                    self.entry_state = state_num
                    break
        else:
            self.entry_state = 0
        
        return self.entry_state is not None
    
    def _extract_transitions(self, handler_body: str, state_var: str) -> List[Tuple[int, Optional[str]]]:
        transitions = []
        assign_pattern = r'\b' + state_var + r'\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)'
        for assign_match in re.finditer(assign_pattern, handler_body):
            expr = assign_match.group(1).replace(' ', '')
            try:
                next_state = eval(expr)
                if isinstance(next_state, int):
                    transitions.append((next_state, None))
            except:
                pass
        
        call_pattern = r'I\s*\[\s*r\s*\[\s*(\d+)\s*\]\s*\]'
        for call_match in re.finditer(call_pattern, handler_body):
            idx = int(call_match.group(1))
            if 1 <= idx <= len(self.strings):
                transitions.append((-1, self.strings[idx - 1]))
        
        return transitions
    
    def _simulate_states(self) -> None:
        visited = set()
        stack = [(self.entry_state, 0)]
        
        while stack:
            state_num, depth = stack.pop()
            if state_num in visited:
                continue
            visited.add(state_num)
            
            handler = self.state_handlers.get(state_num)
            if not handler:
                continue
            
            self.indent_level = depth
            self._emit_handler(handler, state_num)
            
            for next_state, call_name in handler['transitions']:
                if next_state >= 0 and next_state not in visited:
                    stack.append((next_state, depth + 1))
                elif call_name:
                    self.output_lines.append(f"{'  ' * self.indent_level}{call_name}()")
    
    def _emit_handler(self, handler: Dict[str, Any], state_num: int) -> None:
        body = handler['body']
        
        if 'print' in body or 'warn' in body or 'error' in body:
            self._extract_api_calls(body)
        
        assign_pattern = r'(\w+)\s*=\s*Q\s*\[\s*I\s*\[\s*B\s*\+\s*(\d+)\s*\]\s*\]'
        for match in re.finditer(assign_pattern, body):
            var_name = match.group(1)
            offset = int(match.group(2))
            const_idx = offset + 1
            if 1 <= const_idx <= len(self.strings):
                const_value = self.strings[const_idx - 1]
                if isinstance(const_value, str) and const_value and const_value[0].isalpha():
                    self.output_lines.append(f"{'  ' * self.indent_level}local {var_name} = {const_value}")
        
        load_pattern = r'local\s+(\w+)\s*=\s*Q\s*\[\s*I\s*\[\s*B\s*\+\s*(\d+)\s*\]\s*\]'
        for match in re.finditer(load_pattern, body):
            var_name = match.group(1)
            offset = int(match.group(2))
            const_idx = offset + 1
            if 1 <= const_idx <= len(self.strings):
                const_value = self.strings[const_idx - 1]
                if const_value and len(const_value) < 200:
                    self.output_lines.append(f"{'  ' * self.indent_level}local {var_name} = {json.dumps(const_value)}")
        
        call_pattern = r'(\w+)\s*=\s*(\w+)\(\)'
        for match in re.finditer(call_pattern, body):
            dest_var = match.group(1)
            func_name = match.group(2)
            self.output_lines.append(f"{'  ' * self.indent_level}local {dest_var} = {func_name}()")
        
        if 'pcall' in body:
            self._extract_pcall(body)
    
    def _extract_api_calls(self, body: str) -> None:
        print_pattern = r'print\s*\(\s*([^)]+)\s*\)'
        for match in re.finditer(print_pattern, body):
            args = match.group(1)
            resolved_args = self._resolve_strings(args)
            self.output_lines.append(f"{'  ' * self.indent_level}print({resolved_args})")
        
        error_pattern = r'error\s*\(\s*([^)]+)\s*\)'
        for match in re.finditer(error_pattern, body):
            msg = match.group(1)
            resolved_msg = self._resolve_strings(msg)
            self.output_lines.append(f"{'  ' * self.indent_level}error({resolved_msg})")
        
        warn_pattern = r'warn\s*\(\s*([^)]+)\s*\)'
        for match in re.finditer(warn_pattern, body):
            msg = match.group(1)
            resolved_msg = self._resolve_strings(msg)
            self.output_lines.append(f"{'  ' * self.indent_level}warn({resolved_msg})")
    
    def _extract_pcall(self, body: str) -> None:
        pcall_pattern = r'pcall\s*\(\s*(\w+)\s*,\s*\.\.\.\s*\)'
        for match in re.finditer(pcall_pattern, body):
            func_name = match.group(1)
            self.output_lines.append(f"{'  ' * self.indent_level}pcall({func_name}, ...)")
    
    def _resolve_strings(self, expr: str) -> str:
        for i, s in enumerate(self.strings):
            if s and len(s) > 2 and s.isprintable():
                placeholder = f'R[{i + 1}]'
                if placeholder in expr:
                    expr = expr.replace(placeholder, json.dumps(s))
        
        const_pattern = r'R\[(\d+)\]'
        for match in re.finditer(const_pattern, expr):
            idx = int(match.group(1))
            if 1 <= idx <= len(self.strings):
                const_value = self.strings[idx - 1]
                if const_value:
                    expr = expr.replace(match.group(0), json.dumps(const_value))
        
        return expr
    
    def _format_output(self) -> str:
        header = "-- Deobfuscated via state machine devirtualization\n"
        header += "-- Extracted from WeAreDevs while-state VM\n\n"
        
        unique_lines = []
        seen = set()
        for line in self.output_lines:
            if line not in seen:
                unique_lines.append(line)
                seen.add(line)
        
        return header + '\n'.join(unique_lines)
