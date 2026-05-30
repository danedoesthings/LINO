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
        self.transitions: Dict[int, List[int]] = defaultdict(list)
        self.visited_states: Set[int] = set()
        self.output_lines: List[str] = []
        self.indent_level: int = 0
        self.register_map: Dict[str, str] = {}
        self.temp_counter: int = 0
        
    def lift(self) -> Optional[str]:
        self._extract_state_machine()
        if not self.state_handlers:
            return None
        self._find_entry_state()
        if self.entry_state is None:
            return None
        self._build_transition_graph()
        self._trace_execution_path(self.entry_state)
        if not self.output_lines:
            return None
        return self._format_output()
    
    def _extract_state_machine(self) -> None:
        while_match = re.search(r'while\s+(\w+)\s+do\s+(.*?)end\s*(?:\)\s*\)|$)', self.source, re.DOTALL)
        if not while_match:
            return
        
        state_var = while_match.group(1)
        body = while_match.group(2)
        
        pattern = r'if\s+' + state_var + r'\s*<\s*(\d+)\s+then(.*?)(?:elseif\s+' + state_var + r'\s*<\s*(\d+)\s+then(.*?))*?else(.*?)end'
        matches = list(re.finditer(pattern, body, re.DOTALL))
        
        for match in matches:
            state_num = int(match.group(1))
            handler_body = match.group(2).strip()
            self.state_handlers[state_num] = {
                'body': handler_body,
                'raw': match.group(0)
            }
        
        else_body_match = re.search(r'else\s+(.*?)end', body, re.DOTALL)
        if else_body_match and self.state_handlers:
            self.state_handlers[max(self.state_handlers.keys()) + 1] = {
                'body': else_body_match.group(1).strip(),
                'raw': else_body_match.group(0)
            }
    
    def _find_entry_state(self) -> None:
        init_match = re.search(r'(\w+)\s*=\s*(\d+)', self.source[:2000])
        if init_match:
            possible_state = int(init_match.group(2))
            if possible_state in self.state_handlers:
                self.entry_state = possible_state
                return
        
        for state_num in sorted(self.state_handlers.keys()):
            if state_num < 100:
                self.entry_state = state_num
                return
        
        if self.state_handlers:
            self.entry_state = min(self.state_handlers.keys())
    
    def _build_transition_graph(self) -> None:
        for state_num, handler in self.state_handlers.items():
            body = handler['body']
            assign_pattern = r'\b(\w+)\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)'
            for match in re.finditer(assign_pattern, body):
                var_name = match.group(1)
                expr = match.group(2).replace(' ', '')
                if var_name in ['l', 'L', 'state', 'pc', 'ip']:
                    try:
                        next_state = eval(expr)
                        if isinstance(next_state, int) and next_state in self.state_handlers:
                            self.transitions[state_num].append(next_state)
                    except:
                        pass
            
            call_match = re.search(r'\(\s*(\w+)\s*\)', body)
            if call_match and call_match.group(1) in self.strings:
                self.transitions[state_num].append(-1)
    
    def _trace_execution_path(self, start_state: int) -> None:
        stack = [(start_state, 0)]
        
        while stack:
            state_num, depth = stack.pop()
            if state_num in self.visited_states:
                continue
            
            self.visited_states.add(state_num)
            self.indent_level = depth
            
            handler = self.state_handlers.get(state_num)
            if handler:
                self._emit_state_code(handler, state_num)
            
            for next_state in self.transitions.get(state_num, []):
                if next_state >= 0 and next_state not in self.visited_states:
                    stack.append((next_state, depth + 1))
    
    def _emit_state_code(self, handler: Dict[str, Any], state_num: int) -> None:
        body = handler['body']
        
        const_loads = re.findall(r'(\w+)\s*=\s*Q\s*\[\s*I\s*\[\s*B\s*\+\s*(\d+)\s*\]\s*\]', body)
        for var_name, offset in const_loads:
            const_idx = int(offset) + 1
            if 1 <= const_idx <= len(self.strings):
                const_value = self.strings[const_idx - 1]
                if const_value and len(const_value) < 500:
                    if var_name not in self.register_map:
                        self.register_map[var_name] = const_value
                        self._emit_line(f"local {var_name} = {json.dumps(const_value)}")
        
        func_calls = re.findall(r'(\w+)\s*=\s*(\w+)\(\)', body)
        for dest_var, func_name in func_calls:
            if func_name in self.strings:
                actual_func = self.strings[self.strings.index(func_name)]
                self._emit_line(f"local {dest_var} = {actual_func}()")
            else:
                self._emit_line(f"local {dest_var} = {func_name}()")
        
        pcall_match = re.search(r'pcall\s*\(\s*(\w+)\s*,\s*\.\.\.\s*\)', body)
        if pcall_match:
            func_name = pcall_match.group(1)
            self._emit_line(f"pcall({func_name}, ...)")
        
        print_matches = re.finditer(r'print\s*\(\s*([^)]+)\s*\)', body)
        for match in print_matches:
            args = match.group(1)
            resolved_args = self._resolve_string_constant(args)
            self._emit_line(f"print({resolved_args})")
        
        error_matches = re.finditer(r'error\s*\(\s*([^)]+)\s*\)', body)
        for match in error_matches:
            msg = match.group(1)
            resolved_msg = self._resolve_string_constant(msg)
            self._emit_line(f"error({resolved_msg})")
        
        warn_matches = re.finditer(r'warn\s*\(\s*([^)]+)\s*\)', body)
        for match in warn_matches:
            msg = match.group(1)
            resolved_msg = self._resolve_string_constant(msg)
            self._emit_line(f"warn({resolved_msg})")
        
        setmetatable_match = re.search(r'setmetatable\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)', body)
        if setmetatable_match:
            obj = setmetatable_match.group(1)
            mt = setmetatable_match.group(2)
            self._emit_line(f"setmetatable({obj}, {mt})")
        
        getmetatable_match = re.search(r'getmetatable\s*\(\s*(\w+)\s*\)', body)
        if getmetatable_match:
            obj = getmetatable_match.group(1)
            temp_var = f"_temp_{self.temp_counter}"
            self.temp_counter += 1
            self._emit_line(f"local {temp_var} = getmetatable({obj})")
    
    def _resolve_string_constant(self, expr: str) -> str:
        const_pattern = r'R\[(\d+)\]'
        for match in re.finditer(const_pattern, expr):
            idx = int(match.group(1))
            if 1 <= idx <= len(self.strings):
                const_value = self.strings[idx - 1]
                if const_value:
                    expr = expr.replace(match.group(0), json.dumps(const_value))
        
        for var_name, const_value in self.register_map.items():
            if var_name in expr and isinstance(const_value, str):
                expr = expr.replace(var_name, json.dumps(const_value))
        
        return expr
    
    def _emit_line(self, line: str) -> None:
        indent = '  ' * self.indent_level
        self.output_lines.append(f"{indent}{line}")
    
    def _format_output(self) -> str:
        header = "-- Deobfuscated via state machine devirtualization\n"
        header += "-- Extracted from WeAreDevs while-state VM\n"
        header += "-- Original program logic reconstructed from state transitions\n\n"
        
        seen = set()
        unique_lines = []
        for line in self.output_lines:
            if line not in seen:
                unique_lines.append(line)
                seen.add(line)
        
        if not unique_lines:
            return self._fallback_output()
        
        return header + '\n'.join(unique_lines)
    
    def _fallback_output(self) -> str:
        output = []
        output.append("-- Decoded constants from R table:")
        for i, s in enumerate(self.strings):
            if s and len(s) < 100 and s.isprintable():
                output.append(f"-- [{i}] = {json.dumps(s)}")
        
        for state_num, handler in sorted(self.state_handlers.items())[:20]:
            output.append(f"\n-- STATE {state_num}:")
            body_preview = handler['body'][:500].replace('\n', ' ')
            output.append(f"-- {body_preview}")
        
        return '\n'.join(output)
