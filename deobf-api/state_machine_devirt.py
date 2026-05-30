import re
import json
import math
import base64
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional, Any

class StateMachineLifter:
    def __init__(self, source: str, decoded_strings: List[str]):
        self.source = source
        self.strings = decoded_strings
        self.register_state: Dict[int, Any] = {}
        self.stack = []
        self.output_lines = []
        self.handlers: Dict[int, Dict] = {}
        self.state_transitions: Dict[int, List[int]] = defaultdict(list)
        self.visited_states = set()
        self.indent_level = 0
        self.loop_headers = set()
        
    def lift(self) -> Optional[str]:
        if not self._extract_state_handlers():
            return None
        if not self._build_control_flow():
            return None
        self._simulate_execution()
        if not self.output_lines:
            return None
        return '\n'.join(self.output_lines)
    
    def _extract_state_handlers(self) -> bool:
        state_pattern = r'if\s+l\s*<\s*(\d+)\s+then\s*(.*?)elseif\s+l\s*<\s*(\d+)\s+then\s*(.*?)(?:else\s*(.*?))?end'
        
        matches = list(re.finditer(state_pattern, self.source, re.DOTALL))
        if not matches:
            return False
        
        for match in matches:
            for i in range(1, len(match.groups()), 2):
                if match.group(i):
                    state_id = int(match.group(i))
                    body = match.group(i+1) if i+1 < len(match.groups()) else ''
                    if state_id not in self.handlers:
                        self.handlers[state_id] = self._parse_handler_body(body)
        
        entry_match = re.search(r'l\s*=\s*(\d+)', self.source)
        if entry_match:
            self.entry_state = int(entry_match.group(1))
        else:
            self.entry_state = min(self.handlers.keys())
        
        return len(self.handlers) > 0
    
    def _parse_handler_body(self, body: str) -> Dict:
        handler = {'operations': [], 'next_state': None, 'type': 'normal'}
        
        reg_pattern = r'I\s*\[\s*(\w+)\s*\]\s*=\s*([^;\n]+)'
        for match in re.finditer(reg_pattern, body):
            reg_idx = self._extract_register_index(match.group(1))
            value = match.group(2).strip()
            handler['operations'].append(('set_reg', reg_idx, value))
        
        call_pattern = r'(\w+)\s*\(\s*([^)]+)\s*\)'
        for match in re.finditer(call_pattern, body):
            func = match.group(1)
            args = match.group(2)
            handler['operations'].append(('call', func, args))
        
        state_change = re.search(r'l\s*=\s*(\d+)', body)
        if state_change:
            handler['next_state'] = int(state_change.group(1))
        
        print_match = re.search(r'print\s*\(\s*([^)]+)\s*\)', body)
        if print_match:
            handler['operations'].append(('print', print_match.group(1)))
        
        return handler
    
    def _extract_register_index(self, expr: str) -> Optional[int]:
        if expr.isdigit():
            return int(expr)
        bracket_match = re.search(r'r\[(\d+)\]', expr)
        if bracket_match:
            return int(bracket_match.group(1))
        return None
    
    def _build_control_flow(self) -> bool:
        for state_id, handler in self.handlers.items():
            if handler['next_state'] is not None:
                self.state_transitions[state_id].append(handler['next_state'])
        
        for state_id in self.handlers:
            if state_id not in self.state_transitions:
                self.state_transitions[state_id] = []
        
        for transitions in self.state_transitions.values():
            if len(transitions) > 1:
                self.loop_headers.add(transitions[0])
        
        return True
    
    def _simulate_execution(self):
        if not self.entry_state:
            return
        
        stack = [(self.entry_state, 0)]
        visited_depth = {}
        
        while stack:
            state_id, depth = stack.pop()
            
            if state_id in visited_depth and visited_depth[state_id] <= depth:
                continue
            
            visited_depth[state_id] = depth
            
            if state_id not in self.handlers:
                continue
            
            self.visited_states.add(state_id)
            self.indent_level = depth
            
            handler = self.handlers[state_id]
            
            for op in handler['operations']:
                self._execute_operation(op)
            
            if handler['next_state'] is not None:
                next_state = handler['next_state']
                if next_state not in self.visited_states:
                    stack.append((next_state, depth))
                elif next_state in self.loop_headers:
                    self.output_lines.append('  ' * depth + 'end')
    
    def _execute_operation(self, op: Tuple):
        prefix = '  ' * self.indent_level
        
        if op[0] == 'set_reg':
            _, reg_idx, value = op
            resolved = self._resolve_value(value)
            self.register_state[reg_idx] = resolved
            self.output_lines.append(f'{prefix}local reg_{reg_idx} = {resolved}')
        
        elif op[0] == 'call':
            _, func, args = op
            resolved_args = self._resolve_arguments(args)
            if func == 'print':
                self.output_lines.append(f'{prefix}print({", ".join(resolved_args)})')
            elif func == 'pcall':
                self.output_lines.append(f'{prefix}local success, result = pcall(function()')
                self.indent_level += 1
            else:
                self.output_lines.append(f'{prefix}{func}({", ".join(resolved_args)})')
        
        elif op[0] == 'print':
            _, arg = op
            resolved = self._resolve_value(arg)
            self.output_lines.append(f'{prefix}print({resolved})')
    
    def _resolve_value(self, expr: str) -> str:
        expr = expr.strip()
        
        if expr.isdigit():
            return expr
        
        const_match = re.search(r'R\[(\d+)\]', expr)
        if const_match:
            idx = int(const_match.group(1)) - 1
            if 0 <= idx < len(self.strings):
                return json.dumps(self.strings[idx])
        
        reg_match = re.search(r'I\[(\d+)\]', expr)
        if reg_match:
            reg_idx = int(reg_match.group(1))
            if reg_idx in self.register_state:
                return str(self.register_state[reg_idx])
        
        if expr.startswith('"') and expr.endswith('"'):
            return expr
        
        if expr.startswith("'") and expr.endswith("'"):
            return expr
        
        try:
            evaluated = eval(expr, {'math': math})
            if isinstance(evaluated, (int, float, str)):
                return json.dumps(evaluated) if isinstance(evaluated, str) else str(evaluated)
        except:
            pass
        
        return expr
    
    def _resolve_arguments(self, args: str) -> List[str]:
        if not args.strip():
            return []
        
        results = []
        for arg in args.split(','):
            results.append(self._resolve_value(arg.strip()))
        return results
    
    def _generate_lua(self) -> str:
        lines = ['-- Deobfuscated via state machine devirtualization', '']
        lines.extend(self.output_lines)
        
        if not any('print' in line for line in self.output_lines):
            lines.append('')
            lines.append('-- Reconstructed string table:')
            for i, s in enumerate(self.strings):
                if s and len(s) < 100:
                    lines.append(f'--   [{i}] = {json.dumps(s)}')
        
        return '\n'.join(lines)
