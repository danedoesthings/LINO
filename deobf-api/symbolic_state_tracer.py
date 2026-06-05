import re
import json
from typing import Optional, List, Dict, Tuple
from math_fold import safe_eval_int, fold_constants

class SymbolicStateTracer:
    def __init__(self, source: str, decoded_strings: List[str], offset: int = 0):
        self.source = source
        self.strings = decoded_strings
        self.offset = offset
        self.getter_name = None
        self.vm_var = None
        self.states: Dict[int, dict] = {}
        self.entry_state = None
        self.registers: Dict[str, str] = {}
        self.output_lines: List[str] = []
        self.execution_trace: List[str] = []

    def trace(self) -> Optional[str]:
        self._detect_getter()
        self._resolve_all_getter_calls()
        self._extract_vm_structure()
        if not self.states or self.entry_state is None:
            return None
        self._execute_state_machine()
        if self.output_lines:
            return "\n".join(self.output_lines)
        return None

    def _detect_getter(self):
        patterns = [
            r'local\s+function\s+(\w+)\s*\(\s*\1\s*\)\s*return\s+R\s*\[\s*\1\s*\+\s*\(?(-?\d+)\)?\s*\]',
            r'local\s+function\s+(\w+)\s*\(\s*\1\s*\)\s*return\s+R\s*\[\s*\1\s*\+\s*(-?\d+)\s*\]',
        ]
        folded = fold_constants(self.source)
        for p in patterns:
            m = re.search(p, folded)
            if m:
                self.getter_name = m.group(1)
                self.offset = int(m.group(2))
                return

    def _resolve_getter_call(self, match: re.Match) -> str:
        expr = match.group(1).strip()
        n = safe_eval_int(expr)
        if n is not None:
            idx = n + self.offset
            if 1 <= idx <= len(self.strings):
                s = self.strings[idx - 1]
                if s:
                    escaped = json.dumps(s)
                    return escaped
        return match.group(0)

    def _resolve_all_getter_calls(self):
        if not self.getter_name:
            return
        pattern = rf'{re.escape(self.getter_name)}\s*\(\s*([^)]+?)\s*\)'
        self.source = re.sub(pattern, self._resolve_getter_call, self.source)

    def _extract_vm_structure(self):
        while_match = re.search(r'while\s+(\w+)\s+do', self.source)
        if not while_match:
            return
        self.vm_var = while_match.group(1)
        body_start = while_match.end()
        body = self._extract_balanced_block(self.source, body_start)
        if not body:
            return
        self._parse_state_tree(body, [])

    def _extract_balanced_block(self, text: str, start: int) -> Optional[str]:
        if start >= len(text):
            return None
        depth = 1
        pos = start
        while pos < len(text) and depth > 0:
            if text[pos:pos+2] == 'do':
                depth += 1
                pos += 2
            elif text[pos:pos+3] == 'end':
                depth -= 1
                if depth == 0:
                    return text[start:pos]
                pos += 3
            elif text[pos:pos+2] == 'if':
                depth += 1
                pos += 2
            else:
                pos += 1
        return None

    def _parse_state_tree(self, body: str, conditions: List[str]):
        if_match = re.search(r'if\s+(\w+)\s*<\s*(-?\d+)\s+then', body)
        if not if_match:
            self._process_leaf_block(body, conditions)
            return
        var = if_match.group(1)
        boundary = int(if_match.group(2))
        true_start = if_match.end()
        true_body, false_body = self._split_if_else(body[true_start:])
        if true_body is not None:
            self._parse_state_tree(true_body, conditions + [f"{var} < {boundary}"])
        if false_body is not None:
            self._parse_state_tree(false_body, conditions + [f"{var} >= {boundary}"])

    def _split_if_else(self, text: str) -> Tuple[Optional[str], Optional[str]]:
        depth = 0
        pos = 0
        while pos < len(text):
            if text[pos:pos+2] == 'if':
                depth += 1
                pos += 2
            elif text[pos:pos+3] == 'end':
                if depth == 0:
                    return text[:pos].strip(), None
                depth -= 1
                pos += 3
            elif text[pos:pos+4] == 'else' and depth == 0:
                else_pos = pos
                rest = text[else_pos+4:]
                end_pos = rest.find('end')
                if end_pos != -1:
                    return text[:else_pos].strip(), rest[:end_pos].strip()
                return text[:else_pos].strip(), rest.strip()
            else:
                pos += 1
        return text.strip(), None

    def _process_leaf_block(self, body: str, conditions: List[str]):
        state_assign = re.findall(rf'{self.vm_var}\s*=\s*(-?\d+)', body)
        if not state_assign:
            return
        next_state = int(state_assign[-1])
        state_id = next_state
        if state_id in self.states:
            return
        ops = self._extract_operations(body)
        self.states[state_id] = {
            'ops': ops,
            'next': next_state,
            'conditions': conditions,
        }
        if self.entry_state is None:
            self.entry_state = state_id

    def _extract_operations(self, body: str) -> List[dict]:
        ops = []
        patterns = [
            (r'instrTbl\s*\[\s*(\w+)\s*\]\s*=\s*"([^"]*)"', 'LOADK'),
            (r'instrTbl\s*\[\s*(\w+)\s*\]\s*=\s*(\w+)', 'MOVE'),
            (r'(\w+)\s*=\s*EncStr\s*\[\s*"([^"]*)"\s*\]', 'GETGLOBAL'),
            (r'(\w+)\s*=\s*R\s*\[\s*(\w+)\s*\]', 'GETTABLE'),
            (r'(\w+)\s*=\s*(\w+)\s*\.\.\s*(\w+)', 'CONCAT'),
            (r'(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)', 'ADD'),
            (r'(\w+)\s*=\s*(\w+)\s*\-\s*(\w+)', 'SUB'),
            (r'(\w+)\s*=\s*string\.char\s*\(([^)]+)\)', 'STRCHAR'),
            (r'(\w+)\s*\(\s*([^)]*)\s*\)', 'CALL'),
            (r'vmStack\s*\[\s*(\w+)\s*\]\s*=\s*(\w+)', 'PUSH'),
            (r'(\w+)\s*=\s*vmStack\s*\[\s*(\w+)\s*\]', 'POP'),
        ]
        for pattern, op_type in patterns:
            for m in re.finditer(pattern, body):
                ops.append({'type': op_type, 'groups': m.groups()})
        return ops

    def _execute_state_machine(self):
        visited = set()
        self._execute_state(self.entry_state, visited, 0)

    def _execute_state(self, state_id: int, visited: set, depth: int):
        if state_id in visited or state_id not in self.states:
            return
        if depth > 1000:
            return
        visited.add(state_id)
        info = self.states[state_id]
        for op in info['ops']:
            self._apply_operation(op)
        next_state = info.get('next')
        if next_state is not None:
            self._execute_state(next_state, visited, depth + 1)

    def _apply_operation(self, op: dict):
        op_type = op['type']
        groups = op['groups']
        if op_type == 'LOADK' and len(groups) >= 2:
            reg = groups[0]
            val = groups[1]
            self.registers[reg] = val
            self.execution_trace.append(f"local {reg} = {json.dumps(val)}")
        elif op_type == 'MOVE' and len(groups) >= 2:
            dest = groups[0]
            src = groups[1]
            if src in self.registers:
                self.registers[dest] = self.registers[src]
                self.execution_trace.append(f"local {dest} = {src}")
        elif op_type == 'GETGLOBAL' and len(groups) >= 2:
            reg = groups[0]
            key = groups[1]
            if key in self.strings:
                self.registers[reg] = key
                self.execution_trace.append(f"-- {reg} = global {key}")
        elif op_type == 'GETTABLE' and len(groups) >= 2:
            reg = groups[0]
            key_reg = groups[1]
            if key_reg in self.registers:
                self.registers[reg] = self.registers[key_reg]
        elif op_type == 'CONCAT' and len(groups) >= 3:
            dest = groups[0]
            left = groups[1]
            right = groups[2]
            left_val = self.registers.get(left, left)
            right_val = self.registers.get(right, right)
            result = f"{left_val} .. {right_val}"
            self.registers[dest] = result
            self.execution_trace.append(f"local {dest} = {left_val} .. {right_val}")
        elif op_type == 'ADD' and len(groups) >= 3:
            dest = groups[0]
            left = groups[1]
            right = groups[2]
            left_val = self.registers.get(left, left)
            right_val = self.registers.get(right, right)
            result = f"({left_val} + {right_val})"
            self.registers[dest] = result
            self.execution_trace.append(f"local {dest} = {result}")
        elif op_type == 'SUB' and len(groups) >= 3:
            dest = groups[0]
            left = groups[1]
            right = groups[2]
            left_val = self.registers.get(left, left)
            right_val = self.registers.get(right, right)
            result = f"({left_val} - {right_val})"
            self.registers[dest] = result
            self.execution_trace.append(f"local {dest} = {result}")
        elif op_type == 'CALL' and len(groups) >= 1:
            func_name = groups[0]
            args = groups[1] if len(groups) > 1 else ""
            if func_name == 'print':
                arg_val = self.registers.get(args.strip(), args)
                self.output_lines.append(f"print({arg_val})")
            elif func_name == 'error':
                arg_val = self.registers.get(args.strip(), args)
                self.output_lines.append(f"error({arg_val})")
            else:
                self.output_lines.append(f"{func_name}({args})")
        elif op_type == 'STRCHAR' and len(groups) >= 2:
            dest = groups[0]
            chars = groups[1]
            self.output_lines.append(f"local {dest} = string.char({chars})")
