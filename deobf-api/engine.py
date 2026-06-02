import re
import luaparser.ast as lua_ast
from luaparser.astnodes import (
    While, If, Assign, Function, Call, Invoke,
    Block, LocalAssign, Index, Name, Number, String,
    BinaryOp, UnaryOp, Table, Field
)
from typing import Optional, List, Dict, Any, Tuple
from string_decoder import StringTableDecoder


class VMDevirtualizer:
    def __init__(self, source: str, decoder: StringTableDecoder):
        self.source = source
        self.decoder = decoder
        self.strings = decoder.strings
        self.offset = decoder.offset
        self.vm_state_var: str = "vmState"
        self.states: Dict[str, dict] = {}
        self.entry_state: Optional[str] = None
        self.transitions: Dict[str, List[str]] = {}
        self.lifted_code: List[str] = []
        self.diagnostics: List[str] = []
        self._state_counter: int = 0

    def devirtualize(self) -> Optional[str]:
        self.diagnostics = []
        code = self._resolve_all_strings(self.source)
        code = self._sanitize_code(code)
        self.diagnostics.append("Strings resolved and code sanitized")

        try:
            tree = lua_ast.parse(code)
        except Exception as e:
            self.diagnostics.append(f"Parse error after sanitize: {e}")
            return None

        while_node = self._find_dispatcher(tree)
        if while_node is None:
            self.diagnostics.append("No dispatcher while loop found")
            return None

        self.vm_state_var = self._get_while_variable(while_node)
        if not self.vm_state_var:
            self.diagnostics.append("Could not determine VM state variable")
            return None

        self.diagnostics.append(f"Found dispatcher, state var = {self.vm_state_var}")

        self._extract_state_blocks(while_node.body)
        if not self.states:
            self.diagnostics.append("No state blocks extracted")
            return None

        self.diagnostics.append(f"Extracted {len(self.states)} states, entry = {self.entry_state}")

        self._build_transitions()
        self._lift_to_code()

        if not self.lifted_code:
            self.diagnostics.append("Lifting produced no code")
            return None

        return "\n".join(self.lifted_code)

    def _resolve_all_strings(self, code: str) -> str:
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
                return f'({n})'
            except Exception:
                return m.group(0)

        code = re.sub(r'GetStr\s*\(\s*(-?\d+)\s*\)', repl, code)
        return code

    def _sanitize_code(self, code: str) -> str:
        code = re.sub(r'(\b[a-zA-Z_][a-zA-Z0-9_]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*([,})])', r'\1, \2\3', code)
        code = re.sub(r'(\b[a-zA-Z_][a-zA-Z0-9_]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*$', r'\1, \2', code, flags=re.MULTILINE)
        code = re.sub(r'\)\s*\)', '))', code)
        code = re.sub(r'(\w+)\s*\(\s*(\w+)\s*\)\s*(\w+)', r'\1(\2)\3', code)
        code = re.sub(r'\bnil\s*\)', 'nil)', code)
        return code

    def _find_dispatcher(self, tree: lua_ast.Chunk) -> Optional[While]:
        for node in tree.body.body:
            if isinstance(node, While):
                return node
            if hasattr(node, 'body'):
                inner = self._find_in_block(node.body)
                if inner:
                    return inner
        return None

    def _find_in_block(self, block) -> Optional[While]:
        if isinstance(block, list):
            for stmt in block:
                if isinstance(stmt, While):
                    return stmt
                if hasattr(stmt, 'body'):
                    inner = self._find_in_block(stmt.body)
                    if inner:
                        return inner
        elif isinstance(block, Block):
            for stmt in block.body:
                if isinstance(stmt, While):
                    return stmt
                if hasattr(stmt, 'body'):
                    inner = self._find_in_block(stmt.body)
                    if inner:
                        return inner
        return None

    def _get_while_variable(self, node: While) -> Optional[str]:
        if isinstance(node.test, Name):
            return node.test.id
        return None

    def _extract_state_blocks(self, body) -> None:
        for stmt in body.body:
            if isinstance(stmt, If):
                self._walk_if_tree(stmt, [], "")

    def _walk_if_tree(self, node: If, conditions: list, prefix: str) -> None:
        boundary = self._eval_boundary(node.test)
        if boundary is not None:
            true_cond = conditions + [f"{self.vm_state_var} < {boundary}"]
            false_cond = conditions + [f"{self.vm_state_var} >= {boundary}"]

            if len(node.body.body) == 1 and isinstance(node.body.body[0], If):
                self._walk_if_tree(node.body.body[0], true_cond, prefix)
            else:
                self._process_block(node.body.body, true_cond, prefix)

            if node.else_body:
                if len(node.else_body.body) == 1 and isinstance(node.else_body.body[0], If):
                    self._walk_if_tree(node.else_body.body[0], false_cond, prefix)
                else:
                    self._process_block(node.else_body.body, false_cond, prefix)
        else:
            self._process_block(node.body.body, conditions, prefix)

    def _process_block(self, stmts: list, conditions: list, prefix: str) -> None:
        next_state = None
        last_assign = None
        all_targets = []

        for stmt in reversed(stmts):
            if isinstance(stmt, (Assign, LocalAssign)) and self._is_state_assign(stmt):
                if next_state is None:
                    next_state = self._get_assigned_state(stmt)
                    last_assign = stmt
                all_targets.append(self._get_assigned_state(stmt))
            elif isinstance(stmt, If):
                self._extract_all_state_assigns(stmt, all_targets)

        block_id = self._derive_state_id_from_conditions(conditions)

        clean_stmts = [s for s in stmts if s != last_assign]
        code = self._stmts_to_source(clean_stmts)

        self.states[block_id] = {
            'code': code,
            'conditions': conditions,
            'next': next_state,
            'all_targets': all_targets,
        }

        if self.entry_state is None:
            self.entry_state = block_id

    def _extract_all_state_assigns(self, node: If, targets: list) -> None:
        for stmt in node.body.body:
            if isinstance(stmt, (Assign, LocalAssign)) and self._is_state_assign(stmt):
                targets.append(self._get_assigned_state(stmt))
            elif isinstance(stmt, If):
                self._extract_all_state_assigns(stmt, targets)
        if node.else_body:
            for stmt in node.else_body.body:
                if isinstance(stmt, (Assign, LocalAssign)) and self._is_state_assign(stmt):
                    targets.append(self._get_assigned_state(stmt))
                elif isinstance(stmt, If):
                    self._extract_all_state_assigns(stmt, targets)

    def _derive_state_id_from_conditions(self, conditions: list) -> str:
        if not conditions:
            self._state_counter += 1
            return f"entry_{self._state_counter}"
        return " & ".join(conditions)

    def _is_state_assign(self, node) -> bool:
        if isinstance(node, Assign):
            if len(node.targets) != 1:
                return False
            target = node.targets[0]
            if isinstance(target, Name) and target.id == self.vm_state_var:
                return True
        elif isinstance(node, LocalAssign):
            if len(node.targets) != 1:
                return False
            target = node.targets[0]
            if isinstance(target, Name) and target.id == self.vm_state_var:
                return True
        return False

    def _get_assigned_state(self, node) -> Optional[int]:
        if isinstance(node, Assign):
            if len(node.values) != 1:
                return None
            val = node.values[0]
        elif isinstance(node, LocalAssign):
            if len(node.values) != 1:
                return None
            val = node.values[0]
        else:
            return None
        if isinstance(val, Number):
            return int(val.n)
        if isinstance(val, UnaryOp) and val.op == '-' and isinstance(val.operand, Number):
            return -int(val.operand.n)
        return None

    def _eval_boundary(self, node) -> Optional[int]:
        if isinstance(node, BinaryOp) and node.op == '<':
            if isinstance(node.right, Number):
                return int(node.right.n)
            if isinstance(node.right, UnaryOp) and node.right.op == '-' and isinstance(node.right.operand, Number):
                return -int(node.right.operand.n)
        return None

    def _stmts_to_source(self, stmts: list) -> str:
        if not stmts:
            return ""
        lines = []
        for stmt in stmts:
            if hasattr(stmt, 'to_lua'):
                lines.append(stmt.to_lua())
            else:
                lines.append(str(stmt))
        return "\n".join(lines)

    def _build_transitions(self) -> None:
        for state_id, info in self.states.items():
            self.transitions[state_id] = []
            for target in info.get('all_targets', []):
                if target is not None:
                    for other_id, other_info in self.states.items():
                        if other_info.get('conditions') and self._state_matches_conditions(target, other_info['conditions']):
                            self.transitions[state_id].append(other_id)
                            break

    def _state_matches_conditions(self, state_num: int, conditions: list) -> bool:
        if not conditions:
            return False
        for cond in conditions:
            m = re.match(rf'{self.vm_state_var}\s*<\s*(-?\d+)', cond)
            if m:
                boundary = int(m.group(1))
                if state_num >= boundary:
                    return False
            m = re.match(rf'{self.vm_state_var}\s*>=\s*(-?\d+)', cond)
            if m:
                boundary = int(m.group(1))
                if state_num < boundary:
                    return False
        return True

    def _lift_to_code(self) -> None:
        self.lifted_code = []
        self.lifted_code.append("-- VM Devirtualized Output")
        self.lifted_code.append(f"-- {len(self.states)} states, entry = {self.entry_state}")
        self.lifted_code.append("")

        visited = set()
        self._emit_state(self.entry_state, visited, 0)

    def _emit_state(self, state_id: str, visited: set, depth: int) -> None:
        if state_id is None or state_id in visited:
            if state_id in visited:
                self.lifted_code.append("  " * depth + f"-- loop back to state {state_id}")
            return
        visited.add(state_id)
        info = self.states.get(state_id)
        if not info:
            self.lifted_code.append("  " * depth + f"-- unknown state {state_id}")
            return

        code = info['code']
        lifted = self._classify_and_lift(code)
        indent = "  " * depth

        if lifted:
            self.lifted_code.append(indent + f"-- state {state_id}")
            for line in lifted.split("\n"):
                if line.strip():
                    self.lifted_code.append(indent + line)
        else:
            self.lifted_code.append(indent + f"-- state {state_id}: raw code follows")
            for line in code.split("\n"):
                if line.strip():
                    self.lifted_code.append(indent + "-- " + line.strip())

        for next_id in self.transitions.get(state_id, []):
            self._emit_state(next_id, visited, depth + 1)

        next_state = info.get('next')
        if next_state is not None:
            for other_id, other_info in self.states.items():
                if other_info.get('conditions') and self._state_matches_conditions(next_state, other_info['conditions']):
                    self._emit_state(other_id, visited, depth)
                    break

    def _classify_and_lift(self, code: str) -> Optional[str]:
        lines = []
        for line in code.split("\n"):
            line = line.strip()
            if not line:
                continue
            lifted = self._lift_single_line(line)
            if lifted:
                lines.append(lifted)
            else:
                lines.append(f"-- {line}")
        return "\n".join(lines) if lines else None

    def _lift_single_line(self, line: str) -> Optional[str]:
        m_move = re.match(r'(\w+)\s*\[\s*(\w+)\s*\]\s*=\s*(\w+)\s*\[\s*(\w+)\s*\]$', line)
        if m_move:
            dest_tbl, dest_idx, src_tbl, src_idx = m_move.groups()
            return f"local {dest_idx} = {src_idx}  -- MOVE"

        m_loadk = re.match(r'(\w+)\s*\[\s*(\w+)\s*\]\s*=\s*"([^"]*)"$', line)
        if m_loadk:
            tbl, idx, val = m_loadk.groups()
            return f"local {idx} = \"{val}\"  -- LOADK"

        m_loadk_num = re.match(r'(\w+)\s*\[\s*(\w+)\s*\]\s*=\s*(-?\d+)$', line)
        if m_loadk_num:
            tbl, idx, val = m_loadk_num.groups()
            return f"local {idx} = {val}  -- LOADK_NUM"

        m_call = re.match(r'\{?(\w+)\s*\(\s*(\w+)\s*\)\}?$', line)
        if m_call:
            func, arg = m_call.groups()
            return f"{func}({arg})  -- CALL"

        m_closure = re.match(r'(\w+)\s*\[\s*(\w+)\s*\]\s*=\s*(\w+)\s*\(', line)
        if m_closure:
            tbl, idx, factory = m_closure.groups()
            return f"local {idx} = {factory}(...)  -- CLOSURE"

        m_state = re.match(rf'{self.vm_state_var}\s*=\s*(-?\d+)$', line)
        if m_state:
            return f"goto state {m_state.group(1)}"

        return None
