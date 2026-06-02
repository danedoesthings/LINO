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
    def __init__(self, source: str, decoder: StringTableDecoder, wrapper_name: str = "GetStr"):
        self.source = source
        self.decoder = decoder
        self.strings = decoder.strings
        self.offset = decoder.offset
        self.wrapper_name = wrapper_name
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
            m_offset = re.search(rf'{self.wrapper_name}\s*\+\s*\(?\s*(\d+)\s*\)?', code)
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

        code = re.sub(rf'{self.wrapper_name}\s*\(\s*(-?\d+)\s*\)', repl, code)
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

        self.states[block_id] = {
            'stmts': clean_stmts,
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
        if isinstance(node, (Assign, LocalAssign)):
            if len(node.targets) != 1:
                return False
            target = node.targets[0]
            if isinstance(target, Name) and target.id == self.vm_state_var:
                return True
        return False

    def _get_assigned_state(self, node) -> Optional[int]:
        if len(node.values) != 1:
            return None
        val = node.values[0]
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

    def _node_to_source(self, node) -> str:
        if node is None:
            return ""
        if isinstance(node, Block):
            return "\n".join(self._node_to_source(s) for s in node.body)
        if isinstance(node, list):
            return "\n".join(self._node_to_source(s) for s in node)
        if isinstance(node, Name):
            return node.id
        if isinstance(node, Number):
            return str(node.n)
        if isinstance(node, String):
            escaped = node.s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
            return f'"{escaped}"'
        if isinstance(node, Assign):
            targets = ", ".join(self._node_to_source(t) for t in node.targets)
            values = ", ".join(self._node_to_source(v) for v in node.values)
            return f"{targets} = {values}"
        if isinstance(node, LocalAssign):
            targets = ", ".join(self._node_to_source(t) for t in node.targets)
            if node.values:
                values = ", ".join(self._node_to_source(v) for v in node.values)
                return f"local {targets} = {values}"
            return f"local {targets}"
        if isinstance(node, BinaryOp):
            return f"({self._node_to_source(node.left)} {node.op} {self._node_to_source(node.right)})"
        if isinstance(node, UnaryOp):
            return f"({node.op}{self._node_to_source(node.operand)})"
        if isinstance(node, Index):
            obj = self._node_to_source(node.value)
            idx = self._node_to_source(node.idx)
            if isinstance(node.idx, String):
                return f'{obj}["{node.idx.s}"]'
            return f"{obj}[{idx}]"
        if isinstance(node, Call):
            func = self._node_to_source(node.func)
            args = ", ".join(self._node_to_source(a) for a in node.args)
            return f"{func}({args})"
        if isinstance(node, Invoke):
            obj = self._node_to_source(node.source)
            method = node.func.id
            args = ", ".join(self._node_to_source(a) for a in node.args)
            return f"{obj}:{method}({args})"
        if isinstance(node, Function):
            params = ", ".join(p.id for p in node.args)
            body = self._node_to_source(node.body)
            return f"function({params})\n{body}\nend"
        if isinstance(node, If):
            out = f"if {self._node_to_source(node.test)} then\n"
            out += self._node_to_source(node.body)
            if node.else_body:
                out += f"\nelse\n{self._node_to_source(node.else_body)}"
            out += "\nend"
            return out
        if isinstance(node, Table):
            if node.fields:
                fields = []
                for f in node.fields:
                    if isinstance(f, Field):
                        if f.key:
                            fields.append(f"[{self._node_to_source(f.key)}] = {self._node_to_source(f.value)}")
                        else:
                            fields.append(self._node_to_source(f.value))
                return "{" + ", ".join(fields) + "}"
            return "{}"
        if isinstance(node, Field):
            if node.key:
                return f"[{self._node_to_source(node.key)}] = {self._node_to_source(node.value)}"
            return self._node_to_source(node.value)
        if isinstance(node, Vararg):
            return "..."
        if isinstance(node, str):
            return node
        return f"-- <{type(node).__name__}>"

    def _build_transitions(self) -> None:
        for state_id, info in self.states.items():
            self.transitions[state_id] = []
            for target in info.get('all_targets', []):
                if target is not None:
                    for other_id, other_info in self.states.items():
                        if other_info.get('conditions') and self._state_matches_conditions(target, other_info['conditions']):
                            if other_id not in self.transitions[state_id]:
                                self.transitions[state_id].append(other_id)

    def _state_matches_conditions(self, state_num: int, conditions: list) -> bool:
        if not conditions:
            return False
        for cond in conditions:
            m = re.match(rf'{self.vm_state_var}\s*<\s*(-?\d+)', cond)
            if m:
                if state_num >= int(m.group(1)):
                    return False
            m = re.match(rf'{self.vm_state_var}\s*>=\s*(-?\d+)', cond)
            if m:
                if state_num < int(m.group(1)):
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
        if state_id is None:
            return
        if state_id in visited:
            return

        visited.add(state_id)
        info = self.states.get(state_id)
        if not info:
            self.lifted_code.append("  " * depth + f"-- unknown state {state_id}")
            return

        indent = "  " * depth
        self.lifted_code.append(indent + f"-- state section: {state_id}")

        for stmt in info['stmts']:
            lifted_line = self._lift_ast_statement(stmt)
            if lifted_line:
                self.lifted_code.append(indent + lifted_line)

        for next_id in self.transitions.get(state_id, []):
            self._emit_state(next_id, visited, depth)

    def _lift_ast_statement(self, stmt) -> str:
        if isinstance(stmt, (Assign, LocalAssign)) and len(stmt.targets) == 1 and len(stmt.values) == 1:
            target = stmt.targets[0]
            val = stmt.values[0]

            if isinstance(target, Index):
                tbl = self._node_to_source(target.value)
                idx = self._node_to_source(target.idx)

                if isinstance(val, Index):
                    src_tbl = self._node_to_source(val.value)
                    src_idx = self._node_to_source(val.idx)
                    return f"local {idx} = {src_idx}  -- MOVE from {tbl}"
                if isinstance(val, String):
                    return f"local {idx} = \"{val.s}\"  -- LOADK"
                if isinstance(val, Number):
                    return f"local {idx} = {val.n}  -- LOADK_NUM"
                if isinstance(val, Call):
                    func_name = self._node_to_source(val.func)
                    return f"local {idx} = {func_name}(...)  -- CLOSURE"

        if isinstance(stmt, Call):
            func_name = self._node_to_source(stmt.func)
            args = ", ".join(self._node_to_source(a) for a in stmt.args)
            return f"{func_name}({args})  -- CALL"

        if isinstance(stmt, (Assign, LocalAssign)):
            return self._node_to_source(stmt) + "  -- ASSIGN"

        return self._node_to_source(stmt)
