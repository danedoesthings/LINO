import re
import luaparser.ast as lua_ast
from luaparser.astnodes import (
    While, If, Assign, Function,
    Block, LocalAssign, Index, Name, Number, String,
    BinaryOp, UnaryOp, Table, Field
)
from typing import Optional, List, Dict, Any


class StateMachineLifter:
    def __init__(self, source: str, decoded_strings: list = None, offset: int = 0):
        self.source = source
        self.strings = decoded_strings if decoded_strings else []
        self.offset = offset
        self.vm_state_var: Optional[str] = None
        self.entry_state: Optional[int] = None
        self.handlers: Dict[int, dict] = {}
        self.diagnostics: List[str] = []

    def lift(self) -> Optional[str]:
        self.diagnostics = []
        code = self._resolve_getstr(self.source)
        try:
            tree = lua_ast.parse(code)
        except Exception as e:
            self.diagnostics.append(f"Parse error: {e}")
            return None

        while_node = self._find_dispatcher(tree)
        if while_node is None:
            self.diagnostics.append("No 'while' dispatcher found in AST")
            return None

        self.vm_state_var = self._get_while_variable(while_node)
        if not self.vm_state_var:
            self.diagnostics.append("Could not determine VM state variable name")
            return None

        self._extract_states(while_node.body)
        if not self.handlers:
            self.diagnostics.append("No state handlers extracted from dispatcher body")
            return None

        self.diagnostics.append(f"Extracted {len(self.handlers)} states, entry state = {self.entry_state}")
        return self._emit_lua()

    def _resolve_getstr(self, code: str) -> str:
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
                return 'nil'
            except Exception:
                return m.group(0)
        return re.sub(r'GetStr\s*\(\s*(-?\d+)\s*\)', repl, code)

    def _find_dispatcher(self, tree: lua_ast.Chunk) -> Optional[While]:
        for node in tree.body.body:
            if isinstance(node, While):
                self.diagnostics.append(f"Found dispatcher at top level, condition type: {type(node.test)}")
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
        self.diagnostics.append(f"While condition is not a simple name: {type(node.test)}")
        return None

    def _extract_states(self, body: List[Any]) -> None:
        self._walk_ifs(body, [], [])

    def _walk_ifs(self, body: List[Any], parent_conditions: list, prefix: list) -> None:
        statements = []
        for i, stmt in enumerate(body):
            if isinstance(stmt, If):
                remaining = body[i+1:]
                self._handle_if(stmt, parent_conditions, prefix + statements, remaining)
                return
            else:
                statements.append(stmt)
        self._process_leaf(statements, parent_conditions)

    def _handle_if(self, node: If, parent_conditions: list, prefix: list, remaining: list) -> None:
        boundary = self._eval_boundary(node.test)
        if boundary is None:
            self.diagnostics.append(f"If condition not a simple '<': {node.test}")
            self._walk_ifs(node.body.body, parent_conditions, prefix)
            if node.else_body:
                self._walk_ifs(node.else_body.body, parent_conditions, prefix)
            return

        true_cond = parent_conditions + [f"{self.vm_state_var} < {boundary}"]
        false_cond = parent_conditions + [f"{self.vm_state_var} >= {boundary}"]

        self._walk_ifs(node.body.body, true_cond, prefix)

        if node.else_body:
            self._walk_ifs(node.else_body.body, false_cond, prefix)
        else:
            self._walk_ifs(remaining, false_cond, prefix)

    def _process_leaf(self, statements: list, conditions: list) -> None:
        last_assign = None
        state = None
        for stmt in reversed(statements):
            if isinstance(stmt, (Assign, LocalAssign)) and self._is_state_assign(stmt):
                state = self._get_assigned_state(stmt)
                last_assign = stmt
                break
        if state is None:
            return
        block_stmts = statements[:-1] if last_assign else statements
        source_lines = self._statements_to_lines(block_stmts)
        if state not in self.handlers:
            self.handlers[state] = {
                'code': source_lines,
                'conditions': conditions,
                'next': None,
                'conditional': False
            }
        if self.entry_state is None:
            self.entry_state = state

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

    def _statements_to_lines(self, stmts: list) -> str:
        if not stmts:
            return ""
        buf = []
        for stmt in stmts:
            buf.append(self._stmt_to_line(stmt))
        return "\n".join(buf)

    def _stmt_to_line(self, stmt) -> str:
        if hasattr(stmt, 'to_lua'):
            return stmt.to_lua()
        return str(stmt)

    def _emit_lua(self) -> str:
        lines = []
        lines.append("local state_handlers = {}")
        lines.append("")
        for state, info in sorted(self.handlers.items()):
            lines.append(f"state_handlers[{state}] = function()")
            code_lines = info['code'].split('\n')
            if code_lines and code_lines[0] == '':
                code_lines = code_lines[1:]
            for cl in code_lines:
                if cl.strip():
                    lines.append(f"  {cl}")
                else:
                    lines.append("")
            lines.append(f"  return {self._next_state_for(state)}")
            lines.append("end")
            lines.append("")
        lines.append(f"local {self.vm_state_var} = {self.entry_state}")
        lines.append(f"while {self.vm_state_var} do")
        lines.append(f"  local next_state = state_handlers[{self.vm_state_var}]()")
        lines.append(f"  if next_state then")
        lines.append(f"    {self.vm_state_var} = next_state")
        lines.append(f"  else")
        lines.append(f"    {self.vm_state_var} = nil")
        lines.append(f"  end")
        lines.append("end")
        return "\n".join(lines)

    def _next_state_for(self, state: int) -> str:
        info = self.handlers[state]
        code = info.get('code', '')
        m = re.search(rf'{self.vm_state_var}\s*=\s*(-?\d+)', code)
        if m:
            return m.group(1)
        cond_str = " | ".join(info.get('conditions', []))
        if cond_str:
            return f"nil -- conditions: {cond_str}"
        return "nil"
