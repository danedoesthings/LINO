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
        self.states: Dict[int, dict] = {}
        self.entry_state: Optional[int] = None
        self.transitions: Dict[int, List[int]] = {}
        self.lifted_code: List[str] = []
        self.diagnostics: List[str] = []

    def devirtualize(self) -> Optional[str]:
        self.diagnostics = []
        code = self._resolve_all_strings(self.source)
        code = self._fix_missing_commas(code)
        self.diagnostics.append("Strings resolved and commas fixed")

        try:
            tree = lua_ast.parse(code)
        except Exception as e:
            self.diagnostics.append(f"Parse error after fix: {e}")
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
        code = re.sub(r'\bEncStr\s*\[\s*(-?\d+)\s*\]',
                      lambda m: f'"{self.strings[int(m.group(1)) - 1]}"' if 0 <= int(m.group(1)) - 1 < len(self.strings) else m.group(0),
                      code)
        return code

    def _fix_missing_commas(self, code: str) -> str:
        code = re.sub(r'(\b[a-zA-Z_][a-zA-Z0-9_]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*([,})])', r'\1, \2\3', code)
        code = re.sub(r'(\b[a-zA-Z_][a-zA-Z0-9_]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*$', r'\1, \2', code, flags=re.MULTILINE)
        code = re.sub(r'(\b[a-zA-Z_][a-zA-Z0-9_]*)\s+(?=[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*function)', r'\1, ', code)
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
            self._process_block(node.body.body, true_cond, prefix)
            if node.else_body:
                for stmt in node.else_body.body:
                    if isinstance(stmt, If):
                        self._walk_if_tree(stmt, false_cond, prefix)
                    else:
                        self._process_remaining([stmt], false_cond, prefix)
            else:
                self._process_remaining([], false_cond, prefix)
        else:
            self._process_block(node.body.body, conditions, prefix)

    def _process_block(self, stmts: list, conditions: list, prefix: str) -> None:
        last_assign = None
        state = None
        for stmt in reversed(stmts):
            if isinstance(stmt, (Assign, LocalAssign)) and self._is_state_assign(stmt):
                state = self._get_assigned_state(stmt)
                last_assign = stmt
                break
        if state is None:
            self.diagnostics.append(f"No state assignment found in block with {len(stmts)} statements")
            return
        block_stmts = stmts[:-1] if last_assign else stmts
        code = self._stmts_to_source(block_stmts)
        if state not in self.states:
            self.states[state] = {
                'code': code,
                'conditions': conditions,
                'next': None,
            }
        if self.entry_state is None:
            self.entry_state = state

    def _process_remaining(self, stmts: list, conditions: list, prefix: str) -> None:
        if not stmts:
            return
        self._process_block(stmts, conditions, prefix)

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
        for state, info in self.states.items():
            code = info['code']
            m = re.search(rf'{self.vm_state_var}\s*=\s*(-?\d+)', code)
            if m:
                info['next'] = int(m.group(1))
                if state not in self.transitions:
                    self.transitions[state] = []
                self.transitions[state].append(int(m.group(1)))

    def _lift_to_code(self) -> None:
        self.lifted_code = []
        self.lifted_code.append("-- VM Devirtualized Output")
        self.lifted_code.append(f"-- {len(self.states)} states, entry = {self.entry_state}")
        self.lifted_code.append("")

        visited = set()
        self._emit_state(self.entry_state, visited, 0)

    def _emit_state(self, state: int, visited: set, depth: int) -> None:
        if state is None or state in visited:
            if state in visited:
                self.lifted_code.append("  " * depth + f"-- loop back to state {state}")
            return
        visited.add(state)
        info = self.states.get(state)
        if not info:
            self.lifted_code.append("  " * depth + f"-- unknown state {state}")
            return

        code = info['code']
        lifted = self._classify_and_lift(code)
        indent = "  " * depth

        if lifted:
            self.lifted_code.append(indent + f"-- state {state}")
            for line in lifted.split("\n"):
                if line.strip():
                    self.lifted_code.append(indent + line)
        else:
            self.lifted_code.append(indent + f"-- state {state}: raw code follows")
            for line in code.split("\n"):
                if line.strip():
                    self.lifted_code.append(indent + "-- " + line.strip())

        next_state = info.get('next')
        if next_state is not None:
            self._emit_state(next_state, visited, depth)

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
            if dest_tbl in ('instrTbl', 'vmStack') and src_tbl in ('instrTbl', 'vmStack'):
                return f"local {dest_idx} = {src_idx}  -- MOVE"

        m_loadk = re.match(r'(\w+)\s*\[\s*(\w+)\s*\]\s*=\s*"([^"]*)"$', line)
        if m_loadk:
            tbl, idx, val = m_loadk.groups()
            if tbl in ('instrTbl', 'vmStack'):
                return f"local {idx} = \"{val}\"  -- LOADK"

        m_call = re.match(r'\{?(\w+)\s*\(\s*(\w+)\s*\)\}?$', line)
        if m_call:
            func, arg = m_call.groups()
            return f"{func}({arg})  -- CALL"

        m_closure = re.match(r'(\w+)\s*\[\s*(\w+)\s*\]\s*=\s*(\w+)\s*\(', line)
        if m_closure:
            tbl, idx, factory = m_closure.groups()
            if factory in ('funcWrap', 'helperG', 'tokenMap', 'shuffleTbl', 'r5', 'e', 'regD'):
                return f"local {idx} = {factory}(...)  -- CLOSURE"

        m_state = re.match(rf'{self.vm_state_var}\s*=\s*(-?\d+)$', line)
        if m_state:
            return f"goto state {m_state.group(1)}"

        return None
