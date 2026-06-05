class LuaEmitter:
    def __init__(self):
        self.indent = 0

    def emit(self, instructions, blocks, block_map, loop_headers, constants):
        self.indent = 0
        lines = []
        visited = set()
        def get_reg(idx):
            return f'reg_{idx}'
        def get_const(idx):
            if 0 <= idx < len(constants):
                return repr(constants[idx])
            return f'R[{idx}]'
        def emit_block(bid):
            if bid in visited:
                return
            visited.add(bid)
            block = blocks.get(bid)
            if not block:
                return
            prefix = ' ' * self.indent
            is_loop = bid in loop_headers
            if is_loop:
                lines.append(f'{prefix}while true do')
                self.indent += 1
                prefix = ' ' * self.indent
            for instr in block.instructions:
                op = instr.opcode
                ops = instr.operands
                if op == 'LOADK' and len(ops) >= 2:
                    val = get_const(ops[1])
                    lines.append(f'{prefix}local reg_{ops[0]} = {val}')
                elif op == 'MOVE' and len(ops) >= 2:
                    lines.append(f'{prefix}local reg_{ops[0]} = reg_{ops[1]}')
                elif op == 'ADD' and len(ops) >= 3:
                    lines.append(f'{prefix}local reg_{ops[0]} = (reg_{ops[1]} + reg_{ops[2]})')
                elif op == 'SUB' and len(ops) >= 3:
                    lines.append(f'{prefix}local reg_{ops[0]} = (reg_{ops[1]} - reg_{ops[2]})')
                elif op == 'MUL' and len(ops) >= 3:
                    lines.append(f'{prefix}local reg_{ops[0]} = (reg_{ops[1]} * reg_{ops[2]})')
                elif op == 'DIV' and len(ops) >= 3:
                    lines.append(f'{prefix}local reg_{ops[0]} = (reg_{ops[1]} / reg_{ops[2]})')
                elif op == 'CONCAT' and len(ops) >= 3:
                    lines.append(f'{prefix}local reg_{ops[0]} = (reg_{ops[1]} .. reg_{ops[2]})')
                elif op == 'CALL' and ops:
                    func = constants[ops[0]] if ops[0] < len(constants) else f'reg_{ops[0]}'
                    arg_count = ops[1] if len(ops) > 1 else 0
                    args = [f'reg_{ops[2+i]}' for i in range(arg_count) if len(ops) > 2 + i]
                    lines.append(f'{prefix}{func}({", ".join(args)})')
                elif op == 'JMP':
                    break
                elif op == 'CJMP' and ops:
                    lines.append(f'{prefix}if reg_{ops[0]} then')
                elif op == 'RET':
                    if ops:
                        vals = [f'reg_{o}' for o in ops]
                        lines.append(f'{prefix}return {", ".join(vals)}')
                    else:
                        lines.append(f'{prefix}return')
                    break
                elif op == 'EQ' and len(ops) >= 3:
                    lines.append(f'{prefix}local reg_{ops[0]} = (reg_{ops[1]} == reg_{ops[2]})')
                elif op == 'SETMETA' and len(ops) >= 2:
                    lines.append(f'{prefix}setmetatable(reg_{ops[0]}, reg_{ops[1]})')
                elif op == 'GETMETA' and len(ops) >= 2:
                    lines.append(f'{prefix}local reg_{ops[0]} = getmetatable(reg_{ops[1]})')
                elif op == 'PCALL' and ops:
                    func = constants[ops[0]] if ops[0] < len(constants) else f'reg_{ops[0]}'
                    lines.append(f'{prefix}pcall({func})')
                else:
                    lines.append(f'{prefix}-- {op} {ops}')
            if is_loop:
                self.indent -= 1
                prefix = ' ' * self.indent
                lines.append(f'{prefix}end')
            for sid in block.successors:
                if sid not in visited:
                    emit_block(sid)
        if blocks:
            first = min(blocks.keys())
            emit_block(first)
        return '\n'.join(lines) if lines else None

    def emit_ast(self, nodes):
        lines = []
        for node in nodes:
            lines.append(self._node_to_str(node))
        return '\n'.join(lines)

    def _node_to_str(self, node):
        from ast_nodes import (
            ConstNode, VarNode, IndexNode, BinaryOpNode, UnaryOpNode,
            CallNode, AssignNode, IfNode, WhileNode, ForNode,
            FunctionNode, ReturnNode, TableNode
        )
        if isinstance(node, ConstNode):
            return repr(node.value)
        elif isinstance(node, VarNode):
            return node.name
        elif isinstance(node, IndexNode):
            return f"{self._node_to_str(node.table)}[{self._node_to_str(node.key)}]"
        elif isinstance(node, BinaryOpNode):
            return f"({self._node_to_str(node.left)} {node.op} {self._node_to_str(node.right)})"
        elif isinstance(node, UnaryOpNode):
            return f"({node.op}{self._node_to_str(node.operand)})"
        elif isinstance(node, CallNode):
            args = ', '.join(self._node_to_str(a) for a in node.args)
            return f"{self._node_to_str(node.func)}({args})"
        elif isinstance(node, AssignNode):
            if node.local:
                return f"local {self._node_to_str(node.target)} = {self._node_to_str(node.value)}"
            else:
                return f"{self._node_to_str(node.target)} = {self._node_to_str(node.value)}"
        elif isinstance(node, IfNode):
            cond = self._node_to_str(node.condition)
            body = '\n'.join(self._node_to_str(s) for s in node.body)
            out = f"if {cond} then\n{body}\n"
            if node.else_body:
                else_body = '\n'.join(self._node_to_str(s) for s in node.else_body)
                out += f"else\n{else_body}\n"
            out += "end"
            return out
        elif isinstance(node, WhileNode):
            cond = self._node_to_str(node.condition)
            body = '\n'.join(self._node_to_str(s) for s in node.body)
            return f"while {cond} do\n{body}\nend"
        elif isinstance(node, ForNode):
            start = self._node_to_str(node.start)
            end = self._node_to_str(node.end)
            step = self._node_to_str(node.step) if node.step else "1"
            body = '\n'.join(self._node_to_str(s) for s in node.body)
            return f"for {node.var} = {start}, {end}, {step} do\n{body}\nend"
        elif isinstance(node, FunctionNode):
            params = ', '.join(node.params)
            body = '\n'.join(self._node_to_str(s) for s in node.body)
            if node.name:
                return f"function {node.name}({params})\n{body}\nend"
            else:
                return f"function({params})\n{body}\nend"
        elif isinstance(node, ReturnNode):
            vals = ', '.join(self._node_to_str(v) for v in node.values)
            return f"return {vals}"
        elif isinstance(node, TableNode):
            fields = ', '.join(f"[{self._node_to_str(k)}] = {self._node_to_str(v)}" for k, v in node.fields)
            return f"{{{fields}}}"
        else:
            return f"-- <{type(node).__name__}>"
