from ast_nodes import *

class LuaEmitter:
    def __init__(self):
        self.indent = 0

    def emit(self, node):
        if isinstance(node, list):
            return "\n".join(self.emit(n) for n in node)
        method = getattr(self, f"emit_{type(node).__name__}", None)
        if method:
            return method(node)
        return str(node)

    def emit_ConstNode(self, node):
        if isinstance(node.value, str):
            return f'"{node.value}"'
        return str(node.value)

    def emit_VarNode(self, node):
        return node.name

    def emit_IndexNode(self, node):
        return f"{self.emit(node.table)}[{self.emit(node.key)}]"

    def emit_BinaryOpNode(self, node):
        return f"({self.emit(node.left)} {node.op} {self.emit(node.right)})"

    def emit_UnaryOpNode(self, node):
        return f"{node.op}{self.emit(node.operand)}"

    def emit_CallNode(self, node):
        args = ", ".join(self.emit(a) for a in node.args)
        return f"{self.emit(node.func)}({args})"

    def emit_AssignNode(self, node):
        local = "local " if node.local else ""
        return f"{local}{self.emit(node.target)} = {self.emit(node.value)}"

    def emit_IfNode(self, node):
        cond = self.emit(node.condition)
        body = "\n".join(self.indent_str() + self.emit(s) for s in node.body)
        result = f"if {cond} then\n{body}"
        if node.else_body:
            else_body = "\n".join(self.indent_str() + self.emit(s) for s in node.else_body)
            result += f"\nelse\n{else_body}"
        result += "\nend"
        return result

    def emit_WhileNode(self, node):
        cond = self.emit(node.condition)
        body = "\n".join(self.indent_str() + self.emit(s) for s in node.body)
        return f"while {cond} do\n{body}\nend"

    def emit_ForNode(self, node):
        step = f", {self.emit(node.step)}" if node.step else ""
        body = "\n".join(self.indent_str() + self.emit(s) for s in node.body)
        return f"for {node.var} = {self.emit(node.start)}, {self.emit(node.end)}{step} do\n{body}\nend"

    def emit_FunctionNode(self, node):
        name = node.name or ""
        params = ", ".join(node.params)
        body = "\n".join(self.indent_str() + self.emit(s) for s in node.body)
        self.indent += 1
        out = f"function {name}({params})\n{body}\nend"
        self.indent -= 1
        return out

    def emit_ReturnNode(self, node):
        vals = ", ".join(self.emit(v) for v in node.values)
        return f"return {vals}"

    def emit_TableNode(self, node):
        fields = []
        for k, v in node.fields:
            if isinstance(k, int) and k == len(fields)+1:
                fields.append(self.emit(v))
            else:
                fields.append(f"[{self.emit(k)}] = {self.emit(v)}")
        return "{" + ", ".join(fields) + "}"

    def indent_str(self):
        return "    " * self.indent
