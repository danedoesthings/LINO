from vm_state import VMState, SymbolicValue
from ast_nodes import *
from lua_emitter import LuaEmitter

class SymbolicExecutor:
    def __init__(self, string_table):
        self.state = VMState()
        self.state.constants = string_table
        self.ast_nodes = []
        self.emitter = LuaEmitter()
        self.label_counter = 0

    def execute(self, instructions, handlers):
        self.state.instructions = instructions
        while self.state.ip < len(instructions):
            instr = instructions[self.state.ip]
            action = handlers.get(instr.opcode, 'UNKNOWN')
            getattr(self, f'op_{action}', self.op_UNKNOWN)(instr)
            self.state.ip += 1

    def op_LOADK(self, instr):
        idx = instr.operands[0] if instr.operands else 0
        if isinstance(idx, int) and 1 <= idx <= len(self.state.constants):
            val = self.state.constants[idx-1]
        else:
            val = str(idx)
        self.state.stack.append(SymbolicValue('const', val, ConstNode(val)))

    def op_SETGLOBAL(self, instr):
        name = self._resolve_name(instr.operands[0] if instr.operands else "")
        val = self.state.stack.pop() if self.state.stack else SymbolicValue('nil', None, ConstNode(None))
        self.state.globals[name] = val
        self.ast_nodes.append(AssignNode(target=IndexNode(VarNode('_G'), ConstNode(name)), value=val.expr, local=False))

    def op_GETGLOBAL(self, instr):
        name = self._resolve_name(instr.operands[0] if instr.operands else "")
        node = IndexNode(VarNode('_G'), ConstNode(name))
        self.state.stack.append(SymbolicValue('global', name, node))

    def op_CALL(self, instr):
        func_name = self._resolve_name(instr.operands[0] if instr.operands else "unknown")
        arg_count = instr.operands[1] if len(instr.operands) > 1 else 0
        args = []
        for _ in range(arg_count):
            if self.state.stack:
                arg = self.state.stack.pop()
                args.insert(0, arg.expr if arg.expr else ConstNode(None))
        node = CallNode(VarNode(func_name), args)
        self.ast_nodes.append(node)

    def op_RETURN(self, instr):
        vals = []
        while self.state.stack:
            sv = self.state.stack.pop()
            vals.insert(0, sv.expr if sv.expr else ConstNode(None))
        self.ast_nodes.append(ReturnNode(vals))
        return False

    def op_CONCAT(self, instr):
        right = self.state.stack.pop() if self.state.stack else SymbolicValue('nil', None, ConstNode(None))
        left = self.state.stack.pop() if self.state.stack else SymbolicValue('nil', None, ConstNode(None))
        node = BinaryOpNode('..', left.expr or ConstNode(None), right.expr or ConstNode(None))
        self.state.stack.append(SymbolicValue('concat', None, node))

    def op_ARITH(self, instr):
        right = self.state.stack.pop() if self.state.stack else SymbolicValue('nil', None, ConstNode(None))
        left = self.state.stack.pop() if self.state.stack else SymbolicValue('nil', None, ConstNode(None))
        node = BinaryOpNode('+', left.expr or ConstNode(None), right.expr or ConstNode(None))
        self.state.stack.append(SymbolicValue('arith', None, node))

    def op_STRCHAR(self, instr):
        args = []
        while self.state.stack and isinstance(self.state.stack[-1].value, int):
            sv = self.state.stack.pop()
            args.insert(0, sv.expr if sv.expr else ConstNode(sv.value))
        if args:
            node = CallNode(VarNode('string.char'), args)
            self.ast_nodes.append(node)

    def op_TABLECONCAT(self, instr):
        sep = self.state.stack.pop() if self.state.stack else SymbolicValue('nil', None, ConstNode(None))
        tbl = self.state.stack.pop() if self.state.stack else SymbolicValue('nil', None, ConstNode(None))
        node = CallNode(VarNode('table.concat'), [tbl.expr or ConstNode(None), sep.expr or ConstNode(None)])
        self.state.stack.append(SymbolicValue('call', None, node))

    def op_CLOSURE(self, instr):
        name = f"f_{len(self.state.registers)}"
        self.ast_nodes.append(FunctionNode(name, [], []))
        self.state.stack.append(SymbolicValue('closure', name, VarNode(name)))

    def op_NEWTABLE(self, instr):
        self.state.stack.append(SymbolicValue('table', None, TableNode()))

    def op_SETTABLE(self, instr):
        val = self.state.stack.pop() if self.state.stack else SymbolicValue('nil', None, ConstNode(None))
        key = self.state.stack.pop() if self.state.stack else SymbolicValue('nil', None, ConstNode(None))
        tbl = self.state.stack.pop() if self.state.stack else SymbolicValue('nil', None, ConstNode(None))
        node = AssignNode(target=IndexNode(tbl.expr or ConstNode(None), key.expr or ConstNode(None)), value=val.expr or ConstNode(None), local=False)
        self.ast_nodes.append(node)

    def op_GETTABLE(self, instr):
        key = self.state.stack.pop() if self.state.stack else SymbolicValue('nil', None, ConstNode(None))
        tbl = self.state.stack.pop() if self.state.stack else SymbolicValue('nil', None, ConstNode(None))
        node = IndexNode(tbl.expr or ConstNode(None), key.expr or ConstNode(None))
        self.state.stack.append(SymbolicValue('gettable', None, node))

    def op_UNKNOWN(self, instr):
        pass

    def _resolve_name(self, arg):
        if isinstance(arg, int) and 1 <= arg <= len(self.state.constants):
            return self.state.constants[arg-1]
        return str(arg)

    def emit_lua(self):
        return self.emitter.emit_ast(self.ast_nodes)
