import re
import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Set

@dataclass
class Instruction:
    pc: int
    opcode: str
    operands: List[int] = field(default_factory=list)
    handler_body: str = ""

@dataclass
class BasicBlock:
    id: int
    start_pc: int
    end_pc: int
    instructions: List[Instruction] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    branch_condition: Optional[str] = None
    branch_target: Optional[int] = None
    fallthrough_target: Optional[int] = None

class WeAreDevsVMLifter:
    def __init__(self, decoded_strings, offset=0, getter_name=None):
        self.strings = decoded_strings
        self.offset = offset
        self.getter_name = getter_name
        self.instructions = []
        self.handlers = {}
        self.blocks = {}
        self.block_map = {}
        self.register_state = {}
        self.stack = []
        self.output = []
        self.loop_headers = set()
        self.label_counter = 0
        self.indent_level = 0

    def lift(self, source):
        source = self._resolve_getter_calls(source)
        if not source:
            return None
        self._extract_handler_table(source)
        self._extract_instructions(source)
        if len(self.instructions) < 10:
            return None
        self._build_cfg()
        self._detect_loops()
        result = self._emit_lua()
        if result and len(result) > 100:
            return result
        return None

    def _resolve_getter_calls(self, source):
        if not self.getter_name:
            self.getter_name, self.offset = self._detect_getter(source)
        if not self.getter_name or self.offset is None:
            return source
        def repl(m):
            try:
                expr = m.group(1).strip()
                n = safe_eval_int(expr)
                if n is not None:
                    idx = n + self.offset
                    if 1 <= idx <= len(self.strings):
                        return str(idx)
                return m.group(0)
            except:
                return m.group(0)
        pattern = rf'{re.escape(self.getter_name)}\s*\(\s*([^)]+?)\s*\)'
        return re.sub(pattern, repl, source)

    def _detect_getter(self, source):
        patterns = [
            r'local\s+function\s+(\w+)\s*\(\s*\1\s*\)\s*return\s+R\s*\[\s*\1\s*\+\s*\(?(-?\d+(?:[+\-]\d+)*)\)?\s*\]',
            r'local\s+function\s+(\w+)\s*\(\s*\1\s*\)\s*return\s+R\s*\[\s*\1\s*\+\s*\(?([^)]+)\)?\s*\]',
        ]
        for p in patterns:
            m = re.search(p, source)
            if m:
                name = m.group(1)
                offset_str = m.group(2)
                offset = safe_eval_int(offset_str)
                if offset is not None:
                    return name, offset
        return None, 0

    def _extract_handler_table(self, source):
        handler_pattern = r'\[(\d+)\]\s*=\s*function\s*\([^)]*\)(.*?)end\s*[,;]'
        for m in re.finditer(handler_pattern, source, re.DOTALL):
            idx = int(m.group(1))
            body = m.group(2).strip()
            opcode_name = self._classify_opcode(body)
            self.handlers[idx] = {'body': body, 'opcode': opcode_name}
        if not self.handlers:
            dispatch_match = re.search(r'local\s+\w+\s*=\s*\{([^}]+)\}', source)
            if dispatch_match:
                entries = re.findall(r'\[(\d+)\]\s*=\s*(\d+)', dispatch_match.group(1))
                for op_val, handler_idx in entries:
                    op_val = int(op_val)
                    handler_idx = int(handler_idx)
                    if handler_idx not in self.handlers:
                        self.handlers[handler_idx] = {'body': '', 'opcode': f'OP_{op_val}'}
                    self.handlers[op_val] = self.handlers[handler_idx]

    def _classify_opcode(self, body):
        if not body:
            return 'UNKNOWN'
        if 'Q[I[B+' in body and 'R[I[B+' in body:
            return 'LOADK'
        if body.count('Q[I[B+') >= 3:
            if '..' in body:
                return 'CONCAT'
            if '+' in body:
                return 'ADD'
            if '-' in body and '*-' not in body:
                return 'SUB'
            if '*' in body:
                return 'MUL'
            if '/' in body:
                return 'DIV'
            if '%' in body:
                return 'MOD'
            if '^' in body:
                return 'POW'
            return 'MOVE'
        if body.count('Q[I[B+') == 2 and '=' in body:
            return 'MOVE'
        if re.search(r'B\s*=\s*I\s*\[\s*B', body):
            return 'JMP'
        if re.search(r'if\s+Q\s*\[', body):
            return 'CJMP'
        if 'table' in body and 'insert' in body:
            return 'TBLINSERT'
        if 'pcall' in body:
            return 'PCALL'
        if 'return' in body:
            return 'RET'
        if 'string.char' in body:
            return 'STRCHAR'
        if 'loadstring' in body:
            return 'LDSTRING'
        if 'setmetatable' in body:
            return 'SETMETA'
        if 'getmetatable' in body:
            return 'GETMETA'
        if '==' in body:
            return 'EQ'
        if '<=' in body:
            return 'LE'
        if '<' in body:
            return 'LT'
        if '#' in body and 'Q' in body:
            return 'LEN'
        if 'not' in body and 'Q' in body:
            return 'NOT'
        if 'function' in body and '(' in body:
            return 'CLOSURE'
        return 'UNKNOWN'

    def _extract_instructions(self, source):
        inst_match = re.search(r'local\s+\w+\s*=\s*\{([\d,\s]+)\}', source)
        if not inst_match:
            return
        inst_data = [int(n.strip()) for n in inst_match.group(1).split(',') if n.strip().lstrip('-').isdigit()]
        if not inst_data:
            return
        handler_keys = set(self.handlers.keys())
        pc = 0
        while pc < len(inst_data):
            val = inst_data[pc]
            handler_info = self.handlers.get(val, {'opcode': f'OP_{val}', 'body': ''})
            opcode = handler_info['opcode'] if isinstance(handler_info, dict) else 'UNKNOWN'
            operands = []
            temp_pc = pc + 1
            while temp_pc < len(inst_data) and len(operands) < 4:
                next_val = inst_data[temp_pc]
                if next_val in handler_keys and len(operands) > 0:
                    break
                operands.append(next_val)
                temp_pc += 1
            instr = Instruction(pc=pc, opcode=opcode, operands=operands, handler_body=handler_info.get('body', '') if isinstance(handler_info, dict) else '')
            self.instructions.append(instr)
            pc += 1 + len(operands)

    def _build_cfg(self):
        jump_targets = set()
        for instr in self.instructions:
            if instr.opcode in ('JMP', 'CJMP') and instr.operands:
                target = instr.operands[0]
                if isinstance(target, int):
                    jump_targets.add(target)
        block_id = 0
        current_block = BasicBlock(id=block_id, start_pc=0, end_pc=0)
        block_starts = {0}
        block_starts.update(jump_targets)
        for instr in self.instructions:
            if instr.pc in block_starts and current_block.instructions:
                current_block.end_pc = current_block.instructions[-1].pc
                self.blocks[current_block.id] = current_block
                self.block_map[current_block.start_pc] = current_block.id
                block_id = len(self.blocks)
                current_block = BasicBlock(id=block_id, start_pc=instr.pc, end_pc=instr.pc)
            current_block.instructions.append(instr)
        if current_block.instructions:
            current_block.end_pc = current_block.instructions[-1].pc
            self.blocks[current_block.id] = current_block
            self.block_map[current_block.start_pc] = current_block.id
        for bid, block in self.blocks.items():
            if not block.instructions:
                continue
            last = block.instructions[-1]
            if last.opcode == 'JMP' and last.operands:
                target = last.operands[0]
                for tbid, tblk in self.blocks.items():
                    if tblk.start_pc == target:
                        block.successors.append(tbid)
                        self.blocks[tbid].predecessors.append(bid)
                        block.branch_target = target
                        break
            elif last.opcode == 'CJMP' and last.operands:
                target = last.operands[0]
                fallthrough = last.pc + 1 + len(last.operands)
                for tbid, tblk in self.blocks.items():
                    if tblk.start_pc == target:
                        block.successors.append(tbid)
                        self.blocks[tbid].predecessors.append(bid)
                        block.branch_target = target
                        break
                for tbid, tblk in self.blocks.items():
                    if tblk.start_pc == fallthrough:
                        block.successors.append(tbid)
                        self.blocks[tbid].predecessors.append(bid)
                        block.fallthrough_target = fallthrough
                        break
            elif last.opcode != 'RET':
                fallthrough = last.pc + 1 + len(last.operands)
                for tbid, tblk in self.blocks.items():
                    if tblk.start_pc == fallthrough:
                        block.successors.append(tbid)
                        self.blocks[tbid].predecessors.append(bid)
                        break

    def _detect_loops(self):
        visited = set()
        stack = []
        on_stack = set()
        def dfs(bid):
            visited.add(bid)
            stack.append(bid)
            on_stack.add(bid)
            block = self.blocks.get(bid)
            if block:
                for sid in block.successors:
                    if sid not in visited:
                        dfs(sid)
                    elif sid in on_stack:
                        self.loop_headers.add(sid)
            stack.pop()
            on_stack.discard(bid)
        for bid in self.blocks:
            if bid not in visited:
                dfs(bid)

    def _emit_lua(self):
        self.output = []
        self.indent_level = 0
        self.register_state = {}
        visited = set()
        def get_reg(idx):
            return self.register_state.get(idx, f'reg_{idx}')
        def set_reg(idx, val):
            self.register_state[idx] = val
        def emit_block(bid):
            if bid in visited:
                if bid in self.loop_headers:
                    self.output.append(' ' * self.indent_level + 'while true do')
                    self.indent_level += 1
                    return
                return
            visited.add(bid)
            block = self.blocks.get(bid)
            if not block:
                return
            if bid in self.loop_headers:
                self.output.append(' ' * self.indent_level + 'while true do')
                self.indent_level += 1
            for instr in block.instructions:
                prefix = ' ' * self.indent_level
                ops = instr.operands
                if instr.opcode == 'LOADK' and len(ops) >= 2:
                    dest = ops[0]
                    const_idx = ops[1]
                    if 0 <= const_idx < len(self.strings):
                        val = self.strings[const_idx]
                        set_reg(dest, val)
                        self.output.append(f'{prefix}local reg_{dest} = {json.dumps(val)}')
                elif instr.opcode == 'MOVE' and len(ops) >= 2:
                    dest = ops[0]
                    src = ops[1]
                    src_val = get_reg(src)
                    set_reg(dest, src_val)
                    self.output.append(f'{prefix}local reg_{dest} = {src_val}')
                elif instr.opcode == 'ADD' and len(ops) >= 3:
                    dest = ops[0]
                    left = get_reg(ops[1])
                    right = get_reg(ops[2])
                    result = f'({left} + {right})'
                    set_reg(dest, result)
                    self.output.append(f'{prefix}local reg_{dest} = {result}')
                elif instr.opcode == 'SUB' and len(ops) >= 3:
                    dest = ops[0]
                    left = get_reg(ops[1])
                    right = get_reg(ops[2])
                    result = f'({left} - {right})'
                    set_reg(dest, result)
                    self.output.append(f'{prefix}local reg_{dest} = {result}')
                elif instr.opcode == 'MUL' and len(ops) >= 3:
                    dest = ops[0]
                    left = get_reg(ops[1])
                    right = get_reg(ops[2])
                    result = f'({left} * {right})'
                    set_reg(dest, result)
                    self.output.append(f'{prefix}local reg_{dest} = {result}')
                elif instr.opcode == 'DIV' and len(ops) >= 3:
                    dest = ops[0]
                    left = get_reg(ops[1])
                    right = get_reg(ops[2])
                    result = f'({left} / {right})'
                    set_reg(dest, result)
                    self.output.append(f'{prefix}local reg_{dest} = {result}')
                elif instr.opcode == 'CONCAT' and len(ops) >= 3:
                    dest = ops[0]
                    left = get_reg(ops[1])
                    right = get_reg(ops[2])
                    result = f'({left} .. {right})'
                    set_reg(dest, result)
                    self.output.append(f'{prefix}local reg_{dest} = {result}')
                elif instr.opcode == 'CALL' and ops:
                    func_idx = ops[0]
                    if 0 <= func_idx < len(self.strings):
                        func_name = self.strings[func_idx]
                    else:
                        func_name = get_reg(func_idx)
                    arg_count = ops[1] if len(ops) > 1 else 0
                    args = []
                    for i in range(arg_count):
                        arg_reg = ops[2 + i] if len(ops) > 2 + i else None
                        if arg_reg is not None:
                            args.append(get_reg(arg_reg))
                    if arg_count == 1 and func_name == 'print':
                        self.output.append(f'{prefix}print({args[0] if args else ""})')
                    else:
                        self.output.append(f'{prefix}{func_name}({", ".join(args)})')
                elif instr.opcode == 'JMP':
                    break
                elif instr.opcode == 'CJMP' and ops:
                    cond = get_reg(ops[0])
                    self.output.append(f'{prefix}if {cond} then')
                elif instr.opcode == 'RET':
                    if ops:
                        ret_vals = [get_reg(op) for op in ops]
                        self.output.append(f'{prefix}return {", ".join(ret_vals)}')
                    else:
                        self.output.append(f'{prefix}return')
                    break
                elif instr.opcode == 'EQ' and len(ops) >= 3:
                    dest = ops[0]
                    left = get_reg(ops[1])
                    right = get_reg(ops[2])
                    self.output.append(f'{prefix}local reg_{dest} = ({left} == {right})')
                elif instr.opcode == 'LT' and len(ops) >= 3:
                    dest = ops[0]
                    left = get_reg(ops[1])
                    right = get_reg(ops[2])
                    self.output.append(f'{prefix}local reg_{dest} = ({left} < {right})')
                elif instr.opcode == 'LE' and len(ops) >= 3:
                    dest = ops[0]
                    left = get_reg(ops[1])
                    right = get_reg(ops[2])
                    self.output.append(f'{prefix}local reg_{dest} = ({left} <= {right})')
                elif instr.opcode == 'LEN' and len(ops) >= 2:
                    dest = ops[0]
                    src = get_reg(ops[1])
                    self.output.append(f'{prefix}local reg_{dest} = #{src}')
                elif instr.opcode == 'NOT' and len(ops) >= 2:
                    dest = ops[0]
                    src = get_reg(ops[1])
                    self.output.append(f'{prefix}local reg_{dest} = not {src}')
                elif instr.opcode == 'SETMETA' and len(ops) >= 2:
                    self.output.append(f'{prefix}setmetatable({get_reg(ops[0])}, {get_reg(ops[1])})')
                elif instr.opcode == 'GETMETA' and len(ops) >= 2:
                    self.output.append(f'{prefix}local reg_{ops[0]} = getmetatable({get_reg(ops[1])})')
                elif instr.opcode == 'PCALL' and ops:
                    func_name = self.strings[ops[0]] if ops[0] < len(self.strings) else get_reg(ops[0])
                    self.output.append(f'{prefix}pcall({func_name})')
                elif instr.opcode == 'STRCHAR' and ops:
                    dest = ops[0]
                    chars = ', '.join(str(o) for o in ops[1:]) if len(ops) > 1 else str(ops[0])
                    self.output.append(f'{prefix}local reg_{dest} = string.char({chars})')
                else:
                    self.output.append(f'{prefix}-- {instr.opcode} {ops}')
            if bid in self.loop_headers:
                self.indent_level -= 1
                self.output.append(' ' * self.indent_level + 'end')
            for sid in block.successors:
                if sid not in visited or sid in self.loop_headers:
                    emit_block(sid)
        if self.blocks:
            first_block = min(self.blocks.keys())
            emit_block(first_block)
        if not self.output:
            self.output.append('local R = {')
            for i, s in enumerate(self.strings):
                if s:
                    self.output.append(f'\t[{i + 1}] = {json.dumps(s)},')
            self.output.append('}')
        return '\n'.join(self.output)

def safe_eval_int(expr):
    expr = re.sub(r'\s+', '', str(expr))
    expr = expr.replace('--', '+').replace('+-', '-').replace('-+', '-').replace('++', '+')
    while '(' in expr:
        m = re.search(r'\(([^()]+)\)', expr)
        if not m:
            break
        inner = safe_eval_int(m.group(1))
        if inner is None:
            return None
        expr = expr[:m.start()] + str(inner) + expr[m.end():]
    tokens = re.findall(r'[+-]?\d+', expr)
    if tokens:
        return sum(int(t) for t in tokens)
    try:
        return int(expr)
    except ValueError:
        return None
