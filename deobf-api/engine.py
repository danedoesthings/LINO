import re, json, base64, itertools
from typing import List, Dict, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from collections import defaultdict, namedtuple, deque

@dataclass
class VMInstruction:
    opcode: int
    pc: int
    operands: List[int] = field(default_factory=list)
    handler_idx: int = -1

@dataclass
class VMBasicBlock:
    id: int
    start_pc: int
    end_pc: int
    instructions: List[VMInstruction] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    branch_condition: Optional[Any] = None
    branch_target: Optional[int] = None
    fallthrough_target: Optional[int] = None

@dataclass
class VMRegister:
    name: str
    value: Any = None
    symbolic: Any = None
    tainted: bool = False

class SymbolicExpr:
    def __init__(self, kind, value=None, left=None, right=None, args=None):
        self.kind = kind
        self.value = value
        self.left = left
        self.right = right
        self.args = args or []

    @staticmethod
    def const(v):
        return SymbolicExpr('const', value=v)

    @staticmethod
    def reg(name):
        return SymbolicExpr('reg', value=name)

    @staticmethod
    def binary(op, left, right):
        return SymbolicExpr('binary', value=op, left=left, right=right)

    @staticmethod
    def call(func, args):
        return SymbolicExpr('call', value=func, args=args)

    @staticmethod
    def idx(table, key):
        return SymbolicExpr('index', left=table, right=key)

    @staticmethod
    def unary(op, operand):
        return SymbolicExpr('unary', value=op, left=operand)

    def to_lua(self, constants=None):
        if self.kind == 'const':
            if isinstance(self.value, str):
                return _escape_lua_string(self.value)
            if isinstance(self.value, bool):
                return 'true' if self.value else 'false'
            if self.value is None:
                return 'nil'
            return str(self.value)
        elif self.kind == 'reg':
            return self.value
        elif self.kind == 'binary':
            left = self.left.to_lua(constants) if self.left else 'nil'
            right = self.right.to_lua(constants) if self.right else 'nil'
            return f'({left} {self.value} {right})'
        elif self.kind == 'unary':
            opnd = self.left.to_lua(constants) if self.left else 'nil'
            return f'({self.value} {opnd})'
        elif self.kind == 'call':
            func = self.value.to_lua(constants) if isinstance(self.value, SymbolicExpr) else str(self.value)
            args = ', '.join(a.to_lua(constants) for a in self.args)
            return f'{func}({args})'
        elif self.kind == 'index':
            tbl = self.left.to_lua(constants) if self.left else 'nil'
            key = self.right.to_lua(constants) if self.right else 'nil'
            return f'{tbl}[{key}]'
        elif self.kind == 'table':
            items = []
            for k, v in (self.value or {}).items():
                if isinstance(k, int) and k == len(items) + 1:
                    items.append(v.to_lua(constants))
                else:
                    k_str = f'[{k.to_lua(constants)}]' if isinstance(k, SymbolicExpr) else f'[{_escape_lua_string(str(k))}]'
                    items.append(f'{k_str} = {v.to_lua(constants)}')
            return '{' + ', '.join(items) + '}'
        elif self.kind == 'phi':
            return f'-- phi({", ".join(a.to_lua(constants) for a in self.args)})'
        return f'-- {self.kind}'

class VMOpcodeHandler:
    def __init__(self, opcode, handler_idx, handler_body, operand_count, handler_type):
        self.opcode = opcode
        self.handler_idx = handler_idx
        self.handler_body = handler_body
        self.operand_count = operand_count
        self.handler_type = handler_type
        self.register_ops = []
        self.stack_ops = []
        self.branch_ops = []
        self._analyze()

    def _analyze(self):
        body = self.handler_body
        if 'Q[I[B+' in body:
            operands = re.findall(r'I\s*\[\s*B\s*([+-]\s*\d+)\s*\]', body)
            self.operand_count = len(operands)
        if re.search(r'B\s*=\s*I\s*\[\s*B', body) or re.search(r'B\s*=\s*\w+\s*\[\s*B', body):
            self.branch_ops.append('direct_jump')
        if re.search(r'if\s+Q\s*\[', body):
            self.branch_ops.append('conditional_jump')
        if 'Q[I[B+' in body and '=' in body:
            target = re.search(r'Q\s*\[\s*I\s*\[\s*B\s*([+-]\s*\d+)\s*\]\s*\]\s*=\s*', body)
            if target:
                self.register_ops.append('store')
        src_count = len(re.findall(r'Q\s*\[\s*I\s*\[\s*B\s*[+-]', body))
        if src_count >= 2 and '=' in body:
            self.register_ops.append('binary_op')
        if 'R[I[B+' in body:
            self.register_ops.append('loadk')
        if 'function' in body and '(' in body:
            self.stack_ops.append('closure')
        if 'table' in body and 'insert' in body:
            self.stack_ops.append('table_insert')
        if 'concat' in body:
            self.stack_ops.append('concat')
        if 'pcall' in body or 'xpcall' in body:
            self.stack_ops.append('pcall')

@dataclass
class VMLifterState:
    registers: Dict[int, Any] = field(default_factory=dict)
    stack: List[Any] = field(default_factory=list)
    constants: List[str] = field(default_factory=list)
    instructions: List[Any] = field(default_factory=list)
    ip: int = 0
    globals: Dict[str, Any] = field(default_factory=dict)
    upvalues: Dict[str, Any] = field(default_factory=dict)
    locals: Dict[str, Any] = field(default_factory=dict)
    ast_output: List[str] = field(default_factory=list)
    label_counter: int = 0
    visited: Set[int] = field(default_factory=set)
    loop_headers: Set[int] = field(default_factory=set)
    loop_exits: Set[int] = field(default_factory=set)
    blocks: Dict[int, VMBasicBlock] = field(default_factory=dict)
    current_scope: int = 0
    scope_stack: List[Dict] = field(default_factory=list)

def _escape_lua_string(s):
    if not isinstance(s, str):
        s = str(s)
    s = s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    return f'"{s}"'

def _extract_vm_structure(source):
    result = {
        'dispatch_loop': None,
        'instruction_table': None,
        'register_table': None,
        'constant_table': None,
        'handlers': [],
        'handler_map': {},
        'ip_variable': 'B',
        'dispatch_variable': 'l',
        'handler_table_var': 'C',
    }

    ip_match = re.search(r'while\s+(\w+)\s+do\s+local\s+(\w+)\s*=\s*\{[^}]*\}\s*\[\s*(\w+)\s*\[\s*(\w+)\s*\]\s*\]', source, re.DOTALL)
    if ip_match:
        result['dispatch_variable'] = ip_match.group(1)
        result['handler_table_var'] = ip_match.group(2)
        result['instruction_table'] = ip_match.group(3)
        result['ip_variable'] = ip_match.group(4)

    while_match = re.search(r'(while\s+(\w+)\s+do\s+.*?end\s*(?:\)\s*\)|$))', source, re.DOTALL)
    if while_match:
        result['dispatch_loop'] = while_match.group(1)

    inst_match = re.search(r'local\s+(\w+)\s*=\s*\{([\d,\s]{50,})\}', source)
    if inst_match:
        result['instruction_table_var'] = inst_match.group(1)
        nums = [int(n.strip()) for n in inst_match.group(2).split(',') if n.strip().lstrip('-').isdigit()]
        result['instruction_table'] = nums

    reg_match = re.search(r'local\s+(\w+)\s*=\s*\{(\s*(?:\d+\s*,\s*)*\d+\s*)\}', source)
    if reg_match:
        result['register_table_var'] = reg_match.group(1)

    const_match = re.search(r'local\s+(\w+)\s*=\s*\{([^}]+)\}', source)
    if const_match:
        result['constant_table_var'] = const_match.group(1)

    handler_blocks = re.findall(r'\[(\d+)\]\s*=\s*function\s*\([^)]*\)(.*?)end\s*[,;]', source, re.DOTALL)
    for idx_str, body in handler_blocks:
        idx = int(idx_str)
        result['handlers'].append((idx, body.strip()))
        result['handler_map'][idx] = body.strip()

    dispatch_table = re.findall(r'\[(\d+)\]\s*=\s*(\d+)', source)
    dispatch_map = {}
    for idx_str, handler_idx_str in dispatch_table:
        dispatch_map[int(idx_str)] = int(handler_idx_str)
    result['dispatch_map'] = dispatch_map

    return result

def _extract_instruction_stream(source, vm_structure):
    instructions = []
    inst_data = vm_structure.get('instruction_table', [])
    if not inst_data:
        inst_match = re.search(r'local\s+\w+\s*=\s*\{([\d,\s]+)\}', source)
        if inst_match:
            inst_data = [int(n.strip()) for n in inst_match.group(1).split(',') if n.strip().lstrip('-').isdigit()]
        else:
            table_bodies = _find_all_table_bodies(source)
            for body in table_bodies:
                entries = _parse_table_entries(body)
                nums = [e for e in entries if isinstance(e, int) and e >= 0]
                if len(nums) >= 20:
                    inst_data = nums
                    break

    if not inst_data:
        return instructions

    dispatch_map = vm_structure.get('dispatch_map', {})
    if not dispatch_map:
        for m in re.finditer(r'\[(\d+)\]\s*=\s*(\d+)', source):
            dispatch_map[int(m.group(1))] = int(m.group(2))

    pc = 0
    while pc < len(inst_data):
        opcode = inst_data[pc]
        handler_idx = dispatch_map.get(opcode, -1)
        instr = VMInstruction(opcode=opcode, pc=pc, handler_idx=handler_idx)

        operands = []
        temp_pc = pc + 1
        while temp_pc < len(inst_data):
            next_val = inst_data[temp_pc]
            if next_val in dispatch_map:
                break
            if next_val == opcode and temp_pc > pc + 1:
                break
            operands.append(next_val)
            temp_pc += 1
            if len(operands) >= 4:
                break

        instr.operands = operands
        instructions.append(instr)
        pc += 1 + len(operands)

    return instructions

def _classify_handler(body):
    features = set()
    if 'Q[I[B+' in body and 'R[I[B+' in body:
        features.add('loadk')
    if 'Q[I[B+' in body and 'Q[I[B+' in body and body.count('Q[I[B+') >= 3:
        if '+' in body.split('=')[1] if '=' in body else '':
            features.add('add')
        elif '-' in body.split('=')[1] if '=' in body else '':
            features.add('sub')
        elif '*' in body.split('=')[1] if '=' in body else '':
            features.add('mul')
        elif '/' in body.split('=')[1] if '=' in body else '':
            features.add('div')
        elif '%' in body.split('=')[1] if '=' in body else '':
            features.add('mod')
        elif '^' in body.split('=')[1] if '=' in body else '':
            features.add('pow')
        elif '..' in body.split('=')[1] if '=' in body else '':
            features.add('concat')
        else:
            features.add('move')
    if 'Q[I[B+' in body and '=' in body and body.count('Q[I[B+') == 2:
        features.add('move')
    if re.search(r'B\s*=\s*I\s*\[\s*B', body):
        features.add('jump')
    if re.search(r'if\s+Q\s*\[', body) and 'B' in body.split('then')[1] if 'then' in body else False:
        features.add('cjump')
    if 'table' in body and 'insert' in body:
        features.add('table_insert')
    if 'pcall' in body:
        features.add('pcall')
    if 'return' in body:
        features.add('return')
    if 'string.char' in body:
        features.add('strchar')
    if 'loadstring' in body:
        features.add('loadstring')
    if 'setmetatable' in body:
        features.add('setmeta')
    if 'getmetatable' in body:
        features.add('getmeta')
    if '#' in body:
        features.add('len')
    if 'not' in body:
        features.add('not_op')
    if '==' in body:
        features.add('eq')
    if '<' in body and '>' not in body:
        features.add('lt')
    if '<=' in body:
        features.add('le')
    if 'function' in body and '(' in body:
        features.add('closure')
    if 'for' in body:
        features.add('forloop')
    if 'while' in body:
        features.add('whileloop')
    return features

def _build_handler_table(source, vm_structure):
    handlers = {}
    handler_bodies = vm_structure.get('handler_map', {})

    if not handler_bodies:
        handler_blocks = re.findall(r'(\w+)\s*\[\s*(\d+)\s*\]\s*=\s*function\s*\([^)]*\)(.*?)end', source, re.DOTALL)
        for var_name, idx_str, body in handler_blocks:
            idx = int(idx_str)
            handler_bodies[idx] = body

    if not handler_bodies:
        func_defs = re.findall(r'function\s*(\w*)\s*\([^)]*\)(.*?)end', source, re.DOTALL)
        handler_array = re.search(r'local\s+(\w+)\s*=\s*\{[^}]*\}', source)
        if handler_array:
            array_body = handler_array.group(0)
            for i, func_def in enumerate(func_defs):
                if len(func_def[1].strip()) > 20:
                    handler_bodies[i] = func_def[1]

    for idx, body in handler_bodies.items():
        features = _classify_handler(body)
        handler = VMOpcodeHandler(
            opcode=idx,
            handler_idx=idx,
            handler_body=body,
            operand_count=len(re.findall(r'I\s*\[\s*B\s*[+-]', body)),
            handler_type=features
        )
        handlers[idx] = handler

    dispatch_map = vm_structure.get('dispatch_map', {})
    if not dispatch_map and handlers:
        for opcode, handler in handlers.items():
            dispatch_map[opcode] = handler.handler_idx

    opcode_to_handler = {}
    for opcode, handler_idx in dispatch_map.items():
        if handler_idx in handlers:
            opcode_to_handler[opcode] = handlers[handler_idx]

    return opcode_to_handler, handlers

def _build_cfg(instructions, opcode_to_handler):
    blocks = {}
    current_block_id = 0
    current_block = VMBasicBlock(id=current_block_id, start_pc=0, end_pc=0)
    block_starts = {0}
    block_map = {}
    jump_targets = set()

    for instr in instructions:
        handler = opcode_to_handler.get(instr.opcode)
        if handler and ('jump' in handler.handler_type or 'cjump' in handler.handler_type):
            if instr.operands:
                target_pc = instr.operands[0] if isinstance(instr.operands[0], int) else None
                if target_pc is not None:
                    jump_targets.add(target_pc)

    for instr in instructions:
        if instr.pc in block_starts or instr.pc in jump_targets:
            if current_block.instructions:
                current_block.end_pc = current_block.instructions[-1].pc
                blocks[current_block.id] = current_block
                block_map[current_block.start_pc] = current_block.id
            current_block_id = len(blocks)
            current_block = VMBasicBlock(id=current_block_id, start_pc=instr.pc, end_pc=instr.pc)
            block_starts.add(instr.pc)
        current_block.instructions.append(instr)

    if current_block.instructions:
        current_block.end_pc = current_block.instructions[-1].pc
        blocks[current_block.id] = current_block
        block_map[current_block.start_pc] = current_block.id

    for block_id, block in blocks.items():
        if not block.instructions:
            continue
        last_instr = block.instructions[-1]
        handler = opcode_to_handler.get(last_instr.opcode)
        if handler:
            if 'jump' in handler.handler_type and 'cjump' not in handler.handler_type:
                if last_instr.operands:
                    target = last_instr.operands[0]
                    if target in block_map:
                        block.successors.append(block_map[target])
                        blocks[block_map[target]].predecessors.append(block_id)
                        block.branch_target = target
            elif 'cjump' in handler.handler_type:
                fallthrough_pc = last_instr.pc + 1 + len(last_instr.operands)
                if last_instr.operands:
                    target = last_instr.operands[0]
                    if target in block_map:
                        block.successors.append(block_map[target])
                        blocks[block_map[target]].predecessors.append(block_id)
                        block.branch_target = target
                if fallthrough_pc in block_map:
                    block.successors.append(block_map[fallthrough_pc])
                    blocks[block_map[fallthrough_pc]].predecessors.append(block_id)
                    block.fallthrough_target = fallthrough_pc
            elif 'return' not in handler.handler_type:
                fallthrough_pc = last_instr.pc + 1 + len(last_instr.operands)
                if fallthrough_pc in block_map:
                    block.successors.append(block_map[fallthrough_pc])
                    blocks[block_map[fallthrough_pc]].predecessors.append(block_id)

    return blocks, block_map

def _detect_loops(blocks):
    visited = set()
    stack = []
    on_stack = set()
    loop_headers = set()
    back_edges = []

    def dfs(block_id):
        visited.add(block_id)
        stack.append(block_id)
        on_stack.add(block_id)

        block = blocks.get(block_id)
        if block:
            for succ_id in block.successors:
                if succ_id not in visited:
                    dfs(succ_id)
                elif succ_id in on_stack:
                    back_edges.append((block_id, succ_id))
                    loop_headers.add(succ_id)

        stack.pop()
        on_stack.discard(block_id)

    for block_id in blocks:
        if block_id not in visited:
            dfs(block_id)

    loops = {}
    for header in loop_headers:
        loop_blocks = {header}
        queue = deque([header])
        while queue:
            current = queue.popleft()
            block = blocks.get(current)
            if block:
                for succ_id in block.successors:
                    if succ_id not in loop_blocks and succ_id != header:
                        header_block = blocks.get(header)
                        if header_block and succ_id in header_block.predecessors:
                            loop_blocks.add(succ_id)
                            queue.append(succ_id)
                        elif succ_id not in loop_blocks:
                            loop_blocks.add(succ_id)
                            queue.append(succ_id)
        loops[header] = loop_blocks

    return loop_headers, loops

def _symbolic_execute(state, instructions, opcode_to_handler, blocks, block_map, loop_headers):
    output_lines = []
    state.visited = set()
    state.blocks = blocks
    state.loop_headers = loop_headers

    def get_register(idx):
        if idx in state.registers:
            return state.registers[idx]
        return None

    def set_register(idx, value):
        state.registers[idx] = value

    def get_constant(idx):
        if 0 <= idx < len(state.constants):
            return state.constants[idx]
        return f'R[{idx}]'

    def eval_operand(val):
        if isinstance(val, int) and val < 256 and val > 0:
            reg_val = get_register(val)
            if reg_val is not None:
                return reg_val
        if isinstance(val, str):
            return val
        return val

    def execute_block(block_id, indent=0):
        if block_id in state.visited:
            return
        state.visited.add(block_id)

        block = blocks.get(block_id)
        if not block:
            return

        is_loop_header = block_id in loop_headers
        if is_loop_header:
            output_lines.append('  ' * indent + 'while true do')
            indent += 1

        for instr in block.instructions:
            handler = opcode_to_handler.get(instr.opcode)
            if not handler:
                continue

            features = handler.handler_type
            ops = instr.operands

            if 'loadk' in features:
                if len(ops) >= 2:
                    dest_reg = ops[0]
                    const_idx = ops[1]
                    const_val = get_constant(const_idx)
                    set_register(dest_reg, const_val)
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = {_escape_lua_string(const_val) if isinstance(const_val, str) else const_val}')

            elif 'move' in features:
                if len(ops) >= 2:
                    dest_reg = ops[0]
                    src_reg = ops[1]
                    src_val = get_register(src_reg)
                    if src_val is not None:
                        set_register(dest_reg, src_val)
                        output_lines.append('  ' * indent + f'local reg_{dest_reg} = reg_{src_reg}')

            elif 'add' in features:
                if len(ops) >= 3:
                    dest_reg = ops[0]
                    left_val = get_register(ops[1]) if ops[1] < len(state.registers) else ops[1]
                    right_val = get_register(ops[2]) if ops[2] < len(state.registers) else ops[2]
                    result = f'{left_val} + {right_val}'
                    set_register(dest_reg, result)
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = {result}')

            elif 'sub' in features:
                if len(ops) >= 3:
                    dest_reg = ops[0]
                    left_val = get_register(ops[1]) if ops[1] < len(state.registers) else ops[1]
                    right_val = get_register(ops[2]) if ops[2] < len(state.registers) else ops[2]
                    result = f'{left_val} - {right_val}'
                    set_register(dest_reg, result)
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = {result}')

            elif 'mul' in features:
                if len(ops) >= 3:
                    dest_reg = ops[0]
                    left_val = get_register(ops[1]) if ops[1] < len(state.registers) else ops[1]
                    right_val = get_register(ops[2]) if ops[2] < len(state.registers) else ops[2]
                    result = f'{left_val} * {right_val}'
                    set_register(dest_reg, result)
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = {result}')

            elif 'div' in features:
                if len(ops) >= 3:
                    dest_reg = ops[0]
                    left_val = get_register(ops[1]) if ops[1] < len(state.registers) else ops[1]
                    right_val = get_register(ops[2]) if ops[2] < len(state.registers) else ops[2]
                    result = f'{left_val} / {right_val}'
                    set_register(dest_reg, result)
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = {result}')

            elif 'concat' in features:
                if len(ops) >= 3:
                    dest_reg = ops[0]
                    left_val = get_register(ops[1]) if ops[1] < len(state.registers) else ops[1]
                    right_val = get_register(ops[2]) if ops[2] < len(state.registers) else ops[2]
                    result = f'{left_val} .. {right_val}'
                    set_register(dest_reg, result)
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = {result}')

            elif 'strchar' in features:
                if len(ops) >= 1:
                    dest_reg = ops[0]
                    char_args = ops[1:] if len(ops) > 1 else [ops[0]]
                    chars = ', '.join(str(a) for a in char_args)
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = string.char({chars})')

            elif 'table_insert' in features:
                if len(ops) >= 1:
                    output_lines.append('  ' * indent + f'table.insert(reg_{ops[0]}, reg_{ops[1] if len(ops) > 1 else "?"})')

            elif 'call' in features or 'pcall' in features:
                if len(ops) >= 1:
                    func_name = get_constant(ops[0]) if ops[0] < len(state.constants) else f'reg_{ops[0]}'
                    arg_count = ops[1] if len(ops) > 1 else 0
                    args = []
                    for i in range(arg_count):
                        arg_reg = ops[2 + i] if len(ops) > 2 + i else None
                        if arg_reg is not None:
                            arg_val = get_register(arg_reg)
                            args.append(str(arg_val) if arg_val is not None else f'reg_{arg_reg}')
                    output_lines.append('  ' * indent + f'{func_name}({", ".join(args)})')

            elif 'jump' in features and 'cjump' not in features:
                break

            elif 'cjump' in features:
                if ops:
                    cond_reg = ops[0]
                    cond_val = get_register(cond_reg)
                    output_lines.append('  ' * indent + f'if reg_{cond_reg} then')

        if is_loop_header:
            indent -= 1
            output_lines.append('  ' * indent + 'end')

        for succ_id in block.successors:
            if succ_id not in state.visited:
                execute_block(succ_id, indent)

    if blocks:
        first_block = min(blocks.keys())
        execute_block(first_block)

    return '\n'.join(output_lines)

def _extract_all_constants(source, decoded_strings):
    all_constants = list(decoded_strings) if decoded_strings else []

    numeric_constants = re.findall(r'local\s+\w+\s*=\s*\{([\d,\s]+)\}', source)
    for match in numeric_constants:
        nums = [int(n.strip()) for n in match.split(',') if n.strip().lstrip('-').isdigit()]
        all_constants.extend(nums)

    string_literals = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', source)
    for s in string_literals[:50]:
        try:
            decoded = _decode_numeric_escapes(s)
            if len(decoded) > 1 and len(decoded) < 100:
                all_constants.append(decoded)
        except:
            pass

    return all_constants

def _is_wearedevs_vm(source):
    score = 0
    if re.search(r'while\s+\w+\s+do\s+local\s+\w+\s*=\s*\{', source):
        score += 3
    if re.search(r'local\s+\w+\s*=\s*\{[\d,\s]{50,}\}', source):
        score += 2
    if re.search(r'local\s+R\s*=\s*\{', source):
        score += 2
    if re.search(r'local\s+N\s*=\s*\{', source):
        score += 2
    if re.search(r'Q\s*\[\s*I\s*\[\s*B', source):
        score += 3
    if re.search(r'for\s+E,l\s+in\s+ipairs', source):
        score += 1
    return score >= 5

def _lift_wearedevs_vm(source, decoded_strings):
    vm_structure = _extract_vm_structure(source)

    instructions = _extract_instruction_stream(source, vm_structure)

    opcode_to_handler, all_handlers = _build_handler_table(source, vm_structure)

    blocks, block_map = _build_cfg(instructions, opcode_to_handler)

    loop_headers, loops = _detect_loops(blocks)

    constants = _extract_all_constants(source, decoded_strings or [])

    state = VMLifterState()
    state.constants = constants
    state.instructions = instructions

    lifted_code = _symbolic_execute(
        state, instructions, opcode_to_handler,
        blocks, block_map, loop_headers
    )

    if lifted_code and len(lifted_code.strip()) >= 50:
        return lifted_code

    fallback_lines = []
    fallback_lines.append('local R = {')
    for i, s in enumerate(decoded_strings or []):
        if s and len(s) > 1:
            fallback_lines.append(f'\t[{i}] = {_escape_lua_string(s)},')
    fallback_lines.append('}')

    fallback_lines.append('')
    fallback_lines.append('local function vm_instruction(op, a, b, c)')
    fallback_lines.append('\t-- opcodes: 0=LOADK, 1=MOVE, 2=ADD, 3=SUB, 4=MUL, 5=DIV, 6=CONCAT, 7=JMP, 8=CJMP, 9=CALL, 10=RET')
    fallback_lines.append('\t-- instruction stream extracted from obfuscated script')
    fallback_lines.append('end')

    for instr in instructions[:30]:
        handler = opcode_to_handler.get(instr.opcode)
        if handler:
            features = handler.handler_type
            ops = instr.operands
            if 'loadk' in features and len(ops) >= 2:
                const_val = constants[ops[1]] if ops[1] < len(constants) else f'R[{ops[1]}]'
                fallback_lines.append(f'-- [{instr.pc}] LOADK reg_{ops[0]} = {_escape_lua_string(str(const_val))}')
            elif 'move' in features and len(ops) >= 2:
                fallback_lines.append(f'-- [{instr.pc}] MOVE reg_{ops[0]} = reg_{ops[1]}')
            elif 'add' in features and len(ops) >= 3:
                fallback_lines.append(f'-- [{instr.pc}] ADD reg_{ops[0]} = reg_{ops[1]} + reg_{ops[2]}')
            elif 'jump' in features and 'cjump' not in features and ops:
                fallback_lines.append(f'-- [{instr.pc}] JMP -> {ops[0]}')
            elif 'cjump' in features and ops:
                fallback_lines.append(f'-- [{instr.pc}] CJMP reg_{ops[0]} ? -> {ops[0] if len(ops) > 0 else "?"}')
            elif 'call' in features or 'pcall' in features:
                func = constants[ops[0]] if ops and ops[0] < len(constants) else '?'
                fallback_lines.append(f'-- [{instr.pc}] CALL {func}')
            else:
                fallback_lines.append(f'-- [{instr.pc}] OP_{instr.opcode} {ops}')

    return '\n'.join(fallback_lines)
