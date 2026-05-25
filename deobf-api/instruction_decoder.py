from vm_state import Instruction

def decode_instruction_stream(inst_table, handlers):
    stream = []
    pc = 0
    limit = len(inst_table)
    while pc < limit:
        op = inst_table[pc]
        if isinstance(op, int) and op in handlers:
            instr = Instruction(opcode=op, pc=pc)
            action = handlers[op]
            if action == 'LOADK':
                if pc+1 < limit:
                    instr.operands.append(inst_table[pc+1])
                    pc += 1
            elif action in ('SETGLOBAL', 'GETGLOBAL'):
                if pc+1 < limit:
                    instr.operands.append(inst_table[pc+1])
                    pc += 1
            elif action == 'CALL':
                if pc+1 < limit:
                    instr.operands.append(inst_table[pc+1])
                    pc += 1
                if pc+1 < limit and isinstance(inst_table[pc+1], int):
                    instr.operands.append(inst_table[pc+1])
                    pc += 1
            stream.append(instr)
        pc += 1
    return stream
