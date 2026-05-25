from dataclasses import dataclass, field
from typing import Any, List, Dict, Optional, Union

@dataclass
class SymbolicValue:
    kind: str
    value: Any = None
    expr: Optional['ASTNode'] = None
    reg: Optional[int] = None

@dataclass
class Instruction:
    opcode: int
    operands: List[Union[int, str]] = field(default_factory=list)
    pc: int = 0

@dataclass
class BasicBlock:
    id: int
    instructions: List[Instruction] = field(default_factory=list)
    successors: List['BasicBlock'] = field(default_factory=list)
    predecessors: List['BasicBlock'] = field(default_factory=list)

@dataclass
class VMState:
    registers: Dict[int, SymbolicValue] = field(default_factory=dict)
    stack: List[SymbolicValue] = field(default_factory=list)
    constants: List[str] = field(default_factory=list)
    upvalues: Dict[str, SymbolicValue] = field(default_factory=dict)
    globals: Dict[str, SymbolicValue] = field(default_factory=dict)
    ip: int = 0
    instructions: List[Instruction] = field(default_factory=list)
    blocks: List[BasicBlock] = field(default_factory=list)
    current_block: Optional[BasicBlock] = None
