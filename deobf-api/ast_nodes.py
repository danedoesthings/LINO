from dataclasses import dataclass, field
from typing import Any, List, Optional

class ASTNode:
    pass

@dataclass
class ConstNode(ASTNode):
    value: Any

@dataclass
class VarNode(ASTNode):
    name: str

@dataclass
class IndexNode(ASTNode):
    table: ASTNode
    key: ASTNode

@dataclass
class BinaryOpNode(ASTNode):
    op: str
    left: ASTNode
    right: ASTNode

@dataclass
class UnaryOpNode(ASTNode):
    op: str
    operand: ASTNode

@dataclass
class CallNode(ASTNode):
    func: ASTNode
    args: List[ASTNode] = field(default_factory=list)

@dataclass
class AssignNode(ASTNode):
    target: ASTNode
    value: ASTNode
    local: bool = True

@dataclass
class IfNode(ASTNode):
    condition: ASTNode
    body: List[ASTNode] = field(default_factory=list)
    else_body: List[ASTNode] = field(default_factory=list)

@dataclass
class WhileNode(ASTNode):
    condition: ASTNode
    body: List[ASTNode] = field(default_factory=list)

@dataclass
class ForNode(ASTNode):
    var: str
    start: ASTNode
    end: ASTNode
    step: Optional[ASTNode]
    body: List[ASTNode] = field(default_factory=list)

@dataclass
class FunctionNode(ASTNode):
    name: Optional[str]
    params: List[str] = field(default_factory=list)
    body: List[ASTNode] = field(default_factory=list)

@dataclass
class ReturnNode(ASTNode):
    values: List[ASTNode] = field(default_factory=list)

@dataclass
class TableNode(ASTNode):
    fields: List[tuple] = field(default_factory=list)
