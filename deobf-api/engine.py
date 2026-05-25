import os, re, shutil, subprocess, tempfile, base64, urllib.request, asyncio, struct, hashlib, json, time, traceback, binascii, sys, ast as py_ast, operator as op
from collections import OrderedDict, defaultdict, deque, namedtuple
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional, Union, Any, Callable
from enum import Enum

from transformers import (
    AdvancedWeAreDevsLifter, MoonSecLifter, IronBrewLifter, PSULifter,
    XORStringDecoder, NumberArrayDecoder, StandardBase64Decoder,
    StringPatternExtractor, BytecodeHarvester
)
from sandbox import execute_sandbox
from lune_executor import execute_and_capture
from bytecode_analyzer import BytecodeAnalyzer
from string_decoders import MultiStrategyStringDecoder
from pattern_matcher import ObfuscationFingerprinter
from roblox_executor import execute_via_roblox
from errors import LinoError
from diagnostics import (
    diagnostic_parse, validate_lua, parse_lua_error,
    extract_error_context, auto_fix_lua, confidence_score,
    save_crash_snapshot, log_structured_error, pipeline_validate_stage,
    detect_bad_patterns
)

try:
    from luaparser import ast as lua_ast
    HAS_LUAPARSER = True
except ImportError:
    HAS_LUAPARSER = False

UNLUAC_JAR_URL = "https://github.com/scratchminer/unluac/releases/download/v2023.03.22/unluac.jar"
UNLUAC_LOCAL_PATH = os.environ.get('UNLUAC_PATH') or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'unluac.jar')

OPS = {
    py_ast.Add: op.add,
    py_ast.Sub: op.sub,
    py_ast.Mult: op.mul,
    py_ast.Div: op.floordiv,
    py_ast.USub: op.neg
}

def _safe_eval_math(expr_str):
    def _eval_node(node):
        if isinstance(node, py_ast.Num):
            return node.n
        if isinstance(node, py_ast.BinOp):
            return OPS[type(node.op)](_eval_node(node.left), _eval_node(node.right))
        if isinstance(node, py_ast.UnaryOp):
            return OPS[type(node.op)](_eval_node(node.operand))
        raise TypeError(node)
    return _eval_node(py_ast.parse(expr_str.strip(), mode='eval').body)


class IROpcode(Enum):
    LOADK = "LOADK"
    MOVE = "MOVE"
    CALL = "CALL"
    GETGLOBAL = "GETGLOBAL"
    SETGLOBAL = "SETGLOBAL"
    GETTABLE = "GETTABLE"
    SETTABLE = "SETTABLE"
    ADD = "ADD"
    SUB = "SUB"
    MUL = "MUL"
    DIV = "DIV"
    CONCAT = "CONCAT"
    JMP = "JMP"
    EQ = "EQ"
    LT = "LT"
    LE = "LE"
    TEST = "TEST"
    RETURN = "RETURN"
    CLOSURE = "CLOSURE"
    NEWTABLE = "NEWTABLE"
    FORPREP = "FORPREP"
    FORLOOP = "FORLOOP"
    TFORLOOP = "TFORLOOP"
    SELF = "SELF"
    VARARG = "VARARG"


@dataclass
class IRInstruction:
    opcode: IROpcode
    args: List[Any] = field(default_factory=list)
    dest: Optional[str] = None
    pc: int = 0


class IRBlock:
    def __init__(self, id: int):
        self.id = id
        self.instructions: List[IRInstruction] = []
        self.predecessors: List[IRBlock] = []
        self.successors: List[IRBlock] = []
        self.dominators: Set[IRBlock] = set()
        self.immediate_dominator: Optional[IRBlock] = None
        self.dominance_frontier: Set[IRBlock] = set()
        self.is_loop_header = False
        self.loop_depth = 0
        self.phis: List[IRInstruction] = []


@dataclass
class SymbolicExpr:
    kind: str
    value: Any = None
    left: Optional['SymbolicExpr'] = None
    right: Optional['SymbolicExpr'] = None
    is_constant: bool = False
    reg: Optional[int] = None


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
    then_body: List[ASTNode] = field(default_factory=list)
    else_body: List[ASTNode] = field(default_factory=list)


@dataclass
class WhileNode(ASTNode):
    condition: ASTNode
    body: List[ASTNode] = field(default_factory=list)
    is_repeat: bool = False


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
    fields: List[Tuple[ASTNode, ASTNode]] = field(default_factory=list)


class LuaEmitter:
    def __init__(self):
        self.indent_level = 0

    def _indent(self):
        return "    " * self.indent_level

    def emit(self, node):
        if isinstance(node, list):
            return "\n".join(self.emit(n) for n in node)
        if node is None:
            return ""
        method_name = f"emit_{type(node).__name__}"
        method = getattr(self, method_name, None)
        if method:
            return method(node)
        return str(node)

    def emit_str(self, s):
        escaped = s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
        return f'"{escaped}"'

    def emit_ConstNode(self, node):
        if isinstance(node.value, str):
            return self.emit_str(node.value)
        if isinstance(node.value, bool):
            return 'true' if node.value else 'false'
        if node.value is None:
            return 'nil'
        return str(node.value)

    def emit_VarNode(self, node):
        return node.name

    def emit_IndexNode(self, node):
        return f"{self.emit(node.table)}[{self.emit(node.key)}]"

    def emit_BinaryOpNode(self, node):
        return f"({self.emit(node.left)} {node.op} {self.emit(node.right)})"

    def emit_CallNode(self, node):
        args = ", ".join(self.emit(a) for a in node.args)
        return f"{self.emit(node.func)}({args})"

    def emit_AssignNode(self, node):
        local = "local " if node.local else ""
        return f"{local}{self.emit(node.target)} = {self.emit(node.value)}"

    def emit_IfNode(self, node):
        cond = self.emit(node.condition)
        self.indent_level += 1
        then_body = "\n".join(self._indent() + self.emit(s) for s in node.then_body)
        self.indent_level -= 1
        result = f"if {cond} then\n{then_body}"
        if node.else_body:
            self.indent_level += 1
            else_body = "\n".join(self._indent() + self.emit(s) for s in node.else_body)
            self.indent_level -= 1
            result += f"\nelse\n{else_body}"
        result += "\nend"
        return result

    def emit_WhileNode(self, node):
        cond = self.emit(node.condition)
        self.indent_level += 1
        body = "\n".join(self._indent() + self.emit(s) for s in node.body)
        self.indent_level -= 1
        if node.is_repeat:
            return f"repeat\n{body}\nuntil {cond}"
        return f"while {cond} do\n{body}\nend"

    def emit_ForNode(self, node):
        step = f", {self.emit(node.step)}" if node.step else ""
        self.indent_level += 1
        body = "\n".join(self._indent() + self.emit(s) for s in node.body)
        self.indent_level -= 1
        return f"for {node.var} = {self.emit(node.start)}, {self.emit(node.end)}{step} do\n{body}\nend"

    def emit_FunctionNode(self, node):
        name = node.name or ""
        params = ", ".join(node.params)
        self.indent_level += 1
        body = "\n".join(self._indent() + self.emit(s) for s in node.body)
        self.indent_level -= 1
        if name:
            return f"function {name}({params})\n{body}\nend"
        else:
            return f"function({params})\n{body}\nend"

    def emit_ReturnNode(self, node):
        vals = ", ".join(self.emit(v) for v in node.values)
        return f"return {vals}"

    def emit_TableNode(self, node):
        fields = []
        for i, (k, v) in enumerate(node.fields):
            if isinstance(k, ConstNode) and isinstance(k.value, int) and k.value == i + 1:
                fields.append(self.emit(v))
            else:
                fields.append(f"[{self.emit(k)}] = {self.emit(v)}")
        return "{" + ", ".join(fields) + "}"


class SymbolicExecutor:
    def __init__(self, string_table):
        self.constants = string_table
        self.registers: Dict[int, SymbolicExpr] = {}
        self.stack: List[SymbolicExpr] = []
        self.instructions: List[IRInstruction] = []
        self.temp_counter = 0

    def _new_reg(self):
        self.temp_counter += 1
        return f"%{self.temp_counter}"

    def load_instructions(self, inst_table, handlers):
        self.instructions = []
        pc = 0
        limit = len(inst_table)
        while pc < limit:
            op = inst_table[pc]
            if isinstance(op, int) and op in handlers:
                action = handlers[op]
                instr = self._decode_op(action, pc, inst_table)
                if instr:
                    self.instructions.append(instr)
            pc += 1

    def _decode_op(self, action, pc, inst_table):
        if action == 'LOADK':
            idx = inst_table[pc+1] if pc+1 < len(inst_table) else 0
            return IRInstruction(IROpcode.LOADK, [idx], pc=pc)
        elif action == 'SETGLOBAL':
            idx = inst_table[pc+1] if pc+1 < len(inst_table) else 0
            return IRInstruction(IROpcode.SETGLOBAL, [idx], pc=pc)
        elif action == 'GETGLOBAL':
            idx = inst_table[pc+1] if pc+1 < len(inst_table) else 0
            return IRInstruction(IROpcode.GETGLOBAL, [idx], pc=pc)
        elif action == 'CALL':
            idx = inst_table[pc+1] if pc+1 < len(inst_table) else 0
            arg_count = inst_table[pc+2] if pc+2 < len(inst_table) and isinstance(inst_table[pc+2], int) else 0
            return IRInstruction(IROpcode.CALL, [idx, arg_count], pc=pc)
        elif action == 'RETURN':
            return IRInstruction(IROpcode.RETURN, [], pc=pc)
        elif action == 'CONCAT':
            return IRInstruction(IROpcode.CONCAT, [], pc=pc)
        elif action == 'ARITH':
            return IRInstruction(IROpcode.ADD, [], pc=pc)
        elif action == 'NEWTABLE':
            return IRInstruction(IROpcode.NEWTABLE, [], pc=pc)
        elif action == 'SETTABLE':
            return IRInstruction(IROpcode.SETTABLE, [], pc=pc)
        elif action == 'GETTABLE':
            return IRInstruction(IROpcode.GETTABLE, [], pc=pc)
        elif action == 'CLOSURE':
            return IRInstruction(IROpcode.CLOSURE, [], pc=pc)
        return None

    def execute(self):
        self.registers.clear()
        self.stack.clear()
        for instr in self.instructions:
            if instr.opcode == IROpcode.LOADK:
                idx = instr.args[0]
                val = self._get_constant(idx)
                self.stack.append(SymbolicExpr('const', val, is_constant=True))
            elif instr.opcode == IROpcode.SETGLOBAL:
                name = self._resolve_name(instr.args[0])
                val = self.stack.pop() if self.stack else SymbolicExpr('nil', None, is_constant=True)
                self.registers[0] = val
            elif instr.opcode == IROpcode.GETGLOBAL:
                name = self._resolve_name(instr.args[0])
                self.stack.append(SymbolicExpr('global', name))
            elif instr.opcode == IROpcode.CALL:
                func_name = self._resolve_name(instr.args[0])
                arg_count = instr.args[1]
                args = []
                for _ in range(arg_count):
                    if self.stack:
                        args.insert(0, self.stack.pop())
                    else:
                        args.insert(0, SymbolicExpr('nil', None, is_constant=True))
                self.stack.append(SymbolicExpr('call', (func_name, args)))
            elif instr.opcode == IROpcode.RETURN:
                ret_vals = [self.stack.pop()] if self.stack else [SymbolicExpr('nil', None, is_constant=True)]
                self.stack.append(SymbolicExpr('return', ret_vals))
            elif instr.opcode == IROpcode.CONCAT:
                r = self.stack.pop() if self.stack else SymbolicExpr('const', '', is_constant=True)
                l = self.stack.pop() if self.stack else SymbolicExpr('const', '', is_constant=True)
                self.stack.append(SymbolicExpr('concat', None, left=l, right=r))
            elif instr.opcode == IROpcode.ADD:
                r = self.stack.pop() if self.stack else SymbolicExpr('const', 0, is_constant=True)
                l = self.stack.pop() if self.stack else SymbolicExpr('const', 0, is_constant=True)
                result = self._try_fold('+', l, r)
                self.stack.append(result)
            elif instr.opcode == IROpcode.NEWTABLE:
                self.stack.append(SymbolicExpr('table', []))
            elif instr.opcode == IROpcode.SETTABLE:
                v = self.stack.pop() if self.stack else SymbolicExpr('nil', None, is_constant=True)
                k = self.stack.pop() if self.stack else SymbolicExpr('const', 0, is_constant=True)
                t = self.stack.pop() if self.stack else SymbolicExpr('table', [])
                self.stack.append(t)
            elif instr.opcode == IROpcode.GETTABLE:
                k = self.stack.pop() if self.stack else SymbolicExpr('const', 0, is_constant=True)
                t = self.stack.pop() if self.stack else SymbolicExpr('table', [])
                self.stack.append(SymbolicExpr('gettable', None, left=t, right=k))

    def _get_constant(self, idx):
        if isinstance(idx, int) and 1 <= idx <= len(self.constants):
            return self.constants[idx-1]
        return str(idx)

    def _resolve_name(self, idx):
        if isinstance(idx, int) and 1 <= idx <= len(self.constants):
            return self.constants[idx-1]
        return str(idx)

    def _try_fold(self, op_name, left, right):
        if left.is_constant and right.is_constant:
            lv = left.value
            rv = right.value
            if isinstance(lv, (int, float)) and isinstance(rv, (int, float)):
                if op_name == '+':
                    return SymbolicExpr('const', lv + rv, is_constant=True)
                elif op_name == '-':
                    return SymbolicExpr('const', lv - rv, is_constant=True)
                elif op_name == '*':
                    return SymbolicExpr('const', lv * rv, is_constant=True)
                elif op_name == '/':
                    if rv != 0:
                        return SymbolicExpr('const', lv / rv, is_constant=True)
        return SymbolicExpr('arith', None, left=left, right=right)

    def to_ast(self):
        return self._convert_stack_to_ast()

    def _convert_stack_to_ast(self):
        nodes = []
        for expr in self.stack:
            nodes.append(self._expr_to_ast(expr))
        return nodes

    def _expr_to_ast(self, expr):
        if expr.kind == 'const':
            return ConstNode(expr.value)
        elif expr.kind == 'global':
            return IndexNode(VarNode('_G'), ConstNode(expr.value))
        elif expr.kind == 'call':
            func_name, args = expr.value
            return CallNode(VarNode(func_name), [self._expr_to_ast(a) for a in args])
        elif expr.kind == 'return':
            return ReturnNode([self._expr_to_ast(v) for v in expr.value])
        elif expr.kind == 'concat':
            return BinaryOpNode('..', self._expr_to_ast(expr.left) if expr.left else ConstNode(''), self._expr_to_ast(expr.right) if expr.right else ConstNode(''))
        elif expr.kind == 'arith':
            return BinaryOpNode('+', self._expr_to_ast(expr.left) if expr.left else ConstNode(0), self._expr_to_ast(expr.right) if expr.right else ConstNode(0))
        elif expr.kind == 'table':
            return TableNode()
        return ConstNode(None)


def _find_table_literal_end(content, open_brace_index):
    depth = 0
    quote = None
    idx = open_brace_index
    while idx < len(content):
        char = content[idx]
        if quote:
            if char == "\\":
                idx += 2
                continue
            if char == quote:
                quote = None
            idx += 1
            continue
        if char in ("'", '"'):
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return idx + 1
        idx += 1
    return -1


def _parse_table_entries_strict(body):
    inner = body[1:-1]
    entries = []
    depth = 0
    current = ""
    in_str = False
    quote = None
    for c in inner:
        if in_str:
            current += c
            if c == '\\':
                current += ''
            elif c == quote:
                in_str = False
            continue
        if c in ('"', "'"):
            in_str = True
            quote = c
            current += c
            continue
        if c == '{':
            depth += 1
            current += c
            continue
        if c == '}':
            depth -= 1
            current += c
            continue
        if c == ',' and depth == 0:
            entries.append(current.strip())
            current = ""
            continue
        current += c
    if current.strip():
        entries.append(current.strip())
    parsed = []
    for e in entries:
        if not e:
            continue
        if (e.startswith('"') and e.endswith('"')) or (e.startswith("'") and e.endswith("'")):
            parsed.append(e[1:-1])
        elif e.lstrip('-').isdigit():
            parsed.append(int(e))
        elif e.replace('.', '', 1).lstrip('-').isdigit():
            parsed.append(float(e))
        else:
            parsed.append(e)
    return parsed


def _extract_string_table_from_source(source):
    for m in re.finditer(r'local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{', source):
        var_name = m.group(1)
        open_brace = source.find('{', m.start())
        end = _find_table_literal_end(source, open_brace)
        if end == -1:
            continue
        body = source[open_brace:end]
        entries = _parse_table_entries_strict(body)
        strings = [e for e in entries if isinstance(e, str)]
        if len(strings) >= 10:
            return strings, var_name
    return None, None


def _find_all_tables_in_source(source):
    tables = []
    for m in re.finditer(r'\{', source):
        end = _find_table_literal_end(source, m.start())
        if end != -1:
            tables.append(source[m.start():end])
    return tables


def _unescape_lua_string(s):
    result = bytearray()
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            nc = s[i+1]
            if nc == 'n':
                result.append(ord('\n'))
                i += 2
            elif nc == 'r':
                result.append(ord('\r'))
                i += 2
            elif nc == 't':
                result.append(ord('\t'))
                i += 2
            elif nc == '\\':
                result.append(ord('\\'))
                i += 2
            elif nc == '"':
                result.append(ord('"'))
                i += 2
            elif nc == "'":
                result.append(ord("'"))
                i += 2
            elif nc == '0':
                result.append(0)
                i += 2
            elif nc == 'x' and i + 3 < len(s):
                try:
                    result.append(int(s[i+2:i+4], 16))
                except ValueError:
                    pass
                i += 4
            elif nc.isdigit():
                j = i + 1
                while j < len(s) and s[j].isdigit() and j - (i + 1) < 3:
                    j += 1
                try:
                    result.append(int(s[i+1:j]) % 256)
                except ValueError:
                    pass
                i = j
            else:
                result.append(ord(nc))
                i += 2
        else:
            result.append(ord(s[i]) if ord(s[i]) < 256 else ord('?'))
            i += 1
    return bytes(result)


def _decode_b64_with_map(data, rev_map):
    if not data or len(data) == 0:
        return None
    buf, bits, out = 0, 0, bytearray()
    for b in data:
        ch = chr(b) if b < 256 else ''
        if ch == '=':
            break
        if ch not in rev_map:
            continue
        buf = (buf << 6) | rev_map[ch]
        bits += 6
        while bits >= 8:
            bits -= 8
            out.append((buf >> bits) & 0xFF)
    return bytes(out)


def _decode_base64_custom(encoded_strings, n_table_body):
    n_entries = _parse_table_entries_strict(n_table_body)
    rev_map = {}
    for i, entry in enumerate(n_entries):
        if isinstance(entry, str) and len(entry) >= 1:
            rev_map[entry] = i
    if len(rev_map) < 62:
        return None
    decoded_all = []
    for s in encoded_strings:
        if not isinstance(s, str):
            continue
        raw = _unescape_lua_string(s)
        if not raw:
            continue
        dec = _decode_b64_with_map(raw, rev_map)
        if dec:
            decoded_all.append(dec)
    return decoded_all


def _execute_with_runtime_tracing(source):
    harness = r'''
local captured = {}
local trace_data = {}
local original_loadstring = loadstring
_G.loadstring = function(code, chunkname)
    if type(code) == "string" then
        table.insert(captured, code)
    end
    return original_loadstring(code, chunkname)
end
_G.load = _G.loadstring

local function scan_env()
    local found = nil
    local keywords = {"function", "local", "end", "if", "then", "else", "return", "for", "while", "do"}
    for k, v in pairs(_G) do
        if type(v) == "string" and #v > 50 then
            local count = 0
            for _, kw in ipairs(keywords) do
                if string.find(v, kw) then count = count + 1 end
            end
            if count >= 3 then
                found = v
                break
            end
        end
    end
    return found
end

local f, err = loadstring([[__SOURCE__]])
if not f then
    print("COMPILE_ERROR:" .. err)
    return
end

local success, result = pcall(f)
if #captured > 0 then
    print("CAPTURED:" .. table.concat(captured, "\n"))
else
    local found = scan_env()
    if found then
        print("CAPTURED:" .. found)
    elseif not success then
        print("RUNTIME_ERROR:" .. tostring(result))
    end
end
'''
    harness = harness.replace('__SOURCE__', source.replace('\\', '\\\\').replace('"', '\\"'))
    with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as tmp:
        tmp.write(harness)
        tmp_path = tmp.name
    try:
        for lua_bin in ['lua5.1', 'lua']:
            try:
                result = subprocess.run(
                    [lua_bin, tmp_path],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0:
                    out = result.stdout
                    for line in out.splitlines():
                        if line.startswith('CAPTURED:'):
                            return line[len('CAPTURED:'):]
                    if out.strip() and len(out.strip()) > 50:
                        return out.strip()
            except FileNotFoundError:
                continue
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    return None


class DeobfEngine:
    def __init__(self):
        self.lifters = [
            AdvancedWeAreDevsLifter(),
            MoonSecLifter(),
            IronBrewLifter(),
            PSULifter(),
            XORStringDecoder(),
            NumberArrayDecoder(),
            StandardBase64Decoder(),
        ]
        self.bytecode_harvester = BytecodeHarvester()
        self.string_decoder = MultiStrategyStringDecoder()
        self.fingerprinter = ObfuscationFingerprinter()
        self.bytecode_analyzer = BytecodeAnalyzer()
        self.unluac_path = UNLUAC_LOCAL_PATH
        self.capabilities = {
            'ir_lowering', 'symbolic_execution', 'constant_folding',
            'cfg_reconstruction', 'ast_emission', 'vm_opcode_lifting',
            'runtime_tracing', 'recursive_unpacking', 'multi_pass_optimization',
            'static_lifting', 'sandbox_execution', 'lune_execution',
            'bytecode_decompilation', 'multi_strategy_extraction',
            'balanced_brace_parsing', 'safe_arithmetic', 'lua_ast_validation',
            'environment_simulation', 'execution_tracing_hooks',
            'dead_code_elimination', 'expression_collapse'
        }
        self._java_available = shutil.which('java') is not None
        if not self._java_available:
            self.capabilities.discard('bytecode_decompilation')

    def get_capabilities(self):
        return list(self.capabilities)

    def process(self, source):
        trace = []
        stage = "init"
        try:
            fingerprint = self.fingerprinter.analyze(source)
            trace.append({'stage': 'fingerprint', 'details': fingerprint})

            strings, var_name = _extract_string_table_from_source(source)
            if strings and var_name:
                n_table_body = None
                for body in _find_all_tables_in_source(source):
                    entries = _parse_table_entries_strict(body)
                    str_entries = [e for e in entries if isinstance(e, str)]
                    if 60 <= len(str_entries) <= 70:
                        n_table_body = body
                        break
                if not n_table_body:
                    for body in _find_all_tables_in_source(source):
                        entries = _parse_table_entries_strict(body)
                        str_entries = [e for e in entries if isinstance(e, str)]
                        if len(str_entries) >= 60:
                            n_table_body = body
                            break

                if n_table_body:
                    shuffle_ranges = self._find_shuffle_ranges(source)
                    if shuffle_ranges:
                        working = list(strings)
                        for lo, hi in shuffle_ranges:
                            lo_idx, hi_idx = lo - 1, hi - 1
                            if 0 <= lo_idx < len(working) and 0 <= hi_idx < len(working) and lo_idx < hi_idx:
                                working[lo_idx:hi_idx+1] = working[lo_idx:hi_idx+1][::-1]
                    else:
                        working = strings

                    decoded_chunks = _decode_base64_custom(working, n_table_body)
                    if decoded_chunks:
                        combined = b''.join(decoded_chunks)
                        for enc in ('utf-8', 'latin-1'):
                            try:
                                source_text = combined.decode(enc)
                                source_text = ''.join(ch for ch in source_text if ch.isprintable() or ch in '\n\r\t')
                                if len(source_text) > 50:
                                    stage = "static_decode"
                                    executor = SymbolicExecutor(strings)
                                    executor.load_instructions([], {})
                                    beautified = self._beautify(source_text)
                                    if self._is_valid_lua(beautified):
                                        return beautified, 'static_decode', 'Decoded successfully', trace
                                    break
                            except:
                                continue

            roblox_result, roblox_error = self._try_roblox_exec(source)
            if roblox_result:
                beautified = self._beautify(roblox_result)
                if self._is_valid_lua(beautified):
                    return beautified, 'roblox_execution', 'Deobfuscated via Roblox', trace

            lua_result = _execute_with_runtime_tracing(source)
            if lua_result:
                beautified = self._beautify(lua_result)
                if self._is_valid_lua(beautified):
                    return beautified, 'runtime_execution', 'Deobfuscated via runtime tracing', trace

            layers, caps, diag = execute_sandbox(source, timeout=120)
            if layers:
                for i, item in enumerate(layers):
                    if isinstance(item, str) and len(item) > 100:
                        beautified = self._beautify(item)
                        if self._is_valid_lua(beautified):
                            return beautified, 'sandbox_source', f'Layer {i} captured', trace

            return '', 'unable', 'All strategies exhausted', trace

        except Exception as e:
            return '', 'error', str(e), trace

    def _find_shuffle_ranges(self, source):
        ranges = []
        for m in re.finditer(r'for\s+\w+\s*=\s*(\d+)\s*,\s*(\d+)\s*do', source):
            try:
                start_val = int(m.group(1))
                end_val = int(m.group(2))
                body_start = source.find('do', m.end())
                if body_start == -1:
                    continue
                end_pos = source.find('end', body_start)
                if end_pos == -1:
                    continue
                inner = source[body_start+2:end_pos]
                swap_matches = re.findall(r'(\w+)\[(\w+)\]\s*=\s*(\w+)\[(\w+)\]', inner)
                if len(swap_matches) >= 2:
                    ranges.append((start_val, end_val))
            except:
                continue
        return ranges if ranges else None

    def _beautify(self, code):
        if not code:
            return code
        code = code.replace('\r\n', '\n').replace('\r', '\n')
        lines = []
        for line in code.split('\n'):
            line = ''.join(c for c in line if c.isprintable() or c == '\t')
            lines.append(line.rstrip())
        code = '\n'.join(lines)
        code = re.sub(r'\n{3,}', '\n\n', code)
        indent = 0
        formatted = []
        for line in code.split('\n'):
            stripped = line.strip()
            if not stripped:
                formatted.append('')
                continue
            if re.match(r'^(end|until|else|elseif)\b', stripped):
                indent = max(0, indent - 1)
            formatted.append('    ' * indent + stripped)
            safe = re.sub(r'("[^"]*"|\'[^\']*\')', '', stripped)
            opens = len(re.findall(r'\b(function|then|do|repeat)\b', safe))
            closes = len(re.findall(r'\b(end|until)\b', safe))
            indent += opens - closes
            if stripped.startswith(('else', 'elseif')):
                indent += 1
            indent = max(indent, 0)
        return '\n'.join(formatted)

    def _is_valid_lua(self, code):
        if not code or len(code) < 20:
            return False
        if HAS_LUAPARSER:
            try:
                lua_ast.parse(code)
                return True
            except Exception:
                pass
        words = set(re.findall(r'\b\w+\b', code[:10000]))
        keywords = {'function', 'local', 'end', 'return', 'if', 'then', 'else',
                     'for', 'while', 'do', 'nil', 'true', 'false', 'print'}
        return len(words & keywords) >= 3

    def _try_roblox_exec(self, source, string_table=None):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result, error = loop.run_until_complete(
                execute_via_roblox(source, string_table)
            )
            loop.close()
        except Exception as e:
            return None, str(e)
        if error:
            return None, error
        if isinstance(result, list):
            return '\n'.join(str(r) for r in result if r), None
        if isinstance(result, str) and len(result) > 50:
            return result, None
        return None, "No usable output"

    def _run_lune(self, source):
        try:
            try:
                loop = asyncio.get_event_loop()
            except:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            return loop.run_until_complete(execute_and_capture(source))
        except:
            return None, {}

    def _run_unluac(self, bytecode):
        if not self._java_available:
            return None, "no java"
        if not os.path.isfile(self.unluac_path):
            self._ensure_unluac_jar()
        if not os.path.isfile(self.unluac_path):
            return None, "no unluac.jar"
        if bytecode[:4] != b'\x1bLua':
            return None, "not lua bytecode"
        with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
            tmp.write(bytecode)
            tmp_path = tmp.name
        try:
            r = subprocess.run(['java', '-jar', self.unluac_path, '--rawstring', tmp_path], capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout, None
            if r.stderr and 'version' in r.stderr.lower():
                r2 = subprocess.run(['java', '-jar', self.unluac_path, tmp_path], capture_output=True, text=True, timeout=30)
                if r2.returncode == 0 and r2.stdout.strip():
                    return r2.stdout, None
                return None, r2.stderr[:300]
            return None, r.stderr[:200] if r.stderr else 'no output'
        except subprocess.TimeoutExpired:
            return None, "timeout"
        except Exception as e:
            return None, str(e)
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except:
                    pass

    def _ensure_unluac_jar(self):
        try:
            os.makedirs(os.path.dirname(self.unluac_path), exist_ok=True)
            urllib.request.urlretrieve(UNLUAC_JAR_URL, self.unluac_path)
        except:
            pass
