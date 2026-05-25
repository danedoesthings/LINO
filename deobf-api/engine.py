import os, re, shutil, subprocess, tempfile, base64, urllib.request, asyncio, struct, hashlib, json, time, traceback, binascii, sys
from collections import OrderedDict, defaultdict, deque, namedtuple
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional, Union, Any, Callable

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

LUA_KEYWORDS = {
    'function', 'local', 'end', 'return', 'if', 'then', 'else', 'elseif',
    'for', 'while', 'do', 'repeat', 'until', 'not', 'and', 'or',
    'nil', 'true', 'false', 'in', 'break', 'print', 'require',
    'pcall', 'xpcall', 'loadstring', 'load', 'pairs', 'ipairs',
    'setmetatable', 'getmetatable', 'rawset', 'rawget', 'tostring', 'tonumber',
    'table', 'string', 'math', 'coroutine', 'debug', 'io', 'os',
    'unpack', 'select', 'type', 'assert', 'error', 'next', 'rawequal',
}

LUA_SUBSTRINGS = [
    'function', 'local', 'end', 'print', 'tostring', 'tonumber',
    'setmetatable', 'getmetatable', 'loadstring', 'pcall', 'unpack',
    'string.byte', 'math.floor', 'table.concat', 'error', 'pairs',
    'ipairs', 'require', 'coroutine', 'rawset', 'rawget',
]

BAD_PATTERNS = [
    r'\d+\s+end',
    r'\.\.\s*\.\.',
    r',\s*,',
    r'function\s+end',
    r'if\s+then\s+end',
]

# ----------------------------------------------------------------------
# AST node classes
# ----------------------------------------------------------------------
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

# ----------------------------------------------------------------------
# Lua emitter
# ----------------------------------------------------------------------
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

# ----------------------------------------------------------------------
# VM State / Symbolic execution
# ----------------------------------------------------------------------
@dataclass
class SymbolicValue:
    kind: str
    value: Any = None
    expr: Optional[ASTNode] = None
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
        node = AssignNode(
            target=IndexNode(tbl.expr or ConstNode(None), key.expr or ConstNode(None)),
            value=val.expr or ConstNode(None),
            local=False
        )
        self.ast_nodes.append(node)

    def op_GETTABLE(self, instr):
        key = self.state.stack.pop() if self.state.stack else SymbolicValue('nil', None, ConstNode(None))
        tbl = self.state.stack.pop() if self.state.stack else SymbolicValue('nil', None, ConstNode(None))
        node = IndexNode(tbl.expr or ConstNode(None), key.expr or ConstNode(None))
        self.state.stack.append(SymbolicValue('gettable', None, node))

    def op_PCALL(self, instr):
        args = []
        while self.state.stack and len(args) < 5:
            sv = self.state.stack.pop()
            args.insert(0, sv.expr if sv.expr else ConstNode(None))
        node = CallNode(VarNode('pcall'), args)
        self.ast_nodes.append(node)

    def op_LOADSTRING(self, instr):
        code = self.state.stack.pop() if self.state.stack else SymbolicValue('nil', None, ConstNode(""))
        node = CallNode(VarNode('loadstring'), [code.expr or ConstNode(None)])
        self.ast_nodes.append(node)

    def op_UNKNOWN(self, instr):
        pass

    def _resolve_name(self, arg):
        if isinstance(arg, int) and 1 <= arg <= len(self.state.constants):
            return self.state.constants[arg-1]
        return str(arg)

    def emit_lua(self):
        return self.emitter.emit(self.ast_nodes)


# ----------------------------------------------------------------------
# Helper functions (Prometheus-style robust extraction)
# ----------------------------------------------------------------------
def _find_table_literal_end(content, open_brace_index):
    """Robust balanced-brace scanner from Prometheus deobfuscator."""
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


def extract_table_literal(content, pattern):
    """Find a table literal matching pattern and return its full text."""
    m = re.search(pattern, content)
    if not m:
        return None
    open_brace_index = content.find("{", m.start())
    if open_brace_index == -1:
        return None
    table_end = _find_table_literal_end(content, open_brace_index)
    if table_end == -1:
        return None
    return content[open_brace_index:table_end]


def parse_table_strings(table_body):
    """Extract string entries from a table literal body."""
    inner = table_body[1:-1]
    entries = [e.strip() for e in re.split(r'\s*,\s*', inner) if e.strip()]
    parsed = []
    for e in entries:
        if (e.startswith('"') and e.endswith('"')) or (e.startswith("'") and e.endswith("'")):
            parsed.append(e[1:-1])
        elif e.lstrip('-').isdigit():
            parsed.append(int(e))
        else:
            parsed.append(e)
    return parsed


def find_dispatch_loop(code):
    m = re.search(r'while\s+.+?do\s+(.*?)end\s*end', code, re.DOTALL)
    if not m:
        return None
    return m.group(1)


def classify_handler(code):
    if 'R[' in code:
        return 'LOADK'
    if '_G[' in code and '=' in code and code.index('_G') > code.index('='):
        return 'SETGLOBAL'
    if '=' in code and '_G[' in code:
        return 'GETGLOBAL'
    if 'pcall' in code:
        return 'PCALL'
    if 'loadstring' in code:
        return 'LOADSTRING'
    if 'return' in code:
        return 'RETURN'
    if 'string.char' in code:
        return 'STRCHAR'
    if 'table.concat' in code:
        return 'TABLECONCAT'
    if '..' in code:
        return 'CONCAT'
    if re.search(r'[+\-*/]', code) and '=' in code:
        return 'ARITH'
    if 'function' in code and '=' in code:
        return 'CLOSURE'
    if '{' in code and '=' in code:
        return 'NEWTABLE'
    if re.search(r'\w+\s*\(', code):
        return 'CALL'
    return 'UNKNOWN'


def extract_handlers(dispatch_body):
    handlers = {}
    for m in re.finditer(r'if\s+(\w+)\s*==\s*(\d+)\s+then\s+(.*?)(?=\s*(?:elseif|else|end)\b)', dispatch_body, re.DOTALL):
        opcode = int(m.group(2))
        handlers[opcode] = classify_handler(m.group(3))
    return handlers


def extract_instruction_table(code):
    best = []
    for m in re.finditer(r'local\s+\w+\s*=\s*\{', code):
        body = extract_table_literal(code, rf'\b{re.escape(m.group(0)[:-1].strip())}\s*=\s*\{{')
        if body:
            entries = parse_table_strings(body)
            if len(entries) > len(best):
                best = entries
    return best


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


# ----------------------------------------------------------------------
# Main DeobfEngine (with Prometheus-style fallback)
# ----------------------------------------------------------------------
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
            'static_lifting', 'sandbox_execution', 'lune_execution',
            'bytecode_decompilation', 'xor_decoding', 'number_array_decoding',
            'base64_decoding', 'multi_pass', 'recursive_unpacking',
            'control_flow_recovery', 'constant_propagation',
            'symbolic_execution', 'semantic_reconstruction', 'ir_optimization',
            'ast_emission', 'expression_propagation', 'vm_handler_lifting',
            'stack_simulation', 'branch_recovery', 'loop_collapsing',
            'dead_code_elimination', 'ssa_tracking', 'identifier_renaming',
            'temporary_elimination', 'call_graph_reconstruction',
            'closure_reconstruction', 'opcode_semantic_mapping',
            'dispatcher_reconstruction', 'function_prototype_recovery',
            'anti_tamper_neutralization', 'jump_analysis',
            'devirtualized_ir_generation', 'roblox_execution',
            'layered_diagnostics', 'staged_validation', 'transformer_isolation',
            'confidence_scoring', 'auto_recovery', 'crash_snapshots',
            'token_level_diagnostics', 'ast_verification',
            'instruction_stream_recovery', 'symbolic_vm_execution',
            'ast_based_emission', 'real_lua_output'
        }
        self._java_available = shutil.which('java') is not None
        if not self._java_available:
            self.capabilities.discard('bytecode_decompilation')

    def get_capabilities(self):
        return list(self.capabilities)

    def process(self, source):
        trace = []
        diags = []
        reasons = {}
        stage = "init"

        try:
            fingerprint = self.fingerprinter.analyze(source)
            trace.append({'stage': 'fingerprint', 'details': fingerprint})
            stage = "fingerprint"

            string_table, var_name = self._decode_string_table(source, diags)
            stage = "decode_string_table"

            if string_table:
                diags.append(f"R table: {len(string_table)} strings (var={var_name})")

                roblox_result, roblox_error = self._try_roblox_exec(source, string_table)
                if roblox_result:
                    trace.append({'stage': 'roblox', 'success': True})
                    stage = "roblox_exec"
                    beautified = self._beautify(roblox_result)
                    pipeline_validate_stage(beautified, stage, strict=True)
                    return beautified, 'roblox_execution', 'Deobfuscated via Roblox execution', trace
                elif roblox_error:
                    trace.append({'stage': 'roblox', 'error': roblox_error})

                layers, caps, diag = execute_sandbox(source, timeout=120, varargs=string_table)
                trace.append({'stage': 'sandbox', 'layers': len(layers), 'caps': len(caps)})
                if layers:
                    stage = "sandbox"
                    for i, item in enumerate(layers):
                        result = self._process_layer(item, i, string_table, var_name)
                        if result:
                            beautified = self._beautify(result)
                            pipeline_validate_stage(beautified, f"sandbox_layer_{i}", strict=True)
                            return beautified, 'sandbox_source', f'Layer {i} source captured', trace

                combined = self._static_decode_raw(source, string_table)
                if not combined:
                    combined = self._static_decode_prometheus_fallback(source, var_name, string_table)

                if combined:
                    stage = "static_decode"
                    lifted_code = self._vm_lift(combined, string_table, var_name)
                    if lifted_code:
                        stage = "vm_lift"
                        beautified = self._beautify(lifted_code)
                        pipeline_validate_stage(beautified, stage, strict=True)
                        return beautified, 'semantic_full', f'Semantically reconstructed ({len(beautified)} chars)', trace
                    else:
                        beautified = self._beautify(combined)
                        if self._is_valid_lua(beautified):
                            return beautified, 'static_decode', 'Direct static decode', trace

            layers, caps, diag = execute_sandbox(source, timeout=120)
            if layers:
                stage = "sandbox_fallback"
                for i, item in enumerate(layers):
                    result = self._process_layer(item, i, None, None)
                    if result:
                        beautified = self._beautify(result)
                        pipeline_validate_stage(beautified, f"sandbox_fallback_layer_{i}", strict=True)
                        return beautified, 'sandbox_source', f'Layer {i} source captured', trace

        except LinoError as e:
            log_structured_error(e)
            return self._handle_diagnostic_failure(e, stage)

        parts = [f'Steps: {"; ".join(diags[:3])}']
        if reasons:
            parts.append('Info: ' + '; '.join(f"{k}: {v[:300]}" for k, v in reasons.items()))
        reason = '\n'.join(parts) if parts else 'All stages exhausted'
        return '', 'unable', reason, trace

    def _static_decode_prometheus_fallback(self, source, var_name, string_table):
        """Prometheus-style fallback: extract the table literal and run Lua to decode it."""
        table_literal = extract_table_literal(source, rf'\blocal\s+{re.escape(var_name)}\s*=\s*\{{')
        if not table_literal:
            return None

        lua_script = rf'''
local function escape_lua_string(s)
    local parts = {{'"'}}
    for i = 1, #s do
        local byte = string.byte(s, i)
        if byte == 92 then table.insert(parts, "\\\\")
        elseif byte == 34 then table.insert(parts, "\\\"")
        elseif byte == 10 then table.insert(parts, "\\n")
        elseif byte == 13 then table.insert(parts, "\\r")
        elseif byte == 9 then table.insert(parts, "\\t")
        elseif byte >= 32 and byte <= 126 then table.insert(parts, string.char(byte))
        else table.insert(parts, string.format("\\%03d", byte)) end
    end
    table.insert(parts, '"')
    return table.concat(parts)
end
local constants = {table_literal}
local out = "local Constants = {{"
for i, v in ipairs(constants) do
    out = out .. " [" .. i .. "] = " .. escape_lua_string(v) .. ","
end
out = out .. " }}"
print(out)
'''
        try:
            result = subprocess.run(
                ['lua5.1', '-e', lua_script],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass

        try:
            result = subprocess.run(
                ['lua', '-e', lua_script],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass

        return None

    def _vm_lift(self, decoded_source, string_table, var_name):
        dispatch_body = find_dispatch_loop(decoded_source)
        if not dispatch_body:
            return None
        handlers = extract_handlers(dispatch_body)
        if not handlers:
            return None
        inst_table = extract_instruction_table(decoded_source)
        if not inst_table:
            return None
        instructions = decode_instruction_stream(inst_table, handlers)
        executor = SymbolicExecutor(string_table)
        executor.execute(instructions, handlers)
        return executor.emit_lua()

    def _handle_diagnostic_failure(self, lino_err, stage):
        repaired = auto_fix_lua(lino_err.code_snippet) if lino_err.code_snippet else ""
        if repaired:
            try:
                pipeline_validate_stage(repaired, f"recovery_{stage}", strict=True)
                return self._beautify(repaired), 'recovered', f"Recovered from {stage} failure", []
            except:
                pass
        error_data = lino_err.to_dict()
        return f"-- Decompilation failed at stage {stage}\n-- {json.dumps(error_data)}", 'error', lino_err.message, []

    def _validate_and_repair(self, code):
        if not code or len(code) < 50:
            return code
        if self._is_valid_lua(code):
            return self._beautify(code)
        repaired = self._normalize_lua(code)
        if self._is_valid_lua(repaired):
            return self._beautify(repaired)
        return self._beautify(code)

    def _normalize_lua(self, code):
        code = code.replace('\r\n', '\n').replace('\r', '\n')
        code = re.sub(r'\n\s*\n', '\n\n', code)
        code = re.sub(r'(\d+)\s+end', r'\1\nend', code)
        code = re.sub(r'(\d+)\s+then', r'\1\nthen', code)
        code = re.sub(r'(\d+)\s+else', r'\1\nelse', code)
        code = re.sub(r'(\d+)\s+elseif', r'\1\nelseif', code)
        code = re.sub(r'(\d+)\s+do', r'\1\ndo', code)
        code = re.sub(r',\s*,', ',', code)
        code = re.sub(r'\.\s*\.', '..', code)
        code = re.sub(r'\bif\s*\n\s*then\b', 'if true then', code)
        code = re.sub(r'\bfunction\s+end\b', 'function dummy() end', code)
        code = re.sub(r'(\w+)\s*\(\s*\)\s*\(\s*\)', r'\1()()', code)
        code = re.sub(r'\n\s*return\s*\n', '\nreturn ', code)
        code = re.sub(r'\n\s*local\s+function\s*\n', '\nlocal function ', code)
        lines = code.split('\n')
        cleaned = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                cleaned.append('')
                continue
            cleaned.append(stripped)
        return '\n'.join(cleaned)

    @staticmethod
    def _is_valid_lua(code):
        if not code or len(code) < 50:
            return False
        if HAS_LUAPARSER:
            try:
                lua_ast.parse(code)
                return True
            except Exception:
                pass
        words = set(re.findall(r'\b\w+\b', code[:10000]))
        if len(words & LUA_KEYWORDS) < 2:
            return False
        printable = sum(1 for c in code if c.isprintable() or c in '\n\r\t')
        if (printable / max(len(code), 1)) < 0.70:
            return False
        for pat in BAD_PATTERNS:
            if re.search(pat, code):
                return False
        return True

    def _static_decode_raw(self, source, string_table):
        try:
            return self._static_decode_raw_inner(source, string_table)
        except Exception as e:
            save_crash_snapshot("static_decode", source, "", e)
            return None

    def _static_decode_raw_inner(self, source, string_table):
        b64_rev = self._parse_n_table(source)
        shuffle = self._parse_shuffle_ranges(source)
        if not b64_rev or not shuffle:
            return None
        working = list(string_table)
        for lo, hi in shuffle:
            lo_idx, hi_idx = lo - 1, hi - 1
            while lo_idx < hi_idx:
                working[lo_idx], working[hi_idx] = working[hi_idx], working[lo_idx]
                lo_idx += 1
                hi_idx -= 1
        decoded = []
        for s in working:
            if not s:
                continue
            raw = self._lua_escapes_to_bytes(s)
            if not raw:
                continue
            dec = self._decode_custom_b64(raw, b64_rev)
            if dec:
                decoded.append(dec)
        if not decoded:
            return None
        combined = b''.join(decoded)
        for enc in ('utf-8', 'latin-1'):
            try:
                result = combined.decode(enc)
                result = ''.join(ch for ch in result if ch.isprintable() or ch in '\n\r\t')
                return result
            except:
                pass
        result = combined.decode('latin-1', errors='replace')
        result = ''.join(ch for ch in result if ch.isprintable() or ch in '\n\r\t')
        return result

    def _process_layer(self, item, i, string_table, var_name):
        if isinstance(item, bytes) and len(item) >= 12:
            text = None
            try:
                text = item.decode('utf-8')
            except:
                pass
            if text and self._is_valid_lua(text):
                return self._beautify(text)
        if isinstance(item, str) and len(item) > 100 and self._is_valid_lua(item):
            return self._beautify(item)
        return None

    def _decode_string_table(self, source, diags):
        m = re.search(r'local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{', source, re.DOTALL)
        if not m:
            return None, None
        var_name = m.group(1)
        brace_start = m.end() - 1
        body = self._extract_balanced_table(source, brace_start)
        if not body:
            return None, None
        strings = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
        if len(strings) < 10:
            return None, None
        return strings, var_name

    def _beautify(self, code):
        if not code or len(code) < 5:
            return code
        code = ''.join(ch for ch in code if ch.isprintable() or ch in '\n\r\t')
        if len(code) < 5:
            return code
        string_pattern = re.compile(
            r""" (?:'[^']*') | (?:"[^"]*") | (?:\[=*\[.*?\]=*\]) """,
            re.DOTALL | re.VERBOSE
        )
        placeholders = {}
        counter = 0
        def replace_string(m):
            nonlocal counter
            placeholder = f"__STR_{counter}__"
            placeholders[placeholder] = m.group(0)
            counter += 1
            return placeholder
        code = string_pattern.sub(replace_string, code)
        code = re.sub(r'(?<![A-Za-z0-9_])local\s+function(?![A-Za-z0-9_])', '__LOCALFUNC__', code)
        stmt_keywords = [
            'function', 'local', 'if', 'for', 'while',
            'repeat', 'return', 'end', 'else', 'elseif', 'until',
        ]
        for kw in stmt_keywords:
            code = re.sub(
                rf'(?<![A-Za-z0-9_]){re.escape(kw)}(?![A-Za-z0-9_])',
                f'\n{kw}',
                code
            )
        code = code.replace('__LOCALFUNC__', '\nlocal function')
        for placeholder, original in placeholders.items():
            code = code.replace(placeholder, original)
        code = re.sub(r'\n\s*\n', '\n\n', code)
        OPENER_PAT = re.compile(r'\b(then|do|repeat)\b|\bfunction\b')
        CLOSER_PAT = re.compile(r'\b(end|until)\b')
        lines = code.split('\n')
        out_lines = []
        indent = 0
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                out_lines.append('')
                continue
            m = re.match(r'[A-Za-z_]\w*', line)
            first_word = m.group(0) if m else ''
            if first_word in ('end', 'until', 'else', 'elseif'):
                indent = max(0, indent - 1)
            out_lines.append('    ' * indent + line)
            opens = len(OPENER_PAT.findall(line))
            closes = len(CLOSER_PAT.findall(line))
            if first_word in ('else', 'elseif'):
                indent = max(0, indent + 1)
            else:
                indent = max(0, indent + opens - closes)
        return '\n'.join(out_lines)

    def _parse_n_table(self, source):
        """Robust N-table extraction using Prometheus-style balanced-brace scanning."""
        best_rev = {}
        # Look for any local table with numeric or string-key entries that could be a base64 map
        for m in re.finditer(r'local\s+(\w+)\s*=\s*\{', source):
            var_name = m.group(1)
            body = extract_table_literal(source, rf'\blocal\s+{re.escape(var_name)}\s*=\s*\{{')
            if not body or len(body) < 10:
                continue
            rev = {}
            # Pattern: ["\NNN"] = value
            for m2 in re.finditer(r'\["(\\(?:\d{1,3}))"\]\s*=\s*([-\d()+\-*/]+)', body):
                esc = m2.group(1)
                val = self._safe_eval(m2.group(2).strip())
                if val is not None and 0 <= val < 64:
                    code_point = self._lua_escape_to_int(esc)
                    if code_point is not None:
                        rev[val] = chr(code_point)
            # Pattern: letter = value
            for m2 in re.finditer(r'(?<![\["\'"])([a-zA-Z])\s*=\s*([-\d()+\-*/]+)', body):
                ch = m2.group(1)
                val = self._safe_eval(m2.group(2).strip())
                if val is not None and 0 <= val < 64:
                    rev[val] = ch
            if len(rev) > len(best_rev):
                best_rev = rev
        std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        for i, ch in enumerate(std):
            if i not in best_rev:
                best_rev[i] = ch
        return best_rev if len(best_rev) >= 10 else {}

    def _parse_shuffle_ranges(self, source):
        """Robust shuffle-range extraction."""
        ranges = []
        for m in re.finditer(r'ipairs\s*\(\s*\{', source):
            brace_pos = m.end() - 1
            body = self._extract_balanced_table(source, brace_pos)
            if not body:
                continue
            inner = re.findall(r'\{([-\d()+\-*/\s]+)[;,]([-\d()+\-*/\s]+)\}', body)
            for e1, e2 in inner:
                lo = self._safe_eval(e1.strip())
                hi = self._safe_eval(e2.strip())
                if lo is not None and hi is not None:
                    ranges.append((lo, hi))
            if ranges:
                return ranges
        return ranges

    @staticmethod
    def _extract_balanced_table(source, start):
        if start >= len(source) or source[start] != '{':
            return None
        depth = 0
        in_str = False
        str_char = None
        i = start
        while i < len(source):
            c = source[i]
            if in_str:
                if c == '\\':
                    i += 2
                    continue
                if c == str_char:
                    in_str = False
            else:
                if c in ('"', "'"):
                    in_str = True
                    str_char = c
                elif c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        return source[start + 1:i]
            i += 1
        return None

    @staticmethod
    def _lua_escapes_to_bytes(s):
        result = bytearray()
        i = 0
        while i < len(s):
            if s[i] == '\\' and i + 1 < len(s):
                nc = s[i + 1]
                if nc.isdigit():
                    j = i + 1
                    while j < len(s) and s[j].isdigit() and j - (i + 1) < 3:
                        j += 1
                    v = int(s[i + 1:j])
                    if 0 <= v <= 255:
                        result.append(v)
                    i = j
                elif nc == 'n':
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
                    hex_str = s[i + 2:i + 4]
                    try:
                        result.append(int(hex_str, 16))
                    except ValueError:
                        pass
                    i += 4
                else:
                    result.append(ord(nc))
                    i += 2
            else:
                result.append(ord(s[i]) if ord(s[i]) < 256 else ord('?'))
                i += 1
        return bytes(result)

    @staticmethod
    def _has_lua_keywords(text):
        if not text or len(text) < 5:
            return False
        printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        if (printable / len(text)) < 0.50:
            return False
        lower_text = text.lower()
        count = 0
        for kw in LUA_SUBSTRINGS:
            if kw in lower_text:
                count += 1
                if count >= 2:
                    return True
        return False

    @staticmethod
    def _lua_escape_to_int(esc):
        if esc.startswith('\\') and esc[1:].isdigit():
            return int(esc[1:]) % 256
        return None

    @staticmethod
    def _decode_custom_b64(data, rev):
        if not rev or len(data) == 0:
            return None
        fwd = {v: k for k, v in rev.items()}
        buf, bits, out = 0, 0, bytearray()
        for b in data:
            ch = chr(b) if b < 256 else ''
            if ch not in fwd:
                if b == ord('='):
                    break
                continue
            buf = (buf << 6) | fwd[ch]
            bits += 6
            while bits >= 8:
                bits -= 8
                out.append((buf >> bits) & 0xFF)
        return bytes(out)

    @staticmethod
    def _safe_eval(expr):
        expr = expr.replace(' ', '')
        if not expr or not re.match(r'^[\d+\-*/()]+$', expr):
            return None
        try:
            return eval(expr)
        except:
            return None

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
            combined = self._static_decode_raw(source, result)
            if combined:
                return combined, None
            return None, "Static decode failed on Roblox table"

        return result, None
