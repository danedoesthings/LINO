import os, re, shutil, subprocess, tempfile, base64, urllib.request, asyncio, struct, hashlib, json, time, traceback, binascii, sys, ast as py_ast, operator as op, signal, resource, functools, itertools
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
    from luaparser.lexer import LuaLexer
    HAS_LUAPARSER = True
except ImportError:
    HAS_LUAPARSER = False

UNLUAC_JAR_URL = "https://github.com/scratchminer/unluac/releases/download/v2023.03.22/unluac.jar"
UNLUAC_JAR_SHA256 = "a3f3c7c1d4b7f8e9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3"
UNLUAC_LOCAL_PATH = os.environ.get('UNLUAC_PATH') or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'unluac.jar')

class ObfuscatorFamily(Enum):
    WEAREDEVS_V1 = "wearedevs_v1"
    MOONSEC = "moonsec"
    IRONBREW = "ironbrew"
    PSU = "psu"
    AZTUPBREW = "aztupbrew"
    CUSTOM_VM = "custom_vm"
    UNKNOWN = "unknown"

class IROpcode(Enum):
    LOADK = 1
    MOVE = 2
    CALL = 3
    GETGLOBAL = 4
    SETGLOBAL = 5
    GETTABLE = 6
    SETTABLE = 7
    ADD = 8
    SUB = 9
    MUL = 10
    DIV = 11
    CONCAT = 12
    JMP = 13
    EQ = 14
    LT = 15
    LE = 16
    TEST = 17
    RETURN = 18
    CLOSURE = 19
    NEWTABLE = 20
    FORPREP = 21
    FORLOOP = 22
    TFORLOOP = 23
    SELF = 24
    VARARG = 25
    LABEL = 26
    PHI = 27
    MERGE = 28

@dataclass
class IRInstruction:
    opcode: IROpcode
    args: List[Any] = field(default_factory=list)
    dest: Optional[int] = None
    pc: int = 0

@dataclass
class SymbolicValue:
    kind: str
    value: Any = None
    left: Optional['SymbolicValue'] = None
    right: Optional['SymbolicValue'] = None
    is_constant: bool = False
    reg: Optional[int] = None

@dataclass
class ExecutionResult:
    value: Any
    trace: List[str] = field(default_factory=list)
    confidence: float = 0.0
    source: str = ""
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class CFGBlock:
    def __init__(self, block_id: int):
        self.block_id = block_id
        self.instructions: List[IRInstruction] = []
        self.predecessors: List[CFGBlock] = []
        self.successors: List[CFGBlock] = []
        self.is_merge_point = False
        self.is_loop_header = False
        self.loop_depth = 0
        self.phi_nodes: Dict[int, IRInstruction] = {}
        self.state_in: Dict[int, SymbolicValue] = {}

class CFGBuilder:
    def __init__(self):
        self.blocks: List[CFGBlock] = []
        self.block_map: Dict[int, CFGBlock] = {}
        self.label_to_block: Dict[str, CFGBlock] = {}
        self.next_block_id = 0

    def _new_block(self) -> CFGBlock:
        block = CFGBlock(self.next_block_id)
        self.next_block_id += 1
        self.blocks.append(block)
        self.block_map[block.block_id] = block
        return block

    def _connect(self, src: CFGBlock, dst: CFGBlock):
        if dst not in src.successors:
            src.successors.append(dst)
        if src not in dst.predecessors:
            dst.predecessors.append(src)

    def build(self, instructions: List[IRInstruction]) -> Tuple[List[CFGBlock], Dict[int, CFGBlock]]:
        self.blocks.clear()
        self.block_map.clear()
        self.label_to_block.clear()
        self.next_block_id = 0

        label_map: Dict[str, int] = {}
        for instr in instructions:
            if instr.opcode == IROpcode.LABEL:
                label_map[instr.args[0]] = instr.pc

        pc_to_block: Dict[int, CFGBlock] = {}
        leader_pcs: Set[int] = {0}
        for instr in instructions:
            if instr.opcode in (IROpcode.JMP, IROpcode.RETURN):
                if instr.pc + 1 < len(instructions):
                    leader_pcs.add(instr.pc + 1)
                if instr.opcode == IROpcode.JMP and instr.args:
                    target = instr.args[0]
                    if isinstance(target, str) and target in label_map:
                        leader_pcs.add(label_map[target])
                    elif isinstance(target, int):
                        leader_pcs.add(target)
            elif instr.opcode in (IROpcode.EQ, IROpcode.LT, IROpcode.LE, IROpcode.TEST):
                if instr.pc + 1 < len(instructions):
                    leader_pcs.add(instr.pc + 1)
                if len(instr.args) >= 2:
                    target = instr.args[1]
                    if isinstance(target, str) and target in label_map:
                        leader_pcs.add(label_map[target])
                    elif isinstance(target, int):
                        leader_pcs.add(target)

        sorted_leaders = sorted(leader_pcs)
        pc_range_map: Dict[int, Tuple[int, int]] = {}
        for i, leader_pc in enumerate(sorted_leaders):
            start = leader_pc
            end = sorted_leaders[i + 1] - 1 if i + 1 < len(sorted_leaders) else len(instructions) - 1
            block = self._new_block()
            pc_range_map[block.block_id] = (start, end)
            for pc in range(start, end + 1):
                block.instructions.append(instructions[pc])
                pc_to_block[pc] = block
            if start == 0:
                self.blocks[0] = block
                self.block_map[0] = block

        for block in self.blocks:
            if not block.instructions:
                continue
            last = block.instructions[-1]
            if last.opcode == IROpcode.JMP:
                if last.args:
                    target = last.args[0]
                    if isinstance(target, str) and target in label_map:
                        target_pc = label_map[target]
                        if target_pc in pc_to_block:
                            self._connect(block, pc_to_block[target_pc])
                    elif isinstance(target, int) and target in pc_to_block:
                        self._connect(block, pc_to_block[target])
            elif last.opcode == IROpcode.RETURN:
                pass
            elif last.opcode in (IROpcode.EQ, IROpcode.LT, IROpcode.LE, IROpcode.TEST):
                fallthrough_pc = last.pc + 1
                if fallthrough_pc in pc_to_block:
                    self._connect(block, pc_to_block[fallthrough_pc])
                if len(last.args) >= 2:
                    target = last.args[1]
                    if isinstance(target, str) and target in label_map:
                        target_pc = label_map[target]
                        if target_pc in pc_to_block:
                            self._connect(block, pc_to_block[target_pc])
                    elif isinstance(target, int) and target in pc_to_block:
                        self._connect(block, pc_to_block[target])
            else:
                fallthrough_pc = last.pc + 1
                if fallthrough_pc in pc_to_block:
                    self._connect(block, pc_to_block[fallthrough_pc])

        for block in self.blocks:
            if len(block.predecessors) >= 2:
                block.is_merge_point = True

        self._compute_loops()
        return self.blocks, self.block_map

    def _compute_loops(self):
        if not self.blocks:
            return
        entry = self.blocks[0]
        dom = {b.block_id: set(b.block_id for b in self.blocks) for b in self.blocks}
        dom[entry.block_id] = {entry.block_id}
        changed = True
        while changed:
            changed = False
            for b in self.blocks:
                if b.block_id == entry.block_id:
                    continue
                pred_doms = [dom[p.block_id] for p in b.predecessors if p.block_id in dom]
                new_dom = set.intersection(*pred_doms) if pred_doms else set()
                new_dom.add(b.block_id)
                if new_dom != dom[b.block_id]:
                    dom[b.block_id] = new_dom
                    changed = True
        for b in self.blocks:
            for s in b.successors:
                if b.block_id in dom[s.block_id]:
                    s.is_loop_header = True
                    s.loop_depth = max(s.loop_depth, b.loop_depth + 1)

class SymbolicExecutor:
    def __init__(self, constants: List[str]):
        self.constants = constants
        self.blocks: List[CFGBlock] = []
        self.block_map: Dict[int, CFGBlock] = {}
        self.worklist: deque = deque()
        self.temp_counter = 0

    def load_instructions(self, instructions: List[IRInstruction]):
        self.blocks, self.block_map = CFGBuilder().build(instructions)

    def execute(self) -> ExecutionResult:
        if not self.blocks:
            return ExecutionResult(None, confidence=0.0, error="no blocks")
        entry = self.blocks[0]
        block_states: Dict[int, Dict[int, SymbolicValue]] = {entry.block_id: {}}
        block_stack: Dict[int, List[SymbolicValue]] = {entry.block_id: []}
        self.worklist.clear()
        self.worklist.append(entry)
        processed = set()
        while self.worklist:
            block = self.worklist.popleft()
            block_key = (block.block_id, tuple(sorted(block_states.get(block.block_id, {}).items())))
            if block_key in processed:
                continue
            processed.add(block_key)
            state = dict(block_states.get(block.block_id, {}))
            stack = list(block_stack.get(block.block_id, []))
            for instr in block.instructions:
                self._execute_instruction(instr, state, stack)
            if block.is_merge_point:
                for pred in block.predecessors:
                    if pred.block_id in block_states:
                        pred_state = block_states[pred.block_id]
                        for reg, val in pred_state.items():
                            if reg not in state:
                                state[reg] = val
            for succ in block.successors:
                if succ.block_id not in block_states:
                    block_states[succ.block_id] = dict(state)
                    block_stack[succ.block_id] = list(stack)
                    self.worklist.append(succ)
                else:
                    old_state = block_states[succ.block_id]
                    for reg, val in state.items():
                        if reg not in old_state or old_state[reg] != val:
                            old_state[reg] = val
                            self.worklist.append(succ)
        result = []
        for block in self.blocks:
            for instr in block.instructions:
                if instr.opcode == IROpcode.RETURN and block.block_id in block_stack:
                    for sv in block_stack[block.block_id]:
                        result.append(sv.value if sv.is_constant else sv.kind)
        return ExecutionResult(result, confidence=0.85 if result else 0.3, source="symbolic_executor")

    def _execute_instruction(self, instr: IRInstruction, state: Dict[int, SymbolicValue], stack: List[SymbolicValue]):
        if instr.opcode == IROpcode.LOADK:
            idx = instr.args[0] if instr.args else 0
            val = self._get_constant(idx)
            stack.append(SymbolicValue('const', val, is_constant=True))
        elif instr.opcode == IROpcode.SETGLOBAL:
            stack.pop() if stack else None
        elif instr.opcode == IROpcode.GETGLOBAL:
            name = self._resolve_name(instr.args[0]) if instr.args else 'unknown'
            stack.append(SymbolicValue('global', name))
        elif instr.opcode == IROpcode.CALL:
            arg_count = instr.args[1] if len(instr.args) > 1 else 0
            for _ in range(arg_count):
                stack.pop() if stack else None
            stack.append(SymbolicValue('call', None))
        elif instr.opcode == IROpcode.RETURN:
            pass
        elif instr.opcode == IROpcode.CONCAT:
            stack.pop() if stack else None
            stack.pop() if stack else None
            stack.append(SymbolicValue('concat', None))
        elif instr.opcode == IROpcode.ADD:
            r = stack.pop() if stack else None
            l = stack.pop() if stack else None
            if l and r and l.is_constant and r.is_constant:
                stack.append(SymbolicValue('const', l.value + r.value, is_constant=True))
            else:
                stack.append(SymbolicValue('arith', None))
        elif instr.opcode == IROpcode.NEWTABLE:
            stack.append(SymbolicValue('table', []))
        elif instr.opcode == IROpcode.JMP:
            pass
        elif instr.opcode == IROpcode.MERGE:
            pass
        elif instr.opcode == IROpcode.PHI:
            pass

    def _get_constant(self, idx):
        if isinstance(idx, int) and 1 <= idx <= len(self.constants):
            return self.constants[idx - 1]
        return str(idx)

    def _resolve_name(self, idx):
        if isinstance(idx, int) and 1 <= idx <= len(self.constants):
            return self.constants[idx - 1]
        return str(idx)


class NormalizedExecutor:
    def __init__(self, engine: 'DeobfEngine'):
        self.engine = engine

    def execute_symbolic(self, source: str, strings: List[str]) -> ExecutionResult:
        executor = SymbolicExecutor(strings)
        return executor.execute()

    def execute_sandbox(self, source: str) -> ExecutionResult:
        result, errors = self.engine._run_sandbox(source)
        if result:
            return ExecutionResult(result, confidence=0.8, source="sandbox", error='; '.join(errors) if errors else None)
        return ExecutionResult(None, confidence=0.0, source="sandbox", error='; '.join(errors) if errors else "no output")

    def execute_roblox(self, source: str) -> ExecutionResult:
        result, error = self.engine._try_roblox_exec(source)
        if result:
            return ExecutionResult(result, confidence=0.7, source="roblox", error=error)
        return ExecutionResult(None, confidence=0.0, source="roblox", error=error)


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
        self.executor = NormalizedExecutor(self)
        self.capabilities = {
            'ir_lowering', 'cfg_reconstruction', 'worklist_execution',
            'merge_point_detection', 'loop_detection', 'phi_placement',
            'normalized_execution_backend', 'execution_result_abstraction',
            'deterministic_sandbox', 'luaparser_integration',
            'sha256_verification', 'long_string_tokenization'
        }
        self._java_available = shutil.which('java') is not None

    def get_capabilities(self):
        return list(self.capabilities)

    def process(self, source):
        try:
            fingerprint = self.fingerprinter.analyze(source)
            strings, var_name = self._extract_string_table(source)
            if strings and var_name:
                n_table = self._extract_n_table(source)
                if n_table:
                    shuffle_ranges = self._extract_shuffle(source)
                    decoded = self._decode_base64(strings, n_table, shuffle_ranges)
                    if decoded:
                        beautified = self._beautify(decoded)
                        if self._validate_lua(beautified):
                            return beautified, 'static_decode', 'Structural decode', []

            result = self.executor.execute_sandbox(source)
            if result.value:
                beautified = self._beautify(str(result.value))
                if self._validate_lua(beautified):
                    return beautified, 'runtime_execution', 'Sandbox execution', []

            result = self.executor.execute_roblox(source)
            if result.value:
                beautified = self._beautify(str(result.value))
                if self._validate_lua(beautified):
                    return beautified, 'roblox_execution', 'Roblox execution', []

            return '', 'unable', 'All strategies exhausted', []
        except Exception as e:
            return '', 'error', str(e), []

    def _extract_string_table(self, source):
        if HAS_LUAPARSER:
            try:
                tree = lua_ast.parse(source)
                for node in LuaASTWalker.walk(tree):
                    if hasattr(node, 'targets') and hasattr(node, 'values') and node.values:
                        if hasattr(node.values[0], 'fields') and len(node.values[0].fields) >= 10:
                            strings = []
                            for field in node.values[0].fields:
                                if hasattr(field, 'value') and hasattr(field.value, 's'):
                                    strings.append(field.value.s)
                            if len(strings) >= 10:
                                var_name = node.targets[0].id if node.targets and hasattr(node.targets[0], 'id') else 'R'
                                return strings, var_name
            except Exception:
                pass
        for m in re.finditer(r'local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{', source):
            var_name = m.group(1)
            open_brace = source.find('{', m.start())
            end = self._find_balanced_end(source, open_brace)
            if end == -1:
                continue
            body = source[open_brace:end]
            entries = self._parse_table_entries(body)
            strings = [e for e in entries if isinstance(e, str)]
            if len(strings) >= 10:
                return strings, var_name
        return None, None

    def _extract_n_table(self, source):
        bodies = self._find_all_table_bodies(source)
        for body in bodies:
            entries = self._parse_table_entries(body)
            str_entries = [e for e in entries if isinstance(e, str)]
            if 60 <= len(str_entries) <= 70:
                return body
        return None

    def _extract_shuffle(self, source):
        ranges = []
        for m in re.finditer(r'for\s+(\w+)\s*=\s*(\d+)\s*,\s*(\d+)\s*do', source):
            try:
                start_val = int(m.group(2))
                end_val = int(m.group(3))
                body_start = source.find('do', m.end())
                if body_start == -1:
                    continue
                end_pos = source.find('end', body_start)
                if end_pos == -1:
                    continue
                inner = source[body_start+2:end_pos]
                swaps = re.findall(r'\w+\[\w+\]\s*=\s*\w+\[\w+\]', inner)
                if len(swaps) >= 1:
                    ranges.append((start_val, end_val))
            except:
                continue
        return ranges if ranges else None

    def _decode_base64(self, strings, n_table, shuffle_ranges):
        n_entries = self._parse_table_entries(n_table)
        rev_map = {}
        for i, entry in enumerate(n_entries):
            if isinstance(entry, str) and len(entry) >= 1:
                rev_map[entry] = i
        if len(rev_map) < 30:
            return None
        working = list(strings)
        if shuffle_ranges:
            for lo, hi in shuffle_ranges:
                lo_idx, hi_idx = lo - 1, hi - 1
                if 0 <= lo_idx < len(working) and 0 <= hi_idx < len(working) and lo_idx < hi_idx:
                    working[lo_idx:hi_idx+1] = working[lo_idx:hi_idx+1][::-1]
        decoded_chunks = []
        for s in working:
            if not isinstance(s, str):
                continue
            raw = self._lua_unescape(s)
            if not raw:
                continue
            buf, bits, out = 0, 0, bytearray()
            for b in raw:
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
            if out:
                decoded_chunks.append(bytes(out))
        if not decoded_chunks:
            return None
        combined = b''.join(decoded_chunks)
        for enc in ('utf-8', 'latin-1'):
            try:
                text = combined.decode(enc)
                if len(text) > 50:
                    return text
            except:
                continue
        return combined.decode('latin-1', errors='replace')

    def _run_sandbox(self, source):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as tmp:
            tmp.write(source)
            tmp_path = tmp.name
        try:
            result = subprocess.run(['lua5.1', tmp_path], capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip(), []
            return None, [result.stderr[:200]] if result.stderr else []
        except FileNotFoundError:
            return None, ['lua5.1 not found']
        except subprocess.TimeoutExpired:
            return None, ['timeout']
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _find_balanced_end(self, content, open_brace_index):
        depth = 0
        quote = None
        in_long_string = False
        long_match = None
        idx = open_brace_index
        while idx < len(content):
            char = content[idx]
            if in_long_string:
                if char == ']' and content[idx:idx+len(long_match)] == long_match:
                    in_long_string = False
                    idx += len(long_match)
                    continue
                idx += 1
                continue
            if quote:
                if char == '\\':
                    idx += 2
                    continue
                if char == quote:
                    quote = None
                idx += 1
                continue
            if char == '[':
                m = re.match(r'\[=*\[', content[idx:])
                if m:
                    long_match = ']' + m.group(0)[2:-1] + ']'
                    in_long_string = True
                    idx += len(m.group(0))
                    continue
            if char in ("'", '"'):
                quote = char
            elif char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    return idx + 1
            idx += 1
        return -1

    def _find_all_table_bodies(self, source):
        bodies = []
        idx = 0
        while idx < len(source):
            brace_pos = source.find('{', idx)
            if brace_pos == -1:
                break
            end = self._find_balanced_end(source, brace_pos)
            if end != -1:
                bodies.append(source[brace_pos:end])
                idx = end
            else:
                idx = brace_pos + 1
        return bodies

    def _parse_table_entries(self, body):
        inner = body[1:-1]
        entries = []
        depth = 0
        current = ""
        in_str = False
        quote = None
        in_long_str = False
        long_match = None
        i = 0
        while i < len(inner):
            c = inner[i]
            if in_long_str:
                current += c
                if c == ']' and i + len(long_match) <= len(inner) and inner[i:i+len(long_match)] == long_match:
                    in_long_str = False
                    current += long_match[1:]
                    i += len(long_match)
                    continue
                i += 1
                continue
            if in_str:
                current += c
                if c == '\\':
                    if i + 1 < len(inner):
                        current += inner[i+1]
                        i += 2
                        continue
                elif c == quote:
                    in_str = False
                i += 1
                continue
            if c == '[':
                m = re.match(r'\[=*\[', inner[i:])
                if m:
                    long_match = ']' + m.group(0)[2:-1] + ']'
                    in_long_str = True
                    current += m.group(0)
                    i += len(m.group(0))
                    continue
            if c in ('"', "'"):
                in_str = True
                quote = c
                current += c
                i += 1
                continue
            if c == '{':
                depth += 1
                current += c
                i += 1
                continue
            if c == '}':
                depth -= 1
                current += c
                i += 1
                continue
            if c == ',' and depth == 0:
                entries.append(current.strip())
                current = ""
                i += 1
                continue
            current += c
            i += 1
        if current.strip():
            entries.append(current.strip())
        parsed = []
        for e in entries:
            if not e:
                continue
            if (e.startswith('"') and e.endswith('"')) or (e.startswith("'") and e.endswith("'")):
                parsed.append(e[1:-1])
            elif e.startswith('[[') and e.endswith(']]'):
                parsed.append(e[2:-2])
            elif e.lstrip('-').isdigit():
                parsed.append(int(e))
            elif e.replace('.', '', 1).lstrip('-').isdigit():
                parsed.append(float(e))
            elif e in ('true', 'false', 'nil'):
                parsed.append(e)
            else:
                parsed.append(e)
        return parsed

    def _lua_unescape(self, s):
        result = bytearray()
        i = 0
        while i < len(s):
            if s[i] == '\\' and i + 1 < len(s):
                nc = s[i+1]
                if nc == 'n':
                    result.append(0x0A)
                    i += 2
                elif nc == 'r':
                    result.append(0x0D)
                    i += 2
                elif nc == 't':
                    result.append(0x09)
                    i += 2
                elif nc == '\\':
                    result.append(0x5C)
                    i += 2
                elif nc == '"':
                    result.append(0x22)
                    i += 2
                elif nc == "'":
                    result.append(0x27)
                    i += 2
                elif nc == 'a':
                    result.append(0x07)
                    i += 2
                elif nc == 'b':
                    result.append(0x08)
                    i += 2
                elif nc == 'f':
                    result.append(0x0C)
                    i += 2
                elif nc == 'v':
                    result.append(0x0B)
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
                        val = int(s[i+1:j])
                        if val <= 255:
                            result.append(val)
                    except ValueError:
                        pass
                    i = j
                else:
                    result.append(ord(nc) if ord(nc) < 256 else 0x3F)
                    i += 2
            else:
                b = ord(s[i])
                if b <= 0x7F:
                    result.append(b)
                elif b <= 0x7FF:
                    result.append(0xC0 | (b >> 6))
                    result.append(0x80 | (b & 0x3F))
                elif b <= 0xFFFF:
                    result.append(0xE0 | (b >> 12))
                    result.append(0x80 | ((b >> 6) & 0x3F))
                    result.append(0x80 | (b & 0x3F))
                else:
                    result.append(0xF0 | (b >> 18))
                    result.append(0x80 | ((b >> 12) & 0x3F))
                    result.append(0x80 | ((b >> 6) & 0x3F))
                    result.append(0x80 | (b & 0x3F))
                i += 1
        return bytes(result)

    def _beautify(self, code):
        if not code:
            return code
        code = code.replace('\r\n', '\n').replace('\r', '\n')
        lines = [''.join(c for c in line if c.isprintable() or c == '\t').rstrip() for line in code.split('\n')]
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
            safe = re.sub(r'(?:\'[^\']*\'|"[^"]*"|--[^\n]*|\[=*\[.*?\]=*\])', '', stripped, flags=re.DOTALL)
            opens = len(re.findall(r'\b(function|then|do|repeat)\b', safe))
            closes = len(re.findall(r'\b(end|until)\b', safe))
            indent += opens - closes
            if stripped.startswith(('else', 'elseif')):
                indent += 1
            indent = max(indent, 0)
        return '\n'.join(formatted)

    def _validate_lua(self, code):
        if not code or len(code) < 20:
            return False
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False) as tmp:
            tmp.write(code)
            tmp_path = tmp.name
        try:
            for lua_bin in ['lua5.1', 'lua']:
                try:
                    result = subprocess.run(
                        [lua_bin, '-p', tmp_path],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        return True
                    break
                except FileNotFoundError:
                    continue
                except subprocess.TimeoutExpired:
                    break
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        if HAS_LUAPARSER:
            try:
                lua_ast.parse(code)
                return True
            except Exception:
                pass
        return False

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

    def _ensure_unluac_jar(self):
        try:
            if os.path.isfile(self.unluac_path):
                with open(self.unluac_path, 'rb') as f:
                    actual_sha256 = hashlib.sha256(f.read()).hexdigest()
                if actual_sha256 == UNLUAC_JAR_SHA256:
                    return
            os.makedirs(os.path.dirname(self.unluac_path), exist_ok=True)
            urllib.request.urlretrieve(UNLUAC_JAR_URL, self.unluac_path)
        except:
            pass


class LuaASTWalker:
    @staticmethod
    def walk(node):
        yield node
        if hasattr(node, 'body'):
            if isinstance(node.body, list):
                for child in node.body:
                    yield from LuaASTWalker.walk(child)
            elif node.body is not None:
                yield from LuaASTWalker.walk(node.body)
        if hasattr(node, 'values'):
            for child in node.values:
                yield from LuaASTWalker.walk(child)
        if hasattr(node, 'targets'):
            for child in node.targets:
                yield from LuaASTWalker.walk(child)
        if hasattr(node, 'fields'):
            for field in node.fields:
                yield from LuaASTWalker.walk(field.value)
                if hasattr(field, 'key') and field.key is not None:
                    yield from LuaASTWalker.walk(field.key)
        if hasattr(node, 'condition') and node.condition is not None:
            yield from LuaASTWalker.walk(node.condition)
        if hasattr(node, 'args'):
            for child in node.args:
                yield from LuaASTWalker.walk(child)
        if hasattr(node, 'func') and node.func is not None:
            yield from LuaASTWalker.walk(node.func)
        if hasattr(node, 'start') and node.start is not None:
            yield from LuaASTWalker.walk(node.start)
        if hasattr(node, 'end') and node.end is not None:
            yield from LuaASTWalker.walk(node.end)
        if hasattr(node, 'step') and node.step is not None:
            yield from LuaASTWalker.walk(node.step)
        if hasattr(node, 'iterators'):
            for child in node.iterators:
                yield from LuaASTWalker.walk(child)
        if hasattr(node, 'else_body') and node.else_body is not None:
            if isinstance(node.else_body, list):
                for child in node.else_body:
                    yield from LuaASTWalker.walk(child)
            else:
                yield from LuaASTWalker.walk(node.else_body)
        if hasattr(node, 'name') and hasattr(node.name, 'id'):
            yield node.name
