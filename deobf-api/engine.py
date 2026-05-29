import os, re, shutil, subprocess, tempfile, base64, urllib.request, asyncio, struct, hashlib, json, sys, io, math, time, uuid, threading, contextlib, resource, signal, traceback
from collections import OrderedDict, defaultdict, deque, namedtuple, Counter
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional, Union, Any, Callable
from enum import Enum

try:
    from luaparser import ast as lua_ast
    from luaparser.lexer import LuaLexer
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

REJECT_SIGNATURES = [
    "class DeobfEngine",
    "_run_lua_harness",
    "LuaASTWalker",
    "def _beautify",
    "import os, re",
    "UNLUAC_JAR_URL",
]

@contextlib.contextmanager
def _suppress_stderr():
    old_stderr = sys.stderr
    sys.stderr = io.StringIO()
    try:
        yield
    finally:
        sys.stderr = old_stderr

def _shannon_entropy(data):
    if not data:
        return 0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())

def _is_lua_bytecode(raw):
    return raw[:4] == b'\x1bLua'

def _is_self_capture(text):
    if not text:
        return False
    for sig in REJECT_SIGNATURES:
        if sig in text:
            return True
    return False

def _is_probably_text(data):
    if not data:
        return False
    if isinstance(data, str):
        raw = data.encode('latin-1', errors='ignore')
    else:
        raw = data
    if len(raw) < 10:
        return False
    if _is_lua_bytecode(raw):
        return False
    printable = sum(1 for b in raw if 32 <= b <= 126 or b in (9, 10, 13))
    if (printable / len(raw)) < 0.60:
        return False
    if raw.count(b'\x00') > len(raw) * 0.15:
        return False
    if _shannon_entropy(raw) > 7.2:
        return False
    return True

def _try_base64_decode(s):
    try:
        s = s.replace('-', '+').replace('_', '/')
        padded = s + '=' * (-len(s) % 4)
        return base64.b64decode(padded, validate=True)
    except Exception:
        return None

def _decode_numeric_escapes(s):
    return re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))), s)

def _lua_score(text):
    score = sum(1 for kw in LUA_KEYWORDS if kw in text) * 8
    for pat in [r'local\s+\w+', r'function\s*\(', r'end\b', r'return\b', r'if\s+.+\s+then']:
        if re.search(pat, text):
            score += 15
    if _shannon_entropy(text.encode(errors='ignore')) < 7:
        score += 10
    if text.count('(') == text.count(')'):
        score += 10
    funcs = text.count('function')
    ends = text.count('end')
    if funcs > 0 and ends >= funcs:
        score += 25
    return score

def _extract_wearedevs_alphabet(source):
    for table_match in re.finditer(r'local\s+\w+\s*=\s*\{([^}]{400,})\}', source):
        body = table_match.group(1)
        entries = {}
        for m in re.finditer(r'\b([A-Za-z_])\s*=\s*([-\d+*()\s]{3,60}?)(?=[,;\}]|$)', body):
            key = m.group(1)
            try:
                val = int(eval(re.sub(r'\s+', '', m.group(2))))
                if 0 <= val <= 63:
                    entries[key] = val
            except Exception:
                pass
        for m in re.finditer(r'\["\\(\d{1,3})"\]\s*=\s*([-\d+*()\s]{3,60}?)(?=[,;\}]|$)', body):
            key = chr(int(m.group(1)))
            try:
                val = int(eval(re.sub(r'\s+', '', m.group(2))))
                if 0 <= val <= 63:
                    entries[key] = val
            except Exception:
                pass
        if len(entries) < 60:
            continue
        alpha_map = {v: k for k, v in entries.items()}
        if len(alpha_map) < 60:
            continue
        alphabet = ''.join(alpha_map.get(i, '') for i in range(64))
        if len(alphabet) == 64 and '?' not in alphabet and len(set(alphabet)) == 64:
            return alphabet
    for m in re.finditer(r'["\']([A-Za-z0-9+/]{64})["\']', source):
        candidate = m.group(1)
        if len(set(candidate)) == 64:
            return candidate
    return None

def _custom_b64_decode(s, alpha):
    reverse = {c: i for i, c in enumerate(alpha)}
    bits = 0; bit_count = 0; out = bytearray()
    for c in s.rstrip('='):
        if c not in reverse:
            continue
        bits = (bits << 6) | reverse[c]
        bit_count += 6
        if bit_count >= 8:
            bit_count -= 8
            out.append((bits >> bit_count) & 0xFF)
    return bytes(out)

def _extract_r_table_strings(source):
    m = re.search(r'local\s+R\s*=\s*\{(.*?)\}(?=local\s+function)', source, re.DOTALL)
    if not m:
        m = re.search(r'\{((?:\s*"[^"]*"\s*[;,]?\s*){10,})\}', source, re.DOTALL)
    if not m:
        return None
    body = m.group(1)
    raw_entries = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
    if not raw_entries:
        return None
    return [_decode_numeric_escapes(s) for s in raw_entries]

def _extract_shuffle_ops(source):
    ops = []
    m = re.search(r'ipairs\s*\(\s*\{(.*?)\}\s*\)', source, re.DOTALL)
    if not m:
        return ops
    inner = m.group(1)
    for pair in re.finditer(r'\{([^}]+)\}', inner):
        parts = re.split(r'[;,]', pair.group(1))
        if len(parts) >= 2:
            try:
                a = int(eval(re.sub(r'\s+', '', parts[0])))
                b = int(eval(re.sub(r'\s+', '', parts[1])))
                ops.append((a, b))
            except Exception:
                pass
    return ops

def _recursive_decode_bytes(data, custom_alpha, depth=0, max_depth=8):
    if depth > max_depth:
        return data if isinstance(data, str) else data.decode('latin-1', errors='replace')
    if isinstance(data, str):
        raw = data.encode('latin-1', errors='replace')
    else:
        raw = data
    try:
        text = raw.decode('utf-8')
        if len(text) > 1 and _is_probably_text(text) and _shannon_entropy(raw) < 6.5:
            return text
    except:
        pass
    try:
        s = raw.decode('latin-1', errors='replace')
        decoded = _custom_b64_decode(s, custom_alpha)
        if decoded and decoded != raw and len(decoded) >= 2:
            return _recursive_decode_bytes(decoded, custom_alpha, depth + 1, max_depth)
    except:
        pass
    try:
        s = raw.decode('latin-1', errors='replace').strip()
        if re.match(r'^[A-Za-z0-9+/=]+$', s):
            padded = s + '=' * (-len(s) % 4)
            std_decoded = base64.b64decode(padded, validate=True)
            if std_decoded != raw and len(std_decoded) >= 2:
                return _recursive_decode_bytes(std_decoded, custom_alpha, depth + 1, max_depth)
    except:
        pass
    return raw.decode('latin-1', errors='replace')

def _wearedevs_decode(source):
    diag = {}
    alphabet = _extract_wearedevs_alphabet(source)
    diag['custom_alphabet'] = alphabet is not None
    diag['alphabet_preview'] = alphabet[:8] + '...' if alphabet else None
    if not alphabet:
        return {'success': False, 'reason': 'could not extract custom alphabet', 'diagnostics': diag}
    encoded_strings = _extract_r_table_strings(source)
    if not encoded_strings:
        return {'success': False, 'reason': 'could not extract R string table', 'diagnostics': diag}
    diag['string_count'] = len(encoded_strings)
    shuffle_ops = _extract_shuffle_ops(source)
    diag['shuffle_ops'] = len(shuffle_ops)
    strings = list(encoded_strings)
    for a, b in shuffle_ops:
        ai, bi = a - 1, b - 1
        if 0 <= ai < len(strings) and 0 <= bi < len(strings):
            strings[ai], strings[bi] = strings[bi], strings[ai]
    decoded = []
    for s in strings:
        if not s:
            decoded.append('')
            continue
        try:
            raw = _custom_b64_decode(s, alphabet)
            final = _recursive_decode_bytes(raw, alphabet)
            decoded.append(final)
        except Exception:
            if re.match(r'^[A-Za-z0-9+/=]+$', s):
                try:
                    raw = base64.b64decode(s + '=' * (-len(s) % 4), validate=True)
                    final = _recursive_decode_bytes(raw, alphabet)
                    decoded.append(final)
                except:
                    decoded.append(s)
            else:
                decoded.append(s)
    diag['decoded_count'] = len(decoded)
    readable = [s for s in decoded if s and _is_probably_text(s)]
    lua_hits = sum(1 for s in decoded if any(kw in s for kw in LUA_KEYWORDS))
    diag['readable_strings'] = len(readable)
    diag['lua_keyword_hits'] = lua_hits
    if lua_hits < 2 and len(readable) < 3:
        return {
            'success': False,
            'reason': f'decoded {len(decoded)} strings but only {lua_hits} contain Lua keywords',
            'diagnostics': diag,
            'decoded_strings': decoded,
        }
    return {
        'success': True,
        'decoded_strings': decoded,
        'reason': f'decoded {len(decoded)} strings ({lua_hits} with Lua keywords)',
        'diagnostics': diag,
    }

def _find_balanced_end(content, open_brace_index):
    depth = 0; quote = None; in_long_string = False; long_match = None
    idx = open_brace_index
    while idx < len(content):
        char = content[idx]
        if in_long_string:
            if char == ']' and content[idx:idx+len(long_match)] == long_match:
                in_long_string = False; idx += len(long_match); continue
            idx += 1; continue
        if quote:
            if char == '\\': idx += 2; continue
            if char == quote: quote = None
            idx += 1; continue
        if char == '[':
            m = re.match(r'\[=*\[', content[idx:])
            if m:
                long_match = ']' + m.group(0)[2:-1] + ']'; in_long_string = True
                idx += len(m.group(0)); continue
        if char in ("'", '"'): quote = char
        elif char == '{': depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0: return idx + 1
        idx += 1
    return -1

def _find_all_table_bodies(source):
    bodies = []; idx = 0
    while idx < len(source):
        brace_pos = source.find('{', idx)
        if brace_pos == -1: break
        end = _find_balanced_end(source, brace_pos)
        if end != -1:
            bodies.append(source[brace_pos:end]); idx = end
        else:
            idx = brace_pos + 1
    return bodies

def _parse_table_entries(body):
    inner = body[1:-1]; entries = []; depth = 0; current = ""
    in_str = False; quote = None; in_long_str = False; long_match = None; i = 0
    while i < len(inner):
        c = inner[i]
        if in_long_str:
            current += c
            if c == ']' and i + len(long_match) <= len(inner) and inner[i:i+len(long_match)] == long_match:
                in_long_str = False; current += long_match[1:]; i += len(long_match); continue
            i += 1; continue
        if in_str:
            current += c
            if c == '\\':
                if i + 1 < len(inner): current += inner[i+1]; i += 2; continue
            elif c == quote: in_str = False
            i += 1; continue
        if c == '[':
            m = re.match(r'\[=*\[', inner[i:])
            if m:
                long_match = ']' + m.group(0)[2:-1] + ']'; in_long_str = True
                current += m.group(0); i += len(m.group(0)); continue
        if c in ('"', "'"): in_str = True; quote = c; current += c; i += 1; continue
        if c == '{': depth += 1; current += c; i += 1; continue
        if c == '}': depth -= 1; current += c; i += 1; continue
        if c in (',', ';') and depth == 0:
            entries.append(current.strip()); current = ""; i += 1; continue
        current += c; i += 1
    if current.strip(): entries.append(current.strip())
    parsed = []
    for e in entries:
        if not e: continue
        e = e.strip()
        if e.lstrip('-').isdigit(): parsed.append(int(e))
        elif e.replace('.', '', 1).lstrip('-').isdigit(): parsed.append(float(e))
        elif (e.startswith('"') and e.endswith('"')) or (e.startswith("'") and e.endswith("'")): parsed.append(e[1:-1])
        elif e.startswith('[[') and e.endswith(']]'): parsed.append(e[2:-2])
        else: parsed.append(e)
    return parsed

@dataclass
class DiagnosticEvent:
    stage: str
    success: bool
    message: str
    line: Optional[int] = None
    column: Optional[int] = None
    snippet: Optional[str] = None
    exception_type: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

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

class VMLifterState:
    def __init__(self):
        self.registers = {}
        self.stack = []
        self.constants = []
        self.instructions = []
        self.ip = 0
        self.globals = {}
        self.upvalues = {}
        self.locals = {}
        self.ast_output = []
        self.label_counter = 0
        self.visited = set()
        self.loop_headers = set()
        self.loop_exits = set()
        self.blocks = {}
        self.current_scope = 0
        self.scope_stack = []

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
        'instruction_table_var': 'I',
        'register_table_var': 'Q',
        'constant_table_var': 'R',
        'dispatch_map': {},
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
    if not inst_data or not isinstance(inst_data, list):
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

    dispatch_keys = set(dispatch_map.keys())
    pc = 0
    while pc < len(inst_data):
        opcode = inst_data[pc]
        handler_idx = dispatch_map.get(opcode, -1)
        instr = VMInstruction(opcode=opcode, pc=pc, handler_idx=handler_idx)

        operands = []
        temp_pc = pc + 1
        while temp_pc < len(inst_data):
            next_val = inst_data[temp_pc]
            if next_val in dispatch_keys:
                break
            if next_val < 256 and next_val >= 0:
                operands.append(next_val)
                temp_pc += 1
            else:
                operands.append(next_val)
                temp_pc += 1
                break
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
    if body.count('Q[I[B+') >= 3:
        if '+' in body.split('=')[1] if '=' in body and len(body.split('=')) > 1 else False:
            features.add('add')
        elif '-' in body.split('=')[1] if '=' in body and len(body.split('=')) > 1 else False:
            features.add('sub')
        elif '*' in body.split('=')[1] if '=' in body and len(body.split('=')) > 1 else False:
            features.add('mul')
        elif '/' in body.split('=')[1] if '=' in body and len(body.split('=')) > 1 else False:
            features.add('div')
        elif '%' in body.split('=')[1] if '=' in body and len(body.split('=')) > 1 else False:
            features.add('mod')
        elif '^' in body.split('=')[1] if '=' in body and len(body.split('=')) > 1 else False:
            features.add('pow')
        elif '..' in body.split('=')[1] if '=' in body and len(body.split('=')) > 1 else False:
            features.add('concat')
        else:
            features.add('move')
    if body.count('Q[I[B+') == 2 and '=' in body:
        features.add('move')
    if re.search(r'B\s*=\s*I\s*\[\s*B', body):
        features.add('jump')
    if re.search(r'if\s+Q\s*\[', body):
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
    if '#' in body and 'Q' in body:
        features.add('len')
    if 'not' in body and 'Q' in body:
        features.add('not_op')
    if '==' in body:
        features.add('eq')
    if '<' in body and '>' not in body and '<=' not in body:
        features.add('lt')
    if '<=' in body:
        features.add('le')
    if 'function' in body and '(' in body:
        features.add('closure')
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
        elif opcode in handlers:
            opcode_to_handler[opcode] = handlers[opcode]

    return opcode_to_handler, handlers

def _build_cfg(instructions, opcode_to_handler):
    blocks = {}
    block_map = {}
    jump_targets = set()

    for instr in instructions:
        handler = opcode_to_handler.get(instr.opcode)
        if handler:
            if 'jump' in handler.handler_type:
                if instr.operands:
                    target_pc = instr.operands[0]
                    if isinstance(target_pc, int):
                        jump_targets.add(target_pc)
            if 'cjump' in handler.handler_type:
                if len(instr.operands) >= 2:
                    target_pc = instr.operands[1] if isinstance(instr.operands[1], int) else instr.operands[0]
                    if isinstance(target_pc, int):
                        jump_targets.add(target_pc)

    for instr in instructions:
        if instr.pc in jump_targets and instr.pc not in block_map:
            pass

    current_block_id = 0
    current_block = VMBasicBlock(id=current_block_id, start_pc=0, end_pc=0)
    block_starts = {0}
    block_starts.update(jump_targets)

    for instr in instructions:
        if instr.pc in block_starts and current_block.instructions:
            current_block.end_pc = current_block.instructions[-1].pc
            blocks[current_block.id] = current_block
            block_map[current_block.start_pc] = current_block.id
            current_block_id = len(blocks)
            current_block = VMBasicBlock(id=current_block_id, start_pc=instr.pc, end_pc=instr.pc)
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
            handler_types = handler.handler_type
            if 'jump' in handler_types and 'cjump' not in handler_types:
                if last_instr.operands:
                    target = last_instr.operands[0]
                    target_instrs = [i for i in instructions if i.pc == target]
                    if target_instrs:
                        target_block_start = target_instrs[0].pc
                        for bid, blk in blocks.items():
                            if blk.start_pc == target_block_start:
                                block.successors.append(bid)
                                blocks[bid].predecessors.append(block_id)
                                block.branch_target = target
                                break
            elif 'cjump' in handler_types:
                fallthrough_pc = last_instr.pc + 1 + len(last_instr.operands)
                if last_instr.operands:
                    target = last_instr.operands[0]
                    if isinstance(target, int):
                        for bid, blk in blocks.items():
                            if blk.start_pc == target:
                                block.successors.append(bid)
                                blocks[bid].predecessors.append(block_id)
                                block.branch_target = target
                                break
                for bid, blk in blocks.items():
                    if blk.start_pc == fallthrough_pc:
                        block.successors.append(bid)
                        blocks[bid].predecessors.append(block_id)
                        block.fallthrough_target = fallthrough_pc
                        break
            elif 'return' not in handler_types:
                fallthrough_pc = last_instr.pc + 1 + len(last_instr.operands)
                for bid, blk in blocks.items():
                    if blk.start_pc == fallthrough_pc:
                        block.successors.append(bid)
                        blocks[bid].predecessors.append(block_id)
                        break

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
                    if succ_id not in loop_blocks:
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
                output_lines.append('  ' * indent + f'-- unknown opcode {instr.opcode} at pc {instr.pc}')
                continue

            features = handler.handler_type
            ops = instr.operands

            if 'loadk' in features:
                if len(ops) >= 2:
                    dest_reg = ops[0]
                    const_idx = ops[1]
                    const_val = get_constant(const_idx)
                    set_register(dest_reg, const_val)
                    val_repr = _escape_lua_string(const_val) if isinstance(const_val, str) else str(const_val)
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = {val_repr}')

            elif 'add' in features:
                if len(ops) >= 3:
                    dest_reg = ops[0]
                    left_val = get_register(ops[1]) if ops[1] in state.registers else str(ops[1])
                    right_val = get_register(ops[2]) if ops[2] in state.registers else str(ops[2])
                    result = f'{left_val} + {right_val}'
                    set_register(dest_reg, result)
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = {result}')

            elif 'sub' in features:
                if len(ops) >= 3:
                    dest_reg = ops[0]
                    left_val = get_register(ops[1]) if ops[1] in state.registers else str(ops[1])
                    right_val = get_register(ops[2]) if ops[2] in state.registers else str(ops[2])
                    result = f'{left_val} - {right_val}'
                    set_register(dest_reg, result)
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = {result}')

            elif 'mul' in features:
                if len(ops) >= 3:
                    dest_reg = ops[0]
                    left_val = get_register(ops[1]) if ops[1] in state.registers else str(ops[1])
                    right_val = get_register(ops[2]) if ops[2] in state.registers else str(ops[2])
                    result = f'{left_val} * {right_val}'
                    set_register(dest_reg, result)
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = {result}')

            elif 'div' in features:
                if len(ops) >= 3:
                    dest_reg = ops[0]
                    left_val = get_register(ops[1]) if ops[1] in state.registers else str(ops[1])
                    right_val = get_register(ops[2]) if ops[2] in state.registers else str(ops[2])
                    result = f'{left_val} / {right_val}'
                    set_register(dest_reg, result)
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = {result}')

            elif 'mod' in features:
                if len(ops) >= 3:
                    dest_reg = ops[0]
                    left_val = get_register(ops[1]) if ops[1] in state.registers else str(ops[1])
                    right_val = get_register(ops[2]) if ops[2] in state.registers else str(ops[2])
                    result = f'{left_val} % {right_val}'
                    set_register(dest_reg, result)
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = {result}')

            elif 'pow' in features:
                if len(ops) >= 3:
                    dest_reg = ops[0]
                    left_val = get_register(ops[1]) if ops[1] in state.registers else str(ops[1])
                    right_val = get_register(ops[2]) if ops[2] in state.registers else str(ops[2])
                    result = f'{left_val} ^ {right_val}'
                    set_register(dest_reg, result)
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = {result}')

            elif 'concat' in features:
                if len(ops) >= 3:
                    dest_reg = ops[0]
                    left_val = get_register(ops[1]) if ops[1] in state.registers else str(ops[1])
                    right_val = get_register(ops[2]) if ops[2] in state.registers else str(ops[2])
                    result = f'{left_val} .. {right_val}'
                    set_register(dest_reg, result)
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = {result}')

            elif 'move' in features:
                if len(ops) >= 2:
                    dest_reg = ops[0]
                    src_reg = ops[1]
                    src_val = get_register(src_reg)
                    if src_val is not None:
                        set_register(dest_reg, src_val)
                        output_lines.append('  ' * indent + f'local reg_{dest_reg} = reg_{src_reg}')
                    else:
                        set_register(dest_reg, f'reg_{src_reg}')
                        output_lines.append('  ' * indent + f'local reg_{dest_reg} = reg_{src_reg}')

            elif 'strchar' in features:
                if len(ops) >= 1:
                    dest_reg = ops[0]
                    char_args = ops[1:] if len(ops) > 1 else [ops[0]]
                    chars = ', '.join(str(a) for a in char_args)
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = string.char({chars})')

            elif 'table_insert' in features:
                if len(ops) >= 2:
                    output_lines.append('  ' * indent + f'table.insert(reg_{ops[0]}, reg_{ops[1]})')
                else:
                    output_lines.append('  ' * indent + f'table.insert(reg_{ops[0]})')

            elif 'pcall' in features:
                if len(ops) >= 1:
                    func_name = get_constant(ops[0]) if ops[0] < len(state.constants) else f'reg_{ops[0]}'
                    arg_count = ops[1] if len(ops) > 1 else 0
                    args = []
                    for i in range(arg_count):
                        arg_reg = ops[2 + i] if len(ops) > 2 + i else None
                        if arg_reg is not None:
                            arg_val = get_register(arg_reg)
                            args.append(str(arg_val) if arg_val is not None else f'reg_{arg_reg}')
                    output_lines.append('  ' * indent + f'pcall({func_name}, {", ".join(args)})')

            elif 'call' in features:
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

            elif 'eq' in features:
                if len(ops) >= 3:
                    dest_reg = ops[0]
                    left_val = get_register(ops[1]) if ops[1] in state.registers else str(ops[1])
                    right_val = get_register(ops[2]) if ops[2] in state.registers else str(ops[2])
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = ({left_val} == {right_val})')

            elif 'lt' in features:
                if len(ops) >= 3:
                    dest_reg = ops[0]
                    left_val = get_register(ops[1]) if ops[1] in state.registers else str(ops[1])
                    right_val = get_register(ops[2]) if ops[2] in state.registers else str(ops[2])
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = ({left_val} < {right_val})')

            elif 'le' in features:
                if len(ops) >= 3:
                    dest_reg = ops[0]
                    left_val = get_register(ops[1]) if ops[1] in state.registers else str(ops[1])
                    right_val = get_register(ops[2]) if ops[2] in state.registers else str(ops[2])
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = ({left_val} <= {right_val})')

            elif 'len' in features:
                if len(ops) >= 2:
                    dest_reg = ops[0]
                    src_reg = ops[1]
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = #reg_{src_reg}')

            elif 'not_op' in features:
                if len(ops) >= 2:
                    dest_reg = ops[0]
                    src_reg = ops[1]
                    output_lines.append('  ' * indent + f'local reg_{dest_reg} = not reg_{src_reg}')

            elif 'setmeta' in features:
                if len(ops) >= 2:
                    output_lines.append('  ' * indent + f'setmetatable(reg_{ops[0]}, reg_{ops[1]})')

            elif 'getmeta' in features:
                if len(ops) >= 2:
                    output_lines.append('  ' * indent + f'local reg_{ops[0]} = getmetatable(reg_{ops[1]})')

            elif 'closure' in features:
                if len(ops) >= 1:
                    output_lines.append('  ' * indent + f'local reg_{ops[0]} = function() end')

            elif 'loadstring' in features:
                if len(ops) >= 1:
                    src = get_register(ops[0]) if ops[0] in state.registers else f'reg_{ops[0]}'
                    output_lines.append('  ' * indent + f'local loaded = loadstring({src})')

            elif 'return' in features:
                if ops:
                    ret_vals = []
                    for op in ops:
                        val = get_register(op) if op in state.registers else str(op)
                        ret_vals.append(str(val))
                    output_lines.append('  ' * indent + f'return {", ".join(ret_vals)}')
                else:
                    output_lines.append('  ' * indent + 'return')

            else:
                output_lines.append('  ' * indent + f'-- opcode {instr.opcode}: {", ".join(str(o) for o in ops)}')

        if is_loop_header:
            indent -= 1
            output_lines.append('  ' * indent + 'end')

        for succ_id in block.successors:
            if succ_id not in state.visited:
                execute_block(succ_id, indent)

    if blocks:
        first_block = min(blocks.keys())
        execute_block(first_block)

    if not output_lines:
        output_lines.append('local R = {')
        for i, s in enumerate(state.constants or []):
            if s and len(str(s)) > 1:
                output_lines.append(f'\t[{i}] = {_escape_lua_string(str(s))},')
        output_lines.append('}')
        for instr in instructions[:40]:
            handler = opcode_to_handler.get(instr.opcode)
            if handler:
                features = handler.handler_type
                ops = instr.operands
                if 'loadk' in features and len(ops) >= 2:
                    const_val = state.constants[ops[1]] if ops[1] < len(state.constants) else f'R[{ops[1]}]'
                    output_lines.append(f'-- [{instr.pc}] LOADK reg_{ops[0]} = {_escape_lua_string(str(const_val))}')
                elif 'move' in features and len(ops) >= 2:
                    output_lines.append(f'-- [{instr.pc}] MOVE reg_{ops[0]} = reg_{ops[1]}')
                elif 'add' in features and len(ops) >= 3:
                    output_lines.append(f'-- [{instr.pc}] ADD reg_{ops[0]} = reg_{ops[1]} + reg_{ops[2]}')
                elif 'jump' in features and 'cjump' not in features and ops:
                    output_lines.append(f'-- [{instr.pc}] JMP -> {ops[0]}')
                elif 'cjump' in features and ops:
                    output_lines.append(f'-- [{instr.pc}] CJMP reg_{ops[0]} -> {ops[0] if len(ops) > 0 else "?"}')
                elif 'call' in features and ops:
                    func = state.constants[ops[0]] if ops and ops[0] < len(state.constants) else f'reg_{ops[0]}'
                    output_lines.append(f'-- [{instr.pc}] CALL {func}')
                else:
                    output_lines.append(f'-- [{instr.pc}] OP_{instr.opcode} {ops}')

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

def _looks_like_real_code(text):
    if not text or len(text) < 200:
        return False
    lines = text.splitlines()
    structural_kw = {'function', 'while', 'for', 'if', 'repeat'}
    count = sum(1 for line in lines if any(kw in line for kw in structural_kw))
    return count >= 3

class DeobfEngine:
    def __init__(self):
        self.unluac_path = UNLUAC_LOCAL_PATH
        self._java_available = shutil.which('java') is not None
        self.trace = []

    def get_capabilities(self):
        return {
            'lua_harness': True,
            'prometheus_vm': True,
            'wearedevs_decode': True,
            'wearedevs_vm_lift': True,
            'unluac': self._java_available and os.path.isfile(self.unluac_path),
            'luaparser': HAS_LUAPARSER,
        }

    def _trace(self, stage, success, message):
        self.trace.append(DiagnosticEvent(stage=stage, success=success, message=message))

    def _set_process_limits(self):
        try:
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_CPU, (40, 45))
            resource.setrlimit(resource.RLIMIT_NPROC, (30, 30))
            resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
        except Exception:
            pass

    def _run_lua_harness(self, source):
        harness = r'''
local captures = {}
local hook_stats = {loadstring=0,load=0,char=0,concat=0,insert=0,pcall=0,bytecode=0,env_string=0,rejected_size=0}
local CALL_DEPTH = 0
local MAX_DEPTH = 25
local b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
local function b64encode(data)
local result = {}
local padding = ""
for i = 1, #data, 3 do
local a, b, c = data:byte(i, i+2)
b = b or 0; c = c or 0
local n = a * 65536 + b * 256 + c
local c1 = math.floor(n / 262144) % 64
local c2 = math.floor(n / 4096) % 64
local c3 = math.floor(n / 64) % 64
local c4 = n % 64
table.insert(result, b64chars:sub(c1+1, c1+1))
table.insert(result, b64chars:sub(c2+1, c2+1))
if i + 1 > #data then padding = "=="; break end
table.insert(result, b64chars:sub(c3+1, c3+1))
if i + 2 > #data then padding = "="; break end
table.insert(result, b64chars:sub(c4+1, c4+1))
end
return table.concat(result) .. padding
end
local real_insert = table.insert
local function save(tag, data)
if type(data) ~= "string" then return end
if #data < 20 then hook_stats["rejected_size"] = (hook_stats["rejected_size"] or 0) + 1; return end
if CALL_DEPTH > MAX_DEPTH then return end
CALL_DEPTH = CALL_DEPTH + 1
real_insert(captures, {tag=tag, data=b64encode(data), raw_length=#data})
CALL_DEPTH = CALL_DEPTH - 1
end
local real_loadstring = loadstring
local real_load = load or loadstring
local INSIDE_LOAD = false
_G.loadstring = function(code, ...)
hook_stats.loadstring = (hook_stats.loadstring or 0) + 1
if not INSIDE_LOAD then INSIDE_LOAD = true; save("loadstring", code); INSIDE_LOAD = false end
return real_loadstring(code, ...)
end
if load then
_G.load = function(code, ...)
hook_stats.load = (hook_stats.load or 0) + 1
if not INSIDE_LOAD then INSIDE_LOAD = true; save("load", code); INSIDE_LOAD = false end
return real_load(code, ...)
end
end
local real_char = string.char
string.char = function(...)
hook_stats.char = (hook_stats.char or 0) + 1
local out = real_char(...)
if #out > 40 then save("string_char", out) end
return out
end
local real_concat = table.concat
table.concat = function(t, sep, i, j)
hook_stats.concat = (hook_stats.concat or 0) + 1
local out = real_concat(t, sep, i, j)
if type(out) == "string" and #out > 80 then save("concat", out) end
return out
end
local real_insert_hook = table.insert
table.insert = function(t, v, ...)
hook_stats.insert = (hook_stats.insert or 0) + 1
if type(v) == "string" and #v > 20 then save("table_insert", v) end
return real_insert_hook(t, v, ...)
end
local real_pcall = pcall
_G.pcall = function(fn, ...)
hook_stats.pcall = (hook_stats.pcall or 0) + 1
if type(fn) == "function" and debug and debug.getinfo then
local info = debug.getinfo(fn)
if info and info.what == "Lua" then
local ok, dumped = real_pcall(string.dump, fn)
if ok and dumped and #dumped > 50 then save("pcall_fn", dumped) end
end
end
return real_pcall(fn, ...)
end
if string.dump then
local real_dump = string.dump
string.dump = function(fn, ...)
hook_stats.bytecode = (hook_stats.bytecode or 0) + 1
local bc = real_dump(fn, ...)
save("bytecode", bc)
return bc
end
end
os.execute = function() error("os.execute blocked") end
io.popen = function() error("io.popen blocked") end
local f, err = loadfile("_SRCFILE_")
if not f then
print("ERR:COMPILE:" .. tostring(err))
else
local bit32 = bit32 or nil
if not bit32 then
local function bxor(a,b) local r,m=0,1; while a>0 or b>0 do local ab,bb=a%2,b%2; if ab~=bb then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end
local function band(a,b) local r,m=0,1; while a>0 and b>0 do if a%2+b%2==2 then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end
local function bor(a,b) local r,m=0,1; while a>0 or b>0 do if a%2+b%2>0 then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end
bit32={bxor=bxor,band=band,bor=bor,lshift=function(v,n) return math.floor(v*(2^n))%4294967296 end,rshift=function(v,n) return math.floor(v/(2^n)) end}
bit32.arshift=bit32.rshift
end
_G.bit32=bit32; _G.bit=bit32
if debug and debug.sethook then debug.sethook(function() error("instruction limit") end,"",500000) end
local success, result = pcall(f)
if debug and debug.sethook then debug.sethook() end
collectgarbage("collect")
pcall(function()
for k,v in pairs(_G) do
if type(v)=="string" and #v>20 then hook_stats.env_string=(hook_stats.env_string or 0)+1; save("env_"..k, v) end
end
end)
for _,cap in ipairs(captures) do print("CAP:"..cap.tag..":"..cap.data) end
if #captures==0 then
if not success then print("ERR:RUNTIME:"..tostring(result))
else print("ERR:NO_OUTPUT") end
end
end
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as src_tmp:
            src_tmp.write(source); src_path = src_tmp.name
        harness = harness.replace('_SRCFILE_', src_path)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as tmp:
            tmp.write(harness); tmp_path = tmp.name
        captures = []
        try:
            for lua_bin in ['lua5.1', 'lua']:
                try:
                    proc = subprocess.Popen(
                        [lua_bin, tmp_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        preexec_fn=self._set_process_limits, start_new_session=True)
                    try:
                        stdout, _ = proc.communicate(timeout=45)
                        stdout = stdout.decode('latin-1', errors='replace')
                    except subprocess.TimeoutExpired:
                        try: os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        except: pass
                    proc.wait()
                    for line in stdout.splitlines():
                        if line.startswith('CAP:'):
                            captures.append(line[4:])
                    if captures: break
                except FileNotFoundError:
                    continue
        finally:
            for p in (tmp_path, src_path):
                try: os.unlink(p)
                except OSError: pass
        if captures:
            candidates = []
            for cap in captures:
                tag, data = cap.split(':', 1) if ':' in cap else ('unknown', cap)
                try:
                    decoded_data = base64.b64decode(data).decode('latin-1', errors='replace')
                except Exception:
                    decoded_data = data
                if _is_self_capture(decoded_data): continue
                if not _is_probably_text(decoded_data):
                    raw_check = decoded_data.encode('latin-1', errors='ignore')
                    if _is_lua_bytecode(raw_check) and self._java_available:
                        try:
                            dec, _ = self._run_unluac(raw_check)
                            if dec: decoded_data = dec
                        except: pass
                    else:
                        if sum(1 for kw in LUA_KEYWORDS if kw in decoded_data) < 3: continue
                candidates.append({'data': decoded_data, 'tag': tag})
            if candidates:
                return max(candidates, key=lambda x: len(x['data']))['data']
        return None

    def _run_unluac(self, bytecode):
        if not self._java_available: return None, "no java"
        if not os.path.isfile(self.unluac_path): self._ensure_unluac_jar()
        if not os.path.isfile(self.unluac_path): return None, "no unluac.jar"
        if bytecode[:4] != b'\x1bLua': return None, "not lua bytecode"
        with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
            tmp.write(bytecode); tmp_path = tmp.name
        try:
            r = subprocess.run(['java', '-jar', self.unluac_path, '--rawstring', tmp_path],
                              capture_output=True, timeout=10)
            stdout = r.stdout.decode('latin-1', errors='replace')
            return (stdout, None) if r.returncode == 0 and stdout.strip() else (None, "unluac failed")
        except subprocess.TimeoutExpired: return None, "timeout"
        except Exception as e: return None, str(e)
        finally:
            try: os.unlink(tmp_path)
            except: pass

    def _ensure_unluac_jar(self):
        try:
            os.makedirs(os.path.dirname(self.unluac_path), exist_ok=True)
            urllib.request.urlretrieve(UNLUAC_JAR_URL, self.unluac_path)
        except: pass

    def _detect_prometheus_vm(self, source):
        score = sum(1 for p in [r'pc\s*=', r'opcode', r'instructions?\[',
                                r'while\s+true\s+do', r'bit32', r'band\(']
                    if re.search(p, source))
        return score >= 3

    def _prometheus_decompile(self, source):
        bodies = _find_all_table_bodies(source)
        instructions = []
        for body in bodies:
            entries = _parse_table_entries(body)
            nums = [e for e in entries if isinstance(e, int)]
            if len(nums) >= 10: instructions = nums; break
        if not instructions:
            m = re.search(r'\{([\d,\s]{50,})\}', source)
            if m:
                instructions = [int(n.strip()) for n in m.group(1).split(',') if n.strip().isdigit()]
        constants = []
        cm = re.search(r'local\s+\w+\s*=\s*\{([^}]+)\}', source)
        if cm:
            constants = [e for e in _parse_table_entries('{' + cm.group(1) + '}') if isinstance(e, str)]
        if not instructions: return None
        lines = []; ip = 0
        while ip < len(instructions):
            op = instructions[ip]; ip += 1
            if op == 0:
                idx = instructions[ip] if ip < len(instructions) else 0; ip += 1
                lines.append(f"loadk {json.dumps(constants[idx-1] if 1 <= idx <= len(constants) else str(idx))}")
            elif op == 1:
                a = instructions[ip] if ip < len(instructions) else 0; ip += 1
                b = instructions[ip] if ip < len(instructions) else 0; ip += 1
                lines.append(f"{constants[a-1] if 1<=a<=len(constants) else f'var{a}'} = {constants[b-1] if 1<=b<=len(constants) else f'var{b}'}")
            elif op == 2:
                a = instructions[ip] if ip < len(instructions) else 0; ip += 1
                lines.append(f"call {constants[a-1] if 1<=a<=len(constants) else f'var{a}'}")
            else:
                lines.append(f"-- op {op}")
        return '\n'.join(lines)

    def _wearedevs_lift_vm(self, source, decoded_strings):
        self._trace("vm_lift_detect", True, "checking for WeAreDevs VM")
        if not _is_wearedevs_vm(source):
            self._trace("vm_lift_detect", False, "no VM dispatch pattern detected")
            return None
        self._trace("vm_lift_start", True, "extracting VM structure")
        try:
            vm_structure = _extract_vm_structure(source)
            instructions = _extract_instruction_stream(source, vm_structure)
            self._trace("vm_lift_instructions", True, f"extracted {len(instructions)} instructions")
            if len(instructions) < 10:
                self._trace("vm_lift_abort", False, "too few instructions for a meaningful VM")
                return None
            opcode_to_handler, all_handlers = _build_handler_table(source, vm_structure)
            self._trace("vm_lift_handlers", True, f"identified {len(opcode_to_handler)} opcode handlers")
            if not opcode_to_handler:
                self._trace("vm_lift_abort", False, "no handlers could be built")
                return None
            blocks, block_map = _build_cfg(instructions, opcode_to_handler)
            self._trace("vm_lift_cfg", True, f"built {len(blocks)} basic blocks")
            loop_headers, loops = _detect_loops(blocks)
            self._trace("vm_lift_loops", True, f"detected {len(loop_headers)} loops")
            constants = _extract_all_constants(source, decoded_strings or [])
            state = VMLifterState()
            state.constants = constants
            state.instructions = instructions
            lifted = _symbolic_execute(
                state, instructions, opcode_to_handler,
                blocks, block_map, loop_headers
            )
            if lifted and _looks_like_real_code(lifted):
                self._trace("vm_lift_complete", True, f"lifted {len(lifted)} chars of Lua")
                return lifted
            self._trace("vm_lift_complete", False, f"output did not pass structural validation ({len(lifted) if lifted else 0} chars)")
        except Exception as e:
            self._trace("vm_lift_error", False, str(e))
        return None

    def process(self, source):
        self.trace = []
        cleaned = re.sub(r'\s+', '', source.strip())
        if re.match(r'^[A-Za-z0-9+/=]+$', cleaned):
            decoded = _try_base64_decode(cleaned)
            if decoded:
                for enc in ('utf-8', 'latin-1'):
                    try:
                        text = decoded.decode(enc, errors='replace')
                        if len(text) > 50:
                            source = text
                            break
                    except: pass
                self._trace("base64_peel", True, f"outer base64 decoded ({len(text)} chars)")

        self._trace("wearedevs_detect", True, "checking for WeAreDevs obfuscation")
        wd = _wearedevs_decode(source)
        if wd['success']:
            decoded_strings = wd['decoded_strings']
            diag = wd['diagnostics']
            self._trace("wearedevs_decode", True,
                        f"decoded {diag.get('decoded_count',0)} strings, "
                        f"{diag.get('lua_keyword_hits',0)} with Lua keywords")

            self._trace("lua_harness", True, "running Lua execution harness (primary for WeAreDevs VM)")
            harness_result = self._run_lua_harness(source)
            if harness_result and _looks_like_real_code(harness_result):
                self._trace("lua_harness", True, f"captured {len(harness_result)} chars of real Lua")
                return harness_result, 'lua_harness', 'Lua harness captured original source', [vars(t) for t in self.trace]

            vm_result = self._wearedevs_lift_vm(source, decoded_strings)
            if vm_result:
                return vm_result, 'wearedevs_vm_lifted', 'VM lifted successfully', [vars(t) for t in self.trace]

            output_lines = []
            for i, s in enumerate(decoded_strings):
                if s:
                    output_lines.append(f"-- [{i}] {s!r}")
            result = '\n'.join(output_lines)
            return result, 'wearedevs_decode', wd['reason'], [vars(t) for t in self.trace]
        else:
            self._trace("wearedevs_decode", False,
                        f"{wd['reason']} | diag: {json.dumps(wd.get('diagnostics', {}))}")

        if self._detect_prometheus_vm(source):
            self._trace("prometheus_detect", True, "Prometheus VM detected")
            result = self._prometheus_decompile(source)
            if result and len(result) >= 50 and _is_probably_text(result):
                self._trace("prometheus_decompile", True, f"{len(result)} chars")
                return result, 'prometheus_vm', 'Prometheus VM decompiled', [vars(t) for t in self.trace]

        self._trace("lua_harness", True, "running Lua execution harness (fallback)")
        harness_result = self._run_lua_harness(source)
        if harness_result:
            self._trace("lua_harness", True, f"captured {len(harness_result)} chars")
            return harness_result, 'lua_harness', 'Lua harness capture', [vars(t) for t in self.trace]
        self._trace("lua_harness", False, "harness produced no output")

        diag_msg = json.dumps(wd.get('diagnostics', {}), indent=2)
        return '', 'unable', f'no strategies produced output\n{diag_msg}', [vars(t) for t in self.trace]

job_store = {}
job_lock = threading.Lock()

def _run_job(job_id, source):
    engine = DeobfEngine()
    try:
        result, method, diagnostic, trace = engine.process(source)
        with job_lock:
            job_store[job_id] = {
                'status': 'complete', 'result': result, 'detected': method,
                'diagnostic': diagnostic, 'trace': trace,
                'result_length': len(result) if result else 0
            }
    except Exception as e:
        with job_lock:
            job_store[job_id] = {
                'status': 'error', 'error': str(e),
                'traceback': traceback.format_exc()[:4000]
            }

def submit_job(source):
    job_id = str(uuid.uuid4())
    with job_lock:
        job_store[job_id] = {'status': 'processing', 'created': time.time()}
    threading.Thread(target=_run_job, args=(job_id, source), daemon=True).start()
    return job_id

def get_job(job_id):
    with job_lock:
        return job_store.get(job_id)
