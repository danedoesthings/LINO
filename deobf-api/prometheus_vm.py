import re
import base64
import zlib
import logging
from typing import Optional

log = logging.getLogger(__name__)


def safe_eval(expr: str) -> str:
    """Safely evaluate simple arithmetic expressions."""
    try:
        # Only allow basic arithmetic
        if re.match(r'^[\d\s+\-*/%()]+$', expr):
            return str(eval(expr, {"__builtins__": None}, {}))
    except:
        pass
    return expr


def reverse_vmify(code: str) -> str:
    """Reverse VM-ified expressions and arithmetic."""
    # Simplify (var and expr1 or expr2) patterns
    code = re.sub(
        r'(?<!\.)\b([a-zA-Z_]\w*|\([^)]+\))\s*and\s*((?:\([^)]+\)|[-+]?\d+)(?:\s*[-+*/]\s*(?:\([^)]+\)|[-+]?\d+))*)\s*or\s*((?:\([^)]+\)|[-+]?\d+)(?:\s*[-+*/]\s*(?:\([^)]+\)|[-+]?\d+))*)',
        lambda m: f"({m.group(1)} and {safe_eval(m.group(2).strip())} or {safe_eval(m.group(3).strip())})",
        code,
    )

    # Simplify arithmetic expressions
    code = re.sub(
        r'\b([-+]?(?:\d+|\(\s*[-+]?\d+\s*\))(?:\s*[-+*/%]\s*[-+]?(?:\d+|\(\s*[-+]?\d+\s*\)))+)\b',
        lambda m: safe_eval(m.group(0)),
        code,
    )

    # Simplify bitwise masks
    code = re.sub(r'\b(\w+)\s*%\s*1\b', r'\1', code)
    code = re.sub(r'\b(\w+)\s*&\s*0\b', '0', code)
    code = re.sub(r'\b(\w+)\s*\^\s*0\b', r'\1', code)
    code = re.sub(r'\b(\w+)\s*\|\s*0\b', r'\1', code)

    return code


def handle_prometheus_vm(code: str) -> str:
    """Convert Prometheus VM dispatch loops to structured control flow."""
    # Pattern: while true do local op = array[idx]; idx = idx + 1; if op == N then ... end end
    def _rewrite_vm_loop(match: re.Match) -> str:
        loop_body = match.group(1)

        # Extract the opcode variable and array
        op_var_match = re.search(r'local\s+(\w+)\s*=\s*(\w+)\[(\w+)\]', loop_body)
        if not op_var_match:
            return match.group(0)

        op_var, array_var, idx_var = op_var_match.groups()

        # Find all opcode handlers
        handlers = []
        handler_pattern = re.compile(
            rf'if\s+{re.escape(op_var)}\s*==\s*(\d+)\s+then\s+(.*?)(?=\belseif\b|\bend\b)',
            re.DOTALL
        )

        for handler in handler_pattern.finditer(loop_body):
            opcode, body = handler.groups()
            # Clean up the handler body
            body = re.sub(rf'\b{re.escape(idx_var)}\s*=\s*{re.escape(idx_var)}\s*\+\s*\d+\s*;?', '', body)
            body = re.sub(r'\b\w+\s*=\s*\w+\s*\+\s*\d+\s*;?', '', body)
            handlers.append((opcode, body.strip()))

        if not handlers:
            return match.group(0)

        # Build switch-like structure
        cases = []
        for opcode, body in handlers:
            cases.append(f"  -- OP {opcode}")
            cases.append(f"  {body}")
            cases.append(f"  -- end OP {opcode}")

        return (
            f"-- Devirtualized VM dispatch\n"
            f"while {idx_var} <= #{array_var} do\n"
            f"  local {op_var} = {array_var}[{idx_var}]\n"
            f"  {idx_var} = {idx_var} + 1\n"
            + "\n".join(cases) +
            f"\nend"
        )

    code = re.sub(
        r'while\s+true\s+do\s+(.*?)(?=\bend\b)',
        _rewrite_vm_loop,
        code,
        flags=re.DOTALL,
    )

    return code


def decrypt_prometheus_strings(code: str) -> str:
    """Detect and decrypt Prometheus string tables."""
    # Find string tables with encoded content
    table_pattern = re.compile(
        r'local\s+([A-Za-z_]\w*)\s*=\s*\{([^}]+)\}',
        re.DOTALL
    )

    for match in table_pattern.finditer(code):
        table_name, content = match.groups()

        # Check if this looks like an encoded string table
        if not re.search(r'\\\d{3}|\\x[0-9a-f]{2}|[^\x20-\x7E]', content):
            continue

        # Try to decode entries
        entries = re.split(r',\s*(?=")', content)
        decrypted_entries = []

        for entry in entries:
            entry = entry.strip().strip('"')
            if not entry:
                continue

            # Try to decode escape sequences
            try:
                # Lua decimal escapes
                decoded = re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))), entry)
                # Hex escapes
                decoded = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), decoded)
                # Unicode escapes
                decoded = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), decoded)
                decrypted_entries.append(f'"{decoded}"')
            except:
                decrypted_entries.append(f'"{entry}"')

        if decrypted_entries:
            # Replace table declaration with decoded version
            new_table = f"local {table_name} = {{\n  " + ",\n  ".join(decrypted_entries) + "\n}"
            code = code.replace(match.group(0), new_table)

    return code


def enhance_string_decryption(code: str) -> str:
    """Additional string decryption for _G-based calls."""
    # Pattern: _G[N]("\\ddd\\ddd...", offset)
    code = re.sub(
        r'_G\[(\d+)\]\("((?:\\\d{3})+)",([\d]+)\)',
        lambda m: f'"{_decode_decimal_string(m.group(2), int(m.group(3)))}"',
        code,
    )
    return code


def _decode_decimal_string(s: str, offset: int = 0) -> str:
    """Decode a string of decimal escape sequences."""
    try:
        bytes_list = []
        for m in re.finditer(r'\\(\d{1,3})', s):
            b = int(m.group(1))
            bytes_list.append((b - offset) % 256)
        return ''.join(chr(b) for b in bytes_list)
    except:
        return s


def resolve_memory_aliases(code: str) -> str:
    """Resolve memory/global/element aliases."""
    alias_pattern = r'\b(memory|global|element)\s*=\s*([\w_]+)(?:[\s;]+\2\s*=\s*nil\b)?'

    aliases = {}
    for match in re.finditer(alias_pattern, code):
        alias_type, var_name = match.groups()
        aliases[var_name] = alias_type

    # Remove alias declarations
    code = re.sub(alias_pattern, '', code)

    # Replace variable usage with alias type
    for var_name, alias_type in aliases.items():
        code = re.sub(rf'\b{re.escape(var_name)}\b', alias_type, code)

    return code


def handle_antitamper_prometheus(code: str) -> str:
    """Remove Prometheus-specific anti-tamper patterns."""
    # Remove valid=true checks
    code = re.sub(
        r'local valid\s*=\s*true;.*?if valid then else.*?end',
        'local valid = true;',
        code,
        flags=re.DOTALL,
    )

    # Remove function wrappers that just return strings
    code = re.sub(
        r'local function \w+\(.*?\)\s*return "[^"]+"\s*end',
        '',
        code,
        flags=re.DOTALL,
    )

    # Remove dead error calls
    code = re.sub(
        r'\b\w+\s*=\s*error\s*\(\s*\w+\s*\)\s*;?',
        '',
        code,
    )

    return code


def remove_junkcode_prometheus(code: str) -> str:
    """Remove Prometheus junk code patterns."""
    patterns = [
        (r'local function \w+\(.*?\)\s*return "[^"]+"\s*end', '', re.DOTALL),
        (r'if \w+==-\d+then \w+=-\d+end', ''),
        (r'\b\w+=\w+[%+\-/*](?:-?\d+|\(-?\d+[%+\-/*]-?\d+\))', ''),
        (r'\w+\.\w+=(?:nil|-\d+|"")', ''),
        (r'for \w+=-\d+,#\w+,-?\d+do end', ''),
        (r'local \w+=(?:-?\d+|nil)(?=\s*[^\n])', ''),
        (r'\w+\.\w+,\w+\.\w+=nil,nil', ''),
        (r'function\(\.\.\.\)\s*return \{\}\s*end', ''),
        (r'-\s*\[\[.*?\]\]', '', re.DOTALL),
        (r'\b(\w+)=\1[+-]\d+\b', ''),
        (r'\b\w+=\w+[+-]\(\d+\)\s*$', '', re.MULTILINE),
    ]

    for pattern, replacement, *flags in patterns:
        flag = flags[0] if flags else 0
        code = re.sub(pattern, replacement, code, flags=flag)

    return code


def clean_tokenized_syntax_prometheus(code: str) -> str:
    """Clean up tokenized/syntax-noisy code."""
    # Remove block comments
    code = re.sub(r'--\[\[.*?\]\]', '', code, flags=re.DOTALL)
    # Remove line comments
    code = re.sub(r'--.*', '', code)
    # Fix line continuations
    code = re.sub(r'\\\n', '', code)
    # Fix spacing around equals
    code = re.sub(r'(\w)\s*=\s*(\w)', r'\1=\2', code)
    # Fix string concatenation
    code = re.sub(r'"\s*\.\.\s*"', '""', code)
    # Remove empty lines
    code = re.sub(r'\n{3,}', '\n\n', code)

    return code


def reconstruct_functions_prometheus(code: str) -> str:
    """Reconstruct obfuscated function declarations."""
    # Fix function(...)(...)end(...) patterns
    code = re.sub(
        r'function\(\.\.\.\)(.*)end\(\.\.\.\)',
        lambda m: m.group(1),
        code,
        flags=re.DOTALL,
    )

    # Fix vararg patterns
    code = re.sub(r',\s*\.\.\.|\.\.\.\s*,', '', code)
    code = re.sub(r'\(\s*\.\.\.\s*\.\.\.\s*\)', '(...)', code)

    # Fix function parameter formatting
    code = re.sub(
        r'function\(([^)]*)\)',
        lambda m: f"function({','.join(p.strip() for p in m.group(1).split(','))})",
        code,
    )

    return code


def restore_control_flow_prometheus(code: str) -> str:
    """Restore flattened control flow."""
    # Fix else if -> elseif
    code = re.sub(r'else\s+if', 'elseif', code)

    # Fix if/then spacing
    code = re.sub(r'(\bif\b.*?)\s*\n\s*(\bthen\b)', r'\1 \2', code, flags=re.DOTALL)

    # Fix return formatting
    code = re.sub(r'return\s+(\w+)\(\)', r'return \1()', code)

    return code


def demangle_variables_prometheus(code: str) -> str:
    """Demangle common Prometheus variable names."""
    var_map = {
        'V': 'table', 'f': 'function', 'R': 'string', 'O': 'math',
        'N': 'number', 'X': 'char', 'G': 'table.insert',
        'p': 'string.sub', 'i': 'string.concat',
        'H': 'table', 'Y': 'io.read', 'q': 'io.write',
        'y': 'position', 't': 'accumulator', 'K': 'bit32',
        'J': 'table', 'W': 'window', 'm': 'match',
        'C': 'char', 'Z': 'temp', 'Q': 'flag',
        'P': 'number', 'L': 'for', 'F': 'string.format',
        'D': 'buffer', 'B': 'byte', 'A': 'array',
        'S': 'state', 'T': 'type', 'U': 'string',
        'E': 'error', 'I': 'io', 'M': 'math.max',
        'k': 'key', 'j': 'goto', 'w': 'number',
        'z': 'zone', 'x': 'x', 'c': 'char',
        'v': 'version', 'b': 'buffer', 'n': 'count',
        'u': 'user', 'l': 'list', 'g': 'global',
        'd': 'pointer', 's': 'string', 'r': 'result',
        'o': 'object', 'h': 'handle', 'e': 'element',
        'a': 'array',
    }

    for obf, clean in var_map.items():
        code = re.sub(rf'\b{obf}\b', clean, code)

    return code


def handle_string_splitting_prometheus(code: str) -> str:
    """Handle table.concat string splitting patterns."""
    # table.concat({"part1", "part2", ...}) -> "part1part2..."
    code = re.sub(
        r'table\.concat\(\{([^}]+)\}\)',
        lambda m: '"' + ''.join(re.findall(r'"([^"]*)"', m.group(1))) + '"',
        code,
    )

    return code


class PrometheusVMDevirtualizer:
    """Main class for Prometheus VM devirtualization."""

    def __init__(self, source: str):
        self.source = source
        self.code = source

    def devirtualize(self) -> Optional[str]:
        """Run the full Prometheus devirtualization pipeline."""
        try:
            self.code = handle_antitamper_prometheus(self.code)
            self.code = remove_junkcode_prometheus(self.code)
            self.code = clean_tokenized_syntax_prometheus(self.code)
            self.code = reverse_vmify(self.code)
            self.code = handle_prometheus_vm(self.code)
            self.code = decrypt_prometheus_strings(self.code)
            self.code = enhance_string_decryption(self.code)
            self.code = resolve_memory_aliases(self.code)
            self.code = reconstruct_functions_prometheus(self.code)
            self.code = restore_control_flow_prometheus(self.code)
            self.code = demangle_variables_prometheus(self.code)
            self.code = handle_string_splitting_prometheus(self.code)

            # Final cleanup
            self.code = re.sub(r'\n{3,}', '\n\n', self.code)
            self.code = re.sub(r'^\s*\n+', '', self.code)

            if len(self.code) > 50:
                return self.code
            return None
        except Exception as e:
            log.error(f"Prometheus devirtualization failed: {e}")
            return None


def is_prometheus_vm(source: str) -> bool:
    """Check if source looks like a Prometheus/WeAreDevs VM."""
    indicators = [
        r'while\s+true\s+do\s+local\s+\w+\s*=\s*\w+\[\w+\]',
        r'if\s+\w+\s*==\s*\d+\s+then',
        r'accumulator\s*\[\s*\d+\s*\]',
        r'local\s+alphaMap\s*=\s*\{',
        r'wearedevs\.net/obfuscator',
        r'ipairs\s*\(\s*\{\s*\{',
        r'vmState\s*\[\s*\d+\s*\]',
    ]

    score = 0
    for pattern in indicators:
        if re.search(pattern, source):
            score += 1

    return score >= 2
