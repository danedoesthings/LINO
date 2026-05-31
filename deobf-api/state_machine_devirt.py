import re
import ast
from typing import Optional, Dict, List, Tuple, Any

class ExpressionFolder:
    @staticmethod
    def fold_math_expressions(text: str) -> str:
        def evaluate_match(match):
            expr_str = match.group(0).strip()
            try:
                node = ast.parse(expr_str, mode='eval')
                if ExpressionFolder._is_safe_node(node.body):
                    val = eval(compile(node, filename='', mode='eval'))
                    if isinstance(val, (int, float)):
                        return str(int(val))
            except Exception:
                pass
            return expr_str

        for _ in range(8):
            prev = text
            text = re.sub(r'\(([-+]?\d+(?:\s*[-+*/%^]\s*[-+]?\d+)+)\)', evaluate_match, text)
            text = re.sub(r'\b([-+]?\d+(?:\s*[-+*/%^]\s*[-+]?\d+)+)\b', evaluate_match, text)
            if text == prev:
                break
        return text

    @staticmethod
    def _is_safe_node(node) -> bool:
        if isinstance(node, (ast.Num, ast.Constant)):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow)):
            return ExpressionFolder._is_safe_node(node.left) and ExpressionFolder._is_safe_node(node.right)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            return ExpressionFolder._is_safe_node(node.operand)
        return False


class HighLevelDevirtualizer:
    @staticmethod
    def devirtualize(flat_code: str) -> str:
        lines = flat_code.split('\n')
        high_level_lines = []
        symbolic_stack: Dict[str, str] = {}

        for line in lines:
            trimmed = line.strip()
            if not trimmed:
                continue

            if any(k in trimmed for k in ["instrTbl", "shuffleTbl", "allocSlot", "tokenMap", "cleanRef", "funcWrap", "helperG"]):
                continue

            if "vmStack[" in trimmed and "vmState" in trimmed:
                continue

            if '=' in trimmed and not (trimmed.startswith('if') or trimmed.startswith('while')):
                parts = trimmed.split('=', 1)
                targets = [t.strip() for t in parts[0].split(',')]
                exprs = [e.strip() for e in parts[1].split(',')]

                for i, target in enumerate(targets):
                    if i >= len(exprs):
                        break
                    expr_val = exprs[i]

                    for stored_reg, stored_val in list(symbolic_stack.items()):
                        expr_val = re.sub(rf'\bvmStack\[{re.escape(stored_reg)}\]', stored_val, expr_val)

                    stack_target_match = re.match(r'^vmStack\[(\w+)\]$', target)
                    if stack_target_match:
                        reg_id = stack_target_match.group(1)
                        symbolic_stack[reg_id] = expr_val
                    else:
                        for stored_reg, stored_val in list(symbolic_stack.items()):
                            target = re.sub(rf'\bvmStack\[{re.escape(stored_reg)}\]', stored_val, target)
                        if target not in ("GetStr", "") and "vmState" not in target:
                            high_level_lines.append(f"{target} = {expr_val}")
                continue

            call_match = re.match(r'^vmStack\[(\w+)\]\s*\((.*)\)$', trimmed)
            if call_match:
                func_reg = call_match.group(1)
                args_raw = call_match.group(2)
                func_name = symbolic_stack.get(func_reg, f"vmStack[{func_reg}]")

                resolved_args = []
                if args_raw:
                    for arg in [a.strip() for a in args_raw.split(',')]:
                        reg_lookup = re.match(r'^vmStack\[(\w+)\]$', arg)
                        if reg_lookup and reg_lookup.group(1) in symbolic_stack:
                            resolved_args.append(symbolic_stack[reg_lookup.group(1)])
                        else:
                            for stored_reg, stored_val in list(symbolic_stack.items()):
                                arg = re.sub(rf'\bvmStack\[{re.escape(stored_reg)}\]', stored_val, arg)
                            resolved_args.append(arg)

                high_level_lines.append(f"{func_name}({', '.join(resolved_args)})")
                continue

            for stored_reg, stored_val in list(symbolic_stack.items()):
                trimmed = re.sub(rf'\bvmStack\[{re.escape(stored_reg)}\]', stored_val, trimmed)

            if trimmed and not (trimmed.startswith("if vmState") or "vmStack[" in trimmed or "GetStr" in trimmed or "instrTbl" in trimmed):
                high_level_lines.append(trimmed)

        return '\n'.join(high_level_lines)


class LuaBeautifier:
    @staticmethod
    def beautify(code: str) -> str:
        code = re.sub(r'(\w+)\s*\[\s*(\w+)\s*\]', r'\1[\2]', code)
        code = re.sub(r'\s*(==|<=|>=|~=)\s*', r' \1 ', code)
        code = re.sub(r'(?<![=<>~])\s*([=+\-*/%^,])\s*(?![=<>~])', r' \1 ', code)
        code = re.sub(r'\bif\s+', 'if ', code)
        code = re.sub(r'\s+then\b', ' then', code)
        code = re.sub(r' +', ' ', code)
        code = re.sub(r' , ', ', ', code)

        lines = code.split('\n')
        indent_level = 0
        formatted_lines = []

        for line in lines:
            trimmed = line.strip()
            if not trimmed:
                continue

            if trimmed.startswith('end') or trimmed.startswith('else') or trimmed.startswith('elseif'):
                indent_level = max(0, indent_level - 1)

            formatted_lines.append('    ' * indent_level + trimmed)

            if trimmed.endswith('then') or trimmed.endswith('do') or trimmed.startswith('else') or trimmed.startswith('elseif'):
                indent_level += 1

        return '\n'.join(formatted_lines)


class StateMachineLifter:
    def __init__(self, source: str, decoded_strings: list = None):
        self.source = source
        self.strings = decoded_strings if decoded_strings else []
        self.state_var = "vmState"
        self.state_to_block: Dict[int, str] = {}
        self.transitions: Dict[int, Any] = {}
        self.entry_state: Optional[int] = None

    def lift(self) -> Optional[str]:
        self._find_state_var()
        loop_body = self._get_loop_body()
        if not loop_body:
            return None

        blocks = self._parse_nested_tree(loop_body)
        if not blocks:
            return None

        self._map_states_to_blocks(blocks, loop_body)
        if not self.state_to_block:
            return None

        self._analyze_transitions()
        self._find_entry_state()

        return self._emit_linear_code()

    def _find_state_var(self):
        m = re.search(r'while\s+(\w+)\s+do', self.source)
        if m:
            self.state_var = m.group(1)

    def _get_loop_body(self) -> Optional[str]:
        pattern = rf'while\s+{re.escape(self.state_var)}\s+do\s*(.*?)\s*end\s*(?:$|\n)'
        m = re.search(pattern, self.source, re.DOTALL)
        if m:
            return m.group(1)
        return None

    def _parse_nested_tree(self, loop_body: str) -> List[Tuple[List[Tuple[str, int, bool]], str]]:
        lines = loop_body.split('\n')
        stack: List[Tuple[str, int, bool]] = []
        blocks: List[Tuple[List[Tuple[str, int, bool]], str]] = []
        current_lines: List[str] = []
        internal_if_depth = 0

        for line in lines:
            trimmed = line.strip()
            if not trimmed:
                continue

            if_match = re.match(rf'^if\s+{re.escape(self.state_var)}\s*(<|<=|>|>=|==)\s*(-?\d+)\s*then', trimmed)
            elseif_match = re.match(rf'^elseif\s+{re.escape(self.state_var)}\s*(<|<=|>|>=|==)\s*(-?\d+)\s*then', trimmed)

            if if_match and internal_if_depth == 0:
                if current_lines:
                    blocks.append((list(stack), '\n'.join(current_lines)))
                    current_lines = []
                op, val = if_match.group(1), int(if_match.group(2))
                stack.append((op, val, False))

            elif elseif_match and internal_if_depth == 0:
                if current_lines:
                    blocks.append((list(stack), '\n'.join(current_lines)))
                    current_lines = []
                op, val = elseif_match.group(1), int(elseif_match.group(2))
                if stack:
                    prev_op, prev_val, _ = stack.pop()
                    stack.append((prev_op, prev_val, True))
                stack.append((op, val, False))

            elif trimmed == 'else':
                if internal_if_depth == 0:
                    if current_lines:
                        blocks.append((list(stack), '\n'.join(current_lines)))
                        current_lines = []
                    if stack:
                        op, val, _ = stack.pop()
                        stack.append((op, val, True))
                else:
                    current_lines.append(line)

            elif trimmed == 'end':
                if internal_if_depth > 0:
                    internal_if_depth -= 1
                    current_lines.append(line)
                else:
                    if current_lines:
                        blocks.append((list(stack), '\n'.join(current_lines)))
                        current_lines = []
                    if stack:
                        stack.pop()
            else:
                if re.match(r'^if\s', trimmed) and not if_match:
                    internal_if_depth += 1
                current_lines.append(line)

        if current_lines:
            blocks.append((list(stack), '\n'.join(current_lines)))

        return blocks

    def _map_states_to_blocks(self, blocks: list, loop_body: str):
        all_ids = set()
        for num_str in re.findall(r'-?\d+', loop_body):
            try:
                all_ids.add(int(num_str))
            except ValueError:
                pass

        def satisfies(sid: int, constraints: List[Tuple[str, int, bool]]) -> bool:
            for op, val, inverted in constraints:
                if op == '<': result = sid < val
                elif op == '<=': result = sid <= val
                elif op == '>': result = sid > val
                elif op == '>=': result = sid >= val
                elif op == '==': result = sid == val
                else: result = True

                if inverted:
                    result = not result
                if not result:
                    return False
            return True

        for constraints, block_code in blocks:
            clean_code = block_code.strip()
            if not clean_code or clean_code in ('else', 'end', 'then'):
                continue
            for sid in all_ids:
                if satisfies(sid, constraints):
                    existing = self.state_to_block.get(sid, '')
                    if len(clean_code) > len(existing):
                        self.state_to_block[sid] = clean_code

    def _analyze_transitions(self):
        for sid, block in self.state_to_block.items():
            cond_match = re.search(
                rf'{re.escape(self.state_var)}\s*=\s*(.+?)\s+and\s+(-?\d+)\s+or\s+(-?\d+)',
                block
            )
            if cond_match:
                self.transitions[sid] = ('cond', cond_match.group(1).strip(),
                                         int(cond_match.group(2)), int(cond_match.group(3)))
                continue

            assigns = list(re.finditer(rf'{re.escape(self.state_var)}\s*=\s*(-?\d+)', block))
            if assigns:
                self.transitions[sid] = ('simple', int(assigns[-1].group(1)))
            else:
                self.transitions[sid] = ('terminal', None)

    def _find_entry_state(self):
        all_targets = set()
        for t_info in self.transitions.values():
            if t_info[0] == 'simple':
                all_targets.add(t_info[1])
            elif t_info[0] == 'cond':
                all_targets.add(t_info[2])
                all_targets.add(t_info[3])

        sources = set(self.state_to_block.keys())
        potential_entries = sources - all_targets

        if potential_entries:
            self.entry_state = list(potential_entries)[0]
        else:
            self.entry_state = min(self.state_to_block.keys()) if self.state_to_block else None

    def _emit_linear_code(self) -> str:
        visited: set[int] = set()
        output_lines: List[str] = []

        def trace(sid: int, indent: int = 0):
            if sid in visited or sid not in self.state_to_block:
                return
            visited.add(sid)

            block = self.state_to_block[sid]
            clean_block = re.sub(
                rf'[ \t]*{re.escape(self.state_var)}\s*=\s*[^;\n]+[;\n]?', '', block
            ).strip()

            if clean_block:
                for line in clean_block.split('\n'):
                    stripped = line.strip()
                    if stripped:
                        output_lines.append(stripped)

            t_info = self.transitions.get(sid)
            if not t_info:
                return

            t_type = t_info[0]
            if t_type == 'simple':
                trace(t_info[1], indent)
            elif t_type == 'cond':
                cond, left_sid, right_sid = t_info[1], t_info[2], t_info[3]
                clean_cond = self._resolve_string_refs(cond)
                output_lines.append(f'if {clean_cond} then')
                trace(left_sid, indent + 1)
                output_lines.append('else')
                trace(right_sid, indent + 1)
                output_lines.append('end')

        if self.entry_state is not None:
            trace(self.entry_state)

        raw_output = '\n'.join(output_lines)
        resolved_strings = self._resolve_string_refs(raw_output)
        folded_math = ExpressionFolder.fold_math_expressions(resolved_strings)
        high_level_lua = HighLevelDevirtualizer.devirtualize(folded_math)
        return LuaBeautifier.beautify(high_level_lua)

    def _resolve_string_refs(self, code: str) -> str:
        def repl(m):
            n = int(m.group(1))
            if 1 <= n <= len(self.strings):
                s = self.strings[n - 1]
                if s:
                    return repr(s)
            return m.group(0)

        code = re.sub(r'\bGetStr\s*\(\s*(\d+)\s*\)', repl, code)
        return re.sub(r'\bGetStr\s*\[\s*(\d+)\s*\]', repl, code)
