import re
import json
from typing import Optional, List

class InstructionTableDumper:
    def __init__(self, source: str, decoded_strings: List[str]):
        self.source = source
        self.strings = decoded_strings

    def dump(self) -> Optional[str]:
        results = []
        results.append("-- Decoded String Table")
        results.append(f"-- {len(self.strings)} strings decoded")
        results.append("")
        results.append("local R = {")
        for i, s in enumerate(self.strings):
            if s:
                escaped = json.dumps(s)
                results.append(f"\t[{i + 1}] = {escaped},")
        results.append("}")
        results.append("")
        results.append("-- SOURCE RECONSTRUCTION")
        results.append("")
        reconstructed = self._reconstruct_source()
        if reconstructed:
            results.append(reconstructed)
        else:
            results.append("-- Could not reconstruct source from decoded strings")
            results.append("-- Strings found in source context:")
            results.append("")
            results.extend(self._find_string_context())
            results.append("")
            results.append("-- Possible payload reconstruction:")
            results.append("")
            results.extend(self._analyze_strings())
        return "\n".join(results)

    def _reconstruct_source(self) -> Optional[str]:
        source = self.source
        source = self._strip_bootstrap(source)
        getter_name, offset_const = self._detect_getter(source)
        if not getter_name:
            return None
        for i, s in enumerate(self.strings):
            if s:
                escaped = s.replace('\\', '\\\\').replace('"', '\\"')
                source = source.replace(f'R[{i + 1}]', f'"{escaped}"')
        replaced = 0
        def repl(m):
            nonlocal replaced
            try:
                expr = m.group(1).strip()
                n = self._eval_arithmetic(expr)
                if n is None:
                    return m.group(0)
                idx = n + offset_const
                if 1 <= idx <= len(self.strings):
                    s = self.strings[idx - 1]
                    if s:
                        replaced += 1
                        escaped = s.replace('\\', '\\\\').replace('"', '\\"')
                        return f'"{escaped}"'
            except:
                pass
            return m.group(0)
        source = re.sub(rf'{getter_name}\s*\(\s*([^)]+?)\s*\)', repl, source)
        if replaced > 0 and f'{getter_name}(' not in source:
            source = self._strip_string_table(source)
            source = re.sub(r'local\s+function\s+' + getter_name + r'\s*\([^)]*\)\s*return\s+R\s*\[[^\]]+\]\s*end', ' ', source)
            return source
        return None

    def _eval_arithmetic(self, expr: str) -> Optional[int]:
        try:
            cleaned = expr.replace(' ', '').replace('\t', '').replace('\n', '')
            return self._simple_eval(cleaned)
        except:
            return None

    def _simple_eval(self, expr: str) -> int:
        expr = expr.strip()
        while '(' in expr:
            expr = re.sub(r'\(([^()]+)\)', lambda m: str(self._eval_simple_expr(m.group(1))), expr)
        return self._eval_simple_expr(expr)

    def _eval_simple_expr(self, expr: str) -> int:
        expr = expr.replace('--', '+').replace('+-', '-').replace('-+', '-').replace('++', '+')
        tokens = re.findall(r'[+\-]?\d+', expr)
        if tokens:
            return sum(int(t) for t in tokens)
        return 0

    def _strip_bootstrap(self, code: str) -> str:
        markers = ['return(function(R,M,Y,r,m,N,h,d,o,l,q,I,w,g', 'return(function(']
        for marker in markers:
            pos = code.find(marker)
            if pos != -1:
                return code[pos:]
        return code

    def _strip_string_table(self, code: str) -> str:
        return re.sub(r'local\s+R\s*=\s*\{[^}]*\}', '', code, flags=re.DOTALL)

    def _detect_getter(self, source: str):
        from math_fold import fold_constants
        folded = fold_constants(source)
        m = re.search(r'local\s+function\s+(\w+)\s*\(\s*\1\s*\)\s*return\s+R\s*\[\s*\1\s*\+\s*\(?(-?\d+)\)?\s*\]', folded)
        if m:
            name = m.group(1)
            val = int(m.group(2))
            return name, val
        m = re.search(r'local\s+function\s+(\w+)\s*\(\s*\1\s*\)\s*return\s+R\s*\[\s*\1\s*\+\s*(-?\d+)\s*\]', folded)
        if m:
            name = m.group(1)
            val = int(m.group(2))
            return name, val
        for name in ['E', 'GetStr', 'GetString', 'l1', 'l2']:
            m = re.search(rf'local\s+function\s+{name}\s*\(\s*{name}\s*\)\s*return\s+R\s*\[\s*{name}\s*\+\s*\(?(-?\d+)\)?\s*\]', folded)
            if m:
                return name, int(m.group(1))
        return None, 0

    def _find_string_context(self) -> List[str]:
        lines, seen = [], set()
        for pattern in ['E(', 'l1(', 'l2(', 'GetStr(', 'R[', 'EncStr']:
            for m in re.finditer(re.escape(pattern), self.source):
                start, end = max(0, m.start() - 40), min(len(self.source), m.end() + 80)
                ctx = self.source[start:end].replace('\n', ' ').strip()
                if ctx not in seen:
                    seen.add(ctx)
                    lines.append(f"-- {ctx}")
                if len(lines) >= 15:
                    break
            if lines:
                break
        return lines

    def _analyze_strings(self) -> List[str]:
        lines = []
        known = ['print', 'pcall', 'tostring', 'tonumber', 'error', 'math', 'table', 'string',
                 'floor', 'char', 'concat', 'gsub', 'byte', 'len', 'gmatch',
                 'unpack', 'select', 'type', 'assert', 'require', 'loadstring', 'load']
        functions = [s for s in self.strings if s in known]
        others = [s for s in self.strings if s and s not in known and len(s) > 1]
        lines.append("-- Likely function calls:")
        for f in functions:
            lines.append(f"-- {f}(...)")
        lines.append("")
        lines.append("-- Other decoded strings:")
        for s in others:
            lines.append(f"-- {json.dumps(s)}")
        return lines
