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
        source = self._strip_string_table(source)

        for i, s in enumerate(self.strings):
            if s:
                escaped = s.replace('\\', '\\\\').replace('"', '\\"')
                source = source.replace(f'R[{i + 1}]', f'"{escaped}"')
                source = source.replace(f'R[ {i + 1} ]', f'"{escaped}"')
                source = source.replace(f'R["{i + 1}"]', f'"{escaped}"')

        getter_name, offset_const = self._detect_getter(source)
        if getter_name:
            def repl(m):
                try:
                    n = int(m.group(1))
                    idx = n + offset_const
                    if 1 <= idx <= len(self.strings):
                        s = self.strings[idx - 1]
                        if s:
                            return f'"{s}"'
                except:
                    pass
                return m.group(0)
            source = re.sub(rf'{getter_name}\s*\(\s*(-?\d+)\s*\)', repl, source)

        if 'R[' in source or 'GetStr(' in source or 'E(' in source:
            return None
        if 'function' in source or 'local' in source or 'print' in source:
            return source
        return None

    def _strip_bootstrap(self, code: str) -> str:
        markers = [
            'return(function(R,M,Y,r,m,N,h,d,o,l,q,I,w,g',
            'return(function(',
        ]
        for marker in markers:
            pos = code.find(marker)
            if pos != -1:
                return code[pos:]
        return code

    def _strip_string_table(self, code: str) -> str:
        code = re.sub(r'local\s+R\s*=\s*\{[^}]*\}', '', code, flags=re.DOTALL)
        return code

    def _detect_getter(self, source: str):
        for name in ['E', 'GetStr', 'GetString', 'l1', 'l2']:
            m = re.search(rf'local\s+function\s+{name}\s*\(\s*{name}\s*\)\s*return\s+R\s*\[\s*{name}\s*\+\s*\(?(-?\d+)\)?\s*\]', source)
            if m:
                return name, int(m.group(1))
            m = re.search(rf'local\s+{name}\s*=\s*function\s*\([^)]*\)\s*return\s+R\s*\[[^\]]*\+\s*\(?(-?\d+)\)?\s*\]', source)
            if m:
                return name, int(m.group(1))
        return None, 0

    def _find_string_context(self) -> List[str]:
        lines = []
        for pattern in ['EncStr', 'R[', 'E(', 'GetStr(', 'l1(', 'l2(']:
            for m in re.finditer(re.escape(pattern), self.source):
                start = max(0, m.start() - 30)
                end = min(len(self.source), m.end() + 80)
                ctx = self.source[start:end].replace('\n', ' ')
                lines.append(f"-- {ctx}")
                if len(lines) > 20:
                    break
            if lines:
                break
        return lines

    def _analyze_strings(self) -> List[str]:
        lines = []
        known = ['print', 'pcall', 'tostring', 'tonumber', 'error', 'math', 'table',
                 'string', 'floor', 'char', 'concat', 'gsub', 'byte', 'len', 'gmatch',
                 'unpack', 'select', 'type', 'assert', 'require', 'loadstring', 'load']
        functions = [s for s in self.strings if s in known]
        others = [s for s in self.strings if s and s not in known and len(s) > 1]

        lines.append("-- Likely function calls:")
        for f in functions:
            lines.append(f"--   {f}(...)")

        lines.append("")
        lines.append("-- Other decoded strings (likely arguments or values):")
        for s in others:
            lines.append(f"--   {json.dumps(s)}")

        return lines
