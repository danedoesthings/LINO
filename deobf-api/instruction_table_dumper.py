import re
import json
from typing import Optional, List
from math_fold import safe_eval_int, fold_constants

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
        getter_name, offset_const = self._detect_getter(self.source)
        if getter_name and offset_const:
            results.append(f"-- Detected getter: {getter_name}(N + {offset_const})")
            results.append("")
            reconstructed = self._reconstruct_source(getter_name, offset_const)
            if reconstructed:
                results.append("-- SOURCE RECONSTRUCTION (getter calls resolved)")
                results.append("")
                results.append(reconstructed)
                return "\n".join(results)
        results.append("-- SOURCE RECONSTRUCTION")
        results.append("")
        results.append("-- Could not reconstruct source from decoded strings")
        results.append("-- Strings found in source context:")
        results.append("")
        results.extend(self._find_string_context())
        results.append("")
        results.append("-- Possible payload reconstruction:")
        results.append("")
        results.extend(self._analyze_strings())
        return "\n".join(results)

    def _reconstruct_source(self, getter_name: str, offset_const: int) -> Optional[str]:
        source = self.source
        replaced = 0
        def repl(m):
            nonlocal replaced
            try:
                expr = m.group(1).strip()
                n = safe_eval_int(expr)
                if n is None:
                    return m.group(0)
                idx = n + offset_const
                if 1 <= idx <= len(self.strings):
                    s = self.strings[idx - 1]
                    if s:
                        replaced += 1
                        escaped = json.dumps(s)
                        return escaped
            except:
                pass
            return m.group(0)
        source = re.sub(rf'{re.escape(getter_name)}\s*\(\s*([^)]+?)\s*\)', repl, source)
        if replaced > 0:
            return source
        return None

    def _detect_getter(self, source: str):
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
                 'unpack', 'select', 'type', 'assert', 'require', 'loadstring', 'load',
                 'setmetatable', 'getmetatable', 'newproxy', 'getfenv', 'setfenv']
        functions = [s for s in self.strings if s in known]
        others = [s for s in self.strings if s and s not in known and len(s) > 1 and not s.startswith('__')]
        payload_hints = [s for s in others if any(kw in s.lower() for kw in ['http', 'require', 'load', 'game', 'print', 'get', 'set', 'fire', 'hook', 'chat', 'player', 'gui', 'teleport'])]
        lines.append("-- Likely function calls:")
        for f in functions:
            lines.append(f"-- {f}(...)")
        if payload_hints:
            lines.append("")
            lines.append("-- Possible payload-related strings:")
            for s in payload_hints:
                lines.append(f"-- {json.dumps(s)}")
        lines.append("")
        lines.append("-- Other decoded strings:")
        for s in others:
            if s not in payload_hints:
                lines.append(f"-- {json.dumps(s)}")
        return lines
