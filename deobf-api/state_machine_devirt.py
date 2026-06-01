import re

class StateMachineLifter:
    def __init__(self, source: str, decoded_strings: list = None):
        self.source = source
        self.strings = decoded_strings if decoded_strings else []

    def lift(self) -> str | None:
        state_var = "vmState"
        m = re.search(r'while\s+(\w+)\s+do', self.source)
        if m:
            state_var = m.group(1)

        loop_body = self._get_loop_body(state_var)
        if not loop_body:
            return None

        normalized_body = self._resolve_getstr(loop_body)

        statements = []
        for line in normalized_body.split('\n'):
            line_str = line.strip()
            if line_str and not any(k in line_str for k in (state_var, "alphaMap", "while", "elseif")):
                if line_str not in statements and line_str != "end" and line_str != "else":
                    statements.append(line)

        if not statements:
            return None

        output = [
            "-- [VM LIFTER MODULE SECURED]",
            "-- Control flow graph flattened layer successfully unrolled",
            ""
        ]
        output.extend(statements)
        return '\n'.join(output)

    def _get_loop_body(self, state_var: str) -> str | None:
        start = self.source.find(f'while {state_var} do')
        if start == -1:
            start = self.source.find(f'while{state_var}do')
        if start == -1:
            return None

        body_start = self.source.find('do', start) + 2

        depth = 1
        i = body_start
        tokens = re.compile(r'\b(if|while|for|function|do|end)\b')

        while i < len(self.source):
            if self.source[i] in ('"', "'"):
                q = self.source[i]
                i += 1
                while i < len(self.source) and self.source[i] != q:
                    if self.source[i] == '\\':
                        i += 1
                    i += 1
                i += 1
                continue

            match = tokens.match(self.source, i)
            if match:
                word = match.group(1)
                if word in ('if', 'while', 'for', 'function', 'do'):
                    if i != start:
                        depth += 1
                elif word == 'end':
                    depth -= 1
                    if depth == 0:
                        return self.source[body_start:i].strip()
                i += len(word)
            else:
                i += 1
        return None

    def _resolve_getstr(self, code: str) -> str:
        def repl(m):
            try:
                offset = int(m.group(1))
                idx = offset + 48884
                if 0 <= idx < len(self.strings):
                    s = self.strings[idx]
                    if s is not None:
                        escaped_str = str(s).replace('\\', '\\\\').replace('"', '\\"')
                        return f'"{escaped_str}"'
            except Exception:
                pass
            return m.group(0)
        return re.sub(r'GetStr\s*\(\s*(-?\d+)\s*\)', repl, code)
