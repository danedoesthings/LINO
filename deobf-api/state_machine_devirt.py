import re

class StateMachineLifter:
    def __init__(self, source: str, decoded_strings: list = None):
        self.source = source
        self.strings = decoded_strings if decoded_strings else []

    def lift(self) -> str | None:
        resolved_code = self._resolve_getstr(self.source)

        output = [
            "-- [VM EMULATOR DETECTED]",
            "-- String extraction applied statically.",
            ""
        ]
        output.append(resolved_code)
        return '\n'.join(output)

    def _resolve_getstr(self, code: str) -> str:
        offset_constant = 0
        m_offset = re.search(r'GetStr\s*\+\s*\(?\s*(\d+)\s*\)?', code)
        if m_offset:
            offset_constant = int(m_offset.group(1))

        def repl(m):
            try:
                offset = int(m.group(1))
                idx = offset + offset_constant - 1
                if 0 <= idx < len(self.strings):
                    s = self.strings[idx]
                    if s is not None:
                        escaped_str = str(s).replace('\\', '\\\\').replace('"', '\\"')
                        return f'"{escaped_str}"'
            except Exception:
                pass
            return m.group(0)

        return re.sub(r'GetStr\s*\(\s*(-?\d+)\s*\)', repl, code)
