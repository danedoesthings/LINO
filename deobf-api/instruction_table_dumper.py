import re
import json
from typing import Optional, List


class InstructionTableDumper:
    def __init__(self, source: str, decoded_strings: List[str]):
        self.source = source
        self.strings = decoded_strings

    def dump(self) -> Optional[str]:
        results = []
        results.append("-- Instruction Table Dump")
        results.append(f"-- {len(self.strings)} decoded strings available")
        results.append("")

        instr_patterns = [
            r'instrTbl\s*\[\s*(\w+)\s*\]\s*=\s*"([^"]*)"',
            r'instrTbl\s*\[\s*(\w+)\s*\]\s*=\s*\'([^\']*)\'',
            r'instrTbl\s*\[\s*(\d+)\s*\]\s*=\s*"([^"]*)"',
            r'instrTbl\s*\[\s*(\d+)\s*\]\s*=\s*\'([^\']*)\'',
            r'(\w+)\s*\[\s*(\w+)\s*\]\s*=\s*"([^"]*)"',
            r'(\w+)\s*\[\s*(\w+)\s*\]\s*=\s*\'([^\']*)\'',
        ]

        found_any = False
        for pattern in instr_patterns:
            for m in re.finditer(pattern, self.source):
                found_any = True
                key = m.group(1)
                val = m.group(2) if len(m.groups()) == 2 else m.group(3)
                results.append(f"-- instrTbl[{key}] = \"{val}\"")

        if not found_any:
            results.append("-- No instruction table entries found directly")
            results.append("-- Searching for string references to decoded strings...")
            results.append("")

            for i, s in enumerate(self.strings):
                if s and len(s) > 3 and s in self.source:
                    escaped = s.replace('\\', '\\\\').replace('"', '\\"')
                    results.append(f"-- string[{i}] = \"{escaped}\"")

        results.append("")
        results.append("-- All decoded strings:")
        for i, s in enumerate(self.strings):
            if s:
                escaped = s.replace('\\', '\\\\').replace('"', '\\"')
                results.append(f"R[{i + 1}] = \"{escaped}\"")

        return "\n".join(results)
