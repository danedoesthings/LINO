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

        results.append("-- Strings found in source context:")
        results.append("")

        encstr_patterns = [
            r'EncStr\s*\[\s*"([^"]+)"\s*\]',
            r"EncStr\s*\[\s*'([^']+)'\s*\]",
            r'EncStr\s*\[\s*(\w+)\s*\]',
        ]

        found_strings = set()
        for pattern in encstr_patterns:
            for m in re.finditer(pattern, self.source):
                key = m.group(1)
                found_strings.add(key)
                matching = [s for s in self.strings if s == key]
                if matching:
                    idx = self.strings.index(key) + 1
                    results.append(f"-- EncStr[\"{key}\"] -> R[{idx}] = {json.dumps(key)}")
                else:
                    results.append(f"-- EncStr[\"{key}\"] -> (not in decoded strings)")

        results.append("")
        results.append("-- Possible payload reconstruction:")
        results.append("")

        important_strings = [s for s in self.strings if s and len(s) > 2 and not s.startswith("l1") and not s.startswith("l2")]
        important_strings = [s for s in important_strings if not re.match(r'^[A-Za-z0-9]{10,}$', s)]
        important_strings = [s for s in important_strings if not re.match(r'^[A-Z]{2,4}$', s)]

        known_functions = ['print', 'pcall', 'tostring', 'tonumber', 'error', 'math', 'table', 'string',
                          'floor', 'char', 'concat', 'gsub', 'byte', 'len']
        
        results.append("-- Likely function calls:")
        for s in important_strings:
            if s in known_functions:
                results.append(f"--   {s}(...)")

        results.append("")
        results.append("-- Other decoded strings (likely arguments or values):")
        for s in important_strings:
            if s not in known_functions and s not in found_strings:
                results.append(f"--   {json.dumps(s)}")

        return "\n".join(results)
