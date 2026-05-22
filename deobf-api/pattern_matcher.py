import re, hashlib
from collections import defaultdict

class ObfuscationFingerprinter:
    def __init__(self):
        self.signatures = {
            'wearedevs': [
                r'local\s+\w+\s*=\s*\{[^}]*\[\d+\]\s*=\s*"[^"]*"[^}]*\}',
                r'for\s+\w+\s*=\s*\d+\s*,\s*\d+\s*do',
                r'\\\d{2,3}',
                r'string\.char\s*\(',
            ],
            'moonsec': [
                r'getfenv\s*\(\s*\)',
                r'setfenv\s*\(\s*\d+\s*,',
                r'loadstring\s*\(\s*',
            ],
            'ironbrew': [
                r'bit\.bxor',
                r'bit32\.bxor',
                r'string\.byte\s*\(',
            ],
            'psu': [
                r'pcall\s*\(\s*loadstring',
                r'\_G\s*\[',
            ],
            'luraph': [
                r'\_\d+x\d+',
                r'function\s+\w+\d+\s*\(',
            ],
        }

    def analyze(self, source):
        findings = {}
        scores = defaultdict(int)
        for obf_name, patterns in self.signatures.items():
            matches = 0
            for pat in patterns:
                found = len(re.findall(pat, source, re.DOTALL))
                if found > 0:
                    matches += found
            if matches > 0:
                findings[obf_name] = matches
                scores[obf_name] = matches
        total_length = len(source)
        complexity_indicators = {
            'string_char_usage': len(re.findall(r'string\.char', source)),
            'loadstring_usage': len(re.findall(r'loadstring', source)),
            'escape_sequences': len(re.findall(r'\\\d{2,3}', source)),
            'long_strings': len(re.findall(r'"[^"]{100,}"', source)),
            'nested_tables': len(re.findall(r'\{\s*\{', source)),
            'numeric_arrays': len(re.findall(r'\{\s*[\d,\s]{30,}\s*\}', source)),
        }
        findings['complexity'] = complexity_indicators
        findings['total_length'] = total_length
        findings['estimated_type'] = max(scores, key=scores.get) if scores else 'unknown'
        return findings
