import re

def remove_anti_tamper(code: str) -> str:
    code = re.sub(
        r'do\s+local\s+\w+\s*=\s*[^\n]+?\s+for\s+\w+\s*=\s*\d+\s*,\s*\d+\s+do.*?end\s+end',
        '',
        code,
        flags=re.DOTALL
    )
    code = re.sub(
        r'local\s+\w+\s*=\s*debug\s+and\s+debug\s*\.\s*sethook\s+or\s+function\s*\(\s*\)\s*end.*?\1\s*\([^)]*\)',
        '',
        code,
        flags=re.DOTALL
    )
    code = re.sub(r'\n{3,}', '\n\n', code)
    return code.strip()
