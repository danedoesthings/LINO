import re

def remove_anti_tamper(code: str) -> str:
    if not code:
        return code
    patterns = [
        r'do\s+local\s+\w+\s*=\s*getfenv\(\)[\s\S]*?while\s+true\s+do\s+end\s*end',
        r'local\s+r\d+\s*=\s*true[\s\S]*?local\s+v\d+\s*=\s*pcall\(function\(\.\.\.\)[\s\S]*?error\([^)]*\)',
        r'pcall\(function\(\.\.\.\)\s+return\s+"[^"]*"\s*/\s*\([^)]*\)\s+end\)',
        r'for\s+\w+\s*=\s*\d+\s*,\s*r\d+\s+do[\s\S]*?pcall\(function\(\.\.\.\)[\s\S]*?error\([^)]*\)',
        r'return\s*\(\s*function\(\.\.\.\)\s*while\s+true\s+do[\s\S]*?end\s*end\)\(\)',
        r'local\s+\w+\s*=\s*debug\s+and\s+debug\.\w+\s+or\s+function\(\)\s+end[\s\S]*?\w+\([^)]*\)',
        r'if\s+hookfunction\s+then\s+error\s*\(\s*"[^"]*"\s*\)\s+end',
        r'if\s+not\s+hookfunction\s+then\s+error\s*\(\s*"[^"]*"\s*\)\s+end',
        r'\bwhile\s+true\s+do\s*end\b',
        r'\bwhile\s+true\s+do\s+[^\n]*\s+end\b',
    ]
    modified = code
    for pattern in patterns:
        try:
            modified = re.sub(pattern, '', modified, flags=re.DOTALL | re.IGNORECASE)
        except re.error:
            continue
    dead_vars = [f'r{i}' for i in range(1, 21)] + [f'v{i}' for i in range(1, 11)]
    for var in dead_vars:
        try:
            modified = re.sub(rf'\b{var}\s*=\s*[^;\n]+;?', '', modified)
        except re.error:
            continue
    modified = re.sub(r'\n{3,}', '\n\n', modified)
    modified = re.sub(r'^\s*\n+', '', modified)
    return modified
