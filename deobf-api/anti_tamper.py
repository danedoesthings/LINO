import re


def remove_anti_tamper(code: str) -> str:
    """Remove anti-tamper and anti-debug code from obfuscated Lua scripts."""
    if not code:
        return code

    patterns = [
        # getfenv-based anti-tamper
        r'do\s+local\s+\w+\s*=\s*getfenv\(\)\s*[\s\S]*?while\s+true\s+do\s+end\s*end',
        # pcall-based error traps
        r'local\s+r\d+\s*=\s*true[\s\S]*?local\s+v\d+\s*=\s*pcall\(function\(\.\.\.\)[\s\S]*?error\([^)]*\)',
        r'pcall\(function\(\.\.\.\)\s+return\s+"[^"]*"\s*/\s*\([^)]*\)\s+end\)',
        r'for\s+\w+\s*=\s*\d+\s*,\s*r\d+\s+do[\s\S]*?pcall\(function\(\.\.\.\)[\s\S]*?error\([^)]*\)',
        # Infinite loop traps
        r'return\s*\(\s*function\(\.\.\.\)\s*while\s+true\s+do[\s\S]*?end\s*end\)\(\)',
        r'local\s+\w+\s*=\s*debug\s+and\s+debug\.\w+\s+or\s+function\(\)\s+end[\s\S]*?\w+\([^)]*\)',
        # hookfunction checks
        r'if\s+hookfunction\s+then\s+error\s*\(\s*"[^"]*"\s*\)\s+end',
        r'if\s+not\s+hookfunction\s+then\s+error\s*\(\s*"[^"]*"\s*\)\s+end',
        # Standalone infinite loops
        r'\bwhile\s+true\s+do\s*end\b',
        r'\bwhile\s+true\s+do\s+[^\n]*\s+end\b',
        # Additional WeAreDevs patterns
        r'if\s+\w+\s*~=\s*\w+\s+then\s+error\s*\(\s*"[^"]*"\s*\)\s+end',
        r'if\s+\w+\s*==\s*\w+\s+then\s+error\s*\(\s*"[^"]*"\s*\)\s+end',
        r'local\s+\w+\s*=\s*\w+\s*\+\s*\w+\s*if\s+\w+\s*~=\s*\w+\s+then\s+error\s*\(\s*"[^"]*"\s*\)\s+end',
    ]

    modified = code
    for pattern in patterns:
        try:
            modified = re.sub(pattern, '', modified, flags=re.DOTALL | re.IGNORECASE)
        except re.error:
            continue

    # Remove dead variable assignments (r1-r20, v1-v10)
    dead_vars = [f'r{i}' for i in range(1, 21)] + [f'v{i}' for i in range(1, 11)]
    for var in dead_vars:
        try:
            modified = re.sub(rf'\b{var}\s*=\s*[^;\n]+;?', '', modified)
        except re.error:
            continue

    # Clean up excessive whitespace
    modified = re.sub(r'\n{3,}', '\n\n', modified)
    modified = re.sub(r'^\s*\n+', '', modified)
    return modified
