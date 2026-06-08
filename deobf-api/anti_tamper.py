"""
Anti-tamper detection and removal for obfuscated Lua scripts.
Handles various obfuscator tamper protection patterns.
"""

import re


def remove_anti_tamper(code: str) -> str:
    """
    Remove anti-tampering code blocks that crash or hang the script.
    """
    if not code:
        return code

    patterns = [
        # Infinite while-true loops (hang protection)
        r'do\s+local\s+\w+\s*=\s*getfenv\(\)[\s\S]*?while\s+true\s+do\s+end\s+end',
        # Tamper error patterns
        r'local\s+r\d+\s*=\s*true[\s\S]*?local\s+v\d+\s*=\s*pcall\(function\(\.\.\.\)[\s\S]*?error\("Tamper[^"]*"\)[\s\S]*?end\)',
        # Pcall-based tamper checks
        r'pcall\(function\(\.\.\.\)\s+return\s+"[^"]*"\s*/\s*\([^)]*\)\s+end\)',
        # For-loop tamper checks
        r'for\s+\w+\s*=\s*\d+\s*,\s*r\d+\s+do[\s\S]*?pcall\(function\(\.\.\.\)[\s\S]*?error\([^)]*\)[\s\S]*?end\)[\s\S]*?end',
        # Return infinite loop
        r'return\s*\(\s*function\(\.\.\.\)\s*while\s+true\s+do[\s\S]*?end\s*end\)\(\)',
        # Debug-based tamper
        r'local\s+\w+\s*=\s*debug\s+and\s+debug\.\w+\s+or\s+function\(\)\s+end[\s\S]*?\w+\([^)]*\)',
        # Hook detection patterns
        r'if\s+hookfunction\s+then\s+error\s*\(\s*"[^"]*"\s*\)\s+end',
        r'if\s+not\s+hookfunction\s+then\s+error\s*\(\s*"[^"]*"\s*\)\s+end',
        # while true do end (standalone)
        r'\bwhile\s+true\s+do\s*end\b',
        # while true do ... end with body
        r'\bwhile\s+true\s+do\s+[^\n]*\s+end\b',
    ]

    modified = code
    for pattern in patterns:
        try:
            modified = re.sub(pattern, '', modified, flags=re.DOTALL | re.IGNORECASE)
        except re.error:
            continue

    # Remove dead variable assignments (r1-r15, v1-v8 patterns)
    dead_vars = [
        'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10',
        'r11', 'r12', 'r13', 'r14', 'r15', 'r16', 'r17', 'r18', 'r19', 'r20',
        'v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7', 'v8', 'v9', 'v10',
    ]

    for var in dead_vars:
        try:
            # Remove standalone assignments
            modified = re.sub(rf'\b{var}\s*=\s*[^;\n]+;?', '', modified)
        except re.error:
            continue

    # Clean up multiple blank lines
    modified = re.sub(r'\n{3,}', '\n\n', modified)
    modified = re.sub(r'^\s*\n+', '', modified)

    return modified.strip()
