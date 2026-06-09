import re

def remove_anti_tamper(code: str) -> str:
    """Aggressively remove anti-tamper, anti-debug, and dead-code traps from WeAreDevs / Prometheus Lua."""
    if not code:
        return code

    # Phase 1: Remove entire anti-tamper blocks
    block_patterns = [
        r'do\s+local\s+\w+\s*=\s*getfenv\s*\(\s*\)\s*[\s\S]*?while\s+true\s+do\s+end\s*end',
        r'local\s+\w+\s*=\s*true\s*[\s\S]*?local\s+\w+\s*=\s*pcall\s*\(\s*function\s*\(\.\.\.\)[\s\S]*?end\s*\)',
        r'pcall\s*\(\s*function\s*\(\.\.\.\)\s*return\s*"[^"]*"\s*[/^%-]\s*\([^)]*\)\s+end\s*\)',
        r'for\s+\w+\s*=\s*\d+\s*,\s*\w+\s+do[\s\S]*?pcall\s*\(\s*function\s*\(\.\.\.\)[\s\S]*?error\s*\([^)]*\)',
        r'return\s*\(\s*function\s*\(\.\.\.\)\s*while\s+true\s+do[\s\S]*?end\s*end\s*\)\s*\(\s*\)',
        r'if\s+hookfunction\s+then\s+error\s*\(\s*"[^"]*"\s*\)\s+end',
        r'if\s+not\s+hookfunction\s+then\s+error\s*\(\s*"[^"]*"\s*\)\s+end',
        r'if\s+getfenv\s*\(\s*\)\s*~!=\s*getfenv\s*\(\s*\)\s*then\s+error\s*\([^)]*\)\s*end',
        r'if\s+debug\s*\.\s*getinfo\s*\([^)]*\)\s*then\s+error\s*\([^)]*\)\s*end',
    ]

    modified = code
    for pat in block_patterns:
        try:
            modified = re.sub(pat, '', modified, flags=re.DOTALL | re.IGNORECASE)
        except re.error:
            continue

    # Phase 2: Remove standalone infinite loops
    modified = re.sub(r'\bwhile\s+true\s+do\s*end\b', '', modified)
    modified = re.sub(r'\bwhile\s+true\s+do\s+[^\n]*\s+end\b', '', modified)
    modified = re.sub(r'\bwhile\s+true\s+do[\s\S]*?end\b', '', modified, count=3, flags=re.DOTALL)

    # Phase 3: Remove error() calls and wrappers
    modified = re.sub(r'error\s*\(\s*"[^"]*[Tt]amper[^"]*"\s*(?:,\s*\d+)?\s*\)', '', modified)
    modified = re.sub(r'error\s*\(\s*"[^"]*[Dd]ebug[^"]*"\s*(?:,\s*\d+)?\s*\)', '', modified)
    modified = re.sub(r'error\s*\(\s*"[^"]*[Hh]ook[^"]*"\s*(?:,\s*\d+)?\s*\)', '', modified)
    modified = re.sub(r'error\s*\(\s*\w+\s*(?:,\s*\d+)?\s*\)\s*;?', '', modified)

    # Phase 4: Remove anti-tamper function definitions and calls
    anti_funcs = re.findall(
        r'local\s+function\s+(\w+)\s*\([^)]*\)\s*error\s*\([^)]*\)\s*;?\s*return\s*;?\s*end',
        modified, flags=re.DOTALL
    )
    for func in anti_funcs:
        modified = re.sub(
            rf'local\s+function\s+{re.escape(func)}\s*\([^)]*\)\s*error\s*\([^)]*\)\s*;?\s*return\s*;?\s*end\s*',
            '', modified, flags=re.DOTALL
        )
        modified = re.sub(rf'\b{re.escape(func)}\s*\([^)]*\)\s*;?', '', modified)

    # Phase 5: Strip boolean flag chains
    modified = re.sub(r'\w+\s*=\s*\w+\s+and\s*\(\s*pcall\s*\([\s\S]*?\)\s*==\s*false\s+and\s+[^)]+\)', '', modified)
    modified = re.sub(r'\w+\s*=\s*\w+\s+and\s+\w+\s*==\s*[^;\n]+[;\n]?', '', modified)
    modified = re.sub(r'\w+\s*=\s*\w+\s+and\s+0\s*==\s*0\s*;?', '', modified)

    # Phase 6: Remove dead variable assignments (r1-r60, v1-v60)
    for i in range(1, 61):
        for prefix in ['r', 'v']:
            var = f'{prefix}{i}'
            try:
                modified = re.sub(rf'\blocal\s+{var}\s*=\s*[^;\n]+[;\n]?', '', modified)
                modified = re.sub(rf'\b{var}\s*=\s*[^;\n]+[;\n]?', '', modified)
            except re.error:
                continue

    # Phase 7: Remove math.random noise
    modified = re.sub(r'local\s+\w+\s*=\s*math\.random\s*\([^)]*\)\s*;?\s*', '', modified)
    modified = re.sub(r'local\s+\w+\s*=\s*string\.gmatch\s*\([^)]*\)\s*;?\s*', '', modified)

    # Phase 8: Collapse empty control structures
    modified = re.sub(r'if\s+[^;{]+then\s*end\s*', '', modified)
    modified = re.sub(r'for\s+[^;{]+do\s*end\s*', '', modified)
    modified = re.sub(r'while\s+[^;{]+do\s*end\s*', '', modified)

    # Phase 9: Clean whitespace
    modified = re.sub(r'\n{3,}', '\n\n', modified)
    modified = re.sub(r'^\s*\n+', '', modified)
    modified = re.sub(r'[ \t]+\n', '\n', modified)

    return modified
