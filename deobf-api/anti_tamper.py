import re

def remove_anti_tamper(code: str) -> str:
    code = re.sub(
        r'do\s+local\s+\w+\s*=\s*getfenv\(\)[\s\S]*?while\s+true\s+do\s+end\s+end',
        '',
        code,
        flags=re.DOTALL
    )
    code = re.sub(
        r'local\s+r\d+\s*=\s*true[\s\S]*?local\s+v\d+\s*=\s*pcall\(function\(\.\.\.\)[\s\S]*?error\("Tamper[^"]*"\)[\s\S]*?end\)',
        '',
        code,
        flags=re.DOTALL
    )
    code = re.sub(
        r'pcall\(function\(\.\.\.\)\s+return\s+"[^"]*"\s*/\s*\([^)]*\)\s+end\)',
        '',
        code
    )
    code = re.sub(
        r'for\s+\w+\s*=\s*\d+\s*,\s*r\d+\s+do[\s\S]*?pcall\(function\(\.\.\.\)[\s\S]*?error\([^)]*\)[\s\S]*?end\)[\s\S]*?end',
        '',
        code,
        flags=re.DOTALL
    )
    code = re.sub(
        r"return\s*\(function\(\.\.\.\)\s*while\s+true\s+do\s+\w+\s*=\s*\w+\s*;\s*\w+\s*=\s*\w+\s*;\s*\w+\(\)\s*;\s*end\s*end\)\(\)",
        '',
        code,
        flags=re.DOTALL
    )
    code = re.sub(
        r'local\s+\w+\s*=\s*debug\s+and\s+debug\.\w+\s+or\s+function\(\)\s+end[\s\S]*?\w+\([^)]*\)',
        '',
        code
    )
    code = re.sub(r'local\s+Env\s*=\s*getfenv\(\);\s*', '', code)
    code = re.sub(r'local\s+[IV]\s*=\s*\{\};?\s*', '', code)
    dead_vars = ['r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9',
                 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'r16', 'r17',
                 'r18', 'r19', 'r20', 'r21', 'r22', 'r23', 'r24', 'r25',
                 'r26', 'r27', 'r28', 'r29', 'r30', 'v1', 'v2', 'v3', 'v4',
                 'v5', 'v6', 'v7', 'v8']
    for var in dead_vars:
        code = re.sub(rf'\b{var}\s*=\s*[^;\n]+;', '', code)
    code = re.sub(r'\n{3,}', '\n\n', code)
    code = re.sub(r'^\s*\n+', '', code)
    return code.strip()
