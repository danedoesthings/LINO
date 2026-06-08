import re

def beautify(code: str) -> str:
    if not code or len(code) < 10:
        return code
    lines = code.split('\n')
    result = []
    indent_level = 0
    indent_size = 4
    for line in lines:
        stripped = line.strip()
        if not stripped:
            result.append('')
            continue
        if stripped.startswith('--'):
            result.append(' ' * (indent_level * indent_size) + stripped)
            continue
        if stripped in ('else', 'elseif', 'end', 'until'):
            indent_level = max(0, indent_level - 1)
        result.append(' ' * (indent_level * indent_size) + stripped)
        if stripped.endswith('then') or stripped.endswith('do') or stripped == 'repeat' or stripped.startswith('function'):
            indent_level += 1
    code = '\n'.join(result)
    code = re.sub(r'(\S)\s*=\s*(\S)', r'\1 = \2', code)
    code = re.sub(r'(\S)\s*==\s*(\S)', r'\1 == \2', code)
    code = re.sub(r'(\S)\s*~=\s*(\S)', r'\1 ~= \2', code)
    code = re.sub(r'(\S)\s*<=\s*(\S)', r'\1 <= \2', code)
    code = re.sub(r'(\S)\s*>=\s*(\S)', r'\1 >= \2', code)
    code = re.sub(r'(\S)\s*\.\.\s*(\S)', r'\1 .. \2', code)
    code = re.sub(r'(\S)\s*,\s*(\S)', r'\1, \2', code)
    code = re.sub(r'\(\s+', '(', code)
    code = re.sub(r'\s+\)', ')', code)
    code = re.sub(r'\{\s+', '{', code)
    code = re.sub(r'\s+\}', '}', code)
    code = re.sub(r'\n{3,}', '\n\n', code)
    return code.strip()
