import re

_OPENERS = frozenset(['then', 'do', 'else', 'elseif', 'repeat'])
_CLOSERS = frozenset(['end', 'else', 'elseif', 'until'])

_FUNC_PAT = re.compile(r'\bfunction\b')
_KW_OPEN = re.compile(r'\b(?:then|do|repeat)\b')
_KW_CLOSE = re.compile(r'\bend\b')

def beautify(code: str) -> str:
    code = re.sub(r'[ \t]*--\s*-?\d{4,}', ' ', code)
    code = re.sub(r'[ \t]+', ' ', code)
    code = code.replace(';', '\n')

    literal_pattern = r'(?:"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|\[\[.*?\]\]|--\[\[.*?\]\]|--[^\n]*)'
    literals = []

    def shield(match):
        placeholder = f"___LINO_LITERAL_{len(literals)}___"
        literals.append(match.group(0))
        return placeholder

    shielded_code = re.sub(literal_pattern, shield, code, flags=re.DOTALL)

    for kw in ('end', 'local', 'return', 'if', 'else', 'elseif', 'while', 'for', 'repeat', 'until', 'function'):
        escaped = re.escape(kw)
        if kw == 'function':
            pattern = r'(?<!\n)(?<!\blocal\s)\b(' + escaped + r')\b'
        else:
            pattern = r'(?<!\n)\b(' + escaped + r')\b'
        shielded_code = re.sub(pattern, r'\n\1 ', shielded_code)

    shielded_code = re.sub(r'[ \t]{2,}', ' ', shielded_code)
    shielded_code = re.sub(r'(?<![=~<>!])=(?!=)', ' = ', shielded_code)
    shielded_code = re.sub(r'(?<![<>])([<>])(?!=)', r' \1 ', shielded_code)
    shielded_code = re.sub(r'(?<![.])\.\.(?!\.)', ' .. ', shielded_code)
    shielded_code = re.sub(r'[ \t]{2,}', ' ', shielded_code)

    lines = [l.strip() for l in shielded_code.split('\n')]
    depth = 0
    indented_lines = []

    for line in lines:
        if not line:
            indented_lines.append('')
            continue

        first = (line.split() or [''])[0].rstrip('(')
        if first in _CLOSERS:
            depth = max(0, depth - 1)

        indented_lines.append('    ' * depth + line)

        opens = len(_FUNC_PAT.findall(line)) + len(_KW_OPEN.findall(line))
        closes = len(_KW_CLOSE.findall(line))

        if first in ('else', 'elseif'):
            depth += 1
        else:
            delta = opens - closes
            if delta > 0:
                depth += delta

    final_code = '\n'.join(indented_lines)
    
    final_code = re.sub(r'___LINO_LITERAL_(\d+)___', lambda m: literals[int(m.group(1))], final_code)

    result_lines = []
    blank_run = 0
    for ln in final_code.split('\n'):
        if ln.strip() == '':
            blank_run += 1
            if blank_run <= 1:
                result_lines.append('')
        else:
            blank_run = 0
            result_lines.append(ln)

    return '\n'.join(result_lines).strip()
