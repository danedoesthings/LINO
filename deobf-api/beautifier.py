import re

_OPENERS = frozenset(['then', 'do', 'else', 'elseif', 'repeat'])
_CLOSERS = frozenset(['end', 'else', 'elseif', 'until'])

_FUNC_PAT = re.compile(r'\bfunction\b')
_KW_OPEN = re.compile(r'\b(?:then|do|repeat)\b')
_KW_CLOSE = re.compile(r'\bend\b')
_ELSE_PAT = re.compile(r'\b(else|elseif)\b')

def _remove_noise_comments(code: str) -> str:
    return re.sub(r'\s*--\s*-?\d{4,}\b', '', code)

def _semicolons_to_newlines(code: str) -> str:
    return re.sub(r';', '\n', code)

def _expand_compact_blocks(code: str) -> str:
    for kw in ('end', 'local ', 'return ', 'if ', 'else ', 'elseif ',
               'while ', 'for ', 'repeat', 'until ', 'function '):
        escaped = re.escape(kw.rstrip())
        if kw.endswith(' '):
            pattern = r'(?<!\n)\b(' + escaped + r')\s+'
        else:
            pattern = r'(?<!\n)\b(' + escaped + r')\b'
        code = re.sub(pattern, r'\n\1 ', code)
    return code

def _normalise_spaces(code: str) -> str:
    code = re.sub(r'[ \t]{2,}', ' ', code)
    code = re.sub(r'(?<![=~<>!])=(?!=)', ' = ', code)
    code = re.sub(r'(?<![<>])([<>])(?!=)', r' \1 ', code)
    code = re.sub(r'(?<![.])\.\.(?!\.)', ' .. ', code)
    code = re.sub(r'[ \t]{2,}', ' ', code)
    return code

def _strip_string_content(line: str) -> str:
    line = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line)
    line = re.sub(r"'(?:[^'\\]|\\.)*'", "''", line)
    line = re.sub(r'--.*', '', line)
    return line

def _indent(lines: list[str]) -> list[str]:
    depth = 0
    out: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line:
            out.append('')
            continue
        safe = _strip_string_content(line)
        first = (safe.split() or [''])[0].rstrip('(')
        if first in _CLOSERS:
            depth = max(0, depth - 1)
        out.append('    ' * depth + line)
        func_opens = len(_FUNC_PAT.findall(safe))
        kw_opens = len(_KW_OPEN.findall(safe))
        kw_closes = len(_KW_CLOSE.findall(safe))
        opens = func_opens + kw_opens
        closes = kw_closes
        if first in ('else', 'elseif'):
            depth += 1
        else:
            delta = opens - closes
            if delta > 0:
                depth += delta
    return out

def beautify(code: str) -> str:
    code = _remove_noise_comments(code)
    code = _semicolons_to_newlines(code)
    code = _expand_compact_blocks(code)
    code = _normalise_spaces(code)
    lines = [l.rstrip() for l in code.split('\n')]
    lines = _indent(lines)
    result_lines: list[str] = []
    blank_run = 0
    for ln in lines:
        if ln == '':
            blank_run += 1
            if blank_run <= 1:
                result_lines.append('')
        else:
            blank_run = 0
            result_lines.append(ln)
    return '\n'.join(result_lines).strip()
