import re
from typing import Optional

def _clean_signs(expr: str) -> str:
    old = ''
    while old != expr:
        old = expr
        expr = (expr.replace('--', '+').replace('+-', '-')
                .replace('-+', '-').replace('++', '+'))
    return expr

def safe_eval_int(expr: str) -> Optional[int]:
    expr = re.sub(r'\s+', '', str(expr))
    expr = _clean_signs(expr)
    while '(' in expr:
        m = re.search(r'\(([^()]+)\)', expr)
        if not m:
            break
        inner = safe_eval_int(m.group(1))
        if inner is None:
            return None
        expr = expr[:m.start()] + str(inner) + expr[m.end():]
        expr = _clean_signs(expr)
    while True:
        m = re.search(r'(-?\d+)\s*([*/%])\s*(-?\d+)', expr)
        if not m:
            break
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        if op == '*':
            res = a * b
        elif op == '/' and b != 0:
            res = int(a / b)
        elif op == '%' and b != 0:
            res = a % b
        else:
            return None
        expr = _clean_signs(expr[:m.start()] + str(res) + expr[m.end():])
    tokens = re.findall(r'[+-]?\d+', expr)
    if tokens:
        try:
            return sum(int(t) for t in tokens)
        except ValueError:
            pass
    try:
        return int(expr)
    except ValueError:
        return None

_PAREN_EXPR = re.compile(r'\(([^()a-zA-Z_\'"]+)\)')
_BINOP_EXPR = re.compile(r'\b(-?\d+)\s*([+\-*/%])\s*(-?\d+)\b')

def _fold_once(code: str) -> str:
    def _try(m: re.Match) -> str:
        val = safe_eval_int(m.group(1) if m.lastindex == 1 else m.group(0))
        return str(val) if val is not None else m.group(0)
    code = _PAREN_EXPR.sub(lambda m: _try(m), code)
    code = _BINOP_EXPR.sub(lambda m: _try(m), code)
    return code

def fold_constants(code: str, passes: int = 12) -> str:
    for _ in range(passes):
        prev = code
        code = _fold_once(code)
        if code == prev:
            break
    return code

_E_OFFSET_PATS = [
    re.compile(r'local\s+function\s+E\s*\(E\)\s*return\s+R\[E\s*\+\s*\(?(-?\d+(?:[+\-]\d+)*)\)?\]'),
    re.compile(r'\breturn\s+R\s*\[\s*E\s*\+\s*\(?(-?\d+(?:[+\-]\d+)*)\)?\]'),
    re.compile(r'\breturn\s+EncStr\s*\[\s*GetStr\s*\+\s*\(?(-?\d+(?:[+\-]\d+)*)\)?\]'),
]

def get_string_table_offset(source: str) -> int:
    for pat in _E_OFFSET_PATS:
        m = pat.search(source)
        if m:
            val = safe_eval_int(m.group(1))
            if val is not None:
                return val
    return 0
