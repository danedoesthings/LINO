import re

def find_dispatch_loop(code):
    m = re.search(r'while\s+.+?do\s+(.*?)end\s*end', code, re.DOTALL)
    if not m:
        return None
    return m.group(1)

def extract_handlers(dispatch_body):
    handlers = {}
    for m in re.finditer(r'if\s+(\w+)\s*==\s*(\d+)\s+then\s+(.*?)(?=\s*(?:elseif|else|end)\b)', dispatch_body, re.DOTALL):
        opcode = int(m.group(2))
        handler_code = m.group(3)
        handlers[opcode] = classify_handler(handler_code)
    return handlers

def classify_handler(code):
    if 'R[' in code:
        return 'LOADK'
    if '_G[' in code and '=' in code and code.index('_G') > code.index('='):
        return 'SETGLOBAL'
    if '=' in code and '_G[' in code:
        return 'GETGLOBAL'
    if 'pcall' in code:
        return 'PCALL'
    if 'loadstring' in code:
        return 'LOADSTRING'
    if 'return' in code:
        return 'RETURN'
    if 'string.char' in code:
        return 'STRCHAR'
    if 'table.concat' in code:
        return 'TABLECONCAT'
    if '..' in code:
        return 'CONCAT'
    if re.search(r'[+\-*/]', code) and '=' in code:
        return 'ARITH'
    if 'function' in code and '=' in code:
        return 'CLOSURE'
    if '{' in code and '=' in code:
        return 'NEWTABLE'
    if re.search(r'\w+\s*\(', code):
        return 'CALL'
    return 'UNKNOWN'

def extract_instruction_table(code):
    best = []
    for m in re.finditer(r'local\s+\w+\s*=\s*\{', code):
        body = extract_balanced(code, m.end()-1)
        if body:
            entries = parse_table_entries(body)
            if len(entries) > best:
                best = entries
    return best

def extract_balanced(code, start):
    if code[start] != '{':
        return None
    depth = 0
    in_str = False
    quote = None
    i = start
    while i < len(code):
        c = code[i]
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == quote:
                in_str = False
        else:
            if c in ('"', "'"):
                in_str = True
                quote = c
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return code[start:i+1]
        i += 1
    return None

def parse_table_entries(body):
    inner = body[1:-1]
    entries = [e.strip() for e in re.split(r'\s*,\s*', inner) if e.strip()]
    parsed = []
    for e in entries:
        if (e.startswith('"') and e.endswith('"')) or (e.startswith("'") and e.endswith("'")):
            parsed.append(e[1:-1])
        elif e.lstrip('-').isdigit():
            parsed.append(int(e))
        else:
            parsed.append(e)
    return parsed
