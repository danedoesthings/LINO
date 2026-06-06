import re

def beautify(code):
    code = re.sub(r'[ \t]+', ' ', code)
    code = code.replace(';', '\n')
    
    literals = []
    def save_literal(m):
        literals.append(m.group(0))
        return f'__LIT_{len(literals)-1}__'
    
    code = re.sub(r'"(?:[^"\\]|\\.)*"', save_literal, code)
    code = re.sub(r"'(?:[^'\\]|\\.)*'", save_literal, code)
    
    code = re.sub(r'([,{}\[\]\(\)])', r' \1 ', code)
    code = re.sub(r'\b(end)\b(?!\s*then|\s*else|\s*elseif|\s*until)', r'\1\n', code)
    
    for kw in ['local', 'return', 'if', 'else', 'elseif', 'while', 'for', 'repeat', 'until', 'function']:
        code = re.sub(rf'(?<!\n)\b{kw}\b', r'\n\1', code)
    
    code = re.sub(r'[ \t]{2,}', ' ', code)
    code = re.sub(r'(?<![=~<>!])=(?!=)', ' = ', code)
    code = re.sub(r'\s*,\s*', ', ', code)
    code = re.sub(r'\(\s+', '(', code)
    code = re.sub(r'\s+\)', ')', code)
    
    lines = [l.strip() for l in code.split('\n')]
    depth = 0
    indented = []
    
    for line in lines:
        if not line:
            indented.append('')
            continue
        if re.match(r'^(else|elseif|end|until)\b', line):
            depth = max(0, depth - 1)
        indented.append('    ' * depth + line)
        if re.search(r'\b(then|do|repeat|else|elseif|function)\b', line):
            depth += 1
    
    code = '\n'.join(indented)
    for i, lit in enumerate(literals):
        code = code.replace(f'__LIT_{i}__', lit)
    
    return code.strip()
