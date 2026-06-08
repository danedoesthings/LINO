import re

class LuaBeautifier:
    def __init__(self):
        self.indent_size = 4
        self.indent_char = ' '
        self.line_length = 120
        
    def beautify(self, code: str) -> str:
        code = self._fix_operators(code)
        code = self._fix_comments(code)
        code = self._split_statements(code)
        code = self._fix_keywords(code)
        code = self._format_tables(code)
        code = self._format_functions(code)
        code = self._format_control_flow(code)
        code = self._fix_spacing(code)
        code = self._indent_code(code)
        code = self._fix_blank_lines(code)
        return code.strip()
    
    def _fix_operators(self, code: str) -> str:
        ops = [r'\+', r'-', r'\*', r'/', r'%', r'\^', r'#', r'==', r'~=', r'<=', r'>=', r'<', r'>', r'\.\.', r'=']
        for op in ops:
            code = re.sub(rf'(\S)\s*{op}\s*(\S)', rf'\1 {op} \2', code)
            code = re.sub(rf'(\S)\s*{op}\s*(%b\(\))', rf'\1 {op} \2', code)
        code = re.sub(r'(\S)\s*:\s*(\S)', r'\1:\2', code)
        return code
    
    def _fix_comments(self, code: str) -> str:
        lines = code.split('\n')
        result = []
        for line in lines:
            if '--' in line:
                code_part, comment_part = line.split('--', 1)
                if code_part.strip():
                    result.append(code_part.rstrip() + ' --' + comment_part)
                else:
                    result.append('--' + comment_part)
            else:
                result.append(line)
        return '\n'.join(result)
    
    def _split_statements(self, code: str) -> str:
        code = re.sub(r'(%b\(\))', lambda m: m.group(0).replace(';', '__SEMICOLON__'), code)
        code = re.sub(r'("(?:[^"\\]|\\.)*")', lambda m: m.group(0).replace(';', '__SEMICOLON__'), code)
        code = re.sub(r"('(?:[^'\\]|\\.)*')", lambda m: m.group(0).replace(';', '__SEMICOLON__'), code)
        code = code.replace(';', '\n')
        code = code.replace('__SEMICOLON__', ';')
        return code
    
    def _fix_keywords(self, code: str) -> str:
        keywords = ['and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for', 'function', 'if', 
                    'in', 'local', 'nil', 'not', 'or', 'repeat', 'return', 'then', 'true', 'until', 'while']
        for kw in keywords:
            code = re.sub(rf'\b{kw}\b', kw, code, flags=re.IGNORECASE)
        code = re.sub(r'\b(elseif|else|end|until)\b', r'\n\1', code)
        code = re.sub(r'\b(return)\b', r'\n\1 ', code)
        return code
    
    def _format_tables(self, code: str) -> str:
        def format_table(match):
            content = match.group(1)
            if len(content) < 40 and '\n' not in content and content.count(',') <= 3:
                return '{' + content + '}'
            items = content.split(',')
            formatted = ['{']
            for item in items:
                item = item.strip()
                if item:
                    formatted.append('    ' + item + ',')
            formatted.append('}')
            return '\n'.join(formatted)
        
        depth = 0
        result = []
        i = 0
        while i < len(code):
            if code[i] == '{' and (i == 0 or code[i-1] not in '\\"'):
                start = i
                bracket_count = 1
                j = i + 1
                while j < len(code) and bracket_count > 0:
                    if code[j] == '{' and code[j-1] != '\\':
                        bracket_count += 1
                    elif code[j] == '}' and code[j-1] != '\\':
                        bracket_count -= 1
                    j += 1
                table_content = code[start+1:j-1]
                formatted = format_table(table_content)
                result.append(formatted)
                i = j
            else:
                result.append(code[i])
                i += 1
        return ''.join(result)
    
    def _format_functions(self, code: str) -> str:
        code = re.sub(r'\bfunction\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', r'function \1(', code)
        code = re.sub(r'\bfunction\s*\(', r'function(', code)
        code = re.sub(r'\blocal\s+function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', r'local function \1(', code)
        code = re.sub(r'\)\s*$', r')', code, flags=re.MULTILINE)
        return code
    
    def _format_control_flow(self, code: str) -> str:
        patterns = [
            (r'\bif\s+(.+?)\s+then\b', r'if \1 then'),
            (r'\belseif\s+(.+?)\s+then\b', r'elseif \1 then'),
            (r'\bwhile\s+(.+?)\s+do\b', r'while \1 do'),
            (r'\bfor\s+(.+?)\s+do\b', r'for \1 do'),
            (r'\brepeat\s+(.+?)\s+until\b', r'repeat\n\1\nuntil'),
        ]
        for pattern, replacement in patterns:
            code = re.sub(pattern, replacement, code, flags=re.DOTALL)
        return code
    
    def _fix_spacing(self, code: str) -> str:
        code = re.sub(r'[ \t]+', ' ', code)
        code = re.sub(r'\s*,\s*', ', ', code)
        code = re.sub(r'\s*\.\.\s*', ' .. ', code)
        code = re.sub(r'\(\s+', '(', code)
        code = re.sub(r'\s+\)', ')', code)
        code = re.sub(r'\{\s+', '{', code)
        code = re.sub(r'\s+\}', '}', code)
        code = re.sub(r'\s*\n\s*', '\n', code)
        code = re.sub(r' +\n', '\n', code)
        code = re.sub(r'\n +', '\n', code)
        return code
    
    def _indent_code(self, code: str) -> str:
        lines = code.split('\n')
        indent_level = 0
        result = []
        
        for line in lines:
            stripped = line.strip()
            if not stripped:
                result.append('')
                continue
            
            if re.match(r'^(elseif|else|end|until)\b', stripped):
                indent_level = max(0, indent_level - 1)
            
            result.append(self.indent_char * self.indent_size * indent_level + stripped)
            
            if re.search(r'\b(then|do|repeat|else|elseif|function)\s*$', stripped):
                indent_level += 1
            elif stripped == 'else' or stripped.startswith('elseif'):
                pass
            elif re.match(r'^(function|if|for|while)\b', stripped) and not stripped.endswith('end'):
                if not re.search(r'\bend\s*$', stripped):
                    indent_level += 1
        
        return '\n'.join(result)
    
    def _fix_blank_lines(self, code: str) -> str:
        code = re.sub(r'\n{3,}', '\n\n', code)
        lines = code.split('\n')
        result = []
        prev_empty = False
        for line in lines:
            is_empty = line.strip() == ''
            if is_empty and prev_empty:
                continue
            result.append(line)
            prev_empty = is_empty
        return '\n'.join(result)

def beautify(code: str) -> str:
    beautifier = LuaBeautifier()
    return beautifier.beautify(code)
