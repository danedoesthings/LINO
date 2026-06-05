import re
from typing import Any, Dict, List, Optional, Tuple

class LuaParser:
    def __init__(self, source: str):
        self.source = source
        self.pos = 0
        self.line = 1

    def parse(self) -> List[dict]:
        statements = []
        while self.pos < len(self.source):
            self._skip_whitespace()
            if self.pos >= len(self.source):
                break
            try:
                stmt = self._parse_statement()
                if stmt:
                    statements.append(stmt)
            except Exception:
                self.pos += 1
        return statements

    def _skip_whitespace(self):
        while self.pos < len(self.source):
            c = self.source[self.pos]
            if c in ' \t\r':
                self.pos += 1
            elif c == '\n':
                self.pos += 1
                self.line += 1
            elif c == '-' and self.pos + 1 < len(self.source) and self.source[self.pos + 1] == '-':
                self._skip_comment()
            else:
                break

    def _skip_comment(self):
        self.pos += 2
        if self.pos < len(self.source) and self.source[self.pos] == '[' and self.pos + 1 < len(self.source) and self.source[self.pos + 1] == '[':
            self.pos += 2
            while self.pos < len(self.source):
                if self.source[self.pos] == ']' and self.pos + 1 < len(self.source) and self.source[self.pos + 1] == ']':
                    self.pos += 2
                    break
                if self.source[self.pos] == '\n':
                    self.line += 1
                self.pos += 1
        else:
            while self.pos < len(self.source) and self.source[self.pos] != '\n':
                self.pos += 1

    def _parse_statement(self) -> Optional[dict]:
        c = self.source[self.pos] if self.pos < len(self.source) else ''
        if c == 'l' and self.source[self.pos:self.pos+5] == 'local':
            return self._parse_local()
        elif c == 'f' and self.source[self.pos:self.pos+8] == 'function':
            return self._parse_function_def()
        elif c == 'r' and self.source[self.pos:self.pos+6] == 'return':
            return self._parse_return()
        elif c == 'i' and self.source[self.pos:self.pos+2] == 'if':
            return self._parse_if()
        elif c == 'w' and self.source[self.pos:self.pos+5] == 'while':
            return self._parse_while()
        elif c == 'f' and self.source[self.pos:self.pos+3] == 'for':
            return self._parse_for()
        elif c == 'd' and self.source[self.pos:self.pos+2] == 'do':
            return self._parse_do_block()
        elif c == 'e' and self.source[self.pos:self.pos+3] == 'end':
            return None
        elif c == ';':
            self.pos += 1
            return None
        else:
            return self._parse_expression_statement()

    def _parse_local(self) -> dict:
        self.pos += 5
        self._skip_whitespace()
        if self.source[self.pos:self.pos+8] == 'function':
            self.pos += 8
            self._skip_whitespace()
            name = self._parse_identifier()
            self._skip_whitespace()
            self._expect('(')
            params = self._parse_param_list()
            self._expect(')')
            body = self._parse_block()
            return {'type': 'local_function', 'name': name, 'params': params, 'body': body}
        names = [self._parse_identifier()]
        while self.pos < len(self.source) and self.source[self.pos] == ',':
            self.pos += 1
            self._skip_whitespace()
            names.append(self._parse_identifier())
        self._skip_whitespace()
        if self.pos < len(self.source) and self.source[self.pos] == '=':
            self.pos += 1
            self._skip_whitespace()
            values = [self._parse_expression()]
            while self.pos < len(self.source) and self.source[self.pos] == ',':
                self.pos += 1
                self._skip_whitespace()
                values.append(self._parse_expression())
            return {'type': 'local_assign', 'names': names, 'values': values}
        return {'type': 'local_declare', 'names': names}

    def _parse_function_def(self) -> dict:
        self.pos += 8
        self._skip_whitespace()
        name = self._parse_identifier() if self.source[self.pos].isalpha() or self.source[self.pos] == '_' else None
        if name:
            self._skip_whitespace()
            if self.pos < len(self.source) and self.source[self.pos] == '.':
                self.pos += 1
                method = self._parse_identifier()
                name = f"{name}.{method}"
            elif self.pos < len(self.source) and self.source[self.pos] == ':':
                self.pos += 1
                method = self._parse_identifier()
                name = f"{name}:{method}"
        self._skip_whitespace()
        self._expect('(')
        params = self._parse_param_list()
        self._expect(')')
        body = self._parse_block()
        return {'type': 'function_def', 'name': name, 'params': params, 'body': body}

    def _parse_return(self) -> dict:
        self.pos += 6
        self._skip_whitespace()
        values = []
        if self.pos < len(self.source) and not self._is_block_end():
            values.append(self._parse_expression())
            while self.pos < len(self.source) and self.source[self.pos] == ',':
                self.pos += 1
                self._skip_whitespace()
                values.append(self._parse_expression())
        return {'type': 'return', 'values': values}

    def _parse_if(self) -> dict:
        self.pos += 2
        self._skip_whitespace()
        condition = self._parse_expression()
        self._skip_whitespace()
        self._expect_then()
        body = self._parse_block()
        else_body = None
        self._skip_whitespace()
        if self.pos + 4 < len(self.source) and self.source[self.pos:self.pos+4] == 'else':
            self.pos += 4
            self._skip_whitespace()
            if self.pos + 2 < len(self.source) and self.source[self.pos:self.pos+2] == 'if':
                else_body = [self._parse_if()]
            else:
                else_body = self._parse_block()
        self._skip_whitespace()
        if self.pos + 3 < len(self.source) and self.source[self.pos:self.pos+3] == 'end':
            self.pos += 3
        return {'type': 'if', 'condition': condition, 'body': body, 'else_body': else_body}

    def _parse_while(self) -> dict:
        self.pos += 5
        self._skip_whitespace()
        condition = self._parse_expression()
        self._skip_whitespace()
        self._expect_do()
        body = self._parse_block()
        self._skip_whitespace()
        if self.pos + 3 < len(self.source) and self.source[self.pos:self.pos+3] == 'end':
            self.pos += 3
        return {'type': 'while', 'condition': condition, 'body': body}

    def _parse_for(self) -> dict:
        self.pos += 3
        self._skip_whitespace()
        var = self._parse_identifier()
        self._skip_whitespace()
        self._expect('=')
        start = self._parse_expression()
        self._skip_whitespace()
        self._expect(',')
        end = self._parse_expression()
        step = None
        self._skip_whitespace()
        if self.pos < len(self.source) and self.source[self.pos] == ',':
            self.pos += 1
            self._skip_whitespace()
            step = self._parse_expression()
        self._skip_whitespace()
        self._expect_do()
        body = self._parse_block()
        self._skip_whitespace()
        if self.pos + 3 < len(self.source) and self.source[self.pos:self.pos+3] == 'end':
            self.pos += 3
        return {'type': 'for', 'var': var, 'start': start, 'end': end, 'step': step, 'body': body}

    def _parse_do_block(self) -> dict:
        self.pos += 2
        body = self._parse_block()
        self._skip_whitespace()
        if self.pos + 3 < len(self.source) and self.source[self.pos:self.pos+3] == 'end':
            self.pos += 3
        return {'type': 'do', 'body': body}

    def _parse_expression_statement(self) -> dict:
        expr = self._parse_expression()
        return {'type': 'expr_stmt', 'expression': expr}

    def _parse_block(self) -> List[dict]:
        statements = []
        while self.pos < len(self.source):
            self._skip_whitespace()
            if self.pos >= len(self.source):
                break
            c = self.source[self.pos]
            if c == 'e' and self.source[self.pos:self.pos+3] == 'end':
                break
            elif c == 'e' and self.source[self.pos:self.pos+4] == 'else':
                break
            elif c == 'u' and self.source[self.pos:self.pos+5] == 'until':
                break
            stmt = self._parse_statement()
            if stmt:
                statements.append(stmt)
            else:
                break
        return statements

    def _parse_param_list(self) -> List[str]:
        params = []
        self._skip_whitespace()
        if self.pos < len(self.source) and self.source[self.pos] != ')':
            if self.source[self.pos] == '.' and self.pos + 2 < len(self.source) and self.source[self.pos:self.pos+3] == '...':
                self.pos += 3
                params.append('...')
            else:
                params.append(self._parse_identifier())
                self._skip_whitespace()
                while self.pos < len(self.source) and self.source[self.pos] == ',':
                    self.pos += 1
                    self._skip_whitespace()
                    if self.source[self.pos] == '.' and self.pos + 2 < len(self.source) and self.source[self.pos:self.pos+3] == '...':
                        self.pos += 3
                        params.append('...')
                    else:
                        params.append(self._parse_identifier())
                    self._skip_whitespace()
        return params

    def _parse_expression(self) -> dict:
        return self._parse_or()

    def _parse_or(self) -> dict:
        left = self._parse_and()
        while self.pos < len(self.source):
            self._skip_whitespace()
            if self.pos + 2 < len(self.source) and self.source[self.pos:self.pos+2] == 'or':
                self.pos += 2
                self._skip_whitespace()
                right = self._parse_and()
                left = {'type': 'binary_op', 'op': 'or', 'left': left, 'right': right}
            else:
                break
        return left

    def _parse_and(self) -> dict:
        left = self._parse_comparison()
        while self.pos < len(self.source):
            self._skip_whitespace()
            if self.pos + 3 < len(self.source) and self.source[self.pos:self.pos+3] == 'and':
                self.pos += 3
                self._skip_whitespace()
                right = self._parse_comparison()
                left = {'type': 'binary_op', 'op': 'and', 'left': left, 'right': right}
            else:
                break
        return left

    def _parse_comparison(self) -> dict:
        left = self._parse_concat()
        self._skip_whitespace()
        if self.pos < len(self.source):
            ops = ['<=', '>=', '~=', '==', '<', '>']
            for op in ops:
                if self.source[self.pos:self.pos+len(op)] == op:
                    self.pos += len(op)
                    self._skip_whitespace()
                    right = self._parse_concat()
                    return {'type': 'binary_op', 'op': op, 'left': left, 'right': right}
        return left

    def _parse_concat(self) -> dict:
        left = self._parse_term()
        while self.pos < len(self.source):
            self._skip_whitespace()
            if self.source[self.pos:self.pos+2] == '..':
                self.pos += 2
                self._skip_whitespace()
                right = self._parse_term()
                left = {'type': 'binary_op', 'op': '..', 'left': left, 'right': right}
            else:
                break
        return left

    def _parse_term(self) -> dict:
        left = self._parse_factor()
        while self.pos < len(self.source):
            self._skip_whitespace()
            c = self.source[self.pos] if self.pos < len(self.source) else ''
            if c == '+':
                self.pos += 1
                self._skip_whitespace()
                right = self._parse_factor()
                left = {'type': 'binary_op', 'op': '+', 'left': left, 'right': right}
            elif c == '-':
                self.pos += 1
                self._skip_whitespace()
                right = self._parse_factor()
                left = {'type': 'binary_op', 'op': '-', 'left': left, 'right': right}
            else:
                break
        return left

    def _parse_factor(self) -> dict:
        left = self._parse_unary()
        while self.pos < len(self.source):
            self._skip_whitespace()
            c = self.source[self.pos] if self.pos < len(self.source) else ''
            if c == '*':
                self.pos += 1
                self._skip_whitespace()
                right = self._parse_unary()
                left = {'type': 'binary_op', 'op': '*', 'left': left, 'right': right}
            elif c == '/':
                self.pos += 1
                self._skip_whitespace()
                right = self._parse_unary()
                left = {'type': 'binary_op', 'op': '/', 'left': left, 'right': right}
            elif c == '%':
                self.pos += 1
                self._skip_whitespace()
                right = self._parse_unary()
                left = {'type': 'binary_op', 'op': '%', 'left': left, 'right': right}
            elif c == '^':
                self.pos += 1
                self._skip_whitespace()
                right = self._parse_unary()
                left = {'type': 'binary_op', 'op': '^', 'left': left, 'right': right}
            else:
                break
        return left

    def _parse_unary(self) -> dict:
        self._skip_whitespace()
        c = self.source[self.pos] if self.pos < len(self.source) else ''
        if c == '-':
            self.pos += 1
            self._skip_whitespace()
            operand = self._parse_unary()
            return {'type': 'unary_op', 'op': '-', 'operand': operand}
        elif c == 'n' and self.source[self.pos:self.pos+3] == 'not':
            self.pos += 3
            self._skip_whitespace()
            operand = self._parse_unary()
            return {'type': 'unary_op', 'op': 'not', 'operand': operand}
        elif c == '#':
            self.pos += 1
            self._skip_whitespace()
            operand = self._parse_unary()
            return {'type': 'unary_op', 'op': '#', 'operand': operand}
        return self._parse_primary()

    def _parse_primary(self) -> dict:
        self._skip_whitespace()
        c = self.source[self.pos] if self.pos < len(self.source) else ''
        if c == '(':
            self.pos += 1
            expr = self._parse_expression()
            self._skip_whitespace()
            self._expect(')')
            return expr
        elif c == '{':
            return self._parse_table_constructor()
        elif c == '"' or c == "'":
            return self._parse_string()
        elif c == '.' and self.pos + 2 < len(self.source) and self.source[self.pos:self.pos+3] == '...':
            self.pos += 3
            return {'type': 'vararg'}
        elif c == 'n' and self.source[self.pos:self.pos+3] == 'nil':
            self.pos += 3
            return {'type': 'literal', 'value': None}
        elif c == 't' and self.source[self.pos:self.pos+4] == 'true':
            self.pos += 4
            return {'type': 'literal', 'value': True}
        elif c == 'f' and self.source[self.pos:self.pos+5] == 'false':
            self.pos += 5
            return {'type': 'literal', 'value': False}
        elif c == 'f' and self.source[self.pos:self.pos+8] == 'function':
            return self._parse_function_def()
        elif c.isdigit():
            return self._parse_number()
        elif c.isalpha() or c == '_':
            expr = self._parse_identifier_expr()
            while self.pos < len(self.source):
                self._skip_whitespace()
                c2 = self.source[self.pos] if self.pos < len(self.source) else ''
                if c2 == '(':
                    expr = self._parse_function_call(expr)
                elif c2 == '[':
                    expr = self._parse_index(expr)
                elif c2 == '.':
                    self.pos += 1
                    member = self._parse_identifier()
                    expr = {'type': 'member', 'object': expr, 'member': member}
                elif c2 == ':':
                    self.pos += 1
                    method = self._parse_identifier()
                    self._skip_whitespace()
                    self._expect('(')
                    args = []
                    if self.pos < len(self.source) and self.source[self.pos] != ')':
                        args.append(self._parse_expression())
                        while self.pos < len(self.source) and self.source[self.pos] == ',':
                            self.pos += 1
                            self._skip_whitespace()
                            args.append(self._parse_expression())
                    self._expect(')')
                    expr = {'type': 'method_call', 'object': expr, 'method': method, 'args': args}
                else:
                    break
            return expr
        return {'type': 'literal', 'value': None}

    def _parse_identifier(self) -> str:
        result = ''
        while self.pos < len(self.source):
            c = self.source[self.pos]
            if c.isalpha() or c == '_' or (result and c.isdigit()):
                result += c
                self.pos += 1
            else:
                break
        return result

    def _parse_identifier_expr(self) -> dict:
        name = self._parse_identifier()
        return {'type': 'identifier', 'name': name}

    def _parse_number(self) -> dict:
        num_str = ''
        while self.pos < len(self.source):
            c = self.source[self.pos]
            if c.isdigit() or c == '.' or c == 'e' or c == 'E' or c == '-' or c == '+' or c == 'x' or c == 'X' or c in 'abcdefABCDEF':
                num_str += c
                self.pos += 1
            else:
                break
        try:
            if 'x' in num_str or 'X' in num_str:
                value = int(num_str, 16)
            elif '.' in num_str or 'e' in num_str.lower():
                value = float(num_str)
            else:
                value = int(num_str)
        except ValueError:
            value = 0
        return {'type': 'literal', 'value': value}

    def _parse_string(self) -> dict:
        quote = self.source[self.pos]
        self.pos += 1
        result = ''
        while self.pos < len(self.source):
            c = self.source[self.pos]
            if c == quote:
                self.pos += 1
                break
            elif c == '\\' and self.pos + 1 < len(self.source):
                self.pos += 1
                nc = self.source[self.pos]
                if nc == 'n':
                    result += '\n'
                elif nc == 't':
                    result += '\t'
                elif nc == 'r':
                    result += '\r'
                elif nc == '\\':
                    result += '\\'
                elif nc == quote:
                    result += quote
                elif nc.isdigit():
                    digits = ''
                    while self.pos < len(self.source) and self.source[self.pos].isdigit() and len(digits) < 3:
                        digits += self.source[self.pos]
                        self.pos += 1
                    result += chr(int(digits) % 256)
                    self.pos -= 1
                self.pos += 1
            else:
                result += c
                self.pos += 1
        return {'type': 'literal', 'value': result}

    def _parse_table_constructor(self) -> dict:
        self.pos += 1
        fields = []
        self._skip_whitespace()
        while self.pos < len(self.source) and self.source[self.pos] != '}':
            if self.source[self.pos] == '[':
                self.pos += 1
                key = self._parse_expression()
                self._skip_whitespace()
                self._expect(']')
                self._skip_whitespace()
                self._expect('=')
                self._skip_whitespace()
                value = self._parse_expression()
                fields.append({'key': key, 'value': value, 'type': 'keyed'})
            elif self.source[self.pos].isalpha() or self.source[self.pos] == '_':
                name = self._parse_identifier()
                self._skip_whitespace()
                if self.pos < len(self.source) and self.source[self.pos] == '=':
                    self.pos += 1
                    self._skip_whitespace()
                    value = self._parse_expression()
                    fields.append({'key': {'type': 'literal', 'value': name}, 'value': value, 'type': 'keyed'})
                else:
                    fields.append({'value': {'type': 'identifier', 'name': name}, 'type': 'value'})
            else:
                value = self._parse_expression()
                fields.append({'value': value, 'type': 'value'})
            self._skip_whitespace()
            if self.pos < len(self.source) and (self.source[self.pos] == ',' or self.source[self.pos] == ';'):
                self.pos += 1
                self._skip_whitespace()
        if self.pos < len(self.source) and self.source[self.pos] == '}':
            self.pos += 1
        return {'type': 'table_constructor', 'fields': fields}

    def _parse_function_call(self, func_expr) -> dict:
        self.pos += 1
        args = []
        self._skip_whitespace()
        if self.pos < len(self.source) and self.source[self.pos] != ')':
            args.append(self._parse_expression())
            while self.pos < len(self.source) and self.source[self.pos] == ',':
                self.pos += 1
                self._skip_whitespace()
                args.append(self._parse_expression())
        self._skip_whitespace()
        if self.pos < len(self.source) and self.source[self.pos] == ')':
            self.pos += 1
        return {'type': 'function_call', 'func': func_expr, 'args': args}

    def _parse_index(self, obj_expr) -> dict:
        self.pos += 1
        key = self._parse_expression()
        self._skip_whitespace()
        if self.pos < len(self.source) and self.source[self.pos] == ']':
            self.pos += 1
        return {'type': 'index', 'object': obj_expr, 'key': key}

    def _is_block_end(self) -> bool:
        c = self.source[self.pos] if self.pos < len(self.source) else ''
        return c in (')', ']', '}', ',', ';') or (
            c == 'e' and (self.source[self.pos:self.pos+3] == 'end' or self.source[self.pos:self.pos+4] == 'else')
        )

    def _expect(self, c):
        if self.pos < len(self.source) and self.source[self.pos] == c:
            self.pos += 1

    def _expect_then(self):
        if self.pos + 4 < len(self.source) and self.source[self.pos:self.pos+4] == 'then':
            self.pos += 4

    def _expect_do(self):
        if self.pos + 2 < len(self.source) and self.source[self.pos:self.pos+2] == 'do':
            self.pos += 2
