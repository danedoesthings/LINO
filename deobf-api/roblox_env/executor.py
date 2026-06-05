from typing import Any, Dict, List
from .lua_parser import LuaParser

class Executor:
    def __init__(self, emulator):
        self.emulator = emulator
        self.globals = emulator.globals._globals
        self.locals: List[Dict[str, Any]] = [{}]
        self.return_value = None

    def run(self, source: str):
        source = source.strip()
        if source.startswith('return'):
            source = source[6:].strip()
        if source.startswith('(') and source.endswith(')'):
            source = source[1:-1].strip()
        parser = LuaParser(source)
        statements = parser.parse()
        for stmt in statements:
            self._execute_statement(stmt)
        return self.return_value

    def _execute_statement(self, stmt):
        if stmt is None:
            return
        t = stmt.get('type')
        if t == 'local_assign':
            self._exec_local_assign(stmt)
        elif t == 'local_declare':
            self._exec_local_declare(stmt)
        elif t == 'local_function':
            self._exec_local_function(stmt)
        elif t == 'function_def':
            self._exec_function_def(stmt)
        elif t == 'return':
            self._exec_return(stmt)
        elif t == 'if':
            self._exec_if(stmt)
        elif t == 'while':
            self._exec_while(stmt)
        elif t == 'for':
            self._exec_for(stmt)
        elif t == 'do':
            self._exec_block(stmt['body'])
        elif t == 'expr_stmt':
            self._eval_expression(stmt['expression'])

    def _exec_local_assign(self, stmt):
        values = [self._eval_expression(v) for v in stmt['values']]
        for i, name in enumerate(stmt['names']):
            val = values[i] if i < len(values) else None
            self.locals[-1][name] = val

    def _exec_local_declare(self, stmt):
        for name in stmt['names']:
            self.locals[-1][name] = None

    def _exec_local_function(self, stmt):
        func = self._make_function(stmt['params'], stmt['body'])
        self.locals[-1][stmt['name']] = func

    def _exec_function_def(self, stmt):
        func = self._make_function(stmt['params'], stmt['body'])
        if stmt['name']:
            self.globals[stmt['name']] = func

    def _exec_return(self, stmt):
        values = [self._eval_expression(v) for v in stmt['values']]
        self.return_value = values[0] if len(values) == 1 else tuple(values)

    def _exec_if(self, stmt):
        cond = self._eval_expression(stmt['condition'])
        if cond:
            self._exec_block(stmt['body'])
        elif stmt['else_body']:
            self._exec_block(stmt['else_body'])

    def _exec_while(self, stmt):
        max_iter = 100000
        count = 0
        while self._eval_expression(stmt['condition']) and count < max_iter:
            self._exec_block(stmt['body'])
            count += 1

    def _exec_for(self, stmt):
        start = self._eval_expression(stmt['start'])
        end = self._eval_expression(stmt['end'])
        step = self._eval_expression(stmt['step']) if stmt['step'] else 1
        var_name = stmt['var']
        var = start
        max_iter = 100000
        count = 0
        while var <= end and count < max_iter:
            self.locals[-1][var_name] = var
            self._exec_block(stmt['body'])
            var += step
            count += 1

    def _exec_block(self, body):
        self.locals.append({})
        for stmt in body:
            self._execute_statement(stmt)
        self.locals.pop()

    def _make_function(self, params, body):
        executor = self
        emulator = self.emulator
        def func(*args):
            old_locals = executor.locals
            executor.locals = [{}]
            for i, param in enumerate(params):
                if param == '...':
                    executor.locals[-1]['...'] = list(args[i:])
                elif i < len(args):
                    executor.locals[-1][param] = args[i]
                else:
                    executor.locals[-1][param] = None
            executor._exec_block(body)
            result = executor.return_value
            executor.return_value = None
            executor.locals = old_locals
            return result
        return func

    def _eval_expression(self, expr):
        if expr is None:
            return None
        t = expr.get('type')
        if t == 'literal':
            return expr['value']
        elif t == 'identifier':
            return self._resolve_name(expr['name'])
        elif t == 'vararg':
            return self.locals[-1].get('...', [])
        elif t == 'binary_op':
            return self._eval_binary_op(expr)
        elif t == 'unary_op':
            return self._eval_unary_op(expr)
        elif t == 'function_call':
            return self._eval_function_call(expr)
        elif t == 'method_call':
            return self._eval_method_call(expr)
        elif t == 'index':
            return self._eval_index(expr)
        elif t == 'member':
            return self._eval_member(expr)
        elif t == 'table_constructor':
            return self._eval_table_constructor(expr)
        elif t == 'function_def':
            func = self._make_function(expr['params'], expr['body'])
            return func
        return None

    def _resolve_name(self, name):
        for scope in reversed(self.locals):
            if name in scope:
                return scope[name]
        if name in self.globals:
            return self.globals[name]
        return None

    def _eval_binary_op(self, expr):
        left = self._eval_expression(expr['left'])
        right = self._eval_expression(expr['right'])
        op = expr['op']
        try:
            if op == '+': return left + right
            elif op == '-': return left - right
            elif op == '*': return left * right
            elif op == '/': return left / right
            elif op == '%': return left % right
            elif op == '^': return left ** right
            elif op == '..': return str(left) + str(right)
            elif op == '==': return left == right
            elif op == '~=': return left != right
            elif op == '<': return left < right
            elif op == '>': return left > right
            elif op == '<=': return left <= right
            elif op == '>=': return left >= right
            elif op == 'and': return left and right
            elif op == 'or': return left or right
        except Exception:
            return None
        return None

    def _eval_unary_op(self, expr):
        operand = self._eval_expression(expr['operand'])
        op = expr['op']
        try:
            if op == '-': return -operand
            elif op == 'not': return not operand
            elif op == '#': return len(operand) if operand else 0
        except Exception:
            return None
        return None

    def _eval_function_call(self, expr):
        func = self._eval_expression(expr['func'])
        args = [self._eval_expression(a) for a in expr['args']]
        if callable(func):
            try:
                return func(*args)
            except Exception:
                return None
        return None

    def _eval_method_call(self, expr):
        obj = self._eval_expression(expr['object'])
        method_name = expr['method']
        args = [self._eval_expression(a) for a in expr['args']]
        if hasattr(obj, method_name):
            method = getattr(obj, method_name)
            if callable(method):
                try:
                    return method(*args)
                except Exception:
                    return None
        return None

    def _eval_index(self, expr):
        obj = self._eval_expression(expr['object'])
        key = self._eval_expression(expr['key'])
        if isinstance(obj, dict):
            return obj.get(key)
        elif isinstance(obj, (list, tuple)):
            try:
                return obj[int(key) - 1]
            except Exception:
                return None
        elif isinstance(obj, str):
            try:
                return obj[int(key) - 1]
            except Exception:
                return None
        return None

    def _eval_member(self, expr):
        obj = self._eval_expression(expr['object'])
        member = expr['member']
        if hasattr(obj, member):
            return getattr(obj, member)
        elif isinstance(obj, dict) and member in obj:
            return obj[member]
        return None

    def _eval_table_constructor(self, expr):
        result = {}
        array_idx = 1
        for field in expr['fields']:
            if field['type'] == 'keyed':
                key = self._eval_expression(field['key'])
                value = self._eval_expression(field['value'])
                result[key] = value
            else:
                value = self._eval_expression(field['value'])
                result[array_idx] = value
                array_idx += 1
        return result
