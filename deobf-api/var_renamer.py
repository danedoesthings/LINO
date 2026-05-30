import re
import ast as py_ast
from luaparser import ast, astnodes

class VarRenamer:
    def __init__(self):
        self.var_map = {}
        self.counter = 0
        self.reserved = {
            'and','break','do','else','elseif','end','false','for','function','goto',
            'if','in','local','nil','not','or','repeat','return','then','true','until','while',
            'print','require','pcall','xpcall','loadstring','load','pairs','ipairs',
            'setmetatable','getmetatable','rawset','rawget','tostring','tonumber',
            'table','string','math','coroutine','debug','io','os','unpack','select','type',
            'assert','error','next','rawequal','_G','_ENV','self','arg'
        }
        self.prefix = 'v'
        self.name_format = 'alphabetic'

    def rename(self, source):
        try:
            tree = ast.parse(source)
        except:
            return source

        self.var_map.clear()
        self.counter = 0
        self._collect_locals(tree)
        self._walk_and_rename(tree)
        return self._emit(tree)

    def _generate_name(self):
        if self.name_format == 'alphabetic':
            name = ''
            n = self.counter
            while True:
                name = chr(97 + (n % 26)) + name
                n = n // 26
                if n == 0:
                    break
            return self.prefix + '_' + name
        return f'{self.prefix}{self.counter}'

    def _should_rename(self, name):
        if not name or not isinstance(name, str):
            return False
        if name in self.reserved:
            return False
        if name.startswith('_G.') or name.startswith('_ENV.'):
            return False
        if name.startswith('__') and name.endswith('__'):
            return False
        if len(name) == 1 and name.isalpha():
            return False
        return True

    def _collect_locals(self, tree):
        class LocalCollector(ast.ASTVisitor):
            def __init__(self, renamer):
                self.renamer = renamer
                self.scopes = [set()]
                self.function_params = set()

            def visit_LocalFunction(self, node):
                if node.name and self.renamer._should_rename(node.name):
                    self.scopes[-1].add(node.name)
                self.scopes.append(set())
                self.generic_visit(node)
                self.scopes.pop()

            def visit_Function(self, node):
                if node.name and self.renamer._should_rename(node.name):
                    self.scopes[-1].add(node.name)
                self.scopes.append(set())
                for param in node.args:
                    if param and self.renamer._should_rename(param):
                        self.scopes[-1].add(param)
                self.generic_visit(node)
                self.scopes.pop()

            def visit_LocalAssign(self, node):
                for target in node.targets:
                    if isinstance(target, astnodes.Name) and target.id:
                        if self.renamer._should_rename(target.id):
                            self.scopes[-1].add(target.id)
                self.generic_visit(node)

            def visit_For(self, node):
                if node.var and isinstance(node.var, astnodes.Name) and node.var.id:
                    if self.renamer._should_rename(node.var.id):
                        self.scopes[-1].add(node.var.id)
                self.scopes.append(set())
                self.generic_visit(node)
                self.scopes.pop()

            def visit_Fornum(self, node):
                if node.var and isinstance(node.var, astnodes.Name) and node.var.id:
                    if self.renamer._should_rename(node.var.id):
                        self.scopes[-1].add(node.var.id)
                self.scopes.append(set())
                self.generic_visit(node)
                self.scopes.pop()

            def visit_Foreach(self, node):
                for var in node.vars:
                    if isinstance(var, astnodes.Name) and var.id:
                        if self.renamer._should_rename(var.id):
                            self.scopes[-1].add(var.id)
                self.scopes.append(set())
                self.generic_visit(node)
                self.scopes.pop()

            def visit_Repeat(self, node):
                self.scopes.append(set())
                self.generic_visit(node)
                self.scopes.pop()

            def visit_While(self, node):
                self.scopes.append(set())
                self.generic_visit(node)
                self.scopes.pop()

            def visit_If(self, node):
                self.scopes.append(set())
                self.generic_visit(node)
                self.scopes.pop()

        collector = LocalCollector(self)
        collector.visit(tree)

    def _walk_and_rename(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, astnodes.Name) and hasattr(node, 'id') and node.id:
                if self._should_rename(node.id):
                    if node.id not in self.var_map:
                        name = self._generate_name()
                        self.var_map[node.id] = name
                        self.counter += 1

    def _emit(self, tree):
        source = ast.to_lua_source(tree)
        for old, new in sorted(self.var_map.items(), key=lambda x: -len(x[0])):
            source = re.sub(r'\b' + re.escape(old) + r'\b', new, source)
        return source

    def rename_only(self, source, mapping):
        result = source
        for old, new in sorted(mapping.items(), key=lambda x: -len(x[0])):
            result = re.sub(r'\b' + re.escape(old) + r'\b', new, result)
        return result

    def get_mapping(self):
        return dict(self.var_map)

    def reset(self):
        self.var_map.clear()
        self.counter = 0
