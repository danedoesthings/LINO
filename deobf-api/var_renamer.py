import re
from luaparser import ast
from luaparser.astnodes import Name, LocalAssign, Assign, Function, Fornum, Forin, While, Repeat, If, Call, Index, Return

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
            'assert','error','next','rawequal','_G','_ENV'
        }

    def rename(self, source):
        try:
            tree = ast.parse(source)
            self.var_map.clear()
            self.counter = 0
            self._collect_names(tree)
            return self._replace_in_source(source)
        except:
            return source

    def _collect_names(self, node):
        if isinstance(node, Name):
            name = node.id
            if name not in self.reserved and not name.startswith('_G') and not name.startswith('_ENV'):
                if name not in self.var_map:
                    self.var_map[name] = f'v{self.counter}'
                    self.counter += 1
        if isinstance(node, (LocalAssign, Assign)):
            for target in node.targets:
                self._collect_names(target)
            if hasattr(node, 'values'):
                for val in node.values:
                    self._collect_names(val)
            return
        if isinstance(node, Function):
            if hasattr(node, 'name') and node.name:
                self._collect_names(node.name)
            if hasattr(node, 'args'):
                for arg in node.args:
                    if isinstance(arg, Name):
                        self._collect_names(arg)
            if hasattr(node, 'body'):
                for stmt in node.body:
                    self._collect_names(stmt)
            return
        if isinstance(node, Fornum):
            self._collect_names(node.target)
            self._collect_names(node.start)
            self._collect_names(node.end)
            if node.step:
                self._collect_names(node.step)
            for stmt in node.body:
                self._collect_names(stmt)
            return
        if isinstance(node, Forin):
            for target in node.targets:
                self._collect_names(target)
            for expr in node.iter:
                self._collect_names(expr)
            for stmt in node.body:
                self._collect_names(stmt)
            return
        if isinstance(node, (While, Repeat)):
            self._collect_names(node.condition)
            for stmt in node.body:
                self._collect_names(stmt)
            return
        if isinstance(node, If):
            self._collect_names(node.test)
            for stmt in node.body:
                self._collect_names(stmt)
            if hasattr(node, 'orelse') and node.orelse:
                for stmt in node.orelse:
                    self._collect_names(stmt)
            return
        if isinstance(node, Call):
            self._collect_names(node.func)
            for arg in node.args:
                self._collect_names(arg)
            return
        if isinstance(node, Index):
            self._collect_names(node.value)
            self._collect_names(node.idx)
            return
        if isinstance(node, Return):
            if hasattr(node, 'values'):
                for val in node.values:
                    self._collect_names(val)
            return
        if hasattr(node, 'children'):
            for child in node.children():
                self._collect_names(child)

    def _replace_in_source(self, source):
        result = source
        for old, new in sorted(self.var_map.items(), key=lambda x: -len(x[0])):
            result = re.sub(r'\b' + re.escape(old) + r'\b', new, result)
        return result
