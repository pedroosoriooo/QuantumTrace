"""Bounded Python constant/byte-length inference; never evaluates input code.

Only lengths are retained for byte values. Reassigned names, conflicting call
sites and expressions outside this small grammar resolve to None.
"""

import ast


def own_nodes(root):
    yield root
    for child in ast.iter_child_nodes(root):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield from own_nodes(child)


class PythonFacts:
    def __init__(self, tree, resolve):
        self.tree, self.resolve = tree, resolve
        self.functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
        self.scopes = [tree, *self.functions.values()]
        self.owner = {}
        self.bindings = {}
        self.calls = {}
        for scope in self.scopes:
            bindings = {}
            for n in own_nodes(scope):
                self.owner[id(n)] = scope
                if isinstance(n, (ast.Assign, ast.AnnAssign)):
                    targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                    for target in targets:
                        for name in ast.walk(target):
                            if isinstance(name, ast.Name) and isinstance(name.ctx, ast.Store):
                                bindings.setdefault(name.id, []).append((n.value if isinstance(target, ast.Name) else None, n.lineno))
                elif isinstance(n, (ast.AugAssign, ast.NamedExpr)) and isinstance(n.target, ast.Name):
                    bindings.setdefault(n.target.id, []).append((None, n.lineno))
                elif isinstance(n, ast.For):
                    for name in ast.walk(n.target):
                        if isinstance(name, ast.Name):
                            bindings.setdefault(name.id, []).append((None, n.lineno))
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                    self.calls.setdefault(n.func.id, []).append(n)
            self.bindings[id(scope)] = bindings

    def value(self, node, scope=None, depth=0):
        if node is None or depth > 12:
            return None
        scope = scope or self.owner.get(id(node), self.tree)
        recurse = lambda n, s=scope: self.value(n, s, depth + 1)
        if isinstance(node, ast.Constant):
            if type(node.value) is int and abs(node.value) < 1_000_000:
                return node.value
            if isinstance(node.value, bytes):
                return ("bytes", len(node.value))
            if isinstance(node.value, str) and len(node.value) < 200:
                return node.value
        if isinstance(node, ast.Name):
            bindings = self.bindings.get(id(scope), {})
            if node.id in bindings:
                assignments = bindings[node.id]
                if len(assignments) != 1:
                    return None
                value, line = assignments[0]
                if scope is self.tree and line >= node.lineno:
                    return None
                return recurse(value)
            if isinstance(scope, ast.FunctionDef):
                params = [*scope.args.posonlyargs, *scope.args.args]
                if node.id in {p.arg for p in params}:
                    position = next(i for i, p in enumerate(params) if p.arg == node.id)
                    sites = self.calls.get(scope.name, [])
                    if not sites:
                        return None
                    values = []
                    for call in sites:
                        argument = call.args[position] if position < len(call.args) else next((k.value for k in call.keywords if k.arg == node.id), None)
                        if argument is None:
                            default_pos = position - (len(params) - len(scope.args.defaults))
                            if default_pos >= 0:
                                argument = scope.args.defaults[default_pos]
                        values.append(recurse(argument, self.owner.get(id(call), self.tree)))
                    return values[0] if values and values[0] is not None and all(v == values[0] for v in values) else None
                return recurse(node, self.tree)
        if isinstance(node, ast.BinOp):
            a, b = recurse(node.left), recurse(node.right)
            if isinstance(node.op, ast.Mult):
                if type(a) is int and type(b) is int and abs(a * b) < 1_000_000:
                    return a * b
                for length, count in [(a, b), (b, a)]:
                    if isinstance(length, tuple) and length[0] == "bytes" and type(count) is int and 0 <= count <= 4096:
                        return ("bytes", length[1] * count)
            if isinstance(node.op, ast.Add):
                if type(a) is int and type(b) is int and abs(a + b) < 1_000_000:
                    return a + b
                if isinstance(a, tuple) and isinstance(b, tuple) and a[0] == b[0] == "bytes":
                    return ("bytes", a[1] + b[1])
        if isinstance(node, ast.Call):
            from .scanners import _name
            name = self.resolve(_name(node.func))
            if name in {"os.urandom", "secrets.token_bytes"} and node.args:
                length = recurse(node.args[0])
                if type(length) is int and 0 <= length <= 4096:
                    return ("bytes", length)
            if isinstance(node.func, ast.Name) and node.func.id in self.functions:
                function = self.functions[node.func.id]
                # Only a single return and no arguments are handled here.
                returns = [n for n in own_nodes(function) if isinstance(n, ast.Return)]
                if len(returns) == 1 and not function.args.args and not function.args.posonlyargs:
                    return recurse(returns[0].value, function)
        return None

    def integer_arg(self, call, keyword, position=None):
        node = next((k.value for k in call.keywords if k.arg == keyword), None)
        if node is None and position is not None and len(call.args) > position:
            node = call.args[position]
        value = self.value(node)
        return value if type(value) is int else None

    def byte_length(self, node):
        value = self.value(node)
        return value[1] if isinstance(value, tuple) and value[0] == "bytes" else None
