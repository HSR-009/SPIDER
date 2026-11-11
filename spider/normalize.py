"""
spider/normalize.py
--------------------
Deterministic source-to-source normalization. It rewrites four patterns
so a later static scan can see the underlying call:

  1. concat folding    - "a" + "b"            ->  "ab"
  2. import-as aliases - import os as x       ->  os, and uses of x in that scope
  3. literal base64    - base64.b64decode("…") with a constant string
                         -> the decoded bytes literal
  4. 2-arg getattr     - getattr(obj, "name") ->  obj.name

Alias rewrite is scope-sensitive: a function-local `import os as x` rewrites
`x` only inside that function. It does not rewrite `x` in other functions or
in the enclosing module.

Nothing here executes the source. Parsing, transforming, and unparsing only.
A RecursionError on a deeply nested expression returns the original source.
"""

import ast
import base64


# ---------------------------------------------------------------------------
# Rule 1: constant-fold string concatenation
# ---------------------------------------------------------------------------

class ConstantFoldStringConcat(ast.NodeTransformer):
    """
    Folds `"a" + "b" + "c"` (chains of constant string BinOp/Add) into a
    single string constant. Only folds when BOTH operands are already
    constant strings - never touches concatenation involving a variable.
    """

    def visit_BinOp(self, node: ast.BinOp):
        self.generic_visit(node)

        if (
            isinstance(node.op, ast.Add)
            and isinstance(node.left, ast.Constant)
            and isinstance(node.left.value, str)
            and isinstance(node.right, ast.Constant)
            and isinstance(node.right.value, str)
        ):
            return ast.copy_location(
                ast.Constant(value=node.left.value + node.right.value), node
            )
        return node


# ---------------------------------------------------------------------------
# Rule 2: resolve import aliases (per scope)
# ---------------------------------------------------------------------------

def _bindings(stmts, args):
    """Alias map and names bound directly in this scope.

    Nested function and class bodies are separate scopes: an assignment or
    import inside them does not bind the name here, except for the
    function or class name itself.
    """
    aliases = {}
    bound = set()
    if args is not None:
        for arg in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs):
            bound.add(arg.arg)
        if args.vararg is not None:
            bound.add(args.vararg.arg)
        if args.kwarg is not None:
            bound.add(args.kwarg.arg)

    def collect(stmt):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(stmt.name)
            return
        if isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, list):
                    for sub in child:
                        if isinstance(sub, ast.stmt):
                            collect(sub)
            return
        if isinstance(stmt, ast.Try):
            for sub in list(stmt.body) + list(stmt.orelse) + list(stmt.finalbody):
                collect(sub)
            for handler in stmt.handlers:
                if handler.name:
                    bound.add(handler.name)
                for sub in handler.body:
                    collect(sub)
            return
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            for alias in stmt.names:
                local = alias.asname or alias.name.split(".")[0]
                bound.add(local)
                if isinstance(stmt, ast.Import) and alias.asname:
                    aliases[alias.asname] = alias.name
            return
        stack = [stmt]
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    bound.add(node.name)
                continue
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                bound.add(node.id)
            else:
                stack.extend(ast.iter_child_nodes(node))

    for stmt in stmts:
        collect(stmt)
    return aliases, bound


class ResolveImportAliases(ast.NodeTransformer):
    """
    Rewrites `import module as alias` and uses of `alias` in the same
    scope (and enclosing scopes, unless a closer scope binds the name).

    A function-local alias does not leak into other functions or the
    enclosing module. `from X import Y as alias` is left unchanged.
    """

    def __init__(self):
        self.scopes = []

    def _push(self, stmts, args):
        aliases, bound = _bindings(stmts, args)
        self.scopes.append({"aliases": aliases, "bound": bound})

    def _pop(self):
        self.scopes.pop()

    def visit_Module(self, node: ast.Module):
        self._push(node.body, None)
        node.body = [self.visit(stmt) for stmt in node.body]
        self._pop()
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef):
        node.decorator_list = [self.visit(item) for item in node.decorator_list]
        node.args.defaults = [self.visit(item) for item in node.args.defaults]
        node.args.kw_defaults = [
            self.visit(item) if item is not None else None for item in node.args.kw_defaults
        ]
        self._push(node.body, node.args)
        node.body = [self.visit(stmt) for stmt in node.body]
        self._pop()
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        node.decorator_list = [self.visit(item) for item in node.decorator_list]
        node.args.defaults = [self.visit(item) for item in node.args.defaults]
        node.args.kw_defaults = [
            self.visit(item) if item is not None else None for item in node.args.kw_defaults
        ]
        self._push(node.body, node.args)
        node.body = [self.visit(stmt) for stmt in node.body]
        self._pop()
        return node

    def visit_ClassDef(self, node: ast.ClassDef):
        node.decorator_list = [self.visit(item) for item in node.decorator_list]
        node.bases = [self.visit(item) for item in node.bases]
        node.keywords = [self.visit(item) for item in node.keywords]
        self._push(node.body, None)
        node.body = [self.visit(stmt) for stmt in node.body]
        self._pop()
        return node

    def visit_Import(self, node: ast.Import):
        aliases = self.scopes[-1]["aliases"] if self.scopes else {}
        new_names = []
        for alias in node.names:
            if alias.asname and alias.asname in aliases and aliases[alias.asname] == alias.name:
                new_names.append(ast.alias(name=alias.name, asname=None))
            else:
                new_names.append(alias)
        node.names = new_names
        return node

    def visit_Name(self, node: ast.Name):
        for scope in reversed(self.scopes):
            if node.id in scope["bound"] and node.id not in scope["aliases"]:
                return node
            if node.id in scope["aliases"]:
                real = scope["aliases"][node.id]
                if "." in real:
                    return node
                return ast.copy_location(
                    ast.Name(id=real, ctx=node.ctx), node
                )
        return node


# ---------------------------------------------------------------------------
# Rule 3: decode literal base64
# ---------------------------------------------------------------------------

class DecodeLiteralBase64(ast.NodeTransformer):
    """
    Finds `base64.b64decode("...")` (or `b64decode("...")` if imported
    directly) where the argument is a constant string, and replaces the
    whole call with the decoded bytes as a literal.

    If decoding fails (invalid base64), the call is left untouched rather
    than crashing normalization.
    """

    def visit_Call(self, node: ast.Call):
        self.generic_visit(node)

        func = node.func
        is_b64decode = (
            (isinstance(func, ast.Attribute) and func.attr == "b64decode")
            or (isinstance(func, ast.Name) and func.id == "b64decode")
        )

        if is_b64decode and len(node.args) == 1 and isinstance(node.args[0], ast.Constant):
            arg_value = node.args[0].value
            if isinstance(arg_value, str):
                try:
                    decoded = base64.b64decode(arg_value)
                    return ast.copy_location(ast.Constant(value=decoded), node)
                except Exception:
                    return node
        return node


# ---------------------------------------------------------------------------
# Rule 4: getattr(obj, "literal") -> attribute access
# ---------------------------------------------------------------------------

class GetattrToAttribute(ast.NodeTransformer):
    """
    Finds `getattr(obj, "literal_name")` with exactly 2 args, the second
    being a constant string, and rewrites it to `obj.literal_name`.

    Does not touch 3-arg getattr (the default-value form).
    """

    def visit_Call(self, node: ast.Call):
        self.generic_visit(node)

        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) == 2
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
            and node.args[1].value.isidentifier()
        ):
            obj_expr = node.args[0]
            attr_name = node.args[1].value
            return ast.copy_location(
                ast.Attribute(value=obj_expr, attr=attr_name, ctx=ast.Load()), node
            )
        return node


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------

def normalize_source(source: str) -> str:
    """
    Apply all four rules and return the normalized source.

    Raises SyntaxError if the input itself does not parse.
    On RecursionError (deeply nested expressions), returns `source` unchanged.
    """
    try:
        tree = ast.parse(source)
        tree = ConstantFoldStringConcat().visit(tree)
        tree = ResolveImportAliases().visit(tree)
        tree = DecodeLiteralBase64().visit(tree)
        tree = GetattrToAttribute().visit(tree)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
    except RecursionError:
        return source


if __name__ == "__main__":
    examples = [
        '"sys" + "tem"',
        'import os as x\nx.system("ls")',
        'import base64\nbase64.b64decode("aGVsbG8=")',
        'getattr(os, "system")("ls")',
    ]
    for ex in examples:
        print("--- input ---")
        print(ex)
        print("--- normalized ---")
        print(normalize_source(ex))
        print()
