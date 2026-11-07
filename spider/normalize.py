"""
spider/normalize.py
--------------------
⚠️ PLACEHOLDER / BEST-GUESS MODULE ⚠️
Built without access to the real repo's actual module layout, so the
import path `spider.normalize` and any integration points (e.g. a
`--normalize` CLI flag) are GUESSED to match the sprint plan's stated
target path. Verify this is where the real codebase expects it before
merging.

PURPOSE (per Day 4 spec):
Deterministic source-to-source normalization. Reverses specific
obfuscation patterns so a normalized file is easier for the analyzer to
read. Never executes the source it processes - everything here works by
parsing, transforming, and unparsing the AST only.

Four rules, one per Day 4 requirement:
  1. constant_fold_string_concat  - "a" + "b"  ->  "ab"
  2. resolve_import_aliases       - import os as x; x.system(...)  ->  os.system(...)
  3. decode_literal_base64        - base64.b64decode("...") with a constant
                                     string argument -> the decoded bytes literal
  4. getattr_to_attribute         - getattr(obj, "literal")  ->  obj.literal

Each rule is implemented as its own ast.NodeTransformer so they can be
tested and reasoned about independently, then composed in normalize_source().
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
        self.generic_visit(node)  # fold children first (handles chains)

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
# Rule 2: resolve import aliases
# ---------------------------------------------------------------------------

class ResolveImportAliases(ast.NodeTransformer):
    """
    Finds `import X as alias` statements, builds an alias->real-name map,
    then rewrites `alias.attr` usages to `X.attr`. The import statement
    itself is rewritten to drop the alias (import X), so the file is
    self-consistent after normalization.

    Limitation (documented, not silently hidden): only handles simple
    `import module as alias` - does not handle `from X import Y as alias`
    (that's a different AST shape and was out of scope for Day 4's stated
    four rules).
    """

    def __init__(self):
        self.alias_map = {}  # alias name -> real module name

    def visit_Import(self, node: ast.Import):
        new_names = []
        for alias in node.names:
            if alias.asname:
                self.alias_map[alias.asname] = alias.name
                new_names.append(ast.alias(name=alias.name, asname=None))
            else:
                new_names.append(alias)
        node.names = new_names
        return node

    def visit_Name(self, node: ast.Name):
        if node.id in self.alias_map:
            return ast.copy_location(
                ast.Name(id=self.alias_map[node.id], ctx=node.ctx), node
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
    than crashing normalization - malformed input should not break the
    pipeline.
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
                    return node  # leave malformed base64 untouched
        return node


# ---------------------------------------------------------------------------
# Rule 4: getattr(obj, "literal") -> attribute access
# ---------------------------------------------------------------------------

class GetattrToAttribute(ast.NodeTransformer):
    """
    Finds `getattr(obj, "literal_name")` with exactly 2 args, the second
    being a constant string, and rewrites it to `obj.literal_name`.

    Does NOT touch 3-arg getattr (the default-value form), since that's
    not equivalent to plain attribute access and rewriting it would change
    behavior - only the exact 2-arg literal form is safe to normalize.
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
    Applies all four normalization rules in sequence and returns the
    normalized source as a string. Never executes the input - parsing,
    transforming, and unparsing only.

    Raises SyntaxError if the input itself doesn't parse (propagated, not
    swallowed - the caller should decide how to handle unparseable input).
    """
    tree = ast.parse(source)

    tree = ConstantFoldStringConcat().visit(tree)
    tree = ResolveImportAliases().visit(tree)
    tree = DecodeLiteralBase64().visit(tree)
    tree = GetattrToAttribute().visit(tree)

    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


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
