"""
test_normalize.py
------------------
One test per normalization rule, plus a composition test.

⚠️ PLACEHOLDER NOTE: import path assumes `spider/normalize.py` is
importable as `spider.normalize` from the repo root - verify this matches
the real project structure (may need a conftest.py or sys.path adjustment
depending on how the real test suite is set up).
"""

import ast
import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from spider.normalize import (
    normalize_source,
    ConstantFoldStringConcat,
    ResolveImportAliases,
    DecodeLiteralBase64,
    GetattrToAttribute,
)


class TestConstantFoldStringConcat(unittest.TestCase):
    def test_folds_two_constant_strings(self):
        result = normalize_source('x = "sys" + "tem"')
        tree = ast.parse(result)
        # Should be a single assignment with a Constant value "system"
        assign = tree.body[0]
        self.assertIsInstance(assign.value, ast.Constant)
        self.assertEqual(assign.value.value, "system")

    def test_folds_chain_of_three(self):
        result = normalize_source('x = "a" + "b" + "c"')
        tree = ast.parse(result)
        self.assertEqual(tree.body[0].value.value, "abc")

    def test_does_not_fold_when_variable_involved(self):
        source = 'y = "a"\nx = y + "b"'
        result = normalize_source(source)
        # Should NOT have folded - "b" is still a separate constant,
        # concatenation with a variable is left as a BinOp
        tree = ast.parse(result)
        last_assign = tree.body[-1]
        self.assertIsInstance(last_assign.value, ast.BinOp)


class TestResolveImportAliases(unittest.TestCase):
    def test_resolves_simple_alias(self):
        source = 'import os as x\nx.system("ls")'
        result = normalize_source(source)
        self.assertIn("import os", result)
        self.assertNotIn(" as ", result)
        self.assertIn("os.system", result)

    def test_multiple_aliases_in_one_file(self):
        source = 'import os as x\nimport sys as y\nx.getcwd()\ny.exit()'
        result = normalize_source(source)
        self.assertIn("os.getcwd", result)
        self.assertIn("sys.exit", result)
        self.assertNotIn(" as ", result)


class TestDecodeLiteralBase64(unittest.TestCase):
    def test_decodes_constant_base64_string(self):
        source = 'import base64\nbase64.b64decode("aGVsbG8=")'
        result = normalize_source(source)
        tree = ast.parse(result)
        # Second statement's value should now be a bytes constant b'hello'
        expr_stmt = tree.body[-1]
        self.assertIsInstance(expr_stmt.value, ast.Constant)
        self.assertEqual(expr_stmt.value.value, b"hello")

    def test_leaves_malformed_base64_untouched(self):
        source = 'import base64\nbase64.b64decode("not valid base64!!")'
        result = normalize_source(source)
        self.assertIn("b64decode", result)  # call left in place, not crashed


class TestGetattrToAttribute(unittest.TestCase):
    def test_converts_two_arg_getattr(self):
        result = normalize_source('getattr(os, "system")')
        tree = ast.parse(result)
        expr = tree.body[0].value
        self.assertIsInstance(expr, ast.Attribute)
        self.assertEqual(expr.attr, "system")

    def test_does_not_touch_three_arg_getattr(self):
        # 3-arg getattr has a default value - NOT equivalent to attribute
        # access, must be left alone
        source = 'getattr(os, "nonexistent", None)'
        result = normalize_source(source)
        self.assertIn("getattr", result)

    def test_does_not_touch_non_identifier_string(self):
        # "not-a-valid-name" isn't a legal attribute name, so this must
        # not be rewritten even though it's a 2-arg getattr
        source = 'getattr(os, "not-a-valid-name")'
        result = normalize_source(source)
        self.assertIn("getattr", result)


class TestComposition(unittest.TestCase):
    def test_all_four_rules_together(self):
        """
        A combined evasion example using multiple techniques at once -
        confirms the rules compose correctly rather than interfering with
        each other.
        """
        source = (
            'import os as x\n'
            'getattr(x, "sys" + "tem")("ls")'
        )
        result = normalize_source(source)
        # After alias resolution: x -> os
        # After string fold: "sys"+"tem" -> "system"
        # After getattr conversion: getattr(os, "system") -> os.system
        self.assertIn("os.system", result)
        self.assertNotIn("getattr", result)
        self.assertNotIn(" as ", result)

    def test_output_is_always_valid_python(self):
        """Normalized output must always parse as valid Python."""
        sources = [
            '"a" + "b"',
            'import os as x\nx.system("ls")',
            'import base64\nbase64.b64decode("aGVsbG8=")',
            'getattr(os, "system")',
        ]
        for src in sources:
            result = normalize_source(src)
            ast.parse(result)  # raises SyntaxError if invalid - test fails


if __name__ == "__main__":
    unittest.main(verbosity=2)
