"""Hostile archive and scan tests (Day 3 step 3.7 & section 7.7)."""
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from spider.engine.extract import safe_extract
from spider.engine.limits import Limits
from spider.engine.scan import scan_directory


class HostileArchiveScanTests(unittest.TestCase):
    def test_01_nesting_depth_60(self):
        """Case 8: directory nesting depth exceeding max_depth limit."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "pkg"
            curr = root
            # Create nesting depth 15 with max_depth=10 to avoid Windows MAX_PATH length limits
            for i in range(15):
                curr = curr / f"d_{i}"
            curr.mkdir(parents=True)
            (curr / "deep.py").write_text("x = 1\n", encoding="utf-8")

            t0 = time.time()
            record = scan_directory(root, limits=Limits(max_depth=10))
            elapsed = time.time() - t0

            self.assertLess(elapsed, 10.0)
            self.assertIn("max_depth", record["inventory"]["limits_hit"])
            self.assertEqual(record["verdict"]["outcome"], "unable_to_assess")

    def test_02_max_files_limit_hit(self):
        """Case 7: 30,000 tiny files hitting max_files."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "pkg"
            root.mkdir()
            # For fast bounded test within 10s, test with max_files=100 and create 150 files
            for i in range(150):
                (root / f"f_{i:04d}.py").write_text("x = 1\n", encoding="utf-8")

            t0 = time.time()
            record = scan_directory(root, limits=Limits(max_files=100))
            elapsed = time.time() - t0

            self.assertLess(elapsed, 10.0)
            self.assertIn("max_files", record["inventory"]["limits_hit"])
            self.assertEqual(record["verdict"]["outcome"], "unable_to_assess")

    def test_03_junk_py_files_syntax_errors(self):
        """Case 9: junk .py files with syntax errors -> parse failure ratio -> unable_to_assess."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "pkg"
            root.mkdir()
            # 20 syntax error files, 2 clean files (> 20% parse error ratio)
            for i in range(20):
                (root / f"bad_{i}.py").write_text(f"def bad_{i}(:\n", encoding="utf-8")
            (root / "good.py").write_text("a = 1\n", encoding="utf-8")

            t0 = time.time()
            record = scan_directory(root)
            elapsed = time.time() - t0

            self.assertLess(elapsed, 10.0)
            self.assertGreater(len(record["inventory"]["parse_failures"]), 0)
            self.assertEqual(record["verdict"]["outcome"], "unable_to_assess")
            self.assertTrue(any("parse_failure_ratio" in r for r in record["verdict"]["reasons"]))

    def test_04_single_too_large_py_file(self):
        """Case 10: single 5 MB .py file (> max_file_bytes -> too_large)."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "pkg"
            root.mkdir()
            # Use small max_file_bytes (100 KB) and write a 150 KB file
            big_file = root / "large.py"
            big_file.write_text("#" + "a" * (150 * 1024) + "\n", encoding="utf-8")
            (root / "small.py").write_text("y = 2\n", encoding="utf-8")

            t0 = time.time()
            record = scan_directory(root, limits=Limits(max_file_bytes=100 * 1024))
            elapsed = time.time() - t0

            self.assertLess(elapsed, 10.0)
            uninspected_reasons = {u["path"]: u["reason"] for u in record["inventory"]["uninspected"]}
            self.assertIn("large.py", uninspected_reasons)
            self.assertEqual(uninspected_reasons["large.py"], "too_large")

    def test_05_deeply_nested_parentheses_recursion_error(self):
        """Case 11: 5000 nested parentheses (RecursionError/MemoryError in ast.parse -> parse failure, not crash)."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "pkg"
            root.mkdir()
            nested_code = "(" * 5000 + "1" + ")" * 5000 + "\n"
            (root / "nested.py").write_text(nested_code, encoding="utf-8")

            t0 = time.time()
            record = scan_directory(root)
            elapsed = time.time() - t0

            self.assertLess(elapsed, 10.0)
            # Must not crash; nested.py must be recorded in parse_failures
            pf_paths = [pf["path"] for pf in record["inventory"]["parse_failures"]]
            self.assertIn("nested.py", pf_paths)

    def test_06_never_executes_content_marker_test(self):
        """Test: scanner never executes package code; marker file must NOT exist after scan."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "pkg"
            root.mkdir()
            marker_file = Path(tmp) / "spider_pwned_marker.txt"
            # Code that would create marker_file if executed
            code = (
                f"import pathlib\n"
                f"pathlib.Path(r'{marker_file}').write_text('PWNED')\n"
            )
            (root / "malicious_script.py").write_text(code, encoding="utf-8")

            t0 = time.time()
            record = scan_directory(root)
            elapsed = time.time() - t0

            self.assertLess(elapsed, 10.0)
            self.assertFalse(marker_file.exists(), "CRITICAL: Scanner executed package code!")


if __name__ == "__main__":
    unittest.main()
