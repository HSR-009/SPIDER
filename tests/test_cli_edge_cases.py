"""Edge-case tests for the spider CLI (brief section 6.5)."""
from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import spider.cli as cli


class TestCLIEdgeCases(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="spider_cli_edge_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_scan_empty_directory(self):
        """Empty directory should return 20 (unable_to_assess) since files_inspected == 0."""
        empty_dir = self.temp_dir / "empty"
        empty_dir.mkdir()

        out_dir = self.temp_dir / "scans"
        ret = cli.main(["scan", str(empty_dir), "--out", str(out_dir)])
        self.assertEqual(ret, 20)
        self.assertTrue(out_dir.exists())
        scan_records = list(out_dir.glob("*.json"))
        self.assertEqual(len(scan_records), 1)
        data = json.loads(scan_records[0].read_text(encoding="utf-8"))
        self.assertEqual(data["verdict"]["outcome"], "unable_to_assess")
        self.assertIn("nothing_inspected", data["verdict"]["reasons"])
        from spider_contract.validate import validate_record
        self.assertEqual(validate_record(data), [])

    def test_scan_docs_only_directory(self):
        """Directory containing only docs should return 20 (unable_to_assess)."""
        docs_dir = self.temp_dir / "docs_only"
        docs_dir.mkdir()
        (docs_dir / "README.md").write_text("# Documentation\n", encoding="utf-8")
        (docs_dir / "LICENSE").write_text("MIT License\n", encoding="utf-8")

        out_dir = self.temp_dir / "scans"
        ret = cli.main(["scan", str(docs_dir), "--out", str(out_dir)])
        self.assertEqual(ret, 20)
        self.assertTrue(out_dir.exists())
        scan_records = list(out_dir.glob("*.json"))
        self.assertEqual(len(scan_records), 1)
        data = json.loads(scan_records[0].read_text(encoding="utf-8"))
        self.assertEqual(data["verdict"]["outcome"], "unable_to_assess")
        self.assertIn("nothing_inspected", data["verdict"]["reasons"])
        from spider_contract.validate import validate_record
        self.assertEqual(validate_record(data), [])

    def test_scan_clean_py_file_directory(self):
        """Directory containing a clean .py file should return 0 (none_detected_in_this_scan)."""
        clean_dir = self.temp_dir / "clean_pkg"
        clean_dir.mkdir()
        (clean_dir / "module.py").write_text("def hello():\n    return 'world'\n", encoding="utf-8")

        out_dir = self.temp_dir / "scans"
        ret = cli.main(["scan", str(clean_dir), "--out", str(out_dir)])
        self.assertEqual(ret, 0)
        self.assertTrue(out_dir.exists())

    def test_scan_directory_with_only_binaries(self):
        """Directory with only uninspected binaries should yield unable_to_assess (exit 20)."""
        bin_dir = self.temp_dir / "bins_only"
        bin_dir.mkdir()
        (bin_dir / "library.so").write_bytes(b"\x7fELF" + b"\x00" * 100)

        out_dir = self.temp_dir / "scans"
        ret = cli.main(["scan", str(bin_dir), "--out", str(out_dir)])
        self.assertEqual(ret, 20)

    def test_scan_file_not_an_archive(self):
        """Plain text file that is not a supported archive should give error and exit code 2."""
        txt_file = self.temp_dir / "readme.txt"
        txt_file.write_text("just text", encoding="utf-8")

        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            ret = cli.main(["scan", str(txt_file)])
        self.assertEqual(ret, 2)
        err_msg = stderr.getvalue()
        self.assertIn("not an existing directory, supported archive, or name==version", err_msg)
        self.assertNotIn("Traceback", err_msg)

    def test_scan_nonexistent_path(self):
        """Non-existent path should print a clean human error message and exit 2."""
        nonexistent = self.temp_dir / "does_not_exist_xyz"

        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            ret = cli.main(["scan", str(nonexistent)])
        self.assertEqual(ret, 2)
        err_msg = stderr.getvalue()
        self.assertIn("not an existing directory, supported archive, or name==version", err_msg)
        self.assertNotIn("Traceback", err_msg)

    def test_scan_name_version_with_no_network(self):
        """name==version with --no-network should exit 2 with a clean error message."""
        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            ret = cli.main(["scan", "requests==2.31.0", "--no-network"])
        self.assertEqual(ret, 2)
        err_msg = stderr.getvalue()
        self.assertIn("Network access disabled (--no-network)", err_msg)
        self.assertNotIn("Traceback", err_msg)


if __name__ == "__main__":
    unittest.main()

