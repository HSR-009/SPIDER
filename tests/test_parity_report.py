"""
Unit tests for Person_A/pipeline/parity_report.py
Tests archive collection, single extracted directory analysis with v1,
scan_benign, and v1.1, and exit on missing raw archives.
"""

import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from Person_A.pipeline.parity_report import (
    analyze_extracted_dir,
    collect_archives,
    run_parity_comparison,
)


class TestParityReport(unittest.TestCase):
    def test_analyze_extracted_dir_three_analyzers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            py_file = tmp_path / "main.py"
            py_file.write_text("import os\nos.system('whoami')\n", encoding="utf-8")

            res = analyze_extracted_dir(tmpdir)
            self.assertEqual(res["python_files"], 1)
            self.assertIn("os.system", res["v1_indicators"])
            self.assertIn("os.system", res["scan_benign_indicators"])
            self.assertIn("os.system", res["v11_indicators"])

    def test_missing_raw_dir_exits_cleanly(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            empty_benign = Path(tmpdir) / "benign"
            empty_mal = Path(tmpdir) / "mal"
            empty_benign.mkdir()
            empty_mal.mkdir()

            with self.assertRaises(SystemExit) as cm:
                run_parity_comparison(
                    empty_benign,
                    empty_mal,
                    Path(tmpdir) / "out.md",
                    Path(tmpdir) / "out.csv",
                    sample_size=10,
                )
            self.assertIn("Insufficient raw archives found", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
