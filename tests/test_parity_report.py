"""
Unit tests for Person_A/pipeline/parity_report.py
"""

import tempfile
import unittest
from pathlib import Path

from Person_A.pipeline.parity_report import generate_parity_report


class TestParityReport(unittest.TestCase):
    def test_parity_report_execution_and_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_md = Path(tmpdir) / "parity.md"
            out_csv = Path(tmpdir) / "parity.csv"
            res = generate_parity_report(
                out_md=out_md,
                out_csv=out_csv,
                sample_size=10,
                seed=42,
            )
            self.assertTrue(out_md.exists())
            self.assertTrue(out_csv.exists())
            self.assertIn("benign_identical", res)
            self.assertIn("malicious_identical", res)
            md_text = out_md.read_text(encoding="utf-8")
            self.assertIn("Parity Report: Analyzer v1 vs Analyzer v1.1", md_text)
            self.assertIn("Top 10 Indicators Unique to One Side", md_text)


if __name__ == "__main__":
    unittest.main()

