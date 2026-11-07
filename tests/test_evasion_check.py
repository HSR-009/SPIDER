"""
Unit tests for Person_A/pipeline/evasion_check.py
"""

import tempfile
import unittest
from pathlib import Path

from Person_A.pipeline.evasion_check import run_evasion_check


class TestEvasionCheck(unittest.TestCase):
    def test_evasion_check_execution(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_md = Path(tmpdir) / "evasion_check.md"
            results = run_evasion_check(out_md=out_md, seed=42)
            self.assertTrue(out_md.exists())
            self.assertIn("T01", results)
            self.assertIn("T04", results)
            content = out_md.read_text(encoding="utf-8")
            self.assertIn("Adversarial Evasion Verification Report", content)
            self.assertIn("T04", content)


if __name__ == "__main__":
    unittest.main()

