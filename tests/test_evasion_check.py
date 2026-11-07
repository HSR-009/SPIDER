"""
Unit tests for Person_A/pipeline/evasion_check.py
Tests scoring logic by verdict and strong signal, transformation wrapper
execution, and missing raw archives exit.
Never writes to results/evasion_check_by_A.md.
"""

import tempfile
import unittest
from pathlib import Path

from Person_A.pipeline.evasion_check import (
    score_verdict_and_signal,
    apply_transformation_to_code,
    run_evasion_check,
)


class TestEvasionCheck(unittest.TestCase):
    def test_score_verdict_and_signal(self):
        # 1. Recovered: same strong signals still fire
        s = score_verdict_and_signal("suspicious", ["S1_install_command"], "suspicious", ["S1_install_command"])
        self.assertEqual(s, "recovered")

        # 2. Different signal: still suspicious but different signals
        s = score_verdict_and_signal("suspicious", ["S1_install_command"], "suspicious", ["S2_dynamic_exec_plus"])
        self.assertEqual(s, "different_signal")

        # 3. Missed: no longer suspicious
        s = score_verdict_and_signal("suspicious", ["S1_install_command"], "none_detected_in_this_scan", [])
        self.assertEqual(s, "missed")

        s = score_verdict_and_signal("suspicious", ["S1_install_command"], "unable_to_assess", [])
        self.assertEqual(s, "missed")

    def test_apply_transformations(self):
        code = 'import os\nos.system("whoami")\n'
        t01 = apply_transformation_to_code(code, "T01_string_split")
        self.assertIn("system", t01)

        t02 = apply_transformation_to_code(code, "T02_base64")
        self.assertIn("base64", t02)
        self.assertIn("exec", t02)

        t03 = apply_transformation_to_code(code, "T03_rot13")
        self.assertIn("codecs", t03)
        self.assertIn("rot_13", t03)

        t04 = apply_transformation_to_code(code, "T04_getattr")
        self.assertIn("getattr", t04)

        t05 = apply_transformation_to_code(code, "T05_delay")
        self.assertIn("counter", t05)

        t06 = apply_transformation_to_code(code, "T06_import_alias")
        self.assertIn("_mod_alias", t06)

        t07 = apply_transformation_to_code(code, "T07_dunder_import")
        self.assertIn("__import__", t07)

    def test_missing_raw_dir_exits(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            empty_b = Path(tmpdir) / "empty_b"
            empty_m = Path(tmpdir) / "empty_m"
            empty_b.mkdir()
            empty_m.mkdir()

            with self.assertRaises(SystemExit) as cm:
                run_evasion_check(
                    benign_raw=empty_b,
                    mal_raw=empty_m,
                    out_md=Path(tmpdir) / "out.md",
                    n_sample=5,
                )
            self.assertIn("Insufficient raw archives found", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
