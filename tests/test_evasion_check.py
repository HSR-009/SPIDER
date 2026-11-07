"""
Unit tests for Person_A/pipeline/evasion_check.py
Tests Part A seeds evaluation, baseline results parser,
and Part B targeted file transformation logic.
Never writes to results/evasion_check_by_A.md.
"""

import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from Person_A.pipeline.evasion_check import (
    read_c_baseline_results,
    score_verdict_and_signal,
    evaluate_part_a_seeds,
    apply_part_b_transformations,
    run_evasion_check,
)


class TestEvasionCheck(unittest.TestCase):
    def test_read_c_baseline_results(self):
        # Reads person_c/baseline_results.md
        res = read_c_baseline_results()
        self.assertIn("Base64", res)
        self.assertIn("ROT13", res)
        self.assertIn("getattr", res)
        self.assertEqual(res["getattr"]["evaded"], 1)
        self.assertEqual(res["getattr"]["evasion_rate"], "100.0%")

    def test_score_verdict_and_signal(self):
        # 1. Recovered: same strong signals still fire
        s = score_verdict_and_signal("suspicious", ["S1_install_command"], "suspicious", ["S1_install_command"])
        self.assertEqual(s, "recovered")

        # 2. Different signal: still suspicious but via different IDs
        s = score_verdict_and_signal("suspicious", ["S1_install_command"], "suspicious", ["S2_dynamic_exec_plus"])
        self.assertEqual(s, "different_signal")

        # 3. Missed: no longer suspicious
        s = score_verdict_and_signal("suspicious", ["S1_install_command"], "none_detected_in_this_scan", [])
        self.assertEqual(s, "missed")

    def test_evaluate_part_a_seeds(self):
        # Runs against person_c/seeds
        stats = evaluate_part_a_seeds()
        self.assertIn("T01_string_split", stats)
        self.assertIn("T02_base64", stats)
        self.assertIn("T04_getattr", stats)
        self.assertIn("T07_dunder_import", stats)
        # 20 seeds evaluated
        self.assertEqual(stats["T02_base64"]["total"], 20)

    def test_part_b_targeted_archive_transformation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            arc_path = tmp_path / "pkg-1.0.0.tar.gz"

            # Create synthetic archive with setup.py and helper.py
            setup_code = b"import setuptools\nfrom setuptools.command.install import install\nclass C(install):\n def run(self): pass\nsetuptools.setup(cmdclass={'install': C})\n"
            helper_code = b"def helper(): return 42\n"

            ti1 = tarfile.TarInfo("pkg-1.0.0/setup.py")
            ti1.size = len(setup_code)
            ti2 = tarfile.TarInfo("pkg-1.0.0/helper.py")
            ti2.size = len(helper_code)

            with tarfile.open(arc_path, "w:gz") as tf:
                tf.addfile(ti1, io.BytesIO(setup_code))
                tf.addfile(ti2, io.BytesIO(helper_code))

            # Target only setup.py where the strong signal is
            strong_files = {"pkg-1.0.0/setup.py"}
            results = apply_part_b_transformations(arc_path, strong_files, ["S1_install_command"])

            self.assertIn("T02_base64", results)
            self.assertIn("T03_rot13", results)
            self.assertIn("T05_delay", results)
            # T05 on S1 setup override should recover S1
            self.assertEqual(results["T05_delay"], "recovered")

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
                    sample_size=5,
                )
            self.assertIn("Insufficient raw archives found for Part B evasion check", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
