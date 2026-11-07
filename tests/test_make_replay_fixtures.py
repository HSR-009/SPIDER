"""
Unit tests for Person_A/pipeline/make_replay_fixtures.py
Tests selection logic, synthetic extraction, scan_directory execution,
and schema validation in a temporary test directory.
Never outputs to fixtures/replay.
"""

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from Person_A.pipeline.make_replay_fixtures import (
    select_10_packages,
    resolve_archive_path,
    generate_single_replay_fixture,
)
from spider_contract.validate import schema_errors, semantic_errors


class TestMakeReplayFixtures(unittest.TestCase):
    def test_select_10_packages_from_table(self):
        # Uses real malicious_v11.jsonl
        packages = select_10_packages("data/processed/malicious_v11.jsonl")
        self.assertEqual(len(packages), 10)
        roles = [p[0] for p in packages]
        self.assertEqual(
            roles,
            [
                "S1_install_command",
                "S2_dynamic_exec_plus",
                "S3_credential_net",
                "S4_env_post",
                "S5_decode_exec",
                "unable_to_assess",
                "review_recommended",
                "other_none_1",
                "other_none_2",
                "other_none_3",
            ],
        )
        unique_ids = {p[1]["package_id"] for p in packages}
        self.assertEqual(len(unique_ids), 10)

    def test_synthetic_archive_replay_pipeline(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            arc_path = tmp_path / "synthetic_pkg-1.0.0.tar.gz"
            out_dir = tmp_path / "replay_out"

            # Create a tiny synthetic tar.gz
            setup_code = b"import setuptools\nsetuptools.setup(name='synthetic_pkg', version='1.0.0')\n"
            ti = tarfile.TarInfo("synthetic_pkg-1.0.0/setup.py")
            ti.size = len(setup_code)
            with tarfile.open(arc_path, "w:gz") as tf:
                tf.addfile(ti, io.BytesIO(setup_code))

            pkg_row = {
                "package_id": "synthetic_pkg==1.0.0",
                "package_name": "synthetic_pkg",
                "version": "1.0.0",
                "archive_used": str(arc_path),
                "verdict_outcome": "none_detected_in_this_scan",
            }

            dest = generate_single_replay_fixture(arc_path, pkg_row, out_dir, 1)
            self.assertTrue(dest.exists())
            self.assertEqual(dest.name, "01_synthetic_pkg-1.0.0.json")

            rec = json.loads(dest.read_text(encoding="utf-8"))
            self.assertEqual(rec["record_origin"], "replay")
            self.assertEqual(rec["target"]["kind"], "archive")
            self.assertIsNone(rec["target"]["hash_verified"])
            self.assertEqual(schema_errors(rec), [])
            self.assertEqual(semantic_errors(rec), [])

            # Confirm no files were written to fixtures/
            self.assertFalse(str(dest).startswith("fixtures"))

    def test_verdict_mismatch_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            arc_path = tmp_path / "synthetic_pkg-1.0.0.tar.gz"
            out_dir = tmp_path / "replay_out"

            setup_code = b"import setuptools\nsetuptools.setup(name='synthetic_pkg', version='1.0.0')\n"
            ti = tarfile.TarInfo("synthetic_pkg-1.0.0/setup.py")
            ti.size = len(setup_code)
            with tarfile.open(arc_path, "w:gz") as tf:
                tf.addfile(ti, io.BytesIO(setup_code))

            pkg_row = {
                "package_id": "synthetic_pkg==1.0.0",
                "package_name": "synthetic_pkg",
                "version": "1.0.0",
                "archive_used": str(arc_path),
                "verdict_outcome": "suspicious",  # mismatch with actual none_detected_in_this_scan
            }

            with self.assertRaises(ValueError) as cm:
                generate_single_replay_fixture(arc_path, pkg_row, out_dir, 1)
            self.assertIn("Verdict outcome mismatch for package synthetic_pkg==1.0.0", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
