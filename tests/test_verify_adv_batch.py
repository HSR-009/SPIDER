"""
Unit tests for Person_A/pipeline/verify_adv_batch.py
Uses a tiny synthetic batch in a temp dir, not C's real files.
"""

import json
import tempfile
import unittest
from pathlib import Path

from Person_A.pipeline.verify_adv_batch import (
    compute_hashes,
    classify_outcome,
    verify_batch,
)


class TestVerifyAdvBatch(unittest.TestCase):
    def test_compute_hashes(self):
        manifest_obj = {
            "batch_name": "synthetic-batch",
            "entries": [],
            "manifest_hash_sha256": "placeholder",
        }
        manifest_bytes = json.dumps(manifest_obj, indent=2).encode("utf-8")
        hashes = compute_hashes(manifest_bytes, manifest_obj)
        self.assertIn("raw_bytes", hashes)
        self.assertIn("canonical_json", hashes)
        self.assertIn("freeze_batch_method", hashes)

    def test_classify_outcome(self):
        base = [{"category": "Command Execution", "indicator": "os.system"}]

        # Recovered
        cand_rec = [{"category": "Command Execution", "indicator": "os.system"}]
        self.assertEqual(classify_outcome(base, cand_rec), "recovered")

        # Different signal
        cand_diff = [{"category": "Dynamic Code Execution", "indicator": "exec"}]
        self.assertEqual(classify_outcome(base, cand_diff), "different_signal")

        # Missed
        cand_miss = []
        self.assertEqual(classify_outcome(base, cand_miss), "missed")

    def test_synthetic_batch_verification(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_p = Path(tmpdir)
            batch_dir = tmp_p / "adv_batch"
            batch_dir.mkdir()
            samples_dir = batch_dir / "samples"
            samples_dir.mkdir()

            sample_code = "import os\nos.system('whoami')\n"
            sample_file = samples_dir / "adv_001.py"
            sample_file.write_text(sample_code, encoding="utf-8")

            manifest = {
                "batch_name": "synthetic-test",
                "entries": [
                    {
                        "sample_id": "adv_001",
                        "technique": "T05_delay",
                        "source_file": "samples/adv_001.py",
                        "baseline_source": sample_code,
                        "generated_code": sample_code,
                    }
                ],
                "manifest_hash_sha256": "fake_hash",
            }

            manifest_file = batch_dir / "manifest.json"
            manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

            c_table = {
                "summary": {
                    "total_samples": 1,
                    "overall_counts": {"v1": {"recovered": 1, "different_signal": 0, "missed": 0}},
                    "miss_rates_asr": {"v1": 0.0},
                },
                "per_sample": [
                    {
                        "sample_id": "adv_001",
                        "v1": {"outcome": "recovered"},
                        "v1_1": {"outcome": "recovered"},
                    }
                ],
            }
            c_table_file = tmp_p / "c_table.json"
            c_table_file.write_text(json.dumps(c_table), encoding="utf-8")

            out_md = tmp_p / "report.md"
            rows, summary, hashes, verdict_counts, differing = verify_batch(batch_dir, c_table_file, out_md)

            self.assertTrue(out_md.exists())
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["sample_id"], "adv_001")
            self.assertTrue(rows[0]["agree_v1"])
            self.assertTrue(rows[0]["agree_v11"])
            self.assertEqual(len(differing), 0)
            self.assertIn("finding-level evasion rate", out_md.read_text(encoding="utf-8").lower())
            self.assertIn("## interpretation (to be written by a human)", out_md.read_text(encoding="utf-8").lower())

    def test_differing_sample_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_p = Path(tmpdir)
            batch_dir = tmp_p / "adv_batch"
            batch_dir.mkdir()
            samples_dir = batch_dir / "samples"
            samples_dir.mkdir()

            (samples_dir / "adv_001.py").write_text("modified = True\n", encoding="utf-8")

            manifest = {
                "batch_name": "synthetic-test",
                "entries": [
                    {
                        "sample_id": "adv_001",
                        "technique": "T05_delay",
                        "source_file": "samples/adv_001.py",
                        "baseline_source": "x = 1\n",
                        "generated_code": "original_generated = True\n",
                    }
                ],
                "manifest_hash_sha256": "fake_hash",
            }
            (batch_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

            out_md = tmp_p / "report.md"
            rows, summary, hashes, verdict_counts, differing = verify_batch(batch_dir, tmp_p / "nonexistent.json", out_md)
            self.assertEqual(differing, ["adv_001"])


if __name__ == "__main__":
    unittest.main()
