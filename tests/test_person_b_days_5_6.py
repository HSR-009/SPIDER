"""Unit tests for SPIDER Person B Day 5 & Day 6 Deliverables.

Validates:
1. Adversarial batch verification against adv-batch-v1 and expected SHA-256 manifest hash.
2. Normalization adapter contract, determinism, and limitation handling.
3. Resilience table schema, explicit denominators (N=12), and finding vs verdict separation.
4. Observatory UI headless import and safe data handling.
5. False-positive check archive integrity, results JSON, triage CSV, and report.
6. Zero-finding review sample size (N=30) and 4-category coverage.
7. Complete ML methodology documentation.
"""
from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results"
MANIFEST_PATH = ROOT / "person_c" / "adv_batch" / "manifest.json"
EXPECTED_MANIFEST_HASH = "bb7f4fe8676000ef1e2f06e08d8387738e8ee4a3c33ac68ade289ffd8875aaa3"


class PersonBDay5Day6Tests(unittest.TestCase):
    # -------------------------------------------------------------
    # 1. Adversarial Batch Verification (Phase 1)
    # -------------------------------------------------------------
    def test_manifest_verification_and_hash_match(self):
        """Manifest must exist, match schema, and compute to canonical hash."""
        from Person_B.evaluation.verify_adv_batch import (
            compute_manifest_hash,
            verify_adversarial_batch,
        )

        self.assertTrue(MANIFEST_PATH.exists(), f"Manifest missing at {MANIFEST_PATH}")
        manifest_data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertIn("entries", manifest_data)
        self.assertEqual(len(manifest_data["entries"]), 12)

        # Reproduce canonical hash via freeze_batch.py method
        computed_hash = compute_manifest_hash(manifest_data)
        self.assertEqual(
            computed_hash,
            EXPECTED_MANIFEST_HASH,
            f"Computed manifest hash {computed_hash} != expected {EXPECTED_MANIFEST_HASH}",
        )

        # Full verification of all 12 sample files
        res = verify_adversarial_batch()
        self.assertEqual(res["status"], "VERIFIED")
        self.assertEqual(res["differing_samples_count"], 0)
        self.assertEqual(res["total_samples"], 12)

    # -------------------------------------------------------------
    # 2. Normalization Adapter (Phase 2)
    # -------------------------------------------------------------
    def test_normalization_adapter_rules_and_determinism(self):
        """Adapter must rewrite constant strings, aliases, base64, and getattr deterministically."""
        from Person_B.evaluation.normalization_adapter import (
            get_normalization_metadata,
            normalize_code,
        )

        meta = get_normalization_metadata()
        self.assertTrue(meta["available"])
        self.assertFalse(meta["is_official_placeholder"])
        self.assertEqual(len(meta["rules"]), 4)

        # Rule 1: String concat
        src1 = "x = 'sys' + 'tem'"
        norm1, mod1, status1 = normalize_code(src1)
        self.assertTrue(mod1)
        self.assertIn("Normalized", status1)
        self.assertIn("'system'", norm1)

        # Rule 2: Import alias
        src2 = "import os as x\nx.system('id')"
        norm2, mod2, _ = normalize_code(src2)
        self.assertTrue(mod2)
        self.assertIn("os.system('id')", norm2)

        # Rule 4: Getattr
        src4 = "getattr(os, 'system')('id')"
        norm4, mod4, _ = normalize_code(src4)
        self.assertTrue(mod4)
        self.assertIn("os.system('id')", norm4)

        # Determinism: running twice produces identical code
        run_a, _, _ = normalize_code(src2)
        run_b, _, _ = normalize_code(src2)
        self.assertEqual(run_a, run_b)

        # Non-transformable code is preserved
        noop_src = "print('hello world')\n"
        norm_noop, mod_noop, status_noop = normalize_code(noop_src)
        self.assertFalse(mod_noop)
        self.assertIn("No transformation", status_noop)

    # -------------------------------------------------------------
    # 3. Resilience Table & Config (Phase 3)
    # -------------------------------------------------------------
    def test_resilience_table_schema_and_denominators(self):
        """resilience_table.json must have denominator 12 and distinct finding vs verdict metrics."""
        res_json = RESULTS_DIR / "resilience_table.json"
        self.assertTrue(res_json.exists(), f"Missing {res_json}")
        data = json.loads(res_json.read_text(encoding="utf-8"))

        summary = data["summary"]
        self.assertEqual(summary["total_samples"], 12)

        finding_counts = summary["finding_level_counts"]
        for pipe in ["baseline_v1", "normalized_v1", "hardened_v11", "hardened_v11_normalized"]:
            self.assertIn(pipe, finding_counts)
            tot = finding_counts[pipe]["recovered"] + finding_counts[pipe]["different_signal"] + finding_counts[pipe]["missed"]
            self.assertEqual(tot, 12, f"Pipeline {pipe} total count != 12")

        # Hardened v1.1 finding-level evasion must be 0% (all 12 emit some signal)
        self.assertEqual(finding_counts["hardened_v11"]["finding_level_evasion_rate_pct"], 0.0)

        # Verdict counts must separate suspicious, review_kept, and silent
        verdicts = summary["engine_verdicts"]["hardened_v11"]
        self.assertEqual(verdicts["suspicious_count"], 1)
        self.assertEqual(verdicts["review_kept_count"], 5)
        self.assertEqual(verdicts["silent_count"], 6)

        # Markdown table exists
        res_md = RESULTS_DIR / "resilience_table.md"
        self.assertTrue(res_md.exists())

        # Config record exists and confirms data isolation
        res_cfg = RESULTS_DIR / "resilience_config.json"
        self.assertTrue(res_cfg.exists())
        cfg = json.loads(res_cfg.read_text(encoding="utf-8"))
        self.assertFalse(cfg["training_data_isolation"]["adversarial_data_in_training"])
        self.assertFalse(cfg["training_data_isolation"]["holdout_data_in_training"])

    @unittest.skipUnless(importlib.util.find_spec("joblib") is not None, "joblib required for resilience evaluation")
    def test_adv_006_and_hardened_v11_classification_reproducibility(self):
        """adv_006, hardened v1.1, and Pipeline D aggregates must be reproducible without overrides."""
        from Person_B.evaluation.resilience_eval import (
            analyze_with_v11,
            classify_finding_outcome,
        )
        from Person_B.evaluation.normalization_adapter import normalize_code

        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        entries = {e["sample_id"]: e for e in manifest["entries"]}
        self.assertIn("adv_006", entries)

        # adv_006 source analysis
        e6 = entries["adv_006"]
        base_findings, _ = analyze_with_v11(e6["baseline_source"])
        adv_findings, _ = analyze_with_v11(e6["generated_code"])

        # Both detect ('Command Execution', 'os.popen')
        outcome = classify_finding_outcome(base_findings, adv_findings)
        self.assertEqual(outcome, "recovered", "adv_006 must classify as recovered from source analysis")

        # adv_006 normalized analysis (Pipeline D)
        norm_code_6, _, _ = normalize_code(e6["generated_code"])
        adv_norm_findings, _ = analyze_with_v11(norm_code_6)
        outcome_norm = classify_finding_outcome(base_findings, adv_norm_findings)
        self.assertEqual(outcome_norm, "recovered", "adv_006 under v1.1 + normalization must classify as recovered")

        # Verify hardened v1.1 aggregate across all 12 entries (Pipeline C)
        recovered_count = 0
        diff_signal_count = 0
        missed_count = 0
        for entry in manifest["entries"]:
            b_f, _ = analyze_with_v11(entry["baseline_source"])
            a_f, _ = analyze_with_v11(entry["generated_code"])
            out = classify_finding_outcome(b_f, a_f)
            if out == "recovered":
                recovered_count += 1
            elif out == "different_signal":
                diff_signal_count += 1
            elif out == "missed":
                missed_count += 1

        self.assertEqual(recovered_count, 4, f"Expected 4 recovered, got {recovered_count}")
        self.assertEqual(diff_signal_count, 8, f"Expected 8 different_signal, got {diff_signal_count}")
        self.assertEqual(missed_count, 0, f"Expected 0 missed, got {missed_count}")

        # Verify hardened v1.1 + normalized aggregate across all 12 entries (Pipeline D)
        d_recovered = 0
        d_diff_signal = 0
        d_missed = 0
        for entry in manifest["entries"]:
            b_f, _ = analyze_with_v11(entry["baseline_source"])
            norm_code, _, _ = normalize_code(entry["generated_code"])
            norm_f, _ = analyze_with_v11(norm_code)
            out_d = classify_finding_outcome(b_f, norm_f)
            if out_d == "recovered":
                d_recovered += 1
            elif out_d == "different_signal":
                d_diff_signal += 1
            elif out_d == "missed":
                d_missed += 1

        self.assertEqual(d_recovered, 6, f"Expected 6 recovered for Pipeline D, got {d_recovered}")
        self.assertEqual(d_diff_signal, 5, f"Expected 5 different_signal for Pipeline D, got {d_diff_signal}")
        self.assertEqual(d_missed, 1, f"Expected 1 missed for Pipeline D, got {d_missed}")

    # -------------------------------------------------------------
    # 4. Observatory UI Headless Import (Phase 4)
    # -------------------------------------------------------------
    def test_observatory_ui_headless(self):
        """Observatory page must be importable without active Streamlit session and handle missing files safely."""
        from spider.ui.observatory_page import (
            load_baseline_metrics,
            load_peer_context,
            load_resilience_table,
        )

        # Data loaders return valid dicts when files exist
        res = load_resilience_table()
        self.assertIsNotNone(res)
        self.assertEqual(res["adversarial_batch"]["total_samples"], 12)

        base = load_baseline_metrics()
        self.assertIsNotNone(base)
        self.assertEqual(base["rows_frozen_holdout"], 991)

        peer = load_peer_context()
        self.assertIsNotNone(peer)
        self.assertEqual(peer["total_corpus_packages"], 4948)

    # -------------------------------------------------------------
    # 5. False-Positive Check Evaluation (Phase 5)
    # -------------------------------------------------------------
    def test_fp_check_integrity_and_outputs(self):
        """FP check must evaluate all 100 packages, verify hashes, and generate report & triage."""
        fp_json = RESULTS_DIR / "fp_check_results.json"
        fp_csv = RESULTS_DIR / "fp_check_triage.csv"
        fp_md = RESULTS_DIR / "fp_check_report.md"

        self.assertTrue(fp_json.exists())
        self.assertTrue(fp_csv.exists())
        self.assertTrue(fp_md.exists())

        # Verify JSON content
        data = json.loads(fp_json.read_text(encoding="utf-8"))
        summary = data["summary"]
        self.assertEqual(summary["total_packages"], 100)
        self.assertEqual(summary["verified_archives"], 100)
        self.assertEqual(summary["safe_extraction_success"], 100)
        self.assertEqual(len(data["packages"]), 100)

        # Verify CSV schema & rows
        with open(fp_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        self.assertEqual(len(rows), 100)
        required_cols = {
            "package_name", "version", "sha256", "archive_size", "n_py_files", "n_findings",
            "verdict_outcome", "review_recommended", "rf_prob", "xgb_prob",
            "flagged_by_engine", "flagged_by_ml", "triage_classification", "dual_use_justification",
        }
        self.assertTrue(required_cols.issubset(set(reader.fieldnames or [])))

        # Verify MD report contains essential sections
        md_text = fp_md.read_text(encoding="utf-8")
        self.assertIn("False-Positive Evaluation & Benign Triage Report", md_text)
        self.assertIn("Executive Summary & Key Metrics", md_text)
        self.assertIn("Machine Learning Score Distribution", md_text)

    # -------------------------------------------------------------
    # 6. Zero-Finding Malicious Review (Phase 6)
    # -------------------------------------------------------------
    def test_zero_finding_review_completeness(self):
        """Zero-finding review must cover 30 packages across all 4 failure categories."""
        zf_csv = RESULTS_DIR / "zero_finding_review.csv"
        zf_md = RESULTS_DIR / "zero_finding_review.md"

        self.assertTrue(zf_csv.exists())
        self.assertTrue(zf_md.exists())

        with open(zf_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        self.assertEqual(len(rows), 30, f"Expected 30 reviewed packages, got {len(rows)}")
        categories = {r["category"] for r in rows}
        expected_cats = {"parse_failed", "no_python_source", "no_risky_keywords", "risky_keywords_unflagged"}
        self.assertEqual(categories, expected_cats)

        # Check category distribution
        parse_failed_count = sum(1 for r in rows if r["category"] == "parse_failed")
        no_python_count = sum(1 for r in rows if r["category"] == "no_python_source")
        no_risky_count = sum(1 for r in rows if r["category"] == "no_risky_keywords")
        unflagged_count = sum(1 for r in rows if r["category"] == "risky_keywords_unflagged")

        self.assertEqual(parse_failed_count, 10)
        self.assertEqual(no_python_count, 6)
        self.assertEqual(no_risky_count, 7)
        self.assertEqual(unflagged_count, 7)

        # Markdown report exists and contains defense tiers
        md_text = zf_md.read_text(encoding="utf-8")
        self.assertIn("Zero-Finding Malicious Package Review", md_text)
        self.assertIn("Defense Tier Synthesis", md_text)

    # -------------------------------------------------------------
    # 7. ML Methodology Whitepaper (Phase 7)
    # -------------------------------------------------------------
    def test_ml_methodology_whitepaper_exists(self):
        """docs/ML_METHODOLOGY.md must exist and contain the required topics."""
        doc_path = ROOT / "docs" / "ML_METHODOLOGY.md"
        self.assertTrue(doc_path.exists())
        content = doc_path.read_text(encoding="utf-8")
        required_topics = [
            "Data Provenance & Rescan Architecture",
            "Feature Engineering & Allowlist Policy",
            "Data Leakage Prevention & Group Separation",
            "The Package-Size Confound & Ablation Experiments",
            "Model Architecture & Training Protocol",
            "SHAP Interpretability",
            "Adversarial Resilience: Three-Way Defense Evaluation",
            "False-Positive Evaluation on Obscure PyPI Packages",
            "Zero-Finding Malicious Review",
            "Peer-Context Integration",
            "Reproducibility, Integrity Guards & Operational Guidance",
        ]
        for topic in required_topics:
            self.assertIn(topic, content, f"Missing topic in methodology doc: {topic}")


if __name__ == "__main__":
    unittest.main()
