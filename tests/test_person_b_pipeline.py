import unittest
import importlib.util

import pandas as pd

from Person_B.features.extract_features import extract_record_features

has_sklearn = importlib.util.find_spec("sklearn") is not None
if has_sklearn:
    from Person_B.models.splitting import (
        assert_no_leakage,
        grouped_cv_splits,
        make_frozen_holdout,
    )
else:
    assert_no_leakage = None
    grouped_cv_splits = None
    make_frozen_holdout = None


class PersonBPipelineTests(unittest.TestCase):
    def test_parse_error_is_not_a_security_feature(self):
        record = {
            "n_py_files": 2,
            "findings": [
                {"category": "Parse Error", "indicator": "SyntaxError"},
                {"category": "Command Execution", "indicator": "os.system"},
            ],
        }
        features = extract_record_features(record, ["os.system"])
        self.assertEqual(features["category_count__command_execution"], 1)
        self.assertEqual(features["indicator_present__os.system"], 1)

    @unittest.skipUnless(has_sklearn, "scikit-learn required for splitting tests")
    def test_leakage_guard_rejects_identifiers_and_diagnostics(self):
        with self.assertRaises(ValueError):
            assert_no_leakage(["n_py_files", "package_id"])
        with self.assertRaises(ValueError):
            assert_no_leakage(["parse_error_count"])

    @unittest.skipUnless(has_sklearn, "scikit-learn required for splitting tests")
    def test_grouped_holdout_and_cv_do_not_split_package_versions(self):
        rows = []
        for label in (0, 1):
            for package_no in range(25):
                name = f"package-{label}-{package_no}"
                for version in ("1.0", "2.0"):
                    rows.append({
                        "package_id": f"{name}=={version}",
                        "group_id": name,
                        "label": label,
                        "n_py_files": package_no + 1,
                        "feature_a": float(package_no),
                    })
        frame = pd.DataFrame(rows)
        development, holdout = make_frozen_holdout(frame, n_splits=5)
        self.assertTrue(set(development.group_id).isdisjoint(set(holdout.group_id)))
        self.assertEqual(set(development.label), {0, 1})
        self.assertEqual(set(holdout.label), {0, 1})
        for train_idx, valid_idx in grouped_cv_splits(development, n_splits=5):
            train_groups = set(development.iloc[train_idx].group_id)
            valid_groups = set(development.iloc[valid_idx].group_id)
            self.assertTrue(train_groups.isdisjoint(valid_groups))

    @unittest.skipUnless(
        importlib.util.find_spec("xgboost") is not None,
        "xgboost is not installed; skipping ML evaluation test",
    )
    def test_score_predictions_handles_edge_cases(self):
        from Person_B.evaluation.day2_ablation import score_predictions
        scores = score_predictions([0, 1, 0, 1], [0.1, 0.9, 0.2, 0.8])
        self.assertEqual(scores["accuracy"], 1.0)
        self.assertEqual(scores["roc_auc"], 1.0)
        self.assertEqual(scores["fpr"], 0.0)

        scores_single = score_predictions([0, 0, 0], [0.1, 0.2, 0.3])
        self.assertIsNone(scores_single["roc_auc"])
        self.assertIsNone(scores_single["pr_auc"])
        self.assertEqual(scores_single["sample_count"], 3)

    def test_holdout_only_indicators_cannot_enter_vocabulary(self):
        from Person_B.features.extract_features import top_indicator_vocabulary

        dev_records = [
            {
                "package_id": f"dev_pkg_{i}==1.0",
                "findings": [{"category": "Command Execution", "indicator": f"dev_ind_{i % 5}"}],
            }
            for i in range(20)
        ]
        holdout_records = [
            {
                "package_id": f"holdout_pkg_{i}==1.0",
                "findings": [{"category": "Obfuscation", "indicator": "holdout_exclusive_indicator"}],
            }
            for i in range(10)
        ]

        # Holdout package IDs to exclude
        holdout_ids = {r["package_id"] for r in holdout_records}

        # Filter out holdout records before computing vocabulary
        all_records = dev_records + holdout_records
        filtered_dev = [r for r in all_records if r["package_id"] not in holdout_ids]
        vocab = top_indicator_vocabulary(filtered_dev, limit=40)

        # Holdout-exclusive indicator MUST NOT enter the vocabulary
        self.assertNotIn("holdout_exclusive_indicator", vocab)
        # Dev indicators should be present
        for i in range(5):
            self.assertIn(f"dev_ind_{i}", vocab)

        # Conversely, if holdout were improperly included without filtering:
        leaked_vocab = top_indicator_vocabulary(all_records, limit=40)
        self.assertIn("holdout_exclusive_indicator", leaked_vocab)


@unittest.skipUnless(
    importlib.util.find_spec("xgboost") is not None and importlib.util.find_spec("shap") is not None,
    "xgboost or shap is not installed; skipping TestDay3Predictor",
)
class TestDay3Predictor(unittest.TestCase):
    """Day 3 — prediction wrapper, calibration, abstention, SHAP importances."""

    @classmethod
    def setUpClass(cls):
        from pathlib import Path
        from Person_B.models.predict import build_predictor

        ROOT = Path(__file__).resolve().parents[1]
        # n_splits=2 keeps CI fast while still exercising the full pipeline
        cls.predictor, cls.report = build_predictor(n_splits=2, verbose=False)
        df = pd.read_csv(ROOT / "data/processed/feature_table.csv")
        holdout_ids = set(
            pd.read_csv(ROOT / "results/frozen_holdout_packages.csv")["package_id"].astype(str)
        )
        cls.holdout = df[df["package_id"].astype(str).isin(holdout_ids)].copy()
        cls.dev = df[~df["package_id"].astype(str).isin(holdout_ids)].copy()
        cls.ROOT = ROOT

    # ------------------------------------------------------------------
    # 1. predict_package returns a valid structure for a real holdout row
    # ------------------------------------------------------------------
    def test_predict_ok_or_abstained_structure(self):
        row_df = pd.DataFrame([self.holdout.iloc[0]])
        result = self.predictor.predict_package(row_df, explain=False)
        self.assertIn(result["status"], ("ok", "abstained"),
                      msg=f"Unexpected status: {result['status']}")
        self.assertIn("calibrated_probability", result)
        if result["status"] == "ok":
            self.assertIn(result["verdict"], ("suspicious", "none_detected_in_scan"))
        elif result["status"] == "abstained":
            self.assertIsNone(result["verdict"])

    # ------------------------------------------------------------------
    # 2. error status is returned for malformed input (missing features)
    # ------------------------------------------------------------------
    def test_predict_error_on_bad_input(self):
        bad_df = pd.DataFrame([{"irrelevant_col": 42}])
        result = self.predictor.predict_package(bad_df, explain=False)
        self.assertEqual(result["status"], "error")
        self.assertIn("error_message", result)
        self.assertIsNone(result.get("verdict"))

    # ------------------------------------------------------------------
    # 3. abstained verdict is None; forced by delta=0.5 (abstain everything)
    # ------------------------------------------------------------------
    def test_abstained_verdict_is_none(self):
        import joblib
        from pathlib import Path
        from sklearn.isotonic import IsotonicRegression
        from Person_B.models.predict import SPIDERPredictor, top_feature_importances

        ROOT = self.ROOT
        model = joblib.load(
            ROOT / "Person_B/models/saved/random_forest_behavior_without_size.joblib"
        )
        cal = IsotonicRegression(out_of_bounds="clip")
        cal.fit([0.0, 1.0], [0, 1])
        feats = list(model.feature_names_in_)
        imps = top_feature_importances(model, feats, top_n=20)
        # delta=0.5 → abstain on everything (|p - 0.5| < 0.5 always)
        forced_abstain = SPIDERPredictor(
            model=model,
            features=feats,
            calibrator=cal,
            abstention_delta=0.5,
            global_importances=imps,
        )
        row_df = pd.DataFrame([self.holdout.iloc[0]])
        result = forced_abstain.predict_package(row_df, explain=False)
        self.assertEqual(result["status"], "abstained")
        self.assertIsNone(result["verdict"])

    # ------------------------------------------------------------------
    # 4. top_feature_importances returns exactly 20 items with correct keys
    # ------------------------------------------------------------------
    def test_top_feature_importances_returns_20(self):
        imps = self.predictor.global_importances
        self.assertEqual(len(imps), 20)
        for item in imps:
            self.assertIn("feature", item)
            self.assertIn("importance", item)
            self.assertIsInstance(item["importance"], float)

    # ------------------------------------------------------------------
    # 5. calibration uses dev rows only; holdout count matches CSV
    # ------------------------------------------------------------------
    def test_calibration_uses_dev_only(self):
        self.assertEqual(
            self.report["dev_rows"], len(self.dev),
            msg="report dev_rows must match the actual dev set size",
        )
        self.assertEqual(
            self.report["holdout_rows"], len(self.holdout),
            msg="report holdout_rows must match the actual holdout set size",
        )

    # ------------------------------------------------------------------
    # 6. SHAP explanation is returned when explain=True and status is ok
    # ------------------------------------------------------------------
    def test_shap_explanation_returned_when_ok(self):
        # Find a row that the predictor classifies as ok (not abstained)
        explained = None
        for idx in range(min(20, len(self.holdout))):
            row_df = pd.DataFrame([self.holdout.iloc[idx]])
            result = self.predictor.predict_package(row_df, explain=True, top_n=5)
            if result["status"] == "ok":
                explained = result
                break
        if explained is None:
            self.skipTest("No non-abstained holdout rows found in first 20 rows")
        self.assertIn("explanation", explained)
        expl = explained["explanation"]
        self.assertIn("top_shap_factors", expl)
        self.assertLessEqual(len(expl["top_shap_factors"]), 5)
        for factor in expl["top_shap_factors"]:
            self.assertIn("feature", factor)
            self.assertIn("shap_impact", factor)
            self.assertIsInstance(factor["shap_impact"], float)


class TestDay4BaselineV11(unittest.TestCase):
    """Day 4 — v1.1 dataset validation, leakage guards, holdout preservation, and peer-context checks."""

    @classmethod
    def setUpClass(cls):
        from pathlib import Path
        cls.ROOT = Path(__file__).resolve().parents[1]

    def test_v11_dataset_row_counts_and_uniqueness(self):
        import gzip
        import json

        def load_counts(p, is_gz=False):
            op = gzip.open if is_gz else open
            ids = set()
            cnt = 0
            with op(p, "rt", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        cnt += 1
                        rec = json.loads(line)
                        ids.add(rec["package_id"])
            return cnt, len(ids)

        m_cnt, m_uids = load_counts(self.ROOT / "data/processed/malicious_v11.jsonl", False)
        b_cnt, b_uids = load_counts(self.ROOT / "data/processed/benign_v11.jsonl.gz", True)
        self.assertEqual(m_cnt, 2039)
        self.assertEqual(m_uids, 2039)
        self.assertEqual(b_cnt, 2909)
        self.assertEqual(b_uids, 2909)

    def test_frozen_holdout_exact_match_in_v11(self):
        import gzip
        import json

        holdout_df = pd.read_csv(self.ROOT / "results/frozen_holdout_packages.csv")
        self.assertEqual(len(holdout_df), 991)
        self.assertEqual(int((holdout_df["label"] == 1).sum()), 409)
        self.assertEqual(int((holdout_df["label"] == 0).sum()), 582)

        v11_records = {}
        for p, is_gz in [
            (self.ROOT / "data/processed/malicious_v11.jsonl", False),
            (self.ROOT / "data/processed/benign_v11.jsonl.gz", True),
        ]:
            op = gzip.open if is_gz else open
            with op(p, "rt", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        r = json.loads(line)
                        v11_records[str(r["package_id"])] = r

        holdout_pids = set(holdout_df["package_id"].astype(str))
        missing = holdout_pids - set(v11_records.keys())
        self.assertEqual(len(missing), 0, f"Missing holdout IDs in v1.1: {missing}")

        for _, row in holdout_df.iterrows():
            pid = str(row["package_id"])
            self.assertEqual(row["label"], v11_records[pid]["label"])

        holdout_groups = {v11_records[pid]["group_id"] for pid in holdout_pids}
        dev_groups = {
            rec["group_id"] for pid, rec in v11_records.items() if pid not in holdout_pids
        }
        self.assertTrue(holdout_groups.isdisjoint(dev_groups))

    def test_all_forbidden_columns_blocked(self):
        from Person_B.models.splitting import assert_no_leakage, LEAKAGE_COLUMNS

        forbidden_sample = [
            "strong_signals", "verdict_outcome", "review_recommended", "s2_same_file",
            "package_id", "package_name", "version", "group_id", "label", "source",
            "analyzer_version", "ruleset_version", "in_index", "index_annotated",
            "n_findings", "parse_error_count", "failed_static_analysis", "max_severity",
        ]
        for col in forbidden_sample:
            self.assertIn(col, LEAKAGE_COLUMNS)
            with self.assertRaises(ValueError):
                assert_no_leakage([col])

    def test_peer_context_schema_and_statistics(self):
        import json

        peer_context_path = self.ROOT / "results/peer_context.json"
        self.assertTrue(peer_context_path.exists())
        data = json.loads(peer_context_path.read_text(encoding="utf-8"))
        self.assertEqual(data["dataset_version"], "v1.1")
        self.assertEqual(data["total_corpus_packages"], 4948)
        self.assertEqual(data["total_holdout_packages"], 991)
        self.assertIn("size_strata", data)
        strata = {s["bucket_name"]: s for s in data["size_strata"]}
        for expected in ["0_files", "1-5_files", "6-20_files", ">20_files", "all_packages"]:
            self.assertIn(expected, strata)
            s = strata[expected]
            self.assertGreater(s["corpus_package_count"], 0)
            self.assertGreaterEqual(s["malicious_prevalence"], 0.0)
            self.assertLessEqual(s["malicious_prevalence"], 1.0)
            self.assertIn("holdout_evaluation", s)

    def test_v1_artifacts_preserved(self):
        self.assertTrue((self.ROOT / "results/baseline_v1.json").exists())
        self.assertTrue((self.ROOT / "results/baseline_v1.md").exists())
        self.assertTrue((self.ROOT / "results/frozen_holdout_packages.csv").exists())
        self.assertTrue((self.ROOT / "results/baseline_v11.json").exists())
        self.assertTrue((self.ROOT / "results/baseline_v11.md").exists())
        self.assertTrue((self.ROOT / "results/v1_vs_v11_comparison.md").exists())


if __name__ == "__main__":
    unittest.main()
