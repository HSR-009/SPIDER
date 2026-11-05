import unittest

import pandas as pd

from Person_B.features.extract_features import extract_record_features
from Person_B.models.splitting import (
    assert_no_leakage,
    grouped_cv_splits,
    make_frozen_holdout,
)


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

    def test_leakage_guard_rejects_identifiers_and_diagnostics(self):
        with self.assertRaises(ValueError):
            assert_no_leakage(["n_py_files", "package_id"])
        with self.assertRaises(ValueError):
            assert_no_leakage(["parse_error_count"])

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


if __name__ == "__main__":
    unittest.main()
