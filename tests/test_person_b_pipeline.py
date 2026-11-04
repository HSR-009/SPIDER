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


if __name__ == "__main__":
    unittest.main()
