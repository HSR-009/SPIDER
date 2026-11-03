import unittest
import pandas as pd
from spider_contract.dataset import (
    make_group_id,
    assert_no_leaky_columns,
    assert_group_disjoint,
    BANNED_FEATURE_COLUMNS,
)

class TestContract(unittest.TestCase):
    def test_make_group_id_pep503(self):
        self.assertEqual(make_group_id("Requests_Toolbelt"), "requests-toolbelt")
        self.assertEqual(make_group_id("foo...bar"), "foo-bar")
        self.assertEqual(make_group_id("Django_Rest_Framework"), "django-rest-framework")
        self.assertEqual(make_group_id("  Flask.App  "), "flask-app")

    def test_assert_no_leaky_columns_pass(self):
        clean_cols = ["feat_total_calls", "feat_eval_ratio", "feat_max_entropy"]
        # Should not raise
        assert_no_leaky_columns(clean_cols)

    def test_assert_no_leaky_columns_raise_on_label(self):
        dirty_cols = ["feat_total_calls", "label"]
        with self.assertRaises(AssertionError):
            assert_no_leaky_columns(dirty_cols)

    def test_assert_no_leaky_columns_raise_on_metadata_leak(self):
        for col in ["in_index", "index_annotated", "source", "package_id"]:
            with self.assertRaises(AssertionError):
                assert_no_leaky_columns(["feat_total_calls", col])

    def test_assert_group_disjoint_pass(self):
        train_df = pd.DataFrame({"group_id": ["pkg-a", "pkg-b", "pkg-c"]})
        test_df = pd.DataFrame({"group_id": ["pkg-d", "pkg-e"]})
        # Should not raise
        assert_group_disjoint(train_df, test_df)

    def test_assert_group_disjoint_raise_on_leak(self):
        train_df = pd.DataFrame({"group_id": ["pkg-a", "pkg-b", "pkg-c"]})
        test_df = pd.DataFrame({"group_id": ["pkg-b", "pkg-d"]})
        with self.assertRaises(AssertionError):
            assert_group_disjoint(train_df, test_df)

if __name__ == "__main__":
    unittest.main()
