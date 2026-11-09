import unittest
import pandas as pd
from spider_contract.dataset import (
    make_group_id,
    assert_no_leaky_columns,
    assert_group_disjoint,
    BANNED_FEATURE_COLUMNS,
)
from spider_contract.models import ScanRecord, Finding
from spider_contract.verdict import coverage_problems

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

    def test_scan_record_contract_model(self):
        finding = Finding(
            category="Command Execution",
            indicator="os.system",
            severity="HIGH",
            file="sample.py",
            line=4,
            col_offset=0,
            end_lineno=4,
            snippet="os.system('id')",
            rule_id="RULE_CMD_OS_SYSTEM",
            evidence="os.system() call detected"
        )
        record = ScanRecord(
            package_name="test-pkg",
            version="1.0.0",
            package_id="test-pkg==1.0.0",
            group_id="test-pkg",
            verdict="suspicious",
            findings=[finding.to_dict()],
            n_findings=1,
            n_py_files=1
        )
        d = record.to_dict()
        self.assertEqual(d["package_name"], "test-pkg")
        self.assertEqual(d["verdict"], "suspicious")
        self.assertEqual(len(d["findings"]), 1)
        self.assertEqual(d["findings"][0]["rule_id"], "RULE_CMD_OS_SYSTEM")

    def test_coverage_problems_nothing_inspected(self):
        # Record with no files at all
        empty_record = {
            "inventory": {
                "coverage_known": True,
                "limits_hit": [],
                "python_files": 0,
                "parse_failures": [],
                "uninspected": [],
                "files_inspected": 0,
            },
            "target": {"hash_verified": None},
            "files": [],
        }
        problems_empty = coverage_problems(empty_record)
        self.assertIn("nothing_inspected", problems_empty)

        # Record with only doc files
        docs_only_record = {
            "inventory": {
                "coverage_known": True,
                "limits_hit": [],
                "python_files": 0,
                "parse_failures": [],
                "uninspected": [],
                "files_inspected": 0,
            },
            "target": {"hash_verified": None},
            "files": [
                {"path": "README.md", "kind": "doc", "inspected": False},
                {"path": "LICENSE", "kind": "doc", "inspected": False},
            ],
        }
        problems_docs = coverage_problems(docs_only_record)
        self.assertIn("nothing_inspected", problems_docs)

if __name__ == "__main__":
    unittest.main()
