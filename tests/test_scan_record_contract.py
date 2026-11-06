"""Contract tests. Run from the bundle/repo root:

    python -m unittest discover -s tests -v      (or: pytest tests)

Needs only: pip install jsonschema
"""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from spider_contract import adapter, dataset, hashing, verdict  # noqa: E402
from spider_contract.validate import validate_record  # noqa: E402

REC_DIR = ROOT / "fixtures" / "records"
SRC_DIR = ROOT / "fixtures" / "src"


def load(name_prefix):
    path = sorted(REC_DIR.glob(name_prefix + "*.json"))[0]
    return json.loads(path.read_text(encoding="utf-8"))


class FixtureTests(unittest.TestCase):
    def test_all_fixtures_validate_against_real_sources(self):
        files = sorted(REC_DIR.glob("[0-9][0-9]_*.json"))
        self.assertEqual(len(files), 5)
        for path in files:
            record = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(validate_record(record, SRC_DIR), [], path.name)

    def test_expected_verdicts(self):
        expected = {
            "01": "none_detected_in_this_scan",
            "02": "suspicious",
            "03": "suspicious",
            "04": "unable_to_assess",
            "05": "none_detected_in_this_scan",
        }
        for prefix, outcome in expected.items():
            self.assertEqual(load(prefix)["verdict"]["outcome"], outcome, prefix)

    def test_fixtures_cover_every_relation_and_model_state(self):
        records = [load(p) for p in ("01", "02", "03", "04", "05")]
        relation_types = {r["type"] for rec in records for r in rec["relations"]}
        self.assertTrue({"co_occurrence", "possible_flow"} <= relation_types)
        statuses = {rec["model_assessment"]["status"] for rec in records}
        self.assertEqual(statuses, {"not_run", "abstained", "ok"})

    def test_fixtures_are_labelled_as_hand_written(self):
        for p in ("01", "02", "03", "04", "05"):
            self.assertEqual(load(p)["record_origin"], "hand_written_fixture")

    def test_fixture_sources_are_harmless(self):
        # nothing in the synthetic trees may touch the network or real secrets
        banned = ("requests.", "http://", "https://", "~/.ssh", "/etc/passwd", "AWS_SECRET")
        for path in SRC_DIR.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for token in banned:
                self.assertNotIn(token, text, "%s contains %s" % (path, token))


class ValidatorNegativeTests(unittest.TestCase):
    """The validator must reject bad records; otherwise it proves nothing."""

    def setUp(self):
        self.rec = load("03")

    def errors(self, rec):
        return validate_record(rec, SRC_DIR)

    def test_bad_enum_rejected(self):
        self.rec["findings"][0]["severity"] = "catastrophic"
        self.assertTrue(self.errors(self.rec))

    def test_missing_field_rejected(self):
        del self.rec["inventory"]
        self.assertTrue(self.errors(self.rec))

    def test_unknown_top_level_field_rejected(self):
        self.rec["surprise"] = 1
        self.assertTrue(self.errors(self.rec))

    def test_extensions_namespace_is_allowed(self):
        self.rec["extensions"] = {"anything": [1, 2, 3]}
        self.assertEqual(self.errors(self.rec), [])

    def test_confirmed_flow_needs_a_basis(self):
        self.rec["relations"][0]["type"] = "confirmed_flow"
        self.rec["relations"][0]["basis"] = ""
        self.assertTrue(self.errors(self.rec))

    def test_relation_to_missing_finding_rejected(self):
        self.rec["relations"][0]["to"] = "F099"
        self.assertTrue(any("not a finding id" in e for e in self.errors(self.rec)))

    def test_duplicate_finding_ids_rejected(self):
        self.rec["findings"][1]["id"] = "F001"
        self.assertTrue(any("duplicate id" in e for e in self.errors(self.rec)))

    def test_tampered_snippet_detected_against_source(self):
        self.rec["findings"][1]["snippet"] = "exec(other)"
        self.assertTrue(any("does not match source" in e for e in self.errors(self.rec)))

    def test_wrong_verdict_detected(self):
        self.rec["verdict"]["outcome"] = "none_detected_in_this_scan"
        self.assertTrue(any("policy derives" in e for e in self.errors(self.rec)))

    def test_file_not_listed_rejected(self):
        self.rec["findings"][0]["file"] = "nowhere.py"
        self.assertTrue(any("not in files" in e for e in self.errors(self.rec)))

    def test_inventory_counts_must_match_files(self):
        self.rec["inventory"]["files_total"] += 1
        self.assertTrue(any("files_total" in e for e in self.errors(self.rec)))

    def test_not_run_model_cannot_carry_a_score(self):
        rec = load("01")
        rec["model_assessment"]["score"] = 0.5
        self.assertTrue(self.errors(rec))

    def test_fixture_model_values_must_be_flagged_illustrative(self):
        self.rec["model_assessment"]["illustrative"] = False
        self.assertTrue(any("illustrative" in e for e in self.errors(self.rec)))

    def test_real_analyzer_record_cannot_be_illustrative(self):
        self.rec["record_origin"] = "analyzer"
        self.assertTrue(any("illustrative" in e for e in self.errors(self.rec)))

    def test_vendored_flag_must_match_inventory(self):
        rec = load("05")
        rec["findings"][2]["context"]["in_vendored_path"] = False
        self.assertTrue(any("in_vendored_path" in e for e in self.errors(rec)))

    def test_unparsed_file_must_be_accounted_for(self):
        rec = load("04")
        rec["inventory"]["parse_failures"] = []
        self.assertTrue(self.errors(rec))


class VerdictPolicyTests(unittest.TestCase):
    def test_low_findings_alone_are_not_suspicious(self):
        self.assertEqual(load("01")["verdict"]["outcome"], "none_detected_in_this_scan")

    def test_vendored_findings_are_not_auto_suppressed(self):
        rec = load("05")
        # Under Verdict v2, vendored code is not suppressed when a strong signal is present
        rec["findings"][2]["indicator"] = "setuptools.command.install"
        self.assertEqual(verdict.derive_verdict(rec)["outcome"], "suspicious")

    def test_unknown_severity_counts_as_medium(self):
        rec = load("03")
        f = rec["findings"][2]  # call-phase finding
        f["severity"] = "unknown"
        self.assertFalse(verdict.is_triggering(f))
        f["trigger_phase"] = "import"
        self.assertTrue(verdict.is_triggering(f))

    def test_hash_mismatch_blocks_a_clean_verdict(self):
        rec = load("01")
        rec["target"]["hash_verified"] = False
        self.assertEqual(verdict.derive_verdict(rec)["outcome"], "unable_to_assess")

    def test_model_never_changes_the_verdict(self):
        rec = load("01")
        before = verdict.derive_verdict(rec)
        rec["model_assessment"].update(status="ok", label="benign", score=0.01, illustrative=True)
        self.assertEqual(verdict.derive_verdict(rec), before)


class AdapterTests(unittest.TestCase):
    LEGACY = [
        {"category": "Command Execution", "indicator": "os.system", "file": "sample.py", "line": 4,
         "evidence": "os.system() call detected"},
        {"category": "Network Activity", "indicator": "socket.socket", "file": "net.py", "line": 9,
         "evidence": "socket creation detected"},
        {"category": "Parse Error", "indicator": "parse_error", "file": "bad.py", "line": 0,
         "evidence": "invalid syntax"},
    ]

    def test_converted_record_is_valid(self):
        rec = adapter.convert_legacy_scan(self.LEGACY, name="demo", scan_id="12345678-aaaa")
        self.assertEqual(validate_record(rec), [])
        self.assertEqual(rec["record_origin"], "legacy_conversion")

    def test_parse_error_is_not_a_finding(self):
        rec = adapter.convert_legacy_scan(self.LEGACY, name="demo", scan_id="12345678-aaaa")
        self.assertEqual(len(rec["findings"]), 2)
        self.assertEqual([p["path"] for p in rec["inventory"]["parse_failures"]], ["bad.py"])
        self.assertEqual(adapter.failed_static_analysis(rec), 1)

    def test_converted_record_never_says_none_detected(self):
        rec = adapter.convert_legacy_scan([], name="demo", scan_id="12345678-aaaa")
        self.assertEqual(rec["verdict"]["outcome"], "unable_to_assess")
        self.assertIn("coverage_unknown", rec["verdict"]["reasons"])

    def test_nothing_is_invented(self):
        f = adapter.convert_legacy_scan(self.LEGACY, name="demo", scan_id="12345678-aaaa")["findings"][0]
        self.assertEqual((f["severity"], f["confidence"], f["trigger_phase"]), ("unknown", "unknown", "unknown"))
        self.assertIsNone(f["snippet"])
        self.assertIsNone(f["span"]["start_col"])

    def test_round_trip_preserves_the_old_five_fields(self):
        rec = adapter.convert_legacy_scan(self.LEGACY, name="demo", scan_id="12345678-aaaa")
        back = adapter.to_legacy(rec)
        self.assertEqual(back[0], self.LEGACY[0])
        self.assertEqual(back[1]["indicator"], "socket.socket")
        self.assertEqual(back[2]["category"], "Parse Error")

    REAL = [
        {"category": "Dynamic Code Execution", "indicator": "compile", "severity": "HIGH",
         "file": "a.py", "line": 1, "evidence": "compile() call detected"},
        {"category": "Credential / Data Access", "indicator": "os.environ", "severity": "HIGH",
         "file": "a.py", "line": 2, "evidence": "x"},
        {"category": "Install-Time / Package Execution", "indicator": "cmdclass", "severity": "HIGH",
         "file": "setup.py", "line": 3, "evidence": "x"},
        {"category": "Network Activity", "indicator": "requests.get", "severity": "MEDIUM",
         "file": "n.py", "line": 4, "evidence": "x"},
        {"category": "Obfuscation", "indicator": "base64.b64decode", "severity": "MEDIUM",
         "file": "o.py", "line": 5, "evidence": "x"},
        {"category": "Parse Error", "indicator": "SyntaxError", "severity": "MEDIUM",
         "file": "bad.py", "line": 7, "evidence": "Unable to parse Python source: invalid syntax"},
    ]

    def test_real_analyzer_labels_and_severity_convert(self):
        rec = adapter.convert_legacy_scan(self.REAL, name="demo", scan_id="12345678-aaaa")
        self.assertEqual(validate_record(rec), [])
        self.assertEqual(
            [f["category"] for f in rec["findings"]],
            ["dynamic_execution", "credential_access", "install_time", "network_activity", "obfuscation"],
        )
        self.assertEqual([f["severity"] for f in rec["findings"]],
                         ["high", "high", "high", "medium", "medium"])
        self.assertEqual(len(rec["inventory"]["parse_failures"]), 1)

    def test_real_labels_round_trip_exactly(self):
        rec = adapter.convert_legacy_scan(self.REAL, name="demo", scan_id="12345678-aaaa")
        back = adapter.to_legacy(rec)
        self.assertEqual(back[:5], self.REAL[:5])
        self.assertEqual(back[5]["category"], "Parse Error")
        self.assertEqual(back[5]["indicator"], "SyntaxError")

    def test_plain_setup_call_is_not_suspicious_by_itself(self):
        legacy = [{"category": "Install-Time / Package Execution", "indicator": "setuptools.setup",
                   "severity": "HIGH", "file": "setup.py", "line": 1, "evidence": "setup() call"}]
        f = adapter.convert_legacy_scan(legacy, name="demo", scan_id="12345678-aaaa")["findings"][0]
        self.assertEqual(f["severity"], "low")
        self.assertTrue(any("routine packaging" in x for x in f["limitations"]))

    def test_unknown_category_fails_loudly(self):
        with self.assertRaises(adapter.AdapterError):
            adapter.convert_legacy_scan(
                [{"category": "Telepathy", "indicator": "x", "file": "a.py", "line": 1}], name="demo"
            )

    def test_missing_field_fails_loudly(self):
        with self.assertRaises(adapter.AdapterError):
            adapter.convert_legacy_scan([{"category": "Obfuscation", "indicator": "x"}], name="demo")


class DatasetGuardTests(unittest.TestCase):
    def test_index_columns_are_blocked_as_features(self):
        for col in ("in_index", "index_annotated"):
            with self.assertRaises(dataset.LeakageError):
                dataset.assert_no_leaky_columns(["n_py_files", col])

    def test_group_id_is_pep503_name(self):
        self.assertEqual(dataset.make_group_id("Foo_Bar.baz"), "foo-bar-baz")
        self.assertEqual(dataset.make_group_id("requests"), dataset.make_group_id("Requests"))

    def test_versions_of_one_package_share_a_group(self):
        a = dataset.make_group_id(dataset.parse_package_id("requests==2.31.0")[0])
        b = dataset.make_group_id(dataset.parse_package_id("requests==2.32.0")[0])
        self.assertEqual(a, b)

    def test_split_leakage_is_detected(self):
        rows = [
            {"group_id": "requests", "split": "train"},
            {"group_id": "requests", "split": "test"},
            {"group_id": "numpy", "split": "train"},
        ]
        with self.assertRaises(dataset.LeakageError):
            dataset.assert_group_disjoint(rows)

    def test_clean_split_passes(self):
        dataset.assert_group_disjoint(
            [{"group_id": "a", "split": "train"}, {"group_id": "a", "split": "train"}, {"group_id": "b", "split": "test"}]
        )

    def test_leaky_feature_columns_are_blocked(self):
        with self.assertRaises(dataset.LeakageError):
            dataset.assert_no_leaky_columns(["exec_count", "Source", "entropy"])
        dataset.assert_no_leaky_columns(["exec_count", "entropy"])

    def test_dataset_row_schema(self):
        good = {
            "package_id": "requests==2.31.0", "package_name": "requests", "version": "2.31.0", "label": 0,
            "source": "popular_pypi", "group_id": "requests", "analyzer_version": "v1", "ruleset_version": "r1",
        }
        self.assertEqual(dataset.row_errors(good), [])
        bad = dict(good, label=2)
        self.assertTrue(dataset.row_errors(bad))
        missing = {k: v for k, v in good.items() if k != "group_id"}
        self.assertTrue(dataset.row_errors(missing))


class HashingTests(unittest.TestCase):
    def test_tree_hash_is_deterministic_and_content_sensitive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a").mkdir()
            (root / "a" / "x.py").write_text("print(1)\n")
            (root / "y.txt").write_text("hi\n")
            h1 = hashing.tree_sha256(root)
            self.assertEqual(h1, hashing.tree_sha256(root))
            (root / "y.txt").write_text("changed\n")
            self.assertNotEqual(h1, hashing.tree_sha256(root))

    def test_fixture_hash_matches_record(self):
        rec = load("02")
        self.assertEqual(rec["target"]["artifact"]["sha256"], hashing.tree_sha256(SRC_DIR / "demo-installhook"))


if __name__ == "__main__":
    unittest.main()
