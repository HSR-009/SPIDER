import ast
import json
import os
import sys
from pathlib import Path
import unittest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
try:
    import Person_c
    sys.modules.setdefault("person_c", Person_c)
except ImportError:
    pass

from Person_c.disguises import (
    base64_disguise,
    rot13_disguise,
    getattr_disguise,
    delay_disguise,
    string_split_disguise,
)
from Person_c.run_baseline_evasion_experiment import classify_outcome


class TestPersonCEvasionAndCatalog(unittest.TestCase):
    def test_disguise_syntax(self):
        payload = 'print("SPIDER_MARKER_TEST")'

        t01 = string_split_disguise("whoami", seed=42)
        ast.parse(t01)

        t02 = base64_disguise(payload)
        ast.parse(t02)

        t03 = rot13_disguise(payload)
        ast.parse(t03)

        t04 = getattr_disguise("os", "system", '"whoami"')
        ast.parse(t04)

        t05 = delay_disguise(payload, 3)
        ast.parse(t05)

    def test_string_split_determinism(self):
        s1 = string_split_disguise("sensitive_test_payload", seed=42)
        s2 = string_split_disguise("sensitive_test_payload", seed=42)
        self.assertEqual(s1, s2, "string_split_disguise must be deterministic with the same seed")

    def test_fixtures_loaded_and_schema(self):
        records_dir = PROJECT_ROOT / "fixtures" / "records"
        if not records_dir.exists() or len(list(records_dir.glob("*.json"))) == 0:
            records_dir = PROJECT_ROOT / "Person_c" / "fixtures" / "records"
        self.assertTrue(records_dir.exists(), "fixtures/records directory must exist")

        fixture_files = list(records_dir.glob("*.json"))
        self.assertEqual(len(fixture_files), 5, "Must have exactly 5 fixture records")

        allowed_outcomes = {
            "malicious", "suspicious", "needs review",
            "none_detected_in_this_scan", "unable_to_assess"
        }

        for f_path in fixture_files:
            with open(f_path, "r", encoding="utf-8") as f:
                rec = json.load(f)

            pkg_name = rec.get("package_name") or rec.get("target", {}).get("name")
            self.assertIsNotNone(pkg_name, f"Package name missing in {f_path.name}")
            self.assertIn("record_origin", rec)
            self.assertIn(rec["record_origin"], ["fixture", "hand_written_fixture"])

            verdict = rec.get("verdict")
            outcome = verdict.get("outcome") if isinstance(verdict, dict) else verdict
            self.assertIsNotNone(outcome)
            # Strict honesty rule: NEVER use "Safe"
            self.assertIn(
                outcome.lower(),
                allowed_outcomes,
                f"Verdict '{outcome}' in {f_path.name} violates honesty rule (Safe is forbidden)",
            )
            self.assertNotEqual(outcome.lower(), "safe")

    def test_evasion_baseline_results(self):
        res_file = PROJECT_ROOT / "results" / "evasion_baseline_v1.json"
        self.assertTrue(res_file.exists(), "results/evasion_baseline_v1.json must exist")

        with open(res_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        summary = data.get("summary", data.get("overall", {}))
        self.assertEqual(summary["total_tests"], 48)
        self.assertEqual(summary["recovered"], 14)
        self.assertEqual(summary["different_signal"], 16)
        self.assertEqual(summary["missed"], 18)

    def test_three_outcome_scoring_logic(self):
        baseline = [{"category": "Command Execution", "indicator": "os.system"}]

        # Recovered
        res_recovered = classify_outcome(
            baseline,
            [{"category": "Command Execution", "indicator": "os.system"}],
        )
        self.assertEqual(res_recovered, "recovered")

        # Different Signal
        res_diff = classify_outcome(
            baseline,
            [
                {"category": "Obfuscation", "indicator": "base64.b64decode"},
                {"category": "Dynamic Code Execution", "indicator": "exec"},
            ],
        )
        self.assertEqual(res_diff, "different_signal")

        # Missed
        res_missed = classify_outcome(baseline, [])
        self.assertEqual(res_missed, "missed")


if __name__ == "__main__":
    unittest.main()
