import ast
import json
from pathlib import Path
import unittest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
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
        self.assertTrue(records_dir.exists(), "fixtures/records directory must exist")

        fixture_files = list(records_dir.glob("*.json"))
        self.assertEqual(len(fixture_files), 5, "Must have exactly 5 fixture records")

        for f_path in fixture_files:
            with open(f_path, "r", encoding="utf-8") as f:
                rec = json.load(f)

            self.assertIn("package_name", rec)
            self.assertIn("record_origin", rec)
            self.assertEqual(rec["record_origin"], "fixture")
            self.assertIn("verdict", rec)

            # Strict honesty rule: NEVER use "Safe"
            self.assertIn(
                rec["verdict"],
                ["Malicious", "Suspicious", "Needs Review"],
                f"Verdict '{rec['verdict']}' in {f_path.name} violates honesty rule (Safe is forbidden)",
            )
            self.assertNotEqual(rec["verdict"], "Safe")

    def test_evasion_baseline_results(self):
        res_file = PROJECT_ROOT / "results" / "evasion_baseline_v1.json"
        self.assertTrue(res_file.exists(), "results/evasion_baseline_v1.json must exist")

        with open(res_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["overall"]["total_tests"], 50)
        self.assertEqual(data["overall"]["recovered"], 26)
        self.assertEqual(data["overall"]["different_signal"], 16)
        self.assertEqual(data["overall"]["missed"], 8)

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
