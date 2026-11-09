"""Tests for Person_A/pipeline/sanitize_hunt.py."""
import json
import tempfile
import unittest
from pathlib import Path

from Person_A.pipeline.sanitize_hunt import main, sanitize_hunt_data, sanitize_string_paths


class TestSanitizeHunt(unittest.TestCase):
    def test_sanitize_string_paths(self):
        # Linux home
        s1 = "/home/alice/.local/lib/python3.11/site-packages/evil.pth"
        self.assertEqual(sanitize_string_paths(s1), "/home/user/.local/lib/python3.11/site-packages/evil.pth")

        # Windows home
        s2 = r"C:\Users\Bob\AppData\Local\Programs\Python\Lib\site-packages\sitecustomize.py"
        self.assertEqual(sanitize_string_paths(s2), r"/home/user\AppData\Local\Programs\Python\Lib\site-packages\sitecustomize.py")

        # Tilde home
        s3 = "~/.local/lib/python3.10/site-packages"
        self.assertEqual(sanitize_string_paths(s3), "/home/user/.local/lib/python3.10/site-packages")

    def test_sanitize_hunt_data_filtering_and_counts(self):
        # Prepare mock hunt data: 2 HIGH, 3 MEDIUM, 50 LOW items
        items = []
        items.append({
            "dist": "pkg-high-1",
            "version": "1.0",
            "artifact": "pth",
            "path": "/home/eve/.local/lib/python3.11/site-packages/evil.pth",
            "sha256": "h1",
            "severity": "HIGH",
            "priority": 120,
            "reason": "Dangerous code in /home/eve/evil.pth",
        })
        items.append({
            "dist": "pkg-high-2",
            "version": "1.0",
            "artifact": "startup",
            "path": r"C:\Users\Eve\sitecustomize.py",
            "sha256": "h2",
            "severity": "HIGH",
            "priority": 100,
            "reason": "Exec call",
        })
        for i in range(3):
            items.append({
                "dist": f"pkg-med-{i}",
                "version": "1.0",
                "artifact": "tamper",
                "path": f"/home/eve/pkg_{i}.py",
                "sha256": f"m{i}",
                "severity": "MEDIUM",
                "priority": 50,
                "reason": f"Tampered {i}",
            })
        for i in range(50):
            items.append({
                "dist": f"pkg-low-{i}",
                "version": "1.0",
                "artifact": "dist_scan",
                "path": f"/home/eve/low_{i}.py",
                "sha256": f"l{i}",
                "severity": "LOW",
                "priority": 10,
                "reason": f"Low severity {i}",
            })

        mock_data = {
            "hunt_id": "hunt_test123",
            "created_at": "2026-11-07T12:00:00Z",
            "roots": ["/home/eve/.local/lib/python3.11/site-packages", r"C:\Users\Eve\site-packages"],
            "items": items,
            "coverage": {
                "counts": {
                    "skipped_too_large": 2,
                    "missing_in_RECORD": 1,
                    "inspection_timed_out": 0,
                    "file_list_unavailable": 5,
                },
                "dists_without_file_list": ["d1", "d2"],
                "errors": ["/home/eve/large.file: skipped_too_large"],
            },
            "limitations": ["Static only"],
        }

        sanitized = sanitize_hunt_data(mock_data, low_sample_size=40, seed=42)

        # 2 HIGH + 3 MEDIUM + 40 sampled LOW = 45 items
        retained = sanitized["items"]
        self.assertEqual(len(retained), 45)
        self.assertEqual(sum(1 for it in retained if it["severity"] == "HIGH"), 2)
        self.assertEqual(sum(1 for it in retained if it["severity"] == "MEDIUM"), 3)
        self.assertEqual(sum(1 for it in retained if it["severity"] == "LOW"), 40)

        # Assert no occurrence of '/eve' or r'\eve' in paths or roots or reasons
        serialized = json.dumps(sanitized)
        self.assertNotIn("/eve", serialized.lower())
        self.assertNotIn(r"\eve", serialized.lower())
        self.assertIn("/home/user", serialized)

        # Assert coverage counts preserved
        self.assertEqual(sanitized["coverage"]["counts"]["skipped_too_large"], 2)
        self.assertEqual(sanitized["coverage"]["counts"]["file_list_unavailable"], 5)

    def test_cli_execution(self):
        with tempfile.TemporaryDirectory() as td:
            in_file = Path(td) / "kali_first.json"
            out_file = Path(td) / "hunt_sample.json"

            in_file.write_text(json.dumps({
                "hunt_id": "h1",
                "roots": ["/home/kali/.local/lib"],
                "items": [
                    {"severity": "HIGH", "path": "/home/kali/evil.pth", "priority": 100},
                ],
                "coverage": {"errors": []},
            }), encoding="utf-8")

            exit_code = main(["--in", str(in_file), "--out", str(out_file)])
            self.assertEqual(exit_code, 0)
            self.assertTrue(out_file.exists())
            content = out_file.read_text(encoding="utf-8")
            self.assertIn("/home/user", content)
            self.assertNotIn("/home/kali", content)


if __name__ == "__main__":
    unittest.main()
