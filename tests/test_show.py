"""Tests for explaining a saved scan record."""
from __future__ import annotations

import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import spider.cli as cli
from spider.show import format_scan_report


def _record() -> dict:
    """A small in-memory record. One parse failure out of six Python files."""
    return {
        "scan_id": "abcd1234",
        "created_at": "2026-11-09T10:00:00Z",
        "record_origin": "analyzer",
        "tool": {
            "analyzer_version": "v1.1",
            "ruleset_version": "v1.1",
        },
        "target": {
            "kind": "directory",
            "name": "demo",
            "version": None,
            "hash_verified": None,
        },
        "inventory": {
            "coverage_known": True,
            "files_total": 6,
            "python_files": 6,
            "files_inspected": 5,
            "uninspected": [],
            "parse_failures": [{"path": "notes.py", "error": "invalid syntax"}],
            "vendored_paths": [],
            "limits_hit": [],
        },
        "files": [{"path": f"m{i}.py", "kind": "python"} for i in range(6)],
        "findings": [],
        "verdict": {
            "outcome": "none_detected_in_this_scan",
            "reasons": [],
            "limitations": ["Static analysis only."],
        },
    }


class TestFormatScanReport(unittest.TestCase):
    def test_parse_failure_under_the_limit_is_listed_and_stays_under_the_rule(self):
        text = format_scan_report(_record())
        self.assertIn("notes.py: invalid syntax", text)
        self.assertIn("1 of 6 Python files", text)
        self.assertIn("stays under the coverage rule", text)
        self.assertIn("Coverage problems the verdict policy records: none.", text)
        self.assertIn("Verdict: none_detected_in_this_scan", text)

    def test_parse_failure_past_the_limit_is_a_coverage_problem(self):
        record = _record()
        record["inventory"]["python_files"] = 2
        record["inventory"]["files_total"] = 2
        record["files"] = [
            {"path": "ok.py", "kind": "python"},
            {"path": "bad.py", "kind": "python"},
        ]
        record["verdict"]["outcome"] = "unable_to_assess"
        record["verdict"]["reasons"] = ["parse_failure_ratio:0.50"]

        text = format_scan_report(record)
        self.assertIn("past that limit", text)
        self.assertIn("parse_failure_ratio:0.50", text)

    def test_half_uninspected_stays_under_the_rule(self):
        """The policy uses a strict greater-than check, so 50% does not trip it."""
        record = _record()
        record["inventory"]["parse_failures"] = []
        record["inventory"]["python_files"] = 1
        record["inventory"]["files_total"] = 2
        record["inventory"]["uninspected"] = [
            {"path": "library.so", "reason": "binary_not_analyzed"}
        ]
        record["files"] = [
            {"path": "ok.py", "kind": "python"},
            {"path": "library.so", "kind": "binary"},
        ]

        text = format_scan_report(record)
        self.assertIn("library.so: binary_not_analyzed", text)
        self.assertIn("1 of 2 non-doc files", text)
        self.assertIn("Uninspected files: 1 of 2 non-doc files (50%).", text)
        self.assertIn("this share stays under the coverage rule", text)
        self.assertNotIn("uninspected_ratio", text)

    def test_findings_are_grouped_and_ordered(self):
        record = _record()
        record["inventory"]["parse_failures"] = []
        record["findings"] = [
            {
                "category": "Network",
                "severity": "medium",
                "indicator": "urlopen",
                "file": "b.py",
                "span": {"start_line": 10},
                "explanation": "opens a url",
            },
            {
                "category": "Network",
                "severity": "low",
                "indicator": "urlopen",
                "file": "a.py",
                "span": {"start_line": 2},
            },
            {
                "category": "Obfuscation",
                "severity": "high",
                "indicator": "base64",
                "file": "c.py",
                "span": {"start_line": 4},
            },
        ]
        text = format_scan_report(record)
        network = text.index("  [Network]")
        obfuscation = text.index("  [Obfuscation]")
        self.assertLess(network, obfuscation)
        self.assertLess(text.index("a.py:2"), text.index("b.py:10"))
        self.assertIn("opens a url", text)

    def test_non_analyzer_origin_is_labelled(self):
        record = _record()
        record["record_origin"] = "replay"
        text = format_scan_report(record)
        self.assertIn("Origin: replay", text)
        self.assertIn("saved fixture or conversion", text)


class TestShowCommand(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="spider_show_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_missing_scan_id_exits_2(self):
        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            code = cli.main(["show", "does-not-exist", "--scans", str(self.temp_dir)])
        self.assertEqual(code, 2)
        self.assertIn("No scan record", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_invalid_json_exits_2(self):
        path = self.temp_dir / "broken.json"
        path.write_text("{", encoding="utf-8")
        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            code = cli.main(["show", str(path)])
        self.assertEqual(code, 2)
        self.assertIn("not valid JSON", stderr.getvalue())

    def test_scan_then_show_lists_the_gap_the_engine_recorded(self):
        package = self.temp_dir / "pkg"
        package.mkdir()
        (package / "ok.py").write_text("def hello():\n    return 1\n", encoding="utf-8")
        (package / "bad.py").write_text("def (\n", encoding="utf-8")
        (package / "extra.so").write_bytes(b"\x7fELF" + b"\x00" * 16)

        out_dir = self.temp_dir / "scans"
        scan_code = cli.main(["scan", str(package), "--out", str(out_dir)])
        self.assertEqual(scan_code, 20)

        record_path = next(out_dir.glob("*.json"))
        scan_id = json.loads(record_path.read_text(encoding="utf-8"))["scan_id"]

        stdout = io.StringIO()
        with patch("sys.stdout", stdout):
            show_code = cli.main(["show", scan_id, "--scans", str(out_dir)])
        report = stdout.getvalue()
        self.assertEqual(show_code, 20)
        self.assertIn("bad.py", report)
        self.assertIn("extra.so: binary_not_analyzed", report)
        self.assertIn("parse_failure_ratio", report)
        self.assertIn("trips the coverage rule", report)


if __name__ == "__main__":
    unittest.main()
