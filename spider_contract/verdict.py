"""Verdict policy v0.1 (a PROPOSAL for Level 1; tune it, but change it in one place).

Order of decision:
  1. suspicious            if any finding is "triggering"
  2. unable_to_assess      if there is any coverage problem
  3. none_detected_in_this_scan   otherwise

A finding is "triggering" when:
  - severity is high, or
  - severity is medium and the trigger phase is install or import.
Unknown severity is treated as medium (conservative).

Vendored paths are NOT auto-suppressed: attackers hide in bundled code.
The verdict never says "safe", and the ML model never changes the outcome.
"""
from __future__ import annotations

from typing import Any, Dict, List

PARSE_FAILURE_RATIO_LIMIT = 0.20
UNINSPECTED_RATIO_LIMIT = 0.50


def is_triggering(finding: Dict[str, Any]) -> bool:
    severity = finding["severity"]
    if severity == "unknown":
        severity = "medium"
    if severity == "high":
        return True
    return severity == "medium" and finding["trigger_phase"] in ("install", "import")


def coverage_problems(record: Dict[str, Any]) -> List[str]:
    inv = record["inventory"]
    problems = []  # type: List[str]
    non_doc = [f for f in record["files"] if f["kind"] != "doc"]

    if not inv["coverage_known"]:
        problems.append("coverage_unknown")
    if inv["limits_hit"]:
        problems.append("limits_hit:" + ",".join(inv["limits_hit"]))
    if record["target"]["hash_verified"] is False:
        problems.append("hash_mismatch")
    if inv["python_files"] > 0:
        ratio = len(inv["parse_failures"]) / float(inv["python_files"])
        if ratio > PARSE_FAILURE_RATIO_LIMIT:
            problems.append("parse_failure_ratio:%.2f" % ratio)
    if non_doc:
        ratio = len(inv["uninspected"]) / float(len(non_doc))
        if ratio > UNINSPECTED_RATIO_LIMIT:
            problems.append("uninspected_ratio:%.2f" % ratio)
        if inv["files_inspected"] == 0:
            problems.append("nothing_inspected")
    return problems


def derive_verdict(record: Dict[str, Any]) -> Dict[str, Any]:
    """Return {"outcome": ..., "reasons": [...]} for a structurally valid record."""
    triggering = sorted(f["id"] for f in record["findings"] if is_triggering(f))
    if triggering:
        return {"outcome": "suspicious", "reasons": triggering}
    problems = coverage_problems(record)
    if problems:
        return {"outcome": "unable_to_assess", "reasons": problems}
    return {"outcome": "none_detected_in_this_scan", "reasons": []}
