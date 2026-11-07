"""Verdict policy v2 (rules S1 to S5 from brief section 7.5).

Order of decision:
  1. suspicious            if any strong signal (S1..S5) fires
  2. unable_to_assess      if there is any coverage problem
  3. none_detected_in_this_scan   otherwise

Vendored paths are NOT auto-suppressed: attackers hide in bundled code.
The verdict never says "safe", and the ML model never changes the outcome.
Plain setup() and LOW findings never trigger anything.
"""
from __future__ import annotations

from typing import Any, Dict, List

from . import verdict_v2

PARSE_FAILURE_RATIO_LIMIT = 0.20
UNINSPECTED_RATIO_LIMIT = 0.50


def is_triggering(finding: Dict[str, Any]) -> bool:
    """Legacy helper for single-finding triggering check."""
    severity = str(finding.get("severity", "")).lower()
    if severity == "unknown":
        severity = "medium"
    if severity == "high":
        return True
    return severity == "medium" and finding.get("trigger_phase") in ("install", "import")


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
    """Return {"outcome": ..., "reasons": [...], "review_recommended": ...} for a record."""
    problems = coverage_problems(record)
    outcome, strong, review = verdict_v2.decide(record.get("findings", []), problems)
    res: Dict[str, Any] = {
        "outcome": outcome,
        "reasons": strong if outcome == "suspicious" else (problems if outcome == "unable_to_assess" else []),
    }
    if review:
        res["review_recommended"] = True
    return res
