"""Explain a saved scan record.

`scan` writes ``scans/<scan_id>.json`` and prints a short summary. This module
reads that record back. It lists parse failures and uninspected files, and it
says whether those gaps cross the limits in ``spider_contract.verdict``.

It does not re-run the analyzer and it does not change the verdict. The rules
stay frozen; this is a reader for a record the engine already produced.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from spider_contract.validate import validate_record
from spider_contract.verdict import (
    PARSE_FAILURE_RATIO_LIMIT,
    UNINSPECTED_RATIO_LIMIT,
    coverage_problems,
)

from spider.cli import STATIC_ANALYSIS_DISCLAIMER


class ShowError(Exception):
    """A saved record could not be loaded or explained."""


def exit_code_for_outcome(outcome: Optional[str]) -> int:
    """Same exit codes as ``scan``: 0, 10, 20, or 2 for anything else."""
    if outcome == "none_detected_in_this_scan":
        return 0
    if outcome == "suspicious":
        return 10
    if outcome == "unable_to_assess":
        return 20
    return 2


def resolve_scan_path(ref: str, scans_dir: Path) -> Path:
    """Accept a path to a record, or a scan id looked up in ``scans_dir``.

    A value that contains a path separator is only treated as a path. That
    keeps a typo like ``scans/missing.json`` from being searched again as
    ``scans/missing.json.json`` inside the scans directory.
    """
    direct = Path(ref)
    if direct.is_file():
        return direct

    if ref != Path(ref).name:
        raise ShowError(f"Scan record not found: {ref}")

    filename = ref if ref.endswith(".json") else f"{ref}.json"
    path = scans_dir / filename
    if path.is_file():
        return path
    raise ShowError(
        f"No scan record for '{ref}'. Not a file, and {path} does not exist."
    )


def load_scan_record(path: Path) -> Dict[str, Any]:
    """Read one record and refuse it when it breaks the scan_record contract."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ShowError(f"Scan record is not valid JSON: {path} ({exc})") from exc
    except OSError as exc:
        raise ShowError(f"Could not read scan record: {path} ({exc})") from exc

    if not isinstance(data, dict):
        raise ShowError(f"Scan record must be a JSON object: {path}")

    errors = validate_record(data)
    if errors:
        joined = "; ".join(errors)
        raise ShowError(f"Scan record failed schema validation: {joined}")
    return data


def format_scan_report(record: Dict[str, Any]) -> str:
    """Turn one scan record into the text a reviewer should read."""
    lines: List[str] = []
    target = record.get("target") or {}
    version = target.get("version")
    target_label = target.get("name", "?")
    if version:
        target_label = f"{target_label} {version}"

    lines.append(f"Scan {record.get('scan_id', '?')}")
    lines.append(f"Recorded: {record.get('created_at', '?')}")
    origin = record.get("record_origin", "unknown")
    lines.append(f"Origin: {origin}")
    if origin != "analyzer":
        lines.append(
            "This record is a saved fixture or conversion. "
            "Read it as an example, separate from a live analyzer run."
        )
    lines.append(f"Target: {target_label} ({target.get('kind', '?')})")

    tool = record.get("tool") or {}
    lines.append(
        "Analyzer: "
        f"{tool.get('analyzer_version', '?')}  "
        f"ruleset: {tool.get('ruleset_version', '?')}"
    )

    verdict = record.get("verdict") or {}
    lines.append("")
    lines.append(f"Verdict: {verdict.get('outcome', 'unknown')}")
    reasons = verdict.get("reasons") or []
    if reasons:
        lines.append(f"Reasons: {', '.join(str(r) for r in reasons)}")
    if verdict.get("review_recommended"):
        lines.append("Review recommended: True")

    limitations = verdict.get("limitations") or []
    if limitations:
        lines.append("Limitations:")
        for item in limitations:
            lines.append(f"  - {item}")

    lines.append("")
    lines.extend(_coverage_lines(record))
    lines.append("")
    lines.extend(_finding_lines(record.get("findings") or []))
    lines.append("")
    lines.append(STATIC_ANALYSIS_DISCLAIMER)
    return "\n".join(lines)


def _coverage_lines(record: Dict[str, Any]) -> List[str]:
    inv = record.get("inventory") or {}
    files = record.get("files") or []
    parse_failures = inv.get("parse_failures") or []
    uninspected = inv.get("uninspected") or []
    python_files = int(inv.get("python_files") or 0)
    non_doc = [item for item in files if item.get("kind") != "doc"]
    python_label = "Python file" if python_files == 1 else "Python files"

    lines = [
        "Coverage: "
        f"{inv.get('files_inspected', 0)}/{inv.get('files_total', 0)} files inspected "
        f"({python_files} {python_label})"
    ]
    lines.append(_share_line(
        "Parse failures",
        len(parse_failures),
        python_files,
        PARSE_FAILURE_RATIO_LIMIT,
        "Python files",
    ))
    for item in parse_failures:
        lines.append(f"  - {item.get('path', '?')}: {item.get('error', 'parse error')}")

    lines.append(_share_line(
        "Uninspected files",
        len(uninspected),
        len(non_doc),
        UNINSPECTED_RATIO_LIMIT,
        "non-doc files",
    ))
    for item in uninspected:
        lines.append(f"  - {item.get('path', '?')}: {item.get('reason', 'uninspected')}")

    problems = coverage_problems(record)
    if problems:
        lines.append("Coverage problems the verdict policy records:")
        for problem in problems:
            lines.append(f"  - {problem}")
    else:
        lines.append(
            "Coverage problems the verdict policy records: none. "
            "A none_detected_in_this_scan verdict still describes only this scan."
        )
    return lines


def _share_line(label: str, count: int, total: int, limit: float, unit: str) -> str:
    """Say whether a gap is past the limit the verdict policy actually uses."""
    if total == 1 and unit.endswith("s"):
        unit = unit[:-1]
    if total <= 0:
        return f"{label}: {count}. There are no {unit} to compare with the {limit:.0%} limit."
    ratio = count / float(total)
    if ratio > limit:
        relation = "past"
        effect = "this share trips the coverage rule"
    else:
        relation = "inside"
        effect = "this share stays under the coverage rule"
    return (
        f"{label}: {count} of {total} {unit} ({ratio:.0%}). "
        f"The limit is {limit:.0%}. This share is {relation} that limit, so {effect}."
    )


def show_target(ref: str, *, scans_dir: Path, json_output: bool = False) -> int:
    """Load one saved scan and print the report. Returns the scan exit code."""
    try:
        record = load_scan_record(resolve_scan_path(ref, scans_dir))
    except ShowError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 2

    if json_output:
        print(json.dumps(record, indent=2))
    else:
        print(format_scan_report(record))
    outcome = (record.get("verdict") or {}).get("outcome")
    return exit_code_for_outcome(outcome)


def _finding_lines(findings: List[Dict[str, Any]]) -> List[str]:
    lines = [f"Findings: {len(findings)}"]
    if not findings:
        lines.append("  (none)")
        return lines

    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings:
        category = str(finding.get("category") or "uncategorized")
        grouped.setdefault(category, []).append(finding)

    for category in sorted(grouped):
        lines.append(f"  [{category}]")
        ordered = sorted(
            grouped[category],
            key=lambda finding: (
                str(finding.get("file") or ""),
                (finding.get("span") or {}).get("start_line") or 0,
                str(finding.get("indicator") or ""),
            ),
        )
        for finding in ordered:
            span = finding.get("span") or {}
            location = f"{finding.get('file', '?')}:{span.get('start_line', '?')}"
            severity = str(finding.get("severity") or "").upper()
            lines.append(
                f"    [{severity}] {finding.get('indicator', '?')} at {location}"
            )
            if finding.get("explanation"):
                lines.append(f"        {finding['explanation']}")
    return lines
