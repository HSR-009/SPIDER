"""Validate scan records: JSON Schema first, then the rules a schema cannot express.

Usage (from the repo root):
    python -m spider_contract.validate                      # fixtures/records + fixtures/src
    python -m spider_contract.validate scans/abc.json       # one record
    python -m spider_contract.validate --src-root fixtures/src fixtures/records
Exit code is 1 if anything fails.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .verdict import coverage_problems, derive_verdict

SCHEMA_DIR = Path(__file__).parent / "schemas"


def load_schema(name: str = "scan_record.schema.json") -> Dict[str, Any]:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def schema_errors(record: Dict[str, Any]) -> List[str]:
    from jsonschema import Draft7Validator

    validator = Draft7Validator(load_schema())
    errors = []
    for err in sorted(validator.iter_errors(record), key=lambda e: [str(p) for p in e.path]):
        where = ".".join(str(p) for p in err.path) or "<record>"
        errors.append("schema: %s: %s" % (where, err.message))
    return errors


def _under(path: str, prefixes: List[str]) -> bool:
    return any(path == p.rstrip("/") or path.startswith(p.rstrip("/") + "/") for p in prefixes)


def semantic_errors(record: Dict[str, Any], src_root: Optional[Path] = None) -> List[str]:
    errs = []  # type: List[str]
    inv = record["inventory"]
    files = record["files"]
    by_path = {}  # type: Dict[str, Dict[str, Any]]

    for f in files:
        if f["path"] in by_path:
            errs.append("files: duplicate path %s" % f["path"])
        by_path[f["path"]] = f

    # --- inventory must agree with the file list --------------------------
    if inv["files_total"] != len(files):
        errs.append("inventory.files_total=%d but %d files listed" % (inv["files_total"], len(files)))
    py = [f for f in files if f["kind"] == "python"]
    if inv["python_files"] != len(py):
        errs.append("inventory.python_files=%d but %d python files listed" % (inv["python_files"], len(py)))
    n_inspected = sum(1 for f in files if f["inspected"])
    if inv["files_inspected"] != n_inspected:
        errs.append("inventory.files_inspected=%d but %d marked inspected" % (inv["files_inspected"], n_inspected))

    failed = [p["path"] for p in inv["parse_failures"]]
    skipped = [u["path"] for u in inv["uninspected"]]
    for path in failed:
        f = by_path.get(path)
        if f is None or f["kind"] != "python" or f["inspected"]:
            errs.append("parse_failures: %s must be a listed, non-inspected python file" % path)
    for path in skipped:
        f = by_path.get(path)
        if f is None or f["inspected"] or f["kind"] == "doc":
            errs.append("uninspected: %s must be a listed, non-inspected, non-doc file" % path)
    if set(failed) & set(skipped):
        errs.append("a file cannot be in both parse_failures and uninspected")
    for f in files:
        if f["kind"] != "doc" and not f["inspected"]:
            if f["path"] not in failed and f["path"] not in skipped:
                errs.append("%s is not inspected but is in neither parse_failures nor uninspected" % f["path"])

    # --- findings ---------------------------------------------------------
    ids = set()
    for fd in record["findings"]:
        if fd["id"] in ids:
            errs.append("findings: duplicate id %s" % fd["id"])
        ids.add(fd["id"])
        if fd["file"] not in by_path:
            errs.append("%s: file %s is not in files[]" % (fd["id"], fd["file"]))
        sp = fd["span"]
        if sp["end_line"] is not None and sp["end_line"] < sp["start_line"]:
            errs.append("%s: end_line before start_line" % fd["id"])
        if (
            sp["end_line"] == sp["start_line"]
            and sp["start_col"] is not None
            and sp["end_col"] is not None
            and sp["end_col"] < sp["start_col"]
        ):
            errs.append("%s: end_col before start_col" % fd["id"])
        if fd["context"]["in_vendored_path"] != _under(fd["file"], inv["vendored_paths"]):
            errs.append("%s: context.in_vendored_path disagrees with inventory.vendored_paths" % fd["id"])

        # snippet must literally match the source at the span (when sources are available)
        if (
            src_root is not None
            and fd["snippet"] is not None
            and sp["end_line"] == sp["start_line"]
            and sp["start_col"] is not None
            and sp["end_col"] is not None
        ):
            src_file = Path(src_root) / record["target"]["name"] / fd["file"]
            if not src_file.exists():
                errs.append("%s: source %s not found for snippet check" % (fd["id"], src_file))
            else:
                lines = src_file.read_text(encoding="utf-8").splitlines()
                if sp["start_line"] > len(lines):
                    errs.append("%s: start_line beyond end of file" % fd["id"])
                else:
                    got = lines[sp["start_line"] - 1][sp["start_col"] : sp["end_col"]]
                    if got != fd["snippet"]:
                        errs.append("%s: snippet %r does not match source %r" % (fd["id"], fd["snippet"], got))

    # --- relations --------------------------------------------------------
    rids = set()
    for r in record["relations"]:
        if r["id"] in rids:
            errs.append("relations: duplicate id %s" % r["id"])
        rids.add(r["id"])
        for end in ("from", "to"):
            if r[end] not in ids:
                errs.append("%s: %s=%s is not a finding id" % (r["id"], end, r[end]))
        if r["from"] == r["to"]:
            errs.append("%s: relation from a finding to itself" % r["id"])

    # --- verdict policy ---------------------------------------------------
    derived = derive_verdict(record)
    v = record["verdict"]
    if v["outcome"] != derived["outcome"]:
        errs.append("verdict.outcome=%s but policy derives %s" % (v["outcome"], derived["outcome"]))
    elif sorted(v["reasons"]) != sorted(derived["reasons"]):
        errs.append("verdict.reasons %s differ from derived %s" % (sorted(v["reasons"]), sorted(derived["reasons"])))
    if coverage_problems(record) and not v["limitations"]:
        errs.append("coverage problems exist, so verdict.limitations must not be empty")

    # --- honesty rules ----------------------------------------------------
    m = record["model_assessment"]
    if record["record_origin"] == "hand_written_fixture" and m["status"] in ("ok", "abstained"):
        if not m["illustrative"]:
            errs.append("hand-written fixture with model output must set illustrative=true")
    if record["record_origin"] == "analyzer" and m["illustrative"]:
        errs.append("a real analyzer record cannot carry illustrative model values")
    return errs


def validate_record(record: Dict[str, Any], src_root: Optional[Path] = None) -> List[str]:
    errs = schema_errors(record)
    if errs:  # semantic checks assume a structurally valid record
        return errs
    return semantic_errors(record, src_root)


def _collect(paths: List[str]) -> List[Path]:
    out = []  # type: List[Path]
    for p in paths:
        path = Path(p)
        out.extend(sorted(path.glob("*.json")) if path.is_dir() else [path])
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Validate SPIDER scan records (schema v0.1).")
    ap.add_argument("paths", nargs="*", help="record files or directories (default: fixtures/records)")
    ap.add_argument("--src-root", help="directory holding <target.name>/ source trees, to check snippets")
    args = ap.parse_args(argv)

    paths = args.paths or ["fixtures/records"]
    src_root = args.src_root
    if src_root is None and not args.paths and Path("fixtures/src").is_dir():
        src_root = "fixtures/src"

    files = _collect(paths)
    if not files:
        print("no record files found in: %s" % ", ".join(paths))
        return 1
    failed = 0
    for path in files:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # unreadable or not JSON
            print("FAIL %s\n   cannot read: %s" % (path, exc))
            failed += 1
            continue
        errs = validate_record(record, Path(src_root) if src_root else None)
        if errs:
            failed += 1
            print("FAIL %s" % path)
            for e in errs[:25]:
                print("   - " + e)
            if len(errs) > 25:
                print("   ... %d more" % (len(errs) - 25))
        else:
            print("OK   %s  [%s]" % (path, record["verdict"]["outcome"]))
    print("\n%d record(s), %d failed" % (len(files), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
