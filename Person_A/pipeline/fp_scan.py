"""False-positive evaluation scanner (Day 6 step 6.2 & brief 7.10).

Usage:
    python Person_A/pipeline/fp_scan.py \\
        --sel results/fp_check_selection.csv \\
        --archives fp_check/ \\
        --hashes results/fp_check_archives.sha256 \\
        --out results/fp_check_v11.csv
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import shutil
import signal
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from spider.engine.extract import safe_extract
from spider.engine.sanitize import sanitize_snippet
from spider.engine.scan import scan_directory
from spider_contract.adapter import to_legacy
from spider_contract.verdict import coverage_problems
from spider_contract.verdict_v2 import decide


class TimeoutException(Exception):
    pass


def timeout_handler(signum, frame):
    raise TimeoutException("Per-archive scan timeout (60s exceeded)")


def sha256_of_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower()


def load_expected_hashes(hashes_path: Path) -> Dict[str, str]:
    """Load sha256 -> relative archive path from sha256 file."""
    expected: Dict[str, str] = {}
    if not hashes_path.exists():
        return expected

    with hashes_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                sha, rel_path = parts[0].strip().lower(), parts[1].strip()
                expected[rel_path] = sha
    return expected


def extract_family(pkg_name: str) -> str:
    """Return prefix before the first '-' in package name (e.g. mypy-boto3-* -> mypy)."""
    return pkg_name.split("-")[0] if "-" in pkg_name else pkg_name


def scan_single_archive(
    archive_path: Path,
    expected_sha: str,
    name: str,
    version: str,
    timeout_sec: int = 60,
) -> Tuple[Dict[str, Any], Optional[str]]:
    """Safe-extract and scan a single archive within timeout_sec.
    
    Returns (result_dict, triage_excerpt_markdown_or_None).
    """
    family = extract_family(name)
    temp_dir = tempfile.mkdtemp(prefix="spider_fp_scan_")

    try:
        # Set alarm on POSIX
        if sys.platform != "win32" and hasattr(signal, "SIGALRM"):
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(timeout_sec)

        try:
            # 1. Safe extract
            ext_res = safe_extract(archive_path, Path(temp_dir))
            # Treat any rejected member whose reason starts with "unreadable_archive" as unable_to_assess
            has_unreadable = any(str(r.get("reason", "")).startswith("unreadable_archive") for r in ext_res.get("rejected", []))
            if has_unreadable:
                return {
                    "name": name,
                    "version": version,
                    "family": family,
                    "py_files": 0,
                    "verdict": "unable_to_assess",
                    "strong_signals": "",
                    "review_recommended": False,
                    "top_indicators": "",
                    "coverage_problems": "unreadable_archive",
                    "triage_label": "",
                    "triage_note": "",
                }, None
        except TimeoutException as e:
            return {
                "name": name,
                "version": version,
                "family": family,
                "py_files": 0,
                "verdict": "unable_to_assess",
                "strong_signals": "",
                "review_recommended": False,
                "top_indicators": "",
                "coverage_problems": "scan_timeout_60s",
                "triage_label": "",
                "triage_note": "",
            }, None
        except Exception as e:
            return {
                "name": name,
                "version": version,
                "family": family,
                "py_files": 0,
                "verdict": "unable_to_assess",
                "strong_signals": "",
                "review_recommended": False,
                "top_indicators": "",
                "coverage_problems": f"extract_failed:{e}",
                "triage_label": "",
                "triage_note": "",
            }, None

        try:
            # 2. Directory scan with corpus rescan settings
            record = scan_directory(Path(temp_dir), name=name, version=version)
            # Do not set record["target"]["hash_verified"] = True; the sha256 matches our frozen list, leave None
            record["target"]["hash_verified"] = None

            # Wire extraction rejections and limits into record inventory (matching rescan_corpora)
            for rej in ext_res.get("rejected", []):
                record["inventory"]["uninspected"].append({"path": rej.get("name", "unknown"), "reason": rej.get("reason", "rejected")})
            for lim in ext_res.get("limits_hit", []):
                if lim not in record["inventory"]["limits_hit"]:
                    record["inventory"]["limits_hit"].append(lim)

            # 3. Verdict v2 decision (matching rescan_corpora)
            cov_probs = coverage_problems(record)
            findings_legacy = to_legacy(record)
            outcome, strong, review_rec = decide(findings_legacy, cov_probs)

            # Extract non-parse error indicators
            findings = record.get("findings", [])
            non_parse_findings = [f for f in findings if f.get("category") != "Parse Error"]
            inds = [f.get("indicator") for f in non_parse_findings if f.get("indicator")]
            # Keep top 5 unique indicators preserving order
            seen = set()
            top_5_inds = []
            for ind in inds:
                if ind not in seen:
                    seen.add(ind)
                    top_5_inds.append(ind)
                if len(top_5_inds) >= 5:
                    break

            inv = record.get("inventory", {})
            py_files = inv.get("python_files", 0)

            triage_excerpt = None
            if outcome == "suspicious":
                excerpt_lines = [
                    f"### `{name}=={version}`",
                    f"- **Verdict:** suspicious",
                    f"- **Signals:** {', '.join(strong)}",
                    f"- **Archive:** `{archive_path.name}`",
                    "",
                ]
                for f in non_parse_findings:
                    span = f.get("span", {})
                    f_file = f.get("file", "unknown")
                    start_l = span.get("start_line", "?")
                    f_ind = f.get("indicator", "")
                    f_sev = f.get("severity", "")
                    raw_snippet = f.get("snippet") or ""
                    san_snip = sanitize_snippet(raw_snippet)

                    excerpt_lines.append(f"#### [{f_sev.upper()}] `{f_ind}` in `{f_file}:{start_l}`")
                    if san_snip:
                        excerpt_lines.append("```python")
                        excerpt_lines.append(san_snip)
                        excerpt_lines.append("```")
                    excerpt_lines.append("")
                triage_excerpt = "\n".join(excerpt_lines)

            row = {
                "name": name,
                "version": version,
                "family": family,
                "py_files": py_files,
                "verdict": outcome,
                "strong_signals": ";".join(strong) if strong else "",
                "review_recommended": review_rec,
                "top_indicators": ";".join(top_5_inds),
                "coverage_problems": ";".join(cov_probs) if cov_probs else "",
                "triage_label": "",
                "triage_note": "",
            }
            return row, triage_excerpt

        except TimeoutException as e:
            return {
                "name": name,
                "version": version,
                "family": family,
                "py_files": 0,
                "verdict": "unable_to_assess",
                "strong_signals": "",
                "review_recommended": False,
                "top_indicators": "",
                "coverage_problems": "scan_timeout_60s",
                "triage_label": "",
                "triage_note": "",
            }, None
        except Exception as e:
            return {
                "name": name,
                "version": version,
                "family": family,
                "py_files": 0,
                "verdict": "unable_to_assess",
                "strong_signals": "",
                "review_recommended": False,
                "top_indicators": "",
                "coverage_problems": f"scan_crash:{type(e).__name__}",
                "triage_label": "",
                "triage_note": "",
            }, None

    finally:
        if sys.platform != "win32" and hasattr(signal, "alarm"):
            signal.alarm(0)
        shutil.rmtree(temp_dir, ignore_errors=True)


def run_fp_scan(
    sel_path: Path,
    archives_dir: Path,
    hashes_path: Path,
    out_csv_path: Path,
    excerpts_path: Optional[Path] = None,
    timeout_sec: int = 60,
) -> int:
    # 1. Read selection CSV
    if not sel_path.exists():
        sys.stderr.write(f"Selection file not found: {sel_path}\n")
        return 2

    candidates: List[Dict[str, str]] = []
    with sel_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            candidates.append(r)

    # 2. Read hashes
    if not hashes_path.exists():
        sys.stderr.write(f"Hashes file not found: {hashes_path}\n")
        return 2

    expected_hashes = load_expected_hashes(hashes_path)

    # Pre-verify every archive's sha256 against hash list
    missing_files = []
    mismatch_files = []
    archive_map: Dict[str, Tuple[Path, str]] = {}

    for rel_path, exp_sha in expected_hashes.items():
        # Match archive path under archives_dir
        # rel_path format: "fp_check/<sha>/<filename>" or "fp_check/<filename>" or "<filename>"
        norm_parts = Path(rel_path).parts
        if norm_parts and norm_parts[0] == "fp_check":
            cand_path = archives_dir / Path(*norm_parts[1:])
        else:
            cand_path = archives_dir / Path(rel_path)

        # Also search directly by filename or sha/filename
        if not cand_path.exists():
            direct = archives_dir / Path(rel_path).name
            if direct.exists():
                cand_path = direct
            else:
                missing_files.append(rel_path)
                continue

        actual_sha = sha256_of_file(cand_path)
        if actual_sha != exp_sha:
            mismatch_files.append(f"{rel_path} (expected {exp_sha}, got {actual_sha})")
        else:
            archive_map[exp_sha] = (cand_path, exp_sha)

    if missing_files or mismatch_files:
        sys.stderr.write("Verification failed: refusing to scan.\n")
        if missing_files:
            sys.stderr.write(f"Missing archives ({len(missing_files)}):\n")
            for m in missing_files[:10]:
                sys.stderr.write(f"  {m}\n")
        if mismatch_files:
            sys.stderr.write(f"Mismatched sha256 ({len(mismatch_files)}):\n")
            for mm in mismatch_files[:10]:
                sys.stderr.write(f"  {mm}\n")
        return 2

    # Map selection entries to archives via sha256
    rows_to_scan: List[Tuple[Dict[str, str], Path, str]] = []
    for cand in candidates:
        c_sha = cand.get("sha256", "").strip().lower()
        if c_sha in archive_map:
            arc_path, verified_sha = archive_map[c_sha]
            rows_to_scan.append((cand, arc_path, verified_sha))

    if not rows_to_scan:
        sys.stderr.write(f"No selection candidates found in verified archives list.\n")
        return 2

    results: List[Dict[str, Any]] = []
    excerpts: List[str] = [
        "# FP Check Triage Excerpts",
        "",
        "> Reading aid for manual triage of packages flagged suspicious.",
        "",
    ]

    for cand, arc_path, v_sha in rows_to_scan:
        name = cand["name"]
        ver = cand["version"]
        row, excerpt = scan_single_archive(
            archive_path=arc_path,
            expected_sha=v_sha,
            name=name,
            version=ver,
            timeout_sec=timeout_sec,
        )
        results.append(row)
        if excerpt:
            excerpts.append(excerpt)

    # Sort results deterministically by name, version
    results.sort(key=lambda r: (r["name"], r["version"]))

    # Write CSV
    out_csv_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "name",
        "version",
        "family",
        "py_files",
        "verdict",
        "strong_signals",
        "review_recommended",
        "top_indicators",
        "coverage_problems",
        "triage_label",
        "triage_note",
    ]

    with out_csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(r)

    # Write triage excerpts
    if excerpts_path is None:
        excerpts_path = archives_dir / "triage_excerpts.md"
    excerpts_path.parent.mkdir(parents=True, exist_ok=True)
    excerpts_path.write_text("\n".join(excerpts) + "\n", encoding="utf-8")

    # Print summary
    n_scanned = len(results)
    n_suspicious = sum(1 for r in results if r["verdict"] == "suspicious")
    n_review_rec = sum(1 for r in results if r["review_recommended"])
    n_unable = sum(1 for r in results if r["verdict"] == "unable_to_assess")

    per_signal: Dict[str, int] = {}
    for r in results:
        sig_str = r.get("strong_signals", "")
        if sig_str:
            for s in sig_str.split(";"):
                if s:
                    per_signal[s] = per_signal.get(s, 0) + 1

    print(f"FP Scan Summary:")
    print(f"  Scanned:            {n_scanned}")
    print(f"  Suspicious:         {n_suspicious}")
    print(f"  Review recommended: {n_review_rec}")
    print(f"  Unable to assess:   {n_unable}")
    print("  Per-signal counts:")
    for sig, cnt in sorted(per_signal.items()):
        print(f"    {sig}: {cnt}")

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="SPIDER FP Corpus Scanner")
    parser.add_argument("--sel", default="results/fp_check_selection.csv", help="Path to selection CSV")
    parser.add_argument("--archives", default="fp_check", help="Path to fp_check directory")
    parser.add_argument("--hashes", default="results/fp_check_archives.sha256", help="Path to archives sha256 list")
    parser.add_argument("--out", default="results/fp_check_v11.csv", help="Path to output CSV")
    parser.add_argument("--excerpts", default=None, help="Path to output triage excerpts markdown")
    parser.add_argument("--timeout", type=int, default=60, help="Per-archive timeout in seconds")

    args = parser.parse_args(argv)

    return run_fp_scan(
        sel_path=Path(args.sel),
        archives_dir=Path(args.archives),
        hashes_path=Path(args.hashes),
        out_csv_path=Path(args.out),
        excerpts_path=Path(args.excerpts) if args.excerpts else None,
        timeout_sec=args.timeout,
    )


if __name__ == "__main__":
    sys.exit(main())

