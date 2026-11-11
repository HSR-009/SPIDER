"""SPIDER command line interface (section 3.5)."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from spider.engine.extract import safe_extract
from spider.engine.scan import scan_directory
from spider_contract.validate import validate_record
from spider.fetch import fetch_package_archive, FetchError
from spider.hunter.hunt import run_hunt, sanitize_path
from spider.hunter.store import HunterStore

STATIC_ANALYSIS_DISCLAIMER = "Static analysis only: 'none detected in this scan' does not mean the package is safe."
ARCHIVE_EXTENSIONS = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar", ".zip", ".whl")


def format_human_summary(record: Dict[str, Any]) -> str:
    verdict = record.get("verdict", {})
    outcome = verdict.get("outcome", "unknown")
    reasons = verdict.get("reasons", [])
    review_rec = verdict.get("review_recommended", False)
    findings = record.get("findings", [])
    inv = record.get("inventory", {})

    lines = []
    lines.append(f"Verdict: {outcome}")
    if reasons:
        lines.append(f"Reasons: {', '.join(reasons)}")
    if review_rec:
        lines.append("Review Recommended: True")

    lines.append(f"Coverage: {inv.get('files_inspected', 0)}/{inv.get('files_total', 0)} files inspected ({inv.get('python_files', 0)} Python files)")
    if inv.get("parse_failures"):
        lines.append(f"Parse Failures: {len(inv['parse_failures'])}")
    if inv.get("uninspected"):
        lines.append(f"Uninspected: {len(inv['uninspected'])}")

    if findings:
        lines.append("\nTop Findings:")
        for f in findings[:5]:
            span = f.get("span", {})
            loc = f"{f.get('file')}:{span.get('start_line', '?')}"
            lines.append(f"  [{f.get('severity', '').upper()}] {f.get('indicator')} ({f.get('category')}) at {loc}")
            if f.get("explanation"):
                lines.append(f"      {f.get('explanation')}")

    lines.append(f"\n{STATIC_ANALYSIS_DISCLAIMER}")
    return "\n".join(lines)


def scan_target(
    target: str,
    *,
    out_dir: Path,
    json_output: bool = False,
    no_network: bool = False,
    normalize: bool = False,
) -> int:
    target_path = Path(target)
    temp_dir_to_clean: Optional[Path] = None

    scan_dir: Path
    pkg_name: Optional[str] = None
    pkg_version: Optional[str] = None
    hash_verified: Optional[bool] = None

    try:
        if target_path.is_dir():
            scan_dir = target_path
            pkg_name = scan_dir.name
        elif target_path.is_file() and any(target.lower().endswith(ext) for ext in ARCHIVE_EXTENSIONS):
            # Safe extract archive into temporary directory
            td = tempfile.mkdtemp(prefix="spider_scan_")
            temp_dir_to_clean = Path(td)
            ext_res = safe_extract(target_path, temp_dir_to_clean)
            scan_dir = temp_dir_to_clean
            pkg_name = target_path.name.split(".")[0]
        elif "==" in target:
            if no_network:
                sys.stderr.write("Error: Network access disabled (--no-network), cannot fetch package.\n")
                return 2
            name, sep, version = target.partition("==")
            try:
                archive_path, expected_sha, verified = fetch_package_archive(name, version)
            except FetchError as e:
                sys.stderr.write(f"Error fetching package: {e}\n")
                return 2
            hash_verified = verified
            td = tempfile.mkdtemp(prefix="spider_scan_")
            temp_dir_to_clean = Path(td)
            ext_res = safe_extract(archive_path, temp_dir_to_clean)
            scan_dir = temp_dir_to_clean
            pkg_name = name
            pkg_version = version
        else:
            sys.stderr.write(f"Error: Target '{target}' is not an existing directory, supported archive, or name==version specifier.\n")
            return 2

        # Run directory scan
        record = scan_directory(scan_dir, name=pkg_name, version=pkg_version, normalize=normalize)

        if hash_verified is not None:
            record["target"]["hash_verified"] = hash_verified
            # Re-derive verdict with hash_verified knowledge
            from spider_contract.verdict import derive_verdict, coverage_problems
            v_dict = derive_verdict(record)
            record["verdict"]["outcome"] = v_dict["outcome"]
            record["verdict"]["reasons"] = v_dict["reasons"]
            if "review_recommended" in v_dict:
                record["verdict"]["review_recommended"] = v_dict["review_recommended"]
            limitations = [STATIC_ANALYSIS_DISCLAIMER]
            for p in coverage_problems(record):
                limitations.append(f"Coverage problem: {p}")
            record["verdict"]["limitations"] = limitations

        # Validate against schema
        errs = validate_record(record)
        if errs:
            sys.stderr.write(f"Schema validation errors in generated record: {errs}\n")
            return 2

        # Write scans/<scan_id>.json
        out_dir.mkdir(parents=True, exist_ok=True)
        scan_file = out_dir / f"{record['scan_id']}.json"
        scan_file.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")

        if json_output:
            print(json.dumps(record, indent=2))
        else:
            print(format_human_summary(record))

        outcome = record.get("verdict", {}).get("outcome")
        if outcome == "none_detected_in_this_scan":
            return 0
        elif outcome == "suspicious":
            return 10
        elif outcome == "unable_to_assess":
            return 20
        return 2
    except Exception as e:
        sys.stderr.write(f"Unexpected scan error: {e}\n")
        return 2
    finally:
        if temp_dir_to_clean and temp_dir_to_clean.exists():
            import shutil
            shutil.rmtree(temp_dir_to_clean, ignore_errors=True)


def hunt_target(
    *,
    site_packages: Optional[List[str]] = None,
    json_output: bool = False,
    allow_sha256: Optional[str] = None,
    allow_note: Optional[str] = None,
    db_path: Optional[str] = None,
) -> int:
    try:
        # Check non-existent custom site-packages directory (clean error message)
        if site_packages:
            for sp in site_packages:
                if not Path(sp).exists():
                    sys.stderr.write(f"Error: Specified site-packages directory does not exist: {sp}\n")
                    return 2

        store = HunterStore(db_path=db_path)

        if allow_sha256:
            store.add_allow(allow_sha256, note=allow_note or "")
            if not json_output:
                print(f"Allowlisted sha256 {allow_sha256.lower()}")

        result = run_hunt(
            extra_site_packages=site_packages,
            db_path=db_path,
            include_system_defaults=True if not site_packages else False,
        )

        items = result.get("items", [])
        visible_items = [it for it in items if not it.get("allowlisted")]

        if json_output:
            # Deepcopy or sanitize paths with ~ for sharing
            clean_res = json.loads(json.dumps(result))
            for it in clean_res.get("items", []):
                if it.get("path"):
                    it["path"] = sanitize_path(it["path"])
            clean_res["roots"] = [sanitize_path(r) for r in clean_res.get("roots", [])]
            print(json.dumps(clean_res, indent=2))
        else:
            print(f"=== SPIDER Hunter Scan Report [{result.get('hunt_id')}] ===")
            print(f"Time: {result.get('created_at')}")
            print(f"Environments inspected: {len(result.get('roots', []))} roots ({result.get('distributions_count', 0)} distributions)")
            print(f"Items found: {len(visible_items)} active (hidden allowlisted: {len(items) - len(visible_items)})")
            
            if visible_items:
                print("\nFlagged Artifacts:")
                for it in visible_items[:15]:
                    print(f"  [{it.get('severity', '').upper():6}] (priority: {it.get('priority', 0)}) {it.get('artifact')}: {it.get('reason')}")
                    print(f"           Path: {sanitize_path(it.get('path', ''))}")
                    if it.get("evidence_snippet"):
                        print(f"           Evidence: {it.get('evidence_snippet')}")

            cov = result.get("coverage", {})
            counts = cov.get("counts", {})
            if counts:
                print("\nCoverage Summary:")
                print(f"  Skipped too large:            {counts.get('skipped_too_large', 0)}")
                print(f"  Missing in RECORD:             {counts.get('missing_in_RECORD', 0)}")
                print(f"  Inspection timed out:          {counts.get('inspection_timed_out', 0)}")
                print(f"  File list unavailable:         {counts.get('file_list_unavailable', 0)}")
                if counts.get('entrypoint_ownership_unknown'):
                    print(f"  Entrypoint ownership unknown:  {counts.get('entrypoint_ownership_unknown', 0)}")

            if cov.get("errors"):
                print(f"\nCoverage Warnings: {len(cov['errors'])} errors")
            if cov.get("dists_without_file_list"):
                print(f"Distributions without file list: {len(cov['dists_without_file_list'])}")

            for lim in result.get("limitations", []):
                print(f"\n{lim}")

        # Exit code 0 if no HIGH items (among non-allowlisted), 10 otherwise
        has_high = any(it.get("severity") == "HIGH" for it in visible_items)
        return 10 if has_high else 0
    except Exception as e:
        sys.stderr.write(f"Unexpected hunter error: {e}\n")
        return 2


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="spider", description="SPIDER Package Security Scanner")
    subparsers = parser.add_subparsers(dest="subcommand")

    scan_parser = subparsers.add_parser("scan", help="Scan a package directory, archive, or PyPI release")
    scan_parser.add_argument("target", help="Directory, archive (.tar.gz, .zip, .whl), or name==version")
    scan_parser.add_argument("--json", action="store_true", help="Output full JSON scan record")
    scan_parser.add_argument("--out", default="scans", help="Output directory for scan records (default: scans/)")
    scan_parser.add_argument("--no-network", action="store_true", help="Disable network operations")
    scan_parser.add_argument("--normalize", action="store_true", help="Normalize Python source in memory before static analysis")

    hunt_parser = subparsers.add_parser("hunt", help="Scan installed environments for persistence artifacts")
    hunt_parser.add_argument("--site-packages", action="append", help="Extra site-packages directory to scan")
    hunt_parser.add_argument("--json", action="store_true", help="Output JSON hunt result")
    hunt_parser.add_argument("--allow", help="Allowlist a sha256 hash")
    hunt_parser.add_argument("--note", help="Note for allowlisted sha256")
    hunt_parser.add_argument("--db", help="Path to SQLite hunter database")

    show_parser = subparsers.add_parser(
        "show",
        help="Explain a saved scan record, including coverage gaps",
    )
    show_parser.add_argument("record", help="Scan id, or path to a scan record JSON file")
    show_parser.add_argument(
        "--scans",
        default="scans",
        help="Directory of saved scan records when RECORD is a scan id (default: scans/)",
    )
    show_parser.add_argument("--json", action="store_true", help="Print the saved scan record")

    serve_parser = subparsers.add_parser("serve", help="Run the local API and UI on 127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    serve_parser.add_argument("--out", default="scans", help="Directory for scan records (default: scans/)")
    serve_parser.add_argument("--db", help="Path to SQLite hunter database")
    serve_parser.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically")

    args = parser.parse_args(argv)

    if args.subcommand == "serve":
        from spider.api import serve
        serve(port=args.port, scans_dir=args.out, db_path=args.db, open_browser=not args.no_browser)
        return 0
    if args.subcommand == "scan":
        return scan_target(
            args.target,
            out_dir=Path(args.out),
            json_output=args.json,
            no_network=args.no_network,
            normalize=args.normalize,
        )
    elif args.subcommand == "hunt":
        return hunt_target(
            site_packages=args.site_packages,
            json_output=args.json,
            allow_sha256=args.allow,
            allow_note=args.note,
            db_path=args.db,
        )
    elif args.subcommand == "show":
        from spider.show import show_target

        return show_target(
            args.record,
            scans_dir=Path(args.scans),
            json_output=args.json,
        )
    else:
        parser.print_help()
        return 2


if __name__ == "__main__":
    sys.exit(main())

