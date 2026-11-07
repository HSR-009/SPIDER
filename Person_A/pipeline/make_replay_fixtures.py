#!/usr/bin/env python
"""
Person_A/pipeline/make_replay_fixtures.py
----------------------------------------
Selects 10 real packages from the malicious rescan table (`data/processed/malicious_v11.jsonl`):
- 5 suspicious (one each for S1..S5, distinct packages)
- 1 unable_to_assess
- 1 none_detected_in_this_scan with review_recommended: True
- 3 other diverse none_detected_in_this_scan

For each package:
- Resolves its real archive path under --raw-dir.
- Runs spider.engine.extract.safe_extract into a temporary directory.
- Runs the real spider.engine.scan.scan_directory.
- Sets record_origin to "replay" and target.kind to "archive".
- Sanitizes findings snippets (max 8 lines, 120 chars/line, redacted hosts/tokens/blobs).
- Validates the record with spider_contract.validate schema validator.
- Writes to fixtures/replay/NN_<package-name>-<version>.json.

Note: Runs on Kali where raw archives exist. Exits non-zero with a clear error
if raw archives are missing.
"""

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from spider.engine.extract import safe_extract
from spider.engine.scan import scan_directory
from spider.engine.sanitize import sanitize_scan_record_for_replay
from spider_contract.validate import schema_errors, semantic_errors

DEFAULT_TABLE = ROOT / "data" / "processed" / "malicious_v11.jsonl"
DEFAULT_RAW_DIR = ROOT / "data" / "raw" / "malicious" / "pypi"
DEFAULT_OUT_DIR = ROOT / "fixtures" / "replay"


def select_10_packages(table_path):
    table = Path(table_path)
    if not table.exists():
        raise FileNotFoundError(f"Rescan table not found: {table}")

    rows = []
    with open(table, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))

    def pick(criteria, exclude_ids):
        for r in rows:
            if r["package_id"] not in exclude_ids and criteria(r):
                return r
        return None

    chosen = []
    chosen_ids = set()

    for sig in ("S1_install_command", "S2_dynamic_exec_plus", "S3_credential_net", "S4_env_post", "S5_decode_exec"):
        r = pick(lambda row, s=sig: s in row.get("strong_signals", []), chosen_ids)
        if not r:
            raise ValueError(f"Could not find a package with signal {sig}")
        chosen.append((sig, r))
        chosen_ids.add(r["package_id"])

    r_u = pick(lambda row: row.get("verdict_outcome") == "unable_to_assess", chosen_ids)
    if not r_u:
        raise ValueError("Could not find a package with unable_to_assess")
    chosen.append(("unable_to_assess", r_u))
    chosen_ids.add(r_u["package_id"])

    r_r = pick(lambda row: row.get("verdict_outcome") == "none_detected_in_this_scan" and row.get("review_recommended"), chosen_ids)
    if not r_r:
        raise ValueError("Could not find a package with review_recommended")
    chosen.append(("review_recommended", r_r))
    chosen_ids.add(r_r["package_id"])

    for i in range(3):
        r_o = pick(lambda row: row.get("verdict_outcome") == "none_detected_in_this_scan" and not row.get("review_recommended"), chosen_ids)
        if not r_o:
            raise ValueError(f"Could not find a package for other none_detected {i+1}")
        chosen.append((f"other_none_{i+1}", r_o))
        chosen_ids.add(r_o["package_id"])

    return chosen


def resolve_archive_path(raw_dir, pkg_row):
    """
    Finds the archive for a package under raw_dir.
    Checks archive_used relative path or pkg_name/version folder.
    """
    raw_path = Path(raw_dir)
    pkg_name = pkg_row["package_name"]
    ver = pkg_row["version"]

    archive_used = pkg_row.get("archive_used")
    if archive_used:
        # If absolute path from Kali, check relative to pypi
        parts = Path(archive_used).parts
        if "pypi" in parts:
            idx = parts.index("pypi")
            rel_parts = parts[idx + 1:]
            candidate = raw_path.joinpath(*rel_parts)
            if candidate.is_file():
                return candidate
        direct_cand = raw_path / Path(archive_used).name
        if direct_cand.is_file():
            return direct_cand

    pkg_dir = raw_path / pkg_name / ver
    if pkg_dir.is_dir():
        for ext in (".tar.gz", ".tgz", ".zip", ".whl"):
            for f in pkg_dir.glob(f"*{ext}"):
                if f.is_file():
                    return f

    flat_dir = raw_path / pkg_name
    if flat_dir.is_dir():
        for ext in (".tar.gz", ".tgz", ".zip", ".whl"):
            for f in flat_dir.glob(f"*{ext}"):
                if f.is_file():
                    return f

    return None


def generate_single_replay_fixture(archive_path, pkg_row, out_dir, index_num):
    archive_path = Path(archive_path)
    pkg_name = pkg_row["package_name"]
    ver = pkg_row["version"]

    with tempfile.TemporaryDirectory() as extract_dir:
        extract_rep = safe_extract(str(archive_path), extract_dir)

        # Run real scan_directory
        record = scan_directory(extract_dir, name=pkg_name, version=ver)
        record["record_origin"] = "replay"
        record["target"]["kind"] = "archive"
        record["target"]["artifact"]["filename"] = archive_path.name

        lower_name = archive_path.name.lower()
        if lower_name.endswith((".tar.gz", ".tgz")):
            record["target"]["artifact"]["format"] = "tar.gz"
        elif lower_name.endswith(".whl"):
            record["target"]["artifact"]["format"] = "whl"
        else:
            record["target"]["artifact"]["format"] = "other"

        record["target"]["hash_verified"] = None

        # Compare new verdict outcome with table row's verdict_outcome
        expected_outcome = pkg_row.get("verdict_outcome")
        actual_outcome = record.get("verdict", {}).get("outcome")
        if expected_outcome and actual_outcome != expected_outcome:
            raise ValueError(
                f"Verdict outcome mismatch for package {pkg_name}=={ver}: "
                f"expected {expected_outcome!r} from table, got {actual_outcome!r} from rescan."
            )

        # Copy any extraction limits
        for lim in extract_rep.get("limits_hit", []):
            if lim not in record["inventory"]["limits_hit"]:
                record["inventory"]["limits_hit"].append(lim)

        record = sanitize_scan_record_for_replay(record)

        sch_errs = schema_errors(record)
        if sch_errs:
            raise ValueError(f"Schema errors in replay record for {pkg_name}=={ver}: {sch_errs}")

        sem_errs = semantic_errors(record)
        if sem_errs:
            raise ValueError(f"Semantic errors in replay record for {pkg_name}=={ver}: {sem_errs}")

        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        fname = f"{index_num:02d}_{pkg_name}-{ver}.json"
        dest_file = out_path / fname
        with open(dest_file, "w", encoding="utf-8", newline="\n") as f:
            json.dump(record, f, indent=2, sort_keys=True)
            f.write("\n")

        return dest_file


def make_replay_fixtures(table_path=DEFAULT_TABLE, raw_dir=DEFAULT_RAW_DIR, out_dir=DEFAULT_OUT_DIR):
    raw_path = Path(raw_dir)
    if not raw_path.exists():
        sys.exit(f"ERROR: Raw archive directory does not exist: {raw_dir}. This script runs on Kali where raw archives exist.")

    chosen = select_10_packages(table_path)
    print(f"Selected {len(chosen)} target packages from {table_path}")

    missing = []
    resolved = []
    for idx, (role, r) in enumerate(chosen, start=1):
        arc = resolve_archive_path(raw_path, r)
        if not arc or not arc.is_file():
            missing.append(f"{r['package_id']} (archive_used={r.get('archive_used')})")
        else:
            resolved.append((idx, role, r, arc))

    if missing:
        sys.exit(
            f"ERROR: Missing raw archives for {len(missing)} of 10 selected packages under {raw_dir}:\n"
            + "\n".join(f"  - {m}" for m in missing)
            + "\nThis script runs on Kali where raw archives exist."
        )

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    generated = []
    for idx, role, r, arc in resolved:
        dest = generate_single_replay_fixture(arc, r, out_path, idx)
        generated.append(dest)
        print(f"Generated {dest.name} [{role}] from {arc.name}")

    print(f"Successfully created {len(generated)} replay fixtures in {out_dir}")
    return generated


def main():
    parser = argparse.ArgumentParser(description="Generate replay fixtures from real archives and rescan table (runs on Kali)")
    parser.add_argument("--table", default=str(DEFAULT_TABLE), help="Path to malicious_v11.jsonl")
    parser.add_argument("--raw-dir", default=str(DEFAULT_RAW_DIR), help="Path to raw malicious pypi directory")
    parser.add_argument("--out", default=str(DEFAULT_OUT_DIR), help="Output directory for replay fixtures")
    args = parser.parse_args()

    make_replay_fixtures(args.table, args.raw_dir, args.out)


if __name__ == "__main__":
    main()
