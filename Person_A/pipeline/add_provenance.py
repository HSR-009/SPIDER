#!/usr/bin/env python
"""
Adds PEP 503 group_id and analyzer_version to malicious and benign processed files.
Verifies zero group leakage between datasets and runs schema validation.
"""

import gzip
import json
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from spider_contract.dataset import make_group_id
from spider_contract.dataset_check import check_file

ANALYZER_VERSION = "v1.0.0"

def process_file(source_path: Path, dest_path: Path):
    print(f"[*] Processing {source_path} -> {dest_path}")
    source_is_gz = str(source_path).endswith(".gz")
    dest_is_gz = str(dest_path).endswith(".gz")

    opener_in = gzip.open if source_is_gz else open
    mode_in = "rt" if source_is_gz else "r"

    records = []
    group_ids = set()

    with opener_in(source_path, mode_in, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            pkg_name = row.get("package_name", "")
            gid = make_group_id(pkg_name)
            row["group_id"] = gid
            row["analyzer_version"] = ANALYZER_VERSION
            
            # Ensure package_id is deterministic
            if "version" in row and "package_name" in row and not row.get("package_id"):
                row["package_id"] = f"{row['package_name']}=={row['version']}"

            records.append(row)
            group_ids.add(gid)

    # Write out
    opener_out = gzip.open if dest_is_gz else open
    mode_out = "wt" if dest_is_gz else "w"

    with opener_out(dest_path, mode_out, encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    print(f"[+] Written {len(records)} records ({len(group_ids)} unique group_ids) to {dest_path}")
    return group_ids

def main():
    mal_path = PROJECT_ROOT / "data" / "processed" / "malicious_for_b.jsonl"
    ben_plain = PROJECT_ROOT / "data" / "processed" / "benign_for_b.jsonl"
    ben_gz = PROJECT_ROOT / "data" / "processed" / "benign_for_b.jsonl.gz"

    if not mal_path.exists():
        print(f"[-] Malicious dataset not found at {mal_path}")
        sys.exit(1)

    # 1. Update malicious dataset
    mal_groups = process_file(mal_path, mal_path)

    # 2. Update benign dataset
    if ben_plain.exists():
        ben_groups = process_file(ben_plain, ben_plain)
    elif ben_gz.exists():
        ben_groups = process_file(ben_gz, ben_plain)
    else:
        print(f"[-] Benign dataset not found.")
        sys.exit(1)

    # Re-generate .gz file for benign dataset from ben_plain
    process_file(ben_plain, ben_gz)

    # 3. Check for group leakage
    overlap = mal_groups.intersection(ben_groups)
    if overlap:
        print(f"[-] CRITICAL: Group leakage detected! Overlapping groups: {overlap}")
        sys.exit(1)
    else:
        print(f"[+] Disjoint check passed! 0 overlapping groups between {len(mal_groups)} malicious and {len(ben_groups)} benign groups.")

    # 4. Run contract validations
    print("\n[*] Validating updated files against spider_contract:")
    ok_mal = check_file(mal_path)
    ok_ben_gz = check_file(ben_gz)
    ok_ben_plain = check_file(ben_plain)

    if ok_mal and ok_ben_gz and ok_ben_plain:
        print("\n[+] SUCCESS: Provenance columns added and verified cleanly on all datasets.")
    else:
        print("\n[-] Validation failed on updated datasets.")
        sys.exit(1)

if __name__ == "__main__":
    main()
