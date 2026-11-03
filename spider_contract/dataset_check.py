import argparse
import gzip
import json
import sys
from pathlib import Path
from spider_contract.dataset import make_group_id

REQUIRED_COLUMNS = {
    "package_id",
    "package_name",
    "version",
    "label",
    "group_id",
    "analyzer_version"
}

def check_file(file_path: Path) -> bool:
    print(f"[*] Validating dataset: {file_path}")
    if not file_path.exists():
        print(f"[-] File not found: {file_path}")
        return False

    opener = gzip.open if str(file_path).endswith(".gz") else open
    mode = "rt" if str(file_path).endswith(".gz") else "r"

    total_rows = 0
    missing_fields = set()
    invalid_labels = 0
    mismatched_groups = 0

    with opener(file_path, mode, encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            total_rows += 1
            try:
                row = json.loads(line)
            except Exception as e:
                print(f"[-] Line {line_no}: Invalid JSON: {e}")
                return False

            # Check required fields
            for req in REQUIRED_COLUMNS:
                if req not in row:
                    missing_fields.add(req)

            # Check label format
            label = row.get("label")
            if label not in (0, 1, "0", "1"):
                invalid_labels += 1

            # Check group_id normalization
            pkg_name = row.get("package_name", "")
            expected_group = make_group_id(pkg_name)
            actual_group = row.get("group_id", "")
            if actual_group and actual_group != expected_group:
                mismatched_groups += 1

    print(f"[+] Total rows: {total_rows}")
    if missing_fields:
        print(f"[-] Missing required columns: {sorted(list(missing_fields))}")
        return False
    if invalid_labels > 0:
        print(f"[-] Rows with invalid label (must be 0 or 1): {invalid_labels}")
        return False
    if mismatched_groups > 0:
        print(f"[-] Rows with non-PEP 503 compliant group_id: {mismatched_groups}")
        return False

    print(f"[+] Clean! All {total_rows} rows satisfy the dataset contract.")
    return True

def main():
    parser = argparse.ArgumentParser(description="SPIDER Dataset Contract Validator")
    parser.add_argument("paths", nargs="*", help="Paths to JSONL / JSONL.GZ files to check")
    args = parser.parse_args()

    paths = [Path(p) for p in args.paths]
    if not paths:
        # Default to processed files if none supplied
        default_files = [
            Path("data/processed/malicious_for_b.jsonl"),
            Path("data/processed/benign_for_b.jsonl.gz"),
        ]
        paths = [p for p in default_files if p.exists()]

    if not paths:
        print("[-] No dataset files specified or found.")
        sys.exit(1)

    all_ok = True
    for p in paths:
        if not check_file(p):
            all_ok = False

    sys.exit(0 if all_ok else 1)

if __name__ == "__main__":
    main()
