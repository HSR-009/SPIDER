import os
from pathlib import Path
import sys

# Ensure root folder (SPIDER) is available in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import pandas as pd
from Person_B.features.extract_features import extract_code_features
from Person_B.features.metadata_features import (
    compute_typosquat_distance,
    fetch_pypi_metadata,
)


def build_feature_row(
    package_name: str,
    package_version: str,
    raw_ast_summary: dict,
    label: int = 0,
) -> dict:
    """Combines AST code metrics, typosquatting checks, and PyPI metadata into one row."""
    row = {
        "package_name": package_name,
        "package_version": package_version,
    }

    # 1. Code-level features (AST ratios + Shannon entropy)
    code_feats = extract_code_features(raw_ast_summary)
    row.update(code_feats)

    # 2. Typosquatting features (Levenshtein distance)
    squat_feats = compute_typosquat_distance(package_name)
    row.update(squat_feats)

    # 3. PyPI Live Metadata (age, release counts)
    meta_feats = fetch_pypi_metadata(package_name)
    row.update(meta_feats)

    # 4. Target label (0 = benign, 1 = malicious)
    row["label"] = int(label)

    return row


def generate_table(
    records: list, output_csv_path: str = "data/processed/feature_table.csv"
) -> pd.DataFrame:
    """Builds a Pandas DataFrame from raw package records and saves it as a CSV."""
    rows = []
    for item in records:
        row = build_feature_row(
            package_name=item.get("package_name", ""),
            package_version=item.get("package_version", "1.0.0"),
            raw_ast_summary=item.get("ast_summary", {}),
            label=item.get("label", 0),
        )
        rows.append(row)

    df = pd.DataFrame(rows)

    os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)
    df.to_csv(output_csv_path, index=False)
    print(f"[+] Successfully built feature table with {len(df)} records.")
    print(f"[+] Saved to: {output_csv_path}")
    return df


if __name__ == "__main__":
    # Test batch with 1 legitimate package and 1 simulated typosquat/malicious package
    dummy_records = [
        {
            "package_name": "requests",
            "package_version": "2.28.1",
            "label": 0,
            "ast_summary": {
                "total_calls": 250,
                "eval_calls": 0,
                "exec_calls": 0,
                "system_calls": 0,
                "subprocess_calls": 0,
                "strings": ["GET", "https://api.github.com", "User-Agent"],
                "parse_failed": 0,
            },
        },
        {
            "package_name": "reqeusts",
            "package_version": "0.0.1",
            "label": 1,
            "ast_summary": {
                "total_calls": 4,
                "eval_calls": 1,
                "exec_calls": 1,
                "system_calls": 1,
                "subprocess_calls": 1,
                "strings": ["aW1wb3J0IG9zCnN5c3RlbSgnaGFjaycp", "payload_run"],
                "parse_failed": 0,
            },
        },
    ]

    df = generate_table(dummy_records)
    print("\n--- Feature Table Preview ---")
    print(df.to_string())