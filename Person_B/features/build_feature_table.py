"""Build the real Person_B feature table from the shared JSONL datasets."""
import gzip
import json
import re
import sys
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[2]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from Person_B.features.extract_features import (
    BEHAVIOR_FEATURE_COLS, DIAGNOSTIC_FEATURE_COLS, extract_record_features,
)

def normalize_package_name(name):
    return re.sub(r"[-_.]+", "-", str(name or "").strip().lower())

def read_jsonl(path, compressed=False):
    opener = gzip.open if compressed else open
    rows = []
    with opener(path, "rt", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON in {path}, line {line_no}: {exc}") from exc
    return rows

def build_feature_table():
    processed = BASE_DIR / "data" / "processed"
    malicious_path = processed / "malicious_for_b.jsonl"
    benign_path = processed / "benign_for_b.jsonl.gz"
    for path in (malicious_path, benign_path):
        if not path.exists():
            raise FileNotFoundError(
                f"Required dataset not found: {path}\n"
                "Ensure benign_for_b.jsonl.gz is restored from origin/main."
            )

    records = read_jsonl(malicious_path) + read_jsonl(benign_path, compressed=True)
    rows = []
    seen = set()
    for index, record in enumerate(records):
        name = str(record.get("package_name") or "").strip()
        if not name:
            raise ValueError(f"Record {index} has no package_name")
        label = int(record.get("label"))
        if label not in (0, 1):
            raise ValueError(f"Unexpected label {label!r} for package {name}")
        normalized = normalize_package_name(name)
        key = (normalized, str(record.get("version") or ""))
        if key in seen:
            raise ValueError(f"Duplicate package/version record: {key}")
        seen.add(key)
        row = {
            "package_name": name,
            "normalized_package_name": normalized,
            "label": label,
        }
        row.update(extract_record_features(record))
        rows.append(row)

    df = pd.DataFrame(rows)
    # Same normalized package must never have contradictory labels.
    conflicts = df.groupby("normalized_package_name")["label"].nunique()
    conflicts = conflicts[conflicts > 1]
    if not conflicts.empty:
        raise ValueError(f"Contradictory labels for normalized packages: {conflicts.index.tolist()[:10]}")

    # Cross-class overlap is a dataset integrity check, not a feature.
    names_by_label = {
        label: set(df.loc[df.label == label, "normalized_package_name"])
        for label in (0, 1)
    }
    overlap = names_by_label[0] & names_by_label[1]
    if overlap:
        raise ValueError(f"Package names occur in both classes: {sorted(overlap)[:10]}")

    ordered = ["package_name", "normalized_package_name"] + BEHAVIOR_FEATURE_COLS + DIAGNOSTIC_FEATURE_COLS + ["label"]
    df = df[ordered].fillna(0)
    output = processed / "feature_table.csv"
    df.to_csv(output, index=False)
    print(f"Saved {len(df):,} package-version rows to {output}")
    print("Class counts:", df["label"].value_counts().sort_index().to_dict())
    print("Unique packages by label:", df.groupby("label")["normalized_package_name"].nunique().to_dict())
    return df

if __name__ == "__main__":
    build_feature_table()
