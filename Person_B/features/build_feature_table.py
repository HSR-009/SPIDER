"""Build Person B's feature table from the shared, versioned JSONL exports."""
import gzip
import json
import sys
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Person_B.features.extract_features import (
    DIAGNOSTIC_COLUMNS,
    extract_record_features,
    normalize_package_name,
    top_indicator_vocabulary,
    feature_columns,
)


def read_jsonl(path):
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON at {path}:{line_no}") from exc


def get_frozen_holdout_ids(records=None):
    holdout_path = ROOT / "results" / "frozen_holdout_packages.csv"
    if holdout_path.exists():
        holdout_df = pd.read_csv(holdout_path)
        return set(holdout_df["package_id"].astype(str))
    if records is not None:
        from Person_B.models.splitting import make_frozen_holdout
        split_records = [
            {
                "package_id": str(r["package_id"]),
                "group_id": normalize_package_name(r.get("package_name") or r.get("package")),
                "label": int(r["label"]),
            }
            for r in records
        ]
        _, hold_df = make_frozen_holdout(pd.DataFrame(split_records), n_splits=5, random_state=42)
        return set(hold_df["package_id"].astype(str))
    return set()


def build_feature_table(holdout_ids=None, dataset_version="v1.1", out_path=None):
    processed = ROOT / "data" / "processed"
    if dataset_version == "v1.1":
        paths = [processed / "malicious_v11.jsonl", processed / "benign_v11.jsonl.gz"]
        expected_counts = (2039, 2909)
    elif dataset_version == "v1":
        paths = [processed / "malicious_for_b.jsonl", processed / "benign_for_b.jsonl.gz"]
        expected_counts = (2045, 2908)
    else:
        raise ValueError(f"Unknown dataset_version: {dataset_version}")

    missing = [str(path) for path in paths if not path.exists()]
    if missing:
        raise FileNotFoundError("Missing dataset export(s): " + ", ".join(missing))

    records = []
    for path, expected_label, expected_count in zip(paths, (1, 0), expected_counts):
        class_records = []
        for record in read_jsonl(path):
            if int(record.get("label", -1)) != expected_label:
                raise ValueError(f"Wrong label in {path}: {record.get('package_id')}")
            class_records.append(record)
        if len(class_records) != expected_count:
            raise ValueError(
                f"Row count mismatch in {path}: expected {expected_count}, got {len(class_records)}"
            )
        records.extend(class_records)

    if not records:
        raise ValueError("Both JSONL exports are empty.")

    ids = [str(r.get("package_id") or "") for r in records]
    if any(not value for value in ids):
        raise ValueError("Every record must have package_id.")
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate package_id detected.")

    # Determine frozen holdout package IDs to prevent vocabulary leakage
    if holdout_ids is None:
        holdout_ids = get_frozen_holdout_ids(records)
    else:
        holdout_ids = set(str(pid) for pid in holdout_ids)

    # Verify frozen holdout coverage
    holdout_records = [r for r in records if str(r.get("package_id")) in holdout_ids]
    if len(holdout_records) != len(holdout_ids):
        raise ValueError(
            f"Holdout mismatch: expected {len(holdout_ids)} holdout packages in dataset, found {len(holdout_records)}"
        )
    m_holdout = sum(1 for r in holdout_records if int(r.get("label", -1)) == 1)
    b_holdout = sum(1 for r in holdout_records if int(r.get("label", -1)) == 0)
    if (m_holdout, b_holdout) != (409, 582):
        raise ValueError(f"Holdout class mismatch: expected (409, 582), got ({m_holdout}, {b_holdout})")

    # Select top-40 indicator vocabulary using development records ONLY
    dev_records = [r for r in records if str(r.get("package_id")) not in holdout_ids]
    vocabulary = top_indicator_vocabulary(dev_records, limit=40)
    rows = []
    for record in records:
        package_name = normalize_package_name(record.get("package_name") or record.get("package"))
        if not package_name:
            raise ValueError(f"Missing package_name for {record.get('package_id')}")
        group_id = record.get("group_id") or package_name
        row = {
            "package_id": str(record["package_id"]),
            "package_name": package_name,
            "group_id": group_id,
            "version": str(record.get("version") or ""),
            "analyzer_version": record.get("analyzer_version"),
            "label": int(record["label"]),
        }
        row.update(extract_record_features(record, vocabulary))
        rows.append(row)

    df = pd.DataFrame(rows)
    if df.groupby("group_id")["label"].nunique().gt(1).any():
        raise ValueError("A normalized group_id has contradictory labels.")
    overlap = set(df.loc[df.label == 0, "group_id"]) & set(df.loc[df.label == 1, "group_id"])
    if overlap:
        raise ValueError(f"Package groups cross labels: {sorted(overlap)[:10]}")

    # Keep provenance/diagnostic fields in the table; training code explicitly excludes them.
    metadata = ["package_id", "package_name", "group_id", "version", "analyzer_version", "label"]
    feat_cols = feature_columns(vocabulary)
    columns = metadata + feat_cols + DIAGNOSTIC_COLUMNS
    df = df[columns]
    numeric_columns = feat_cols + DIAGNOSTIC_COLUMNS
    df[numeric_columns] = df[numeric_columns].fillna(0)

    if out_path is not None:
        out = Path(out_path)
        df.to_csv(out, index=False)
    else:
        if dataset_version == "v1.1":
            out = processed / "feature_table_v11.csv"
            df.to_csv(out, index=False)
            df.to_csv(processed / "feature_table.csv", index=False)
            (processed / "top40_indicators_v11.json").write_text(
                json.dumps(vocabulary, indent=2), encoding="utf-8"
            )
            (processed / "top40_indicators.json").write_text(
                json.dumps(vocabulary, indent=2), encoding="utf-8"
            )
        else:
            out = processed / "feature_table_v1.csv"
            df.to_csv(out, index=False)
            (processed / "top40_indicators_v1.json").write_text(
                json.dumps(vocabulary, indent=2), encoding="utf-8"
            )

    print(f"Feature table ({dataset_version}): {out} | rows={len(df)} | groups={df.group_id.nunique()}")
    print("Labels:", df.label.value_counts().sort_index().to_dict())
    print("Top-indicator vocabulary size:", len(vocabulary))
    return df


if __name__ == "__main__":
    build_feature_table(dataset_version="v1.1")
