import re
from typing import Iterable, Set

BANNED_FEATURE_COLUMNS: Set[str] = {
    "label",
    "source",
    "package_id",
    "version",
    "malicious_evidence",
    "in_index",
    "index_annotated",
    "collection_date",
    "sha256",
    "artifact_sha256",
    "url",
    "upload_time",
    "archive_path",
    "filename",
    "packagetype",
    "size_bytes",
    "group_id",
    "split",
    "campaign",
    "comment",
    "details",
    "purl",
    "reportSource",
    "reported",
    "targetedOS",
}

def make_group_id(package_name: str) -> str:
    """
    Normalizes a package name according to PEP 503 rules.
    Converts to lowercase and collapses runs of [-_.] to a single dash '-'.
    """
    if not package_name:
        return ""
    return re.sub(r"[-_.]+", "-", str(package_name).strip().lower())

def assert_no_leaky_columns(columns: Iterable[str]) -> None:
    """
    Guards ML model training against data leakage.
    Raises AssertionError if any banned target, identifier, or origin metadata column
    is found in the feature set.
    """
    cols_set = set(columns)
    leaked = cols_set.intersection(BANNED_FEATURE_COLUMNS)
    if leaked:
        raise AssertionError(
            f"Data leakage guard triggered! The following banned columns are present in features: {sorted(list(leaked))}"
        )

def assert_group_disjoint(train_df, test_df, group_col: str = "group_id") -> None:
    """
    Verifies that package groups are strictly disjoint between train and test partitions.
    """
    if group_col not in train_df.columns:
        raise ValueError(f"Column '{group_col}' missing from train dataset.")
    if group_col not in test_df.columns:
        raise ValueError(f"Column '{group_col}' missing from test dataset.")

    train_groups = set(train_df[group_col].dropna())
    test_groups = set(test_df[group_col].dropna())
    overlap = train_groups.intersection(test_groups)

    if overlap:
        raise AssertionError(
            f"Group leakage detected! {len(overlap)} groups present in both train and test splits. Examples: {list(overlap)[:5]}"
        )
