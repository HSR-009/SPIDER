"""Leakage-safe package-group splitting utilities."""
import re
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

def normalize_package_name(name):
    return re.sub(r"[-_.]+", "-", str(name or "").strip().lower())

def split_dataset_by_package(
    df: pd.DataFrame,
    group_col: str = "package_name",
    target_col: str = "label",
    test_size: float = 0.2,
    random_state: int = 42,
):
    if group_col not in df or target_col not in df:
        raise ValueError(f"Required columns missing: {group_col!r} and/or {target_col!r}")
    work = df.copy()
    groups = work[group_col].map(normalize_package_name)
    if groups.eq("").any():
        raise ValueError("Empty package name found; cannot perform grouped split.")
    label_counts = work.assign(_group=groups).groupby("_group")[target_col].nunique()
    inconsistent = label_counts[label_counts > 1]
    if not inconsistent.empty:
        raise ValueError(f"Package groups have inconsistent labels: {inconsistent.index.tolist()[:10]}")
    for seed in range(random_state, random_state + 200):
        splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
        train_idx, test_idx = next(splitter.split(work, y=work[target_col], groups=groups))
        train_df, test_df = work.iloc[train_idx].copy(), work.iloc[test_idx].copy()
        if train_df[target_col].nunique() == 2 and test_df[target_col].nunique() == 2:
            train_groups = set(groups.iloc[train_idx])
            test_groups = set(groups.iloc[test_idx])
            if train_groups.isdisjoint(test_groups):
                return train_df, test_df
    raise ValueError("Could not create train/test groups containing both classes. Check package-level class counts.")
