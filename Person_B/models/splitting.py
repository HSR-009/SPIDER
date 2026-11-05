"""Grouped holdout and cross-validation helpers for SPIDER."""
import re
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

LEAKAGE_COLUMNS = {
    "label", "package_id", "package_name", "group_id", "version",
    "source", "malicious_evidence", "in_index", "index_annotated",
    "analyzer_version", "collection_date", "parse_error_count",
    "failed_static_analysis", "n_findings",
}

def assert_no_leakage(feature_columns):
    forbidden = sorted(set(feature_columns) & LEAKAGE_COLUMNS)
    if forbidden:
        raise ValueError(f"Leakage guard blocked model fit; forbidden columns: {forbidden}")

def make_frozen_holdout(df, group_col="group_id", target_col="label", n_splits=5, random_state=42):
    if group_col not in df or target_col not in df:
        raise ValueError(f"Missing required split columns: {group_col}, {target_col}")
    groups = df[group_col].astype(str)
    y = df[target_col].astype(int)
    if groups.eq("").any():
        raise ValueError("Empty group_id is not allowed.")
    if df.assign(_g=groups).groupby("_g")[target_col].nunique().gt(1).any():
        raise ValueError("A group_id has multiple labels.")
    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    for train_idx, hold_idx in splitter.split(df, y, groups):
        y_train, y_hold = y.iloc[train_idx], y.iloc[hold_idx]
        if y_train.nunique() == 2 and y_hold.nunique() == 2:
            train, hold = df.iloc[train_idx].copy(), df.iloc[hold_idx].copy()
            if set(train[group_col]).isdisjoint(set(hold[group_col])):
                return train, hold
    raise ValueError("Could not form a two-class grouped frozen holdout.")

def grouped_cv_splits(df, group_col="group_id", target_col="label", n_splits=5, random_state=42):
    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    groups = df[group_col].astype(str)
    y = df[target_col].astype(int)
    for train_idx, valid_idx in splitter.split(df, y, groups):
        if set(groups.iloc[train_idx]).intersection(set(groups.iloc[valid_idx])):
            raise AssertionError("Group leakage detected in CV split.")
        yield train_idx, valid_idx
