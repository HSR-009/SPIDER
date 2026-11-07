"""PDF-aligned baseline: grouped CV, frozen holdout, leakage guards and reports."""
import json
import sys
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Person_B.models.splitting import assert_no_leakage, grouped_cv_splits, make_frozen_holdout

RESULTS_DIR = ROOT / "results"
MODEL_DIR = ROOT / "Person_B" / "models" / "saved"
DATA_PATH = ROOT / "data" / "processed" / "feature_table.csv"
METADATA_COLUMNS = {"package_id", "package_name", "group_id", "version", "analyzer_version", "label"}
DIAGNOSTIC_COLUMNS = {"n_findings", "parse_error_count", "failed_static_analysis"}
SIZE_COLUMN = "n_py_files"


def get_feature_sets(df):
    excluded = METADATA_COLUMNS | DIAGNOSTIC_COLUMNS
    behavior = [c for c in df.columns if c not in excluded and c != SIZE_COLUMN]
    if not behavior:
        raise ValueError("No behavior features found.")
    if SIZE_COLUMN not in df:
        raise ValueError("n_py_files is required for size ablation.")
    return {
        "behavior_without_size": behavior,
        "behavior_with_size": behavior + [SIZE_COLUMN],
        "size_only": [SIZE_COLUMN],
    }


def make_models(y):
    positives, negatives = int((y == 1).sum()), int((y == 0).sum())
    scale = negatives / positives if positives else 1.0
    return {
        "random_forest": RandomForestClassifier(
            n_estimators=300,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        ),
        "xgboost": XGBClassifier(
            n_estimators=200,
            max_depth=4,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=scale,
            eval_metric="logloss",
            random_state=42,
            n_jobs=4,
        ),
    }


def score_predictions(y_true, probabilities, threshold=0.5):
    y_true = np.asarray(y_true, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    predicted = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predicted, labels=[0, 1]).ravel()
    return {
        "threshold": threshold,
        "accuracy": float(accuracy_score(y_true, predicted)),
        "precision": float(precision_score(y_true, predicted, zero_division=0)),
        "recall": float(recall_score(y_true, predicted, zero_division=0)),
        "f1": float(f1_score(y_true, predicted, zero_division=0)),
        "pr_auc": float(average_precision_score(y_true, probabilities)),
        "roc_auc": float(roc_auc_score(y_true, probabilities)),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "fpr": float(fp / (fp + tn)) if fp + tn else 0.0,
    }


def fit_checked(model, X, y):
    assert_no_leakage(list(X.columns))
    if X.columns.duplicated().any():
        raise ValueError("Duplicate feature columns.")
    model.fit(X.astype(float).replace([np.inf, -np.inf], 0).fillna(0), y.astype(int))
    return model


def run_baseline(version="v1.1"):
    """Run baseline evaluation. Defaults to v1.1. Never overwrites v1 baseline or frozen holdout."""
    if version == "v1.1":
        from Person_B.evaluation.baseline_v11 import run_baseline_v11
        return run_baseline_v11()
    elif version == "v1":
        # Check if v1 baseline already exists; do not silently overwrite
        v1_path = RESULTS_DIR / "baseline_v1.json"
        if v1_path.exists():
            print("baseline_v1.json already exists; preserving existing v1 baseline.")
            return json.loads(v1_path.read_text(encoding="utf-8"))
        raise RuntimeError("v1 baseline generation requested but preserved files must not be recreated.")
    else:
        raise ValueError(f"Unknown baseline version: {version}")


if __name__ == "__main__":
    run_baseline(version="v1.1")
