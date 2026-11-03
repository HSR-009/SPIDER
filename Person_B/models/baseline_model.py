"""Train leakage-safe RF/XGBoost baselines and feature ablations on real data."""
import json
from pathlib import Path
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)
from xgboost import XGBClassifier

BASE_DIR = Path(__file__).resolve().parents[2]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from Person_B.features.extract_features import BEHAVIOR_FEATURE_COLS, DIAGNOSTIC_FEATURE_COLS
from Person_B.models.splitting import split_dataset_by_package

SIZE_FEATURE_COLS = ["n_py_files", "n_findings"]
QUALITY_DIAGNOSTIC_COLS = ["parse_error_count", "failed_static_analysis"]
EXPERIMENTS = {
    "behavior_only": BEHAVIOR_FEATURE_COLS,
    "size_only": SIZE_FEATURE_COLS,
    "behavior_plus_size": BEHAVIOR_FEATURE_COLS + SIZE_FEATURE_COLS,
}

def make_models(y_train):
    positives = int((y_train == 1).sum())
    negatives = int((y_train == 0).sum())
    weight = negatives / positives if positives else 1.0
    return {
        "random_forest": RandomForestClassifier(
            n_estimators=300, min_samples_leaf=2, class_weight="balanced",
            random_state=42, n_jobs=-1,
        ),
        "xgboost": XGBClassifier(
            n_estimators=200, max_depth=4, learning_rate=0.05,
            subsample=0.8, colsample_bytree=0.8,
            scale_pos_weight=weight, eval_metric="logloss",
            random_state=42, n_jobs=4,
        ),
    }

def evaluate(model, X_test, y_test):
    pred = model.predict(X_test)
    prob = model.predict_proba(X_test)[:, 1]
    return {
        "accuracy": accuracy_score(y_test, pred),
        "precision": precision_score(y_test, pred, zero_division=0),
        "recall": recall_score(y_test, pred, zero_division=0),
        "f1": f1_score(y_test, pred, zero_division=0),
        "roc_auc": roc_auc_score(y_test, prob) if y_test.nunique() == 2 else float("nan"),
        "confusion_matrix": confusion_matrix(y_test, pred, labels=[0, 1]).tolist(),
        "classification_report": classification_report(y_test, pred, labels=[0, 1], target_names=["benign", "malicious"], zero_division=0, output_dict=True),
    }

def train_all():
    data_path = BASE_DIR / "data" / "processed" / "feature_table.csv"
    if not data_path.exists():
        raise FileNotFoundError(f"{data_path} not found. First run: python -m Person_B.features.build_feature_table")
    df = pd.read_csv(data_path)
    required = set(["package_name", "label"] + BEHAVIOR_FEATURE_COLS + SIZE_FEATURE_COLS)
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError(f"Feature table schema is outdated/missing columns: {missing}. Rebuild it first.")
    train_df, test_df = split_dataset_by_package(df, "normalized_package_name" if "normalized_package_name" in df.columns else "package_name")
    y_train = train_df["label"].astype(int)
    y_test = test_df["label"].astype(int)
    if y_train.nunique() != 2 or y_test.nunique() != 2:
        raise ValueError("Both train and test partitions must contain benign and malicious packages.")

    output_dir = BASE_DIR / "Person_B" / "models" / "saved"
    output_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for experiment, columns in EXPERIMENTS.items():
        X_train = train_df[columns].astype(float).replace([np.inf, -np.inf], 0).fillna(0)
        X_test = test_df[columns].astype(float).replace([np.inf, -np.inf], 0).fillna(0)
        for model_name, model in make_models(y_train).items():
            print(f"Training {model_name} | {experiment} ({len(columns)} features)")
            model.fit(X_train, y_train)
            metrics = evaluate(model, X_test, y_test)
            row = {"model": model_name, "experiment": experiment, **{k: v for k, v in metrics.items() if k not in ("confusion_matrix", "classification_report")}}
            results.append(row)
            joblib.dump(model, output_dir / f"{model_name}_{experiment}.joblib")
            with open(output_dir / f"{model_name}_{experiment}_details.json", "w", encoding="utf-8") as handle:
                json.dump(metrics, handle, indent=2)
            print(f"  precision={metrics['precision']:.3f} recall={metrics['recall']:.3f} f1={metrics['f1']:.3f} auc={metrics['roc_auc']:.3f}")
            print("  confusion matrix [benign, malicious]:", metrics["confusion_matrix"])

    pd.DataFrame(results).to_csv(output_dir / "baseline_metrics.csv", index=False)
    test_columns = ["package_name", "normalized_package_name", "label"]
    test_df[[c for c in test_columns if c in test_df.columns]].to_csv(output_dir / "heldout_test_packages.csv", index=False)
    print(f"Saved models, metrics and held-out package list under {output_dir}")
    print(f"Train rows: {len(train_df)} | Test rows: {len(test_df)}")
    print("Train class counts:", y_train.value_counts().sort_index().to_dict())
    print("Test class counts:", y_test.value_counts().sort_index().to_dict())

if __name__ == "__main__":
    train_all()
