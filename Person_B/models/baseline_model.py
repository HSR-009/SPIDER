import os
import sys
from pathlib import Path
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from xgboost import XGBClassifier

# Ensure root folder (SPIDER) is available in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from Person_B.models.splitting import split_dataset_by_package

FEATURE_COLS = [
    "feat_total_calls",
    "feat_eval_ratio",
    "feat_exec_ratio",
    "feat_system_call_ratio",
    "feat_subprocess_ratio",
    "feat_max_entropy",
    "feat_avg_entropy",
    "feat_parse_failed",
    "feat_min_edit_distance",
    "feat_is_potential_squat",
    "feat_package_age_days",
    "feat_total_releases",
    "feat_pypi_exists"
]

def prepare_data(csv_path: str):
    """Loads CSV, verifies schema, converts types, and applies group splitting."""
    df = pd.read_csv(csv_path)

    missing = [col for col in FEATURE_COLS if col not in df.columns]
    if missing:
        raise ValueError(f"Missing expected feature columns in dataset: {missing}")

    # Ensure label is clean integer 0 and 1
    df["label"] = df["label"].astype(int)

    train_df, test_df = split_dataset_by_package(df, group_col="package_name", target_col="label")

    # Safety check: if split ended up with only 1 class in train, retry split with a different seed
    seed = 42
    while len(train_df["label"].unique()) < 2:
        seed += 1
        train_df, test_df = split_dataset_by_package(df, group_col="package_name", target_col="label", random_state=seed)

    X_train = train_df[FEATURE_COLS].astype(float)
    y_train = train_df["label"].astype(int)
    X_test = test_df[FEATURE_COLS].astype(float)
    y_test = test_df["label"].astype(int)

    return X_train, X_test, y_train, y_test

def train_and_evaluate(X_train, X_test, y_train, y_test, output_dir: str = "Person_B/models/saved"):
    """Trains Random Forest and XGBoost, evaluates metrics, and saves weights."""
    os.makedirs(output_dir, exist_ok=True)

    neg_count = int((y_train == 0).sum())
    pos_count = int((y_train == 1).sum())
    scale_pos_weight = float(neg_count / pos_count) if pos_count > 0 else 1.0

    models = {
        "RandomForest": RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced",
            random_state=42
        ),
        "XGBoost": XGBClassifier(
            n_estimators=100,
            scale_pos_weight=scale_pos_weight,
            eval_metric="logloss",
            random_state=42
        )
    }

    trained_models = {}

    for name, model in models.items():
        print(f"\n==================== Training {name} ====================")
        model.fit(X_train, y_train)
        preds = model.predict(X_test)
        
        print("\n--- Confusion Matrix ---")
        print(confusion_matrix(y_test, preds))

        print("\n--- Classification Report ---")
        print(classification_report(y_test, preds, zero_division=0))

        if len(set(y_test)) > 1:
            probs = model.predict_proba(X_test)[:, 1]
            auc = roc_auc_score(y_test, probs)
            print(f"ROC-AUC Score: {auc:.4f}")

        save_path = os.path.join(output_dir, f"{name.lower()}_baseline.joblib")
        joblib.dump(model, save_path)
        print(f"[+] Model saved to: {save_path}")

        trained_models[name] = model

    return trained_models

def generate_mock_dataset(csv_path: str):
    """Generates a balanced mock dataset with multiple packages and versions."""
    np.random.seed(42)
    packages = [f"pkg_{i}" for i in range(30)]
    records = []
    
    for i, pkg in enumerate(packages):
        # Guarantee a balanced spread: first 15 benign, remaining 15 malicious
        is_malicious = 1 if i >= 15 else 0
        for ver in ["1.0.0", "1.1.0"]:
            row = {
                "package_name": pkg,
                "package_version": ver,
                "feat_total_calls": int(np.random.randint(5, 500)),
                "feat_eval_ratio": float(np.random.uniform(0.1, 0.9) if is_malicious else 0.0),
                "feat_exec_ratio": float(np.random.uniform(0.1, 0.5) if is_malicious else 0.0),
                "feat_system_call_ratio": float(np.random.uniform(0.1, 0.8) if is_malicious else 0.0),
                "feat_subprocess_ratio": float(np.random.uniform(0.1, 0.5) if is_malicious else 0.0),
                "feat_max_entropy": float(np.random.uniform(3.5, 5.0) if is_malicious else np.random.uniform(1.5, 2.8)),
                "feat_avg_entropy": float(np.random.uniform(3.0, 4.5) if is_malicious else np.random.uniform(1.2, 2.5)),
                "feat_parse_failed": 0,
                "feat_min_edit_distance": int(np.random.choice([1, 2]) if is_malicious else np.random.choice([0, 5, 8])),
                "feat_is_potential_squat": int(1 if is_malicious else 0),
                "feat_package_age_days": int(np.random.randint(1, 10) if is_malicious else np.random.randint(100, 2000)),
                "feat_total_releases": int(np.random.randint(1, 3) if is_malicious else np.random.randint(5, 50)),
                "feat_pypi_exists": 1,
                "label": int(is_malicious)
            }
            records.append(row)

    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    pd.DataFrame(records).to_csv(csv_path, index=False)
    print(f"[+] Balanced dataset created at {csv_path}")

if __name__ == "__main__":
    csv_file = "data/processed/feature_table.csv"

    # Regenerate the table with guaranteed class diversity
    generate_mock_dataset(csv_file)

    X_tr, X_te, y_tr, y_te = prepare_data(csv_file)
    train_and_evaluate(X_tr, X_te, y_tr, y_te)