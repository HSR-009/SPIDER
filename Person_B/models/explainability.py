"""SHAP explainability for the trained SPIDER baseline models."""
from pathlib import Path
import joblib
import pandas as pd
import shap
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data" / "processed" / "feature_table.csv"
HOLDOUT = ROOT / "results" / "frozen_holdout_packages.csv"
MODEL = ROOT / "Person_B" / "models" / "saved" / "xgboost_behavior_without_size.joblib"
OUT = ROOT / "Person_B" / "models" / "saved"

def load_holdout_artifacts(model_path=MODEL):
    for path in (DATA, HOLDOUT, model_path):
        if not path.exists():
            raise FileNotFoundError(f"Required artifact missing: {path}")
    model = joblib.load(model_path)
    frame = pd.read_csv(DATA)
    holdout_ids = set(pd.read_csv(HOLDOUT)["package_id"].astype(str))
    test = frame[frame["package_id"].astype(str).isin(holdout_ids)].copy()
    columns = list(getattr(model, "feature_names_in_", []))
    if not columns:
        raise ValueError("Model does not expose feature_names_in_; retrain using baseline_model.py.")
    X = test[columns].astype(float).replace([float("inf"), float("-inf")], 0).fillna(0)
    return model, X, test

def generate_shap_summary(model, X, output_dir=OUT):
    output_dir.mkdir(parents=True, exist_ok=True)
    explainer = shap.TreeExplainer(model)
    values = explainer.shap_values(X)
    if isinstance(values, list):
        values = values[1]
    shap.summary_plot(values, X, show=False, max_display=20)
    path = output_dir / "shap_summary_plot.png"
    plt.tight_layout()
    plt.savefig(path, dpi=250, bbox_inches="tight")
    plt.close()
    return explainer, path

def explain_single_package(explainer, model, feature_vector):
    probability = float(model.predict_proba(feature_vector)[0, 1])
    values = explainer.shap_values(feature_vector)
    if isinstance(values, list):
        values = values[1]
    values = values[0] if getattr(values, "ndim", 1) == 2 else values
    impacts = [
        {"feature": name, "value": float(value), "shap_impact": float(impact)}
        for name, value, impact in zip(feature_vector.columns, feature_vector.iloc[0], values)
    ]
    impacts.sort(key=lambda item: abs(item["shap_impact"]), reverse=True)
    return {"malicious_probability": probability, "top_contributing_factors": impacts[:5]}

if __name__ == "__main__":
    model, X, frame = load_holdout_artifacts()
    explainer, path = generate_shap_summary(model, X)
    print(f"SHAP summary saved: {path}")
    if not X.empty:
        result = explain_single_package(explainer, model, X.iloc[[0]])
        print({"package_id": frame.iloc[0]["package_id"], **result})
