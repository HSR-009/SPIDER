import os
import sys
from pathlib import Path
import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap

# Ensure root folder (SPIDER) is available in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from Person_B.models.baseline_model import FEATURE_COLS


def load_artifacts(
    model_path: str = "Person_B/models/saved/xgboost_baseline.joblib",
    data_path: str = "data/processed/feature_table.csv",
):
    """Loads trained model and test feature samples."""
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model weight not found at {model_path}")
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Data table not found at {data_path}")

    model = joblib.load(model_path)
    df = pd.read_csv(data_path)
    X = df[FEATURE_COLS].astype(float)

    return model, X, df


def generate_shap_summary(
    model, X: pd.DataFrame, output_dir: str = "Person_B/models/saved"
):
    """Generates and saves global SHAP feature importance plots."""
    os.makedirs(output_dir, exist_ok=True)

    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X)

    # In binary XGBoost, shap_values is a 2D array (n_samples, n_features)
    if isinstance(shap_values, list):
        shap_vals_matrix = shap_values[1]
    else:
        shap_vals_matrix = shap_values

    plt.figure(figsize=(10, 6))
    shap.summary_plot(shap_vals_matrix, X, show=False)

    summary_plot_path = os.path.join(output_dir, "shap_summary_plot.png")
    plt.tight_layout()
    plt.savefig(summary_plot_path, dpi=300, bbox_inches="tight")
    plt.close()

    print(f"[+] Global SHAP summary plot saved to: {summary_plot_path}")
    return explainer


def explain_single_package(explainer, model, feature_vector: pd.DataFrame):
    """Computes a clean dictionary breakdown of top contributing risk factors

    for a single package (ready for Person C's dashboard).
    """
    prediction_prob = model.predict_proba(feature_vector)[0][1]
    shap_vals = explainer.shap_values(feature_vector)

    if isinstance(shap_vals, list):
        sample_shap = shap_vals[1][0]
    elif len(shap_vals.shape) == 2:
        sample_shap = shap_vals[0]
    else:
        sample_shap = shap_vals

    feature_impacts = []
    for col, val, impact in zip(
        feature_vector.columns, feature_vector.iloc[0], sample_shap
    ):
        feature_impacts.append(
            {
                "feature": col,
                "value": round(float(val), 4),
                "shap_impact": round(float(impact), 4),
            }
        )

    # Sort by absolute SHAP impact (most influential features first)
    feature_impacts.sort(key=lambda x: abs(x["shap_impact"]), reverse=True)

    return {
        "malicious_probability": round(float(prediction_prob), 4),
        "top_contributing_factors": feature_impacts[:5],
    }


if __name__ == "__main__":
    print("[*] Initializing Explainability Engine...")
    model, X, raw_df = load_artifacts()

    # 1. Global attribution summary
    explainer = generate_shap_summary(model, X)

    # 2. Local attribution check on a sample package
    sample_row = X.iloc[[0]]
    package_name = raw_df.iloc[0].get("package_name", "sample_pkg")
    explanation = explain_single_package(explainer, model, sample_row)

    print(f"\n--- SHAP Attribution for Package: '{package_name}' ---")
    print(f"Predicted Malicious Probability: {explanation['malicious_probability'] * 100:.2f}%")
    print("Top Influential Features:")
    for item in explanation["top_contributing_factors"]:
        sign = "+" if item["shap_impact"] > 0 else "-"
        print(f"  [{sign}] {item['feature']} (Value: {item['value']}) -> Impact: {item['shap_impact']}")