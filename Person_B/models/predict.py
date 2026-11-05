"""
SPIDER Day 3 — Prediction wrapper with calibration, abstention, and SHAP explanations.

Responsibilities:
1. Fit an isotonic-regression probability calibrator using OOF (out-of-fold) dev-set
   probabilities.  Holdout data is never used for calibration or threshold selection.
2. Select a confidence-based abstention threshold from OOF validation data only
   (maximises F1 on the samples that are *not* abstained, subject to abstention rate <= 20%).
3. Expose `predict_package()` returning one of three statuses:
       "ok"        — model is confident enough to emit a verdict
       "abstained" — model probability is in the low-confidence zone; no verdict emitted
       "error"     — feature extraction or model inference failed
4. Provide `top_feature_importances()` returning the global top-N importance scores.
5. Provide `explain_prediction()` returning per-instance SHAP values for the top-N features.

Design constraints (all enforced here):
- Calibration is fitted on dev OOF probabilities only.
- Abstention threshold is selected on dev OOF probabilities only.
- Holdout and Person C adversarial data are never used for fitting or threshold selection.
- No live PyPI calls; no package execution.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import shap
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import f1_score, roc_auc_score
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Person_B.models.splitting import assert_no_leakage, grouped_cv_splits

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DATA_PATH = ROOT / "data" / "processed" / "feature_table.csv"
HOLDOUT_PATH = ROOT / "results" / "frozen_holdout_packages.csv"
MODEL_DIR = ROOT / "Person_B" / "models" / "saved"
RESULTS_DIR = ROOT / "results"

# Primary model experiment (behaviour features only, no size leakage)
PRIMARY_EXPERIMENT = "behavior_without_size"
PRIMARY_MODEL = "random_forest"

METADATA_COLUMNS = {
    "package_id", "package_name", "group_id", "version",
    "analyzer_version", "label",
}
DIAGNOSTIC_COLUMNS = {"n_findings", "parse_error_count", "failed_static_analysis"}
SIZE_COLUMN = "n_py_files"

# Abstention budget: at most 20 % of predictions may be abstained.
MAX_ABSTENTION_RATE = 0.20
# Threshold search grid (symmetric around 0.5 means low/high confidence zones)
_THRESHOLD_GRID = np.linspace(0.05, 0.45, 41)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_behavior_features(df: pd.DataFrame) -> list[str]:
    excluded = METADATA_COLUMNS | DIAGNOSTIC_COLUMNS | {SIZE_COLUMN}
    cols = [c for c in df.columns if c not in excluded]
    if not cols:
        raise ValueError("No behaviour feature columns found in feature table.")
    return cols


def _safe_X(df: pd.DataFrame, features: list[str]) -> pd.DataFrame:
    return (
        df[features]
        .astype(float)
        .replace([np.inf, -np.inf], 0)
        .fillna(0)
    )


# ---------------------------------------------------------------------------
# Step 1 — Gather OOF probabilities on the development set
# ---------------------------------------------------------------------------

def _collect_oof_probabilities(
    dev: pd.DataFrame,
    features: list[str],
    n_splits: int = 5,
    random_state: int = 42,
) -> np.ndarray:
    """Return out-of-fold malicious probabilities (uncalibrated) for each dev row."""
    assert_no_leakage(features)
    y = dev["label"].astype(int)
    positives = int((y == 1).sum())
    negatives = int((y == 0).sum())
    scale = negatives / positives if positives else 1.0

    oof = np.zeros(len(dev), dtype=float)
    for train_idx, val_idx in grouped_cv_splits(dev, n_splits=n_splits, random_state=random_state):
        X_tr = _safe_X(dev.iloc[train_idx], features)
        y_tr = y.iloc[train_idx].values
        X_va = _safe_X(dev.iloc[val_idx], features)

        rf = RandomForestClassifier(
            n_estimators=300, min_samples_leaf=2,
            class_weight="balanced", random_state=random_state, n_jobs=-1,
        )
        rf.fit(X_tr, y_tr)
        oof[val_idx] = rf.predict_proba(X_va)[:, 1]

    return oof


# ---------------------------------------------------------------------------
# Step 2 — Fit isotonic calibrator from OOF probabilities
# ---------------------------------------------------------------------------

def _fit_calibrator(
    oof_probs: np.ndarray,
    y_true: np.ndarray,
) -> IsotonicRegression:
    """Fit isotonic regression on OOF raw probabilities → calibrated probabilities."""
    cal = IsotonicRegression(out_of_bounds="clip")
    cal.fit(oof_probs, y_true)
    return cal


# ---------------------------------------------------------------------------
# Step 3 — Select abstention threshold from OOF data only
# ---------------------------------------------------------------------------

def _select_abstention_threshold(
    oof_probs_cal: np.ndarray,
    y_true: np.ndarray,
    max_abstention_rate: float = MAX_ABSTENTION_RATE,
) -> tuple[float, dict[str, Any]]:
    """
    Choose the half-width δ of the abstention zone [0.5-δ, 0.5+δ].

    For each candidate δ, abstain when |p - 0.5| < δ.
    Among thresholds where abstention rate ≤ max_abstention_rate,
    pick the δ that maximises F1 on the non-abstained samples.

    Returns (best_delta, diagnostics_dict).
    """
    best_delta = 0.0
    best_f1 = 0.0
    best_diag: dict[str, Any] = {}

    candidates = []
    for delta in _THRESHOLD_GRID:
        mask_keep = np.abs(oof_probs_cal - 0.5) >= delta
        abstention_rate = float(1.0 - mask_keep.mean())
        if abstention_rate > max_abstention_rate:
            continue
        if mask_keep.sum() < 10:
            continue
        y_keep = y_true[mask_keep]
        p_keep = oof_probs_cal[mask_keep]
        preds_keep = (p_keep >= 0.5).astype(int)
        f1 = float(f1_score(y_keep, preds_keep, zero_division=0))
        candidates.append({
            "delta": float(delta),
            "abstention_rate": abstention_rate,
            "f1_on_kept": f1,
            "n_kept": int(mask_keep.sum()),
        })
        if f1 > best_f1:
            best_f1 = f1
            best_delta = float(delta)
            best_diag = candidates[-1].copy()

    # Fallback: never abstain if no candidate improved F1
    if not best_diag:
        best_delta = 0.0
        best_diag = {
            "delta": 0.0, "abstention_rate": 0.0,
            "f1_on_kept": float(f1_score(y_true, (oof_probs_cal >= 0.5).astype(int), zero_division=0)),
            "n_kept": int(len(y_true)),
        }

    return best_delta, {"best": best_diag, "all_candidates": candidates}


# ---------------------------------------------------------------------------
# Step 4 — Global feature importances (top-N)
# ---------------------------------------------------------------------------

def top_feature_importances(
    model: RandomForestClassifier | XGBClassifier,
    features: list[str],
    top_n: int = 20,
) -> list[dict[str, Any]]:
    """Return top-N global feature importance scores from the fitted model."""
    imp = getattr(model, "feature_importances_", None)
    if imp is None:
        raise ValueError("Model does not expose feature_importances_.")
    ranked = sorted(
        zip(features, imp.tolist()),
        key=lambda x: -x[1],
    )[:top_n]
    return [{"feature": name, "importance": round(score, 6)} for name, score in ranked]


# ---------------------------------------------------------------------------
# Step 5 — Per-instance SHAP explanation
# ---------------------------------------------------------------------------

def explain_prediction(
    explainer: shap.TreeExplainer,
    model: RandomForestClassifier | XGBClassifier,
    feature_vector: pd.DataFrame,
    top_n: int = 20,
) -> dict[str, Any]:
    """
    Return malicious probability and top-N SHAP impacts for one package.

    feature_vector must be a single-row DataFrame with feature columns.
    """
    probability = float(model.predict_proba(feature_vector)[0, 1])
    shap_vals = explainer.shap_values(feature_vector)
    # shap >= 0.46 returns ndarray of shape (n_samples, n_features, n_classes)
    # older versions return a list [neg_class_array, pos_class_array]
    if isinstance(shap_vals, list):
        # older shap: list of per-class arrays, each (n_samples, n_features)
        vals = shap_vals[1][0]  # positive class, first (only) sample
    elif hasattr(shap_vals, "ndim") and shap_vals.ndim == 3:
        # newer shap: (n_samples, n_features, n_classes) → take class-1, sample-0
        vals = shap_vals[0, :, 1]
    else:
        # 2D fallback: (n_samples, n_features)
        vals = shap_vals[0]
    impacts = [
        {"feature": name, "value": float(val), "shap_impact": float(impact)}
        for name, val, impact in zip(
            feature_vector.columns, feature_vector.iloc[0].tolist(), vals.tolist()
        )
    ]
    impacts.sort(key=lambda x: abs(x["shap_impact"]), reverse=True)
    return {
        "malicious_probability": probability,
        "top_shap_factors": impacts[:top_n],
    }


# ---------------------------------------------------------------------------
# Public prediction wrapper
# ---------------------------------------------------------------------------

class SPIDERPredictor:
    """
    Wraps the trained SPIDER model with:
    - Isotonic probability calibration (dev OOF fitted)
    - Confidence-based abstention (threshold from dev OOF)
    - SHAP explanations (lazy-initialised)

    Status semantics:
      "ok"        — prediction is confident; verdict and probability are valid.
      "abstained" — raw probability is too close to the decision boundary.
      "error"     — an exception occurred during inference.
    """

    def __init__(
        self,
        model: RandomForestClassifier | XGBClassifier,
        features: list[str],
        calibrator: IsotonicRegression,
        abstention_delta: float,
        global_importances: list[dict[str, Any]],
    ) -> None:
        self.model = model
        self.features = features
        self.calibrator = calibrator
        self.abstention_delta = abstention_delta
        self.global_importances = global_importances
        self._explainer: shap.TreeExplainer | None = None

    @property
    def explainer(self) -> shap.TreeExplainer:
        if self._explainer is None:
            self._explainer = shap.TreeExplainer(self.model)
        return self._explainer

    def predict_package(
        self,
        feature_row: pd.DataFrame,
        explain: bool = False,
        top_n: int = 20,
    ) -> dict[str, Any]:
        """
        Score a single package given its feature row.

        Parameters
        ----------
        feature_row : single-row DataFrame with the model's feature columns.
        explain     : if True, include SHAP explanation in the result.
        top_n       : number of top SHAP factors to include.

        Returns
        -------
        dict with keys:
          status          : "ok" | "abstained" | "error"
          raw_probability : uncalibrated model output (float or None on error)
          calibrated_probability : isotonic-corrected probability (float or None)
          verdict         : "suspicious" | "none_detected_in_scan" | None (abstained/error)
          abstention_delta: the zone half-width used
          explanation     : dict with SHAP factors (only when explain=True and status="ok")
          error_message   : str (only when status="error")
        """
        try:
            X = _safe_X(feature_row, self.features)
            raw_prob = float(self.model.predict_proba(X)[0, 1])
            cal_prob = float(np.clip(self.calibrator.predict([raw_prob])[0], 0.0, 1.0))

            # Abstention check
            if abs(cal_prob - 0.5) < self.abstention_delta:
                result: dict[str, Any] = {
                    "status": "abstained",
                    "raw_probability": raw_prob,
                    "calibrated_probability": cal_prob,
                    "verdict": None,
                    "abstention_delta": self.abstention_delta,
                }
                return result

            verdict = "suspicious" if cal_prob >= 0.5 else "none_detected_in_scan"
            result = {
                "status": "ok",
                "raw_probability": raw_prob,
                "calibrated_probability": cal_prob,
                "verdict": verdict,
                "abstention_delta": self.abstention_delta,
            }
            if explain:
                result["explanation"] = explain_prediction(
                    self.explainer, self.model, X, top_n=top_n
                )
            return result

        except Exception as exc:  # noqa: BLE001
            return {
                "status": "error",
                "raw_probability": None,
                "calibrated_probability": None,
                "verdict": None,
                "abstention_delta": self.abstention_delta,
                "error_message": str(exc),
            }

    def to_dict(self) -> dict[str, Any]:
        """Serialisable summary of calibration and abstention settings."""
        return {
            "abstention_delta": self.abstention_delta,
            "abstention_zone": [
                round(0.5 - self.abstention_delta, 4),
                round(0.5 + self.abstention_delta, 4),
            ],
            "feature_count": len(self.features),
            "global_top20_importances": self.global_importances,
        }


# ---------------------------------------------------------------------------
# Factory — build SPIDERPredictor from stored artefacts + dev OOF calibration
# ---------------------------------------------------------------------------

def build_predictor(
    model_path: Path | None = None,
    n_splits: int = 5,
    random_state: int = 42,
    max_abstention_rate: float = MAX_ABSTENTION_RATE,
    verbose: bool = True,
) -> tuple[SPIDERPredictor, dict[str, Any]]:
    """
    Build and return a fully calibrated SPIDERPredictor.

    Uses dev-set OOF probabilities exclusively for calibration and
    threshold selection; the frozen holdout is never touched.

    Returns (predictor, calibration_report_dict).
    """
    # --- Load data ---
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Feature table missing: {DATA_PATH}")
    if not HOLDOUT_PATH.exists():
        raise FileNotFoundError(f"Frozen holdout missing: {HOLDOUT_PATH}")

    df = pd.read_csv(DATA_PATH)
    holdout_ids = set(pd.read_csv(HOLDOUT_PATH)["package_id"].astype(str))
    dev = df[~df["package_id"].astype(str).isin(holdout_ids)].copy().reset_index(drop=True)
    holdout = df[df["package_id"].astype(str).isin(holdout_ids)].copy()

    if verbose:
        print(f"[*] Dev rows: {len(dev)} | Holdout rows: {len(holdout)}")

    features = _get_behavior_features(df)
    assert_no_leakage(features)

    # --- Load saved model ---
    if model_path is None:
        model_path = MODEL_DIR / f"{PRIMARY_MODEL}_{PRIMARY_EXPERIMENT}.joblib"
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")
    model: RandomForestClassifier = joblib.load(model_path)
    if verbose:
        print(f"[*] Loaded model: {model_path.name} | features: {len(features)}")

    # --- OOF probabilities (dev only) ---
    if verbose:
        print("[*] Generating OOF probabilities on dev set (5-fold CV)...")
    oof_probs = _collect_oof_probabilities(dev, features, n_splits=n_splits, random_state=random_state)
    y_dev = dev["label"].astype(int).values

    oof_auc = float(roc_auc_score(y_dev, oof_probs))
    if verbose:
        print(f"[*] OOF ROC-AUC (uncalibrated): {oof_auc:.4f}")

    # --- Calibration ---
    if verbose:
        print("[*] Fitting isotonic calibrator on OOF probabilities...")
    calibrator = _fit_calibrator(oof_probs, y_dev)
    oof_probs_cal = np.clip(calibrator.predict(oof_probs), 0.0, 1.0)
    cal_auc = float(roc_auc_score(y_dev, oof_probs_cal))
    if verbose:
        print(f"[*] OOF ROC-AUC (calibrated):   {cal_auc:.4f}")

    # Brier score improvement check
    brier_raw = float(np.mean((oof_probs - y_dev) ** 2))
    brier_cal = float(np.mean((oof_probs_cal - y_dev) ** 2))
    if verbose:
        print(f"[*] Brier score — raw: {brier_raw:.4f} | calibrated: {brier_cal:.4f}")

    # --- Abstention threshold ---
    if verbose:
        print("[*] Selecting abstention threshold (dev OOF only)...")
    best_delta, threshold_diag = _select_abstention_threshold(
        oof_probs_cal, y_dev, max_abstention_rate=max_abstention_rate
    )
    if verbose:
        best = threshold_diag["best"]
        print(
            f"[*] Abstention delta={best_delta:.3f} | "
            f"abstention_rate={best['abstention_rate']:.2%} | "
            f"F1_kept={best['f1_on_kept']:.4f}"
        )

    # --- Global feature importances ---
    importances = top_feature_importances(model, features, top_n=20)

    # --- Build predictor ---
    predictor = SPIDERPredictor(
        model=model,
        features=features,
        calibrator=calibrator,
        abstention_delta=best_delta,
        global_importances=importances,
    )

    # --- Calibration report ---
    report: dict[str, Any] = {
        "experiment": PRIMARY_EXPERIMENT,
        "model": PRIMARY_MODEL,
        "feature_count": len(features),
        "dev_rows": int(len(dev)),
        "holdout_rows": int(len(holdout)),
        "calibration": {
            "method": "isotonic_regression_on_oof_probabilities",
            "cv_folds": n_splits,
            "oof_roc_auc_uncalibrated": round(oof_auc, 6),
            "oof_roc_auc_calibrated": round(cal_auc, 6),
            "brier_score_uncalibrated": round(brier_raw, 6),
            "brier_score_calibrated": round(brier_cal, 6),
        },
        "abstention": {
            "max_allowed_rate": max_abstention_rate,
            "selected_delta": round(best_delta, 4),
            "abstention_zone_low": round(0.5 - best_delta, 4),
            "abstention_zone_high": round(0.5 + best_delta, 4),
            **threshold_diag["best"],
            "threshold_search_candidates": threshold_diag["all_candidates"],
        },
        "global_top20_importances": importances,
        "leakage_note": (
            "Calibration and abstention threshold were fitted exclusively on "
            "development-set OOF probabilities. The frozen holdout (results/"
            "frozen_holdout_packages.csv) was not used for fitting, calibration, "
            "or threshold selection."
        ),
    }

    return predictor, report


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    predictor, report = build_predictor(verbose=True)

    out_path = RESULTS_DIR / "day3_calibration_report.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\n[+] Calibration report saved: {out_path}")

    # Quick smoke-test on a few holdout rows
    df = pd.read_csv(DATA_PATH)
    holdout_ids = set(pd.read_csv(HOLDOUT_PATH)["package_id"].astype(str))
    holdout = df[df["package_id"].astype(str).isin(holdout_ids)].copy()
    sample = holdout.head(5)

    print("\n--- Smoke-test on 5 holdout rows ---")
    for _, row in sample.iterrows():
        row_df = pd.DataFrame([row])
        result = predictor.predict_package(row_df, explain=False)
        cal_p = result["calibrated_probability"]
        cal_str = f"{cal_p:.3f}" if cal_p is not None else "N/A"
        print(
            f"  {str(row['package_id'])[:40]:<40} "
            f"label={int(row['label'])}  "
            f"status={result['status']:<10}  "
            f"cal_prob={cal_str}  "
            f"verdict={result['verdict']}"
        )

    # One row with SHAP explanation
    explain_row = pd.DataFrame([holdout.iloc[0]])
    explained = predictor.predict_package(explain_row, explain=True, top_n=20)
    print("\n--- SHAP explanation (first holdout row) ---")
    if explained["status"] == "ok":
        for factor in explained["explanation"]["top_shap_factors"][:5]:
            print(f"  {factor['feature']:<55} impact={factor['shap_impact']:+.4f}")
    else:
        print(f"  status={explained['status']}")

    print(f"\n[+] Abstention delta = {predictor.abstention_delta:.3f}")
    print(f"[+] Top-20 feature importances:")
    for item in predictor.global_importances[:5]:
        print(f"  {item['feature']:<55} {item['importance']:.6f}")

    print("\n[+] Day 3 SPIDERPredictor complete.")


if __name__ == "__main__":
    main()
