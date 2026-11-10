"""Streamlit page component for SPIDER Model Observatory & Adversarial Resilience.

Provides interactive evaluation dashboards for:
1. Three-way adversarial resilience evaluation (Baseline v1, Normalized, Hardened v1.1).
2. Engine verdict vs finding-level evasion separation.
3. Per-technique adversarial breakdown (T01-T09).
4. Machine Learning model metrics (CV, frozen holdout, confusion matrices).
5. Size confound analysis & peer-group stratification.
6. Honest defense limitations and research boundaries.

Design Guard:
Streamlit is imported ONLY inside render(st).
Test: python -c "import spider.ui.observatory_page" passes without streamlit installed.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = ROOT / "results"


def load_resilience_table() -> Optional[Dict[str, Any]]:
    """Safely load adversarial resilience table JSON."""
    res_path = RESULTS_DIR / "resilience_table.json"
    if not res_path.exists():
        return None
    try:
        return json.loads(res_path.read_text(encoding="utf-8"))
    except Exception:
        return None


def load_baseline_metrics() -> Optional[Dict[str, Any]]:
    """Safely load v1.1 baseline training and holdout metrics."""
    base_path = RESULTS_DIR / "baseline_v11.json"
    if not base_path.exists():
        return None
    try:
        return json.loads(base_path.read_text(encoding="utf-8"))
    except Exception:
        return None


def load_peer_context() -> Optional[Dict[str, Any]]:
    """Safely load package-size peer context statistics."""
    peer_path = RESULTS_DIR / "peer_context.json"
    if not peer_path.exists():
        return None
    try:
        return json.loads(peer_path.read_text(encoding="utf-8"))
    except Exception:
        return None


def render(st: Any = None) -> None:
    """Render the SPIDER Model Observatory tab.

    Import streamlit inside render so that headless imports and unit tests do not require streamlit.
    """
    if st is None:
        import streamlit as st  # type: ignore

    st.title("🔬 SPIDER — Model Observatory & Resilience Dashboard")
    st.caption("Person B Machine Learning & Security Resilience Evaluation — Days 4–6")

    # Load evaluation artifacts
    resilience_data = load_resilience_table()
    baseline_data = load_baseline_metrics()
    peer_data = load_peer_context()

    tabs = st.tabs([
        "🛡️ Adversarial Resilience (Day 5)",
        "📊 ML Model Performance (Day 4)",
        "⚖️ Size Confound & Peer Context",
        "⚠️ Honest Defense Limitations",
    ])

    # ------------------------------------------------------------------
    # TAB 1: Adversarial Resilience (Day 5)
    # ------------------------------------------------------------------
    with tabs[0]:
        st.subheader("1. Three-Way Adversarial Resilience Comparison")
        st.markdown(
            "Evaluation across the frozen **`adv-batch-v1`** release (12 samples, hash: `bb7f4fe8676...`). "
            "Evaluates whether AST indicators fire when evasion techniques (string splitting, aliasing, encoding, delay) are applied."
        )

        if not resilience_data:
            st.warning("`results/resilience_table.json` not found. Run `python Person_B/evaluation/resilience_eval.py` to generate.")
        else:
            summary = resilience_data.get("summary", {})
            findings = summary.get("finding_level_counts", {})
            verdicts = summary.get("engine_verdicts", {})
            ml_summary = summary.get("ml_model_detections", {})

            # KPI Highlights
            kpi_cols = st.columns(4)
            with kpi_cols[0]:
                base_evasion = findings.get("baseline_v1", {}).get("finding_level_evasion_rate_pct", 0)
                st.metric("AST v1 Evasion Rate", f"{base_evasion}%", delta=f"{findings.get('baseline_v1', {}).get('missed', 0)}/12 missed", delta_color="inverse")
            with kpi_cols[1]:
                norm_evasion = findings.get("normalized_v1", {}).get("finding_level_evasion_rate_pct", 0)
                st.metric("v1 + Normalization Evasion", f"{norm_evasion}%", delta=f"{findings.get('normalized_v1', {}).get('missed', 0)}/12 missed", delta_color="inverse")
            with kpi_cols[2]:
                hard_evasion = findings.get("hardened_v11", {}).get("finding_level_evasion_rate_pct", 0)
                st.metric("Hardened v1.1 Evasion", f"{hard_evasion}%", delta="0/12 missed (all emit signals)")
            with kpi_cols[3]:
                rf_det = ml_summary.get("hardened_v11", {}).get("rf_detection_rate_pct", 0)
                st.metric("ML Model (RF) Detection", f"{rf_det}%", delta=f"{ml_summary.get('hardened_v11', {}).get('rf_positive_count', 0)}/12 captured")
                st.caption("Reported / Experimental — Person B results; not independently verified by Person A.")

            st.markdown("### Overall Finding-Level Comparison Table")
            st.caption("⚠️ **Notice:** Normalization pipelines (B, D) and ML model detection rates are: *Reported / Experimental — Person B results; not independently verified by Person A.*")
            comparison_rows = [
                {
                    "Pipeline": "A. Baseline (AST v1)",
                    "Recovered (Exact)": findings.get("baseline_v1", {}).get("recovered", 0),
                    "Different Signal": findings.get("baseline_v1", {}).get("different_signal", 0),
                    "Missed (Evaded)": findings.get("baseline_v1", {}).get("missed", 0),
                    "Finding Evasion Rate": f"{findings.get('baseline_v1', {}).get('finding_level_evasion_rate_pct', 0)}%",
                    "RF Det (P≥0.5) [Reported]": f"{ml_summary.get('baseline_v1', {}).get('rf_positive_count', 0)}/12",
                    "XGB Det (P≥0.5) [Reported]": f"{ml_summary.get('baseline_v1', {}).get('xgb_positive_count', 0)}/12",
                },
                {
                    "Pipeline": "B. Normalized (v1 + Normalize) [Reported]",
                    "Recovered (Exact)": findings.get("normalized_v1", {}).get("recovered", 0),
                    "Different Signal": findings.get("normalized_v1", {}).get("different_signal", 0),
                    "Missed (Evaded)": findings.get("normalized_v1", {}).get("missed", 0),
                    "Finding Evasion Rate": f"{findings.get('normalized_v1', {}).get('finding_level_evasion_rate_pct', 0)}%",
                    "RF Det (P≥0.5) [Reported]": f"{ml_summary.get('normalized_v1', {}).get('rf_positive_count', 0)}/12",
                    "XGB Det (P≥0.5) [Reported]": f"{ml_summary.get('normalized_v1', {}).get('xgb_positive_count', 0)}/12",
                },
                {
                    "Pipeline": "C. Hardened (AST v1.1)",
                    "Recovered (Exact)": findings.get("hardened_v11", {}).get("recovered", 0),
                    "Different Signal": findings.get("hardened_v11", {}).get("different_signal", 0),
                    "Missed (Evaded)": findings.get("hardened_v11", {}).get("missed", 0),
                    "Finding Evasion Rate": f"{findings.get('hardened_v11', {}).get('finding_level_evasion_rate_pct', 0)}%",
                    "RF Det (P≥0.5) [Reported]": f"{ml_summary.get('hardened_v11', {}).get('rf_positive_count', 0)}/12",
                    "XGB Det (P≥0.5) [Reported]": f"{ml_summary.get('hardened_v11', {}).get('xgb_positive_count', 0)}/12",
                },
                {
                    "Pipeline": "D. Hardened + Normalized [Reported]",
                    "Recovered (Exact)": findings.get("hardened_v11_normalized", {}).get("recovered", 0),
                    "Different Signal": findings.get("hardened_v11_normalized", {}).get("different_signal", 0),
                    "Missed (Evaded)": findings.get("hardened_v11_normalized", {}).get("missed", 0),
                    "Finding Evasion Rate": f"{findings.get('hardened_v11_normalized', {}).get('finding_level_evasion_rate_pct', 0)}%",
                    "RF Det (P≥0.5) [Reported]": f"{ml_summary.get('hardened_v11_normalized', {}).get('rf_positive_count', 0)}/12",
                    "XGB Det (P≥0.5) [Reported]": f"{ml_summary.get('hardened_v11_normalized', {}).get('xgb_positive_count', 0)}/12",
                },
            ]
            st.table(comparison_rows)

            # Finding-level vs Verdict distinction warning
            st.info(
                "ℹ️ **Finding-Level vs Package-Level Distinction:** "
                "Emitting a `different_signal` means an AST rule (e.g. `Obfuscation`) fired, but **does not guarantee a Suspicious package verdict**. "
                "See the Verdict breakdown below."
            )

            st.subheader("2. Hardened Engine Verdicts (v1.1 Verdict v2 Contract)")
            v_cols = st.columns(3)
            with v_cols[0]:
                st.metric("Suspicious Verdicts", f"{verdicts.get('hardened_v11', {}).get('suspicious_count', 0)} / 12", "adv_001 (Base64 exec)")
            with v_cols[1]:
                st.metric("Review-Kept", f"{verdicts.get('hardened_v11', {}).get('review_kept_count', 0)} / 12", "ROT13, Delay, Aliasing")
            with v_cols[2]:
                st.metric("Silent (Needs Review / Zero)", f"{verdicts.get('hardened_v11', {}).get('silent_count', 0)} / 12", "Evaded review triage")

            st.caption(
                f"**Review Recommendation Rate on Non-Suspicious Packages:** "
                f"`{verdicts.get('hardened_v11', {}).get('review_recommendation_rate_pct', 0)}%` (5 / 11 packages kept for human triage)."
            )

            st.subheader("3. Per-Technique Resilience Breakdown")
            by_tech = resilience_data.get("by_technique", {})
            tech_rows = []
            for t_name, t_info in by_tech.items():
                tech_rows.append({
                    "Technique": t_name,
                    "Samples": ", ".join(t_info.get("sample_ids", [])),
                    "Baseline v1": f"{t_info['baseline_v1']['recovered']} rec, {t_info['baseline_v1']['missed']} miss",
                    "Normalized v1": f"{t_info['normalized_v1']['recovered']} rec, {t_info['normalized_v1']['missed']} miss",
                    "Hardened v1.1": f"{t_info['hardened_v11']['recovered']} rec, {t_info['hardened_v11']['different_signal']} diff",
                })
            st.table(tech_rows)

    # ------------------------------------------------------------------
    # TAB 2: ML Model Performance (Day 4)
    # ------------------------------------------------------------------
    with tabs[1]:
        st.subheader("Machine Learning Baseline Performance (v1.1 Dataset)")
        st.markdown(
            "Evaluation protocol: **5-fold StratifiedGroupKFold on development set (N=3,957 packages, 2,119 groups)** "
            "and evaluation on the **frozen holdout set (N=991 packages, 582 benign / 409 malicious)**. "
            "Leakage guard: Grouped by package name (`group_id`); frozen holdout IDs strictly isolated."
        )

        if not baseline_data:
            st.warning("`results/baseline_v11.json` not found.")
        else:
            exps = baseline_data.get("experiments", {})
            model_choice = st.selectbox("Select Model Architecture:", ["Random Forest", "XGBoost"])
            model_key = "random_forest" if model_choice == "Random Forest" else "xgboost"

            exp_cols = st.columns(3)
            with exp_cols[0]:
                st.markdown("#### 1. Behavior Without Size")
                st.caption("54 behavioral AST indicators (no size confound)")
                b_info = exps.get("behavior_without_size", {}).get(model_key, {})
                b_cv = b_info.get("cv_5fold", {}).get("mean_std", {})
                b_ho = b_info.get("frozen_holdout", {}).get("metrics", {})
                st.write(f"- **CV ROC-AUC:** {b_cv.get('roc_auc', {}).get('mean', 0):.4f} ± {b_cv.get('roc_auc', {}).get('std', 0):.4f}")
                st.write(f"- **CV PR-AUC:** {b_cv.get('pr_auc', {}).get('mean', 0):.4f} ± {b_cv.get('pr_auc', {}).get('std', 0):.4f}")
                st.write(f"- **CV F1 Score:** {b_cv.get('f1', {}).get('mean', 0):.4f}")
                st.write(f"- **Holdout ROC-AUC:** {b_ho.get('roc_auc', 0):.4f}")
                st.write(f"- **Holdout PR-AUC:** {b_ho.get('pr_auc', 0):.4f}")
                st.write(f"- **Holdout FPR:** {b_ho.get('fpr', 0):.4f}")

            with exp_cols[1]:
                st.markdown("#### 2. Behavior With Size")
                st.caption("54 behavioral AST indicators + n_py_files")
                ws_info = exps.get("behavior_with_size", {}).get(model_key, {})
                ws_cv = ws_info.get("cv_5fold", {}).get("mean_std", {})
                ws_ho = ws_info.get("frozen_holdout", {}).get("metrics", {})
                st.write(f"- **CV ROC-AUC:** {ws_cv.get('roc_auc', {}).get('mean', 0):.4f} ± {ws_cv.get('roc_auc', {}).get('std', 0):.4f}")
                st.write(f"- **CV PR-AUC:** {ws_cv.get('pr_auc', {}).get('mean', 0):.4f} ± {ws_cv.get('pr_auc', {}).get('std', 0):.4f}")
                st.write(f"- **CV F1 Score:** {ws_cv.get('f1', {}).get('mean', 0):.4f}")
                st.write(f"- **Holdout ROC-AUC:** {ws_ho.get('roc_auc', 0):.4f}")
                st.write(f"- **Holdout PR-AUC:** {ws_ho.get('pr_auc', 0):.4f}")
                st.write(f"- **Holdout FPR:** {ws_ho.get('fpr', 0):.4f}")

            with exp_cols[2]:
                st.markdown("#### 3. Size Only (Ablation)")
                st.caption("Only n_py_files (benchmark baseline)")
                s_info = exps.get("size_only", {}).get(model_key, {})
                s_cv = s_info.get("cv_5fold", {}).get("mean_std", {})
                s_ho = s_info.get("frozen_holdout", {}).get("metrics", {})
                st.write(f"- **CV ROC-AUC:** {s_cv.get('roc_auc', {}).get('mean', 0):.4f} ± {s_cv.get('roc_auc', {}).get('std', 0):.4f}")
                st.write(f"- **CV PR-AUC:** {s_cv.get('pr_auc', {}).get('mean', 0):.4f} ± {s_cv.get('pr_auc', {}).get('std', 0):.4f}")
                st.write(f"- **CV F1 Score:** {s_cv.get('f1', {}).get('mean', 0):.4f}")
                st.write(f"- **Holdout ROC-AUC:** {s_ho.get('roc_auc', 0):.4f}")
                st.write(f"- **Holdout PR-AUC:** {s_ho.get('pr_auc', 0):.4f}")
                st.write(f"- **Holdout FPR:** {s_ho.get('fpr', 0):.4f}")

            st.markdown("### Frozen Holdout Confusion Matrix (`behavior_without_size`)")
            ho_cm = b_info.get("frozen_holdout", {}).get("confusion_counts", {})
            cm_col1, cm_col2 = st.columns(2)
            with cm_col1:
                st.table([
                    {"Ground Truth": "Actual Benign (N=582)", "Pred Benign (TN)": ho_cm.get("tn", 0), "Pred Malicious (FP)": ho_cm.get("fp", 0)},
                    {"Ground Truth": "Actual Malicious (N=409)", "Pred Benign (FN)": ho_cm.get("fn", 0), "Pred Malicious (TP)": ho_cm.get("tp", 0)},
                ])
            with cm_col2:
                st.markdown(
                    f"- **Holdout Precision:** `{b_ho.get('precision', 0):.4f}`\n"
                    f"- **Holdout Recall:** `{b_ho.get('recall', 0):.4f}`\n"
                    f"- **Holdout F1:** `{b_ho.get('f1', 0):.4f}`\n"
                    f"- **Holdout FPR:** `{b_ho.get('fpr', 0):.4f}`\n"
                    f"- **Holdout PR-AUC:** `{b_ho.get('pr_auc', 0):.4f}`"
                )

            # Feature Importance & SHAP Explainability
            st.markdown("### Feature Importance & SHAP Explainability")
            shap_plot_path = ROOT / "Person_B" / "models" / "saved" / "shap_summary_plot.png"
            if shap_plot_path.exists():
                st.image(str(shap_plot_path), caption="SHAP Summary Plot — Top Behavioral AST Features Driving Predictions")
            cal_path = RESULTS_DIR / "day3_calibration_report.json"
            if cal_path.exists():
                try:
                    cal_data = json.loads(cal_path.read_text(encoding="utf-8"))
                    top_importances = cal_data.get("global_top20_importances", [])
                    if top_importances:
                        st.markdown("#### Global Top-20 Feature Importances (Tree Ensemble)")
                        st.table([{"Rank": i + 1, "Feature": item["feature"], "Importance": f"{item['importance']:.6f}"} for i, item in enumerate(top_importances)])
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # TAB 3: Size Confound & Peer Context
    # ------------------------------------------------------------------
    with tabs[2]:
        st.subheader("Size Confound Analysis & Peer-Group Stratification")
        st.markdown(
            "> **The Size Confound Warning:** In the v1.1 rescan, the median analyzed `.py` file count was 12 for benign packages vs 2 for malicious packages (`results/rescan_v11_summary.md`). "
            "A naive model using file count learns an artificial shortcut linking small codebase size directly to malice. "
            "Person B separates size from behavior (`behavior_without_size`) to avoid relying on direct file counts, though residual correlation in counts and presence cannot be ruled out."
        )

        if peer_data:
            total_pkgs = peer_data.get("total_corpus_packages") or peer_data.get("total_packages", 0)
            st.markdown(f"**Dataset Provenance:** {peer_data.get('dataset_version', 'v1.1')} | Total Packages: {total_pkgs}")
            strata = peer_data.get("size_strata", [])
            bucket_rows = []
            if isinstance(strata, list):
                for s in strata:
                    bucket_rows.append({
                        "Strata Name": s.get("bucket_name", "strata"),
                        "Size Range": f"{s.get('min_py_files', 0)} - {s.get('max_py_files', 0)} files",
                        "Total Count": s.get("corpus_package_count", 0),
                        "Malicious Count": s.get("corpus_malicious_count", 0),
                        "Benign Count": s.get("corpus_benign_count", 0),
                        "Malicious Prevalence": f"{s.get('malicious_prevalence', 0) * 100:.1f}%",
                    })
            st.table(bucket_rows)
        else:
            st.info("Peer context data not available.")

    # ------------------------------------------------------------------
    # TAB 4: Honest Defense Limitations
    # ------------------------------------------------------------------
    with tabs[3]:
        st.subheader("⚠️ Honest Security Defense Limitations")
        st.markdown(
            """
            Static AST analysis and machine learning indicators have distinct strengths and inherent boundaries:

            ### 1. AST Normalization Limitations
            - **Prototype Scope:** The normalization adapter implements four specific AST rewrites (constant string fold, `import as` aliasing, base64 literals, and 2-arg `getattr`).
            - **Unhandled Evasions:**
              - Does not handle `from module import func as alias` aliasing.
              - Does not reverse ROT13 encodings (`codecs.decode(..., 'rot_13')`).
              - Does not resolve dynamic `__import__` dunder imports.
              - Does not reconstruct strings assembled via character joins (`"".join([chr(...)])`).
              - Does not resolve hex-encoded byte escapes (`bytes.fromhex(...)`).
              - Cannot detect execution delay counters statically without symbolic simulation.

            ### 2. Dual-Use Benign Indicators
            - Many benign packages legitimately invoke subprocesses, base64 decoders, or HTTP requests (e.g. for telemetry, installation checks, or API calls).
            - Static indicators cannot distinguish intent without execution provenance or peer context.

            ### 3. Verdict v2 Triage Contract
            - Static analysis in SPIDER **never marks an unflagged package as 'Safe'**.
            - Packages with zero AST findings are assigned `Needs Review` (triage recommended), acknowledging that evasive malware can slip past static rules.
            """
        )
