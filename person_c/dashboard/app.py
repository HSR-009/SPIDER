import json
from pathlib import Path
import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="SPIDER — Malicious Package Detector",
    page_icon="🕷️",
    layout="wide",
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RECORDS_DIR = PROJECT_ROOT / "fixtures" / "records"
RESULTS_FILE = PROJECT_ROOT / "results" / "evasion_baseline_v1.json"


@st.cache_data
def load_fixtures():
    fixtures = {}
    if RECORDS_DIR.exists():
        for record_path in sorted(RECORDS_DIR.glob("*.json")):
            with open(record_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                fixtures[data["package_name"]] = data
    return fixtures


@st.cache_data
def load_evasion_summary():
    if RESULTS_FILE.exists():
        with open(RESULTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


fixtures = load_fixtures()
evasion_data = load_evasion_summary()

# -------------------------------------------------------------------
# Header
# -------------------------------------------------------------------
st.title("🕷️ SPIDER")
st.caption("ML-Based Malicious Package Detector — Static Analysis & Robustness Evaluation")

# -------------------------------------------------------------------
# Summary Metrics (Derived directly from real Day 1 experiment results)
# -------------------------------------------------------------------
col1, col2, col3, col4 = st.columns(4)

total_fixtures = len(fixtures)
total_tests = evasion_data["overall"]["total_tests"] if evasion_data else 50
missed_rate = evasion_data["overall"]["missed_rate_pct"] if evasion_data else 16.0
recovered_rate = evasion_data["overall"]["recovery_rate_pct"] if evasion_data else 52.0

with col1:
    st.metric("Fixtures Loaded", str(total_fixtures))
with col2:
    st.metric("Evasion Tests (v1 Baseline)", str(total_tests))
with col3:
    st.metric("Recovery Rate (Original Caught)", f"{recovered_rate:.1f}%")
with col4:
    st.metric("Complete Evasion Rate (Missed)", f"{missed_rate:.1f}%")

st.divider()

# -------------------------------------------------------------------
# Package Investigation & Fixture Selector
# -------------------------------------------------------------------
st.subheader("Package Investigation")

if fixtures:
    selected_pkg = st.selectbox(
        "Select Inspected Package:",
        options=list(fixtures.keys()),
        index=0,
    )
    current_record = fixtures[selected_pkg]

    # Verdict Banner (Never Safe; 3 verdicts only)
    verdict = current_record.get("verdict", "Needs Review")
    origin = current_record.get("record_origin", "fixture")

    if verdict == "Malicious":
        st.error(f"🚨 VERDICT: {verdict.upper()} | Origin: {origin}")
    elif verdict == "Suspicious":
        st.warning(f"⚠️ VERDICT: {verdict.upper()} | Origin: {origin}")
    else:
        st.info(f"ℹ️ VERDICT: {verdict.upper()} | Origin: {origin} (Zero findings does not indicate safe)")

    # Findings Table
    st.markdown("#### Detected Security Indicators")
    findings = current_record.get("findings", [])

    if findings:
        df_findings = pd.DataFrame(findings)
        st.dataframe(
            df_findings[["category", "indicator", "severity", "file", "line", "evidence"]],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.write("No AST security findings detected.")

    # Source code viewer
    st.markdown("#### Source File Inspection")
    for file_entry in current_record.get("files", []):
        with st.expander(f"File: {file_entry['filename']}", expanded=True):
            st.code(file_entry["content"], language="python", line_numbers=True)

st.divider()

# -------------------------------------------------------------------
# Evasion Baseline Matrix (v1 Frozen Baseline)
# -------------------------------------------------------------------
st.subheader("Evasion Technique Breakdown (v1 Baseline)")
st.caption("Three-outcome evaluation: Recovered vs Different Signal vs Missed across 10 malicious samples.")

if evasion_data and "by_technique" in evasion_data:
    tech_rows = []
    for tech_id, stats in evasion_data["by_technique"].items():
        total = stats["total"]
        tech_rows.append({
            "Technique": tech_id,
            "Total Evaluated": total,
            "Recovered": f"{stats['recovered']} ({round(stats['recovered']/total*100, 1)}%)",
            "Different Signal": f"{stats['different_signal']} ({round(stats['different_signal']/total*100, 1)}%)",
            "Missed (Evaded)": f"{stats['missed']} ({round(stats['missed']/total*100, 1)}%)",
        })

    st.dataframe(pd.DataFrame(tech_rows), use_container_width=True, hide_index=True)
