import streamlit as st
import pandas as pd


st.set_page_config(
    page_title="SPIDER — Malicious Package Detector",
    page_icon="🕷️",
    layout="wide",
)


# -------------------------------------------------------------------
# Placeholder data — will be replaced by real analyzer/model output.
# -------------------------------------------------------------------

findings_data = [
    {
        "file": "system_command.py",
        "category": "Command Execution",
        "indicator": "os.system",
        "severity": "HIGH",
    },
    {
        "file": "subprocess_call.py",
        "category": "Command Execution",
        "indicator": "subprocess.run",
        "severity": "HIGH",
    },
    {
        "file": "encoded_exec.py",
        "category": "Obfuscation",
        "indicator": "base64.b64decode",
        "severity": "MEDIUM",
    },
    {
        "file": "encoded_exec.py",
        "category": "Dynamic Code Execution",
        "indicator": "exec",
        "severity": "HIGH",
    },
]

evasion_data = [
    {
        "file": "system_command.py",
        "technique": "getattr",
        "result": "EVASION SUCCESS",
    },
    {
        "file": "subprocess_call.py",
        "technique": "getattr",
        "result": "EVASION SUCCESS",
    },
    {
        "file": "encoded_exec.py",
        "technique": "getattr",
        "result": "EVASION SUCCESS",
    },
]


# -------------------------------------------------------------------
# Header
# -------------------------------------------------------------------

st.title("🕷️ SPIDER")
st.caption("ML-Based Malicious Package Detector")
st.markdown(
    "Static analysis dashboard for detection, evasion testing, "
    "and robustness evaluation."
)


# -------------------------------------------------------------------
# Summary metrics
# -------------------------------------------------------------------

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Files Analyzed", "3")

with col2:
    st.metric("Findings", "4")

with col3:
    st.metric("Evasion Tests", "13")

with col4:
    st.metric("Evasion Success Rate", "23.08%")


st.divider()


# -------------------------------------------------------------------
# Detection findings
# -------------------------------------------------------------------

st.subheader("Detection Findings")

findings_df = pd.DataFrame(findings_data)

st.dataframe(
    findings_df,
    width="stretch",
    hide_index=True,
)


# -------------------------------------------------------------------
# Evasion experiment
# -------------------------------------------------------------------

st.subheader("Evasion Experiment")

evasion_df = pd.DataFrame(evasion_data)

st.dataframe(
    evasion_df,
    width="stretch",
    hide_index=True,
)


# -------------------------------------------------------------------
# Sidebar
# -------------------------------------------------------------------

st.sidebar.title("SPIDER Controls")

st.sidebar.selectbox(
    "Analysis Mode",
    [
        "Static Analysis",
        "Evasion Analysis",
        "Robustness Evaluation",
    ],
)

st.sidebar.info(
    "Dashboard currently uses placeholder data. "
    "Real analyzer and ML outputs will be connected later."
)
