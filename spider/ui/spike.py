import json
from pathlib import Path
import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="SPIDER — Security Investigation UI Spike",
    page_icon="🕷️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for Cybersecurity SOC Look
st.markdown(
    """
    <style>
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    .verdict-malicious {
        background: linear-gradient(90deg, rgba(239, 68, 68, 0.25) 0%, rgba(185, 28, 28, 0.1) 100%);
        border-left: 5px solid #ef4444;
        padding: 14px 20px;
        border-radius: 6px;
        margin-bottom: 20px;
    }
    .verdict-suspicious {
        background: linear-gradient(90deg, rgba(245, 158, 11, 0.25) 0%, rgba(180, 83, 9, 0.1) 100%);
        border-left: 5px solid #f59e0b;
        padding: 14px 20px;
        border-radius: 6px;
        margin-bottom: 20px;
    }
    .verdict-needs-review {
        background: linear-gradient(90deg, rgba(59, 130, 246, 0.25) 0%, rgba(29, 78, 216, 0.1) 100%);
        border-left: 5px solid #3b82f6;
        padding: 14px 20px;
        border-radius: 6px;
        margin-bottom: 20px;
    }
    .badge-origin {
        display: inline-block;
        padding: 3px 8px;
        font-size: 11px;
        font-weight: 600;
        border-radius: 4px;
        background-color: #1e293b;
        color: #94a3b8;
        border: 1px solid #334155;
        margin-left: 8px;
    }
    .badge-illustrative {
        display: inline-block;
        padding: 3px 8px;
        font-size: 11px;
        font-weight: 600;
        border-radius: 4px;
        background-color: #451a03;
        color: #f59e0b;
        border: 1px solid #78350f;
    }
    .code-line-highlight {
        background-color: rgba(239, 68, 68, 0.25);
        border-left: 3px solid #ef4444;
        display: block;
        padding: 2px 6px;
        font-family: monospace;
    }
    .code-line-normal {
        display: block;
        padding: 2px 6px;
        font-family: monospace;
        color: #cbd5e1;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RECORDS_DIR = PROJECT_ROOT / "person_c" / "fixtures" / "records"


@st.cache_data
def load_all_fixtures():
    fixtures = {}
    if not RECORDS_DIR.exists():
        return fixtures

    for json_file in sorted(RECORDS_DIR.glob("*.json")):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                fixtures[data["package_name"]] = data
        except Exception as e:
            st.error(f"Error loading fixture {json_file.name}: {e}")
    return fixtures


def render_verdict_banner(verdict: str, origin: str):
    css_class = "verdict-needs-review"
    icon = "ℹ️"
    if verdict == "Malicious":
        css_class = "verdict-malicious"
        icon = "🚨"
    elif verdict == "Suspicious":
        css_class = "verdict-suspicious"
        icon = "⚠️"

    st.markdown(
        f"""
        <div class="{css_class}">
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <div>
                    <span style="font-size: 20px; font-weight: bold;">{icon} VERDICT: {verdict.upper()}</span>
                    <span class="badge-origin">ORIGIN: {origin.upper()}</span>
                </div>
                <div>
                    <span style="font-size: 12px; color: #94a3b8;">STATIC AST EVALUATION (HONEST TRIAGE)</span>
                </div>
            </div>
            <div style="font-size: 13px; color: #cbd5e1; margin-top: 6px;">
                Note: In SPIDER, static analysis never assigns a "Safe" verdict. Zero findings indicates "Needs Review".
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_package_investigation():
    st.title("🕷️ SPIDER — Package Investigation Spike")
    st.caption("Day 6 Spike: AST Static Findings, Exact Code Span Inspection & Provenance")

    fixtures = load_all_fixtures()

    if not fixtures:
        st.error(f"No fixture records found in {RECORDS_DIR}. Run `person_c/make_fixtures.py` first.")
        return

    # Sidebar: Fixture Picker & Filters
    with st.sidebar:
        st.header("📦 Package Selector")
        selected_pkg = st.selectbox(
            "Select Target Package / Fixture:",
            options=list(fixtures.keys()),
            index=0,
        )

        fixture_data = fixtures[selected_pkg]

        st.divider()
        st.markdown("**Package Metadata**")
        st.markdown(f"**Version:** `{fixture_data.get('version', 'unknown')}`")
        st.markdown(f"**Origin:** `{fixture_data.get('record_origin', 'unknown')}`")

        # Illustrative Model Assessment
        model_info = fixture_data.get("model_assessment", {})
        st.markdown("**ML Risk Assessment:**")
        st.metric(
            label="Baseline Model Risk Score",
            value=f"{model_info.get('risk_score', 0.0):.2f}",
        )
        st.markdown('<span class="badge-illustrative">Illustrative Score</span>', unsafe_allow_html=True)
        st.caption("Score generated for UI spike demonstration prior to frozen baseline training.")

    # Top Section: Verdict Banner
    render_verdict_banner(
        verdict=fixture_data.get("verdict", "Needs Review"),
        origin=fixture_data.get("record_origin", "fixture"),
    )

    # Main Grid: Findings Table and Code Viewer
    col_left, col_right = st.columns([1, 1], gap="medium")

    findings = fixture_data.get("findings", [])
    files = fixture_data.get("files", [])

    with col_left:
        st.subheader("🔍 Security Findings")

        if findings:
            df_findings = pd.DataFrame(findings)

            # Filtering Controls
            cat_filter = st.multiselect(
                "Filter Category:",
                options=sorted(df_findings["category"].unique()),
                default=sorted(df_findings["category"].unique()),
            )
            sev_filter = st.multiselect(
                "Filter Severity:",
                options=sorted(df_findings["severity"].unique()),
                default=sorted(df_findings["severity"].unique()),
            )

            filtered_df = df_findings[
                df_findings["category"].isin(cat_filter) & df_findings["severity"].isin(sev_filter)
            ]

            st.dataframe(
                filtered_df[["category", "indicator", "severity", "file", "line", "evidence"]],
                use_container_width=True,
                hide_index=True,
            )

            highlight_line = st.selectbox(
                "Focus on Finding Line:",
                options=[None] + list(filtered_df["line"].unique()),
                format_func=lambda x: "No highlight" if x is None else f"Line {x}",
            )
        else:
            st.info("No security findings triggered by current AST ruleset.")
            highlight_line = None

    with col_right:
        st.subheader("📄 Source Code Viewer")

        file_names = [f["filename"] for f in files]
        selected_file_name = st.selectbox("Inspect File:", options=file_names, index=0)

        selected_file_obj = next(f for f in files if f["filename"] == selected_file_name)
        source_code = selected_file_obj["content"]

        finding_lines_for_file = {
            f["line"]: f["indicator"] for f in findings if f.get("file") == selected_file_name
        }

        # Render custom code viewer with line-level finding highlights
        lines = source_code.splitlines()
        code_html = ['<div style="border: 1px solid #334155; border-radius: 6px; padding: 10px; background-color: #0f172a; max-height: 400px; overflow-y: auto;">']

        for idx, line_text in enumerate(lines, start=1):
            escaped_line = line_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            is_finding_line = idx in finding_lines_for_file
            is_focused = (highlight_line is not None and idx == highlight_line)

            if is_focused or is_finding_line:
                indicator_tag = f" <span style='color: #ef4444; font-size: 11px;'>[FINDING: {finding_lines_for_file.get(idx, 'Trigger')}]</span>"
                code_html.append(
                    f'<div class="code-line-highlight">'
                    f'<span style="color: #64748b; margin-right: 12px; user-select: none;">{idx:3d}</span>'
                    f'<span>{escaped_line}</span>{indicator_tag}'
                    f'</div>'
                )
            else:
                code_html.append(
                    f'<div class="code-line-normal">'
                    f'<span style="color: #475569; margin-right: 12px; user-select: none;">{idx:3d}</span>'
                    f'<span>{escaped_line}</span>'
                    f'</div>'
                )

        code_html.append('</div>')
        st.markdown("".join(code_html), unsafe_allow_html=True)


def main():
    with st.sidebar:
        st.title("🕷️ SPIDER Security Suite")
        page = st.radio(
            "Navigate View:",
            ["📦 Package Investigation", "🔬 Model Observatory", "🕵️ Hunter-lite"],
            index=0,
        )
        st.divider()

    if page == "📦 Package Investigation":
        render_package_investigation()
    elif page == "🔬 Model Observatory":
        from spider.ui.observatory_page import render as render_observatory
        render_observatory(st)
    elif page == "🕵️ Hunter-lite":
        from spider.ui.hunter_page import render as render_hunter
        render_hunter(st)


if __name__ == "__main__":
    main()
