"""Streamlit page function for SPIDER Hunter-lite (brief section 5.7).

Allows reading hunt JSON from hunts/ or running the hunt interactively.
Presents table with severity colouring, 'new since last scan' filter, allowlist button,
and 'Coming soon' tiles for 'Live monitoring' and 'Cross-machine hunt'.

Streamlit is imported ONLY inside render(st).
Test: python -c "import spider.ui.hunter_page" passes without streamlit installed.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]


def render(st: Any = None) -> None:
    """Render the Hunter dashboard tab. Import streamlit inside render."""
    if st is None:
        import streamlit as st  # type: ignore

    st.title("🕵️ SPIDER Hunter-lite")
    st.markdown("Scan installed Python environments for install-time persistence artifacts and suspicious hooks.")

    # Sidebar / controls
    st.subheader("Inspection & History")
    hunts_dir = ROOT / "hunts"
    hunts_dir.mkdir(parents=True, exist_ok=True)
    hunt_files = sorted(list(hunts_dir.glob("*.json")), reverse=True)

    action = st.radio("Source", ["Load existing report", "Run fresh hunt"], horizontal=True)

    hunt_data: Optional[Dict[str, Any]] = None

    if action == "Load existing report":
        if not hunt_files:
            st.info("No recorded hunts found in `hunts/`. Run a fresh hunt or supply a hunt JSON file.")
        else:
            selected_file = st.selectbox("Select Hunt JSON", hunt_files, format_func=lambda p: p.name)
            if selected_file:
                try:
                    hunt_data = json.loads(selected_file.read_text(encoding="utf-8"))
                except Exception as e:
                    st.error(f"Error loading {selected_file.name}: {e}")
    else:
        st.write("Scan python environments found on this machine:")
        extra_dir = st.text_input("Optional extra site-packages directory:")
        if st.button("Start Hunt"):
            from spider.hunter.hunt import run_hunt
            with st.spinner("Hunting for persistence artifacts..."):
                extra_paths = [extra_dir] if extra_dir.strip() else None
                hunt_data = run_hunt(extra_site_packages=extra_paths)
                st.success(f"Hunt completed: {hunt_data.get('hunt_id')}")

    if hunt_data:
        st.markdown(f"**Hunt ID:** `{hunt_data.get('hunt_id')}` | **Scanned at:** {hunt_data.get('created_at')}")
        roots = hunt_data.get("roots", [])
        st.markdown(f"**Environments Inspected:** {len(roots)} roots ({hunt_data.get('distributions_count', 0)} distributions)")

        items: List[Dict[str, Any]] = hunt_data.get("items", [])
        
        # Filter controls
        col1, col2 = st.columns(2)
        with col1:
            show_only_new = st.checkbox("Show only 'New since last scan'", value=False)
        with col2:
            include_allowed = st.checkbox("Include allowlisted items", value=False)

        filtered = items
        if show_only_new:
            filtered = [it for it in filtered if it.get("new_since_last")]
        if not include_allowed:
            filtered = [it for it in filtered if not it.get("allowlisted")]

        st.markdown(f"### Detected Artifacts ({len(filtered)})")

        if not filtered:
            st.info("No suspicious artifacts matching the selected filters.")
        else:
            for it in filtered:
                sev = it.get("severity", "LOW").upper()
                badge_color = {
                    "HIGH": "red",
                    "MEDIUM": "orange",
                    "LOW": "blue",
                }.get(sev, "gray")

                with st.expander(f":{badge_color}[{sev}] {it.get('artifact')}: {it.get('reason')} (Priority: {it.get('priority')})"):
                    st.markdown(f"- **Path:** `{it.get('path')}`")
                    st.markdown(f"- **Distribution:** `{it.get('dist') or 'N/A'}` (v{it.get('version') or 'N/A'})")
                    st.markdown(f"- **SHA-256:** `{it.get('sha256')}`")
                    st.markdown(f"- **New since last scan:** {it.get('new_since_last')}")
                    if it.get("evidence_snippet"):
                        st.code(it["evidence_snippet"])

                    if not it.get("allowlisted"):
                        if st.button(f"Allowlist hash", key=f"btn_{it.get('sha256')}_{it.get('path')}"):
                            from spider.hunter.store import HunterStore
                            store = HunterStore()
                            store.add_allow(it.get("sha256", ""), note=f"Allowed via UI: {it.get('reason')}")
                            st.success(f"Hash {it.get('sha256')} added to allowlist. Re-run hunt to refresh.")

    # Two "Coming soon" tiles required by section 5.7
    st.markdown("---")
    st.markdown("### Upcoming Capabilities")
    c1, c2 = st.columns(2)
    with c1:
        st.info("🕒 **Live Monitoring**\n\nContinuous file-system watcher for real-time detection of stealth `.pth` additions and rogue sitecustomize hooks. *(Coming soon)*")
    with c2:
        st.info("🌐 **Cross-Machine Hunt**\n\nCentralized telemetry ingestion to correlate persistence artifacts across development fleets and CI runners. *(Coming soon)*")

