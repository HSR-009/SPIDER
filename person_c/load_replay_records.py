"""
load_replay_records.py
-----------------------
Loader for scan_record JSON files (replay records and contract fixtures),
ready for consumption by the UI dashboard and evaluation pipelines.

Strict honesty adherence:
- Preserves genuine 'record_origin' ('replay', 'fixture', 'hand_written_fixture', etc.)
- Normalizes package identifiers via target.name or package_name
- Never raises an error if the directory does not exist yet; returns empty list gracefully
"""

from __future__ import annotations

import glob
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPLAY_DIR = REPO_ROOT / "fixtures" / "replay"
DEFAULT_FIXTURE_DIR = REPO_ROOT / "fixtures" / "records"


def load_replay_records(
    replay_dir: Optional[str | Path] = None,
    include_contract_fixtures_fallback: bool = False,
) -> List[Dict[str, Any]]:
    """
    Loads scan_record JSON files from target directory.
    Returns empty list if the directory is missing or empty.
    """
    target_dir = Path(replay_dir) if replay_dir else DEFAULT_REPLAY_DIR

    if not target_dir.is_dir():
        if include_contract_fixtures_fallback and DEFAULT_FIXTURE_DIR.is_dir():
            target_dir = DEFAULT_FIXTURE_DIR
        else:
            return []

    records = []
    for filepath in sorted(target_dir.glob("*.json")):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"WARNING: could not load {filepath}: {e}")
            continue

        # Respect existing record_origin per honesty rules; only default if absent
        if "record_origin" not in data:
            data["record_origin"] = "replay" if "replay" in str(target_dir) else "fixture"

        # Contract schema compatibility helper
        pkg_name = data.get("package_name") or data.get("target", {}).get("name", "unknown")
        data["_package_name_resolved"] = pkg_name
        data["_source_file"] = str(filepath)
        records.append(data)

    return records


if __name__ == "__main__":
    records = load_replay_records()
    if not records:
        print(f"No replay records found at '{DEFAULT_REPLAY_DIR}'.")
        print("Checking contract fixtures:")
        fallback = load_replay_records(include_contract_fixtures_fallback=True)
        print(f"Loaded {len(fallback)} contract fixture records.")
        for r in fallback:
            print(f"  - {r.get('_package_name_resolved')} (origin: {r.get('record_origin')}) from {r['_source_file']}")
    else:
        print(f"Loaded {len(records)} replay records:")
        for r in records:
            print(f"  - {r.get('_package_name_resolved')} (origin: {r.get('record_origin')}) from {r['_source_file']}")
