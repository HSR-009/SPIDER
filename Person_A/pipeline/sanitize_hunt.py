"""Sanitize and downsample hunter report for distribution / fixtures.

Usage:
    python Person_A/pipeline/sanitize_hunt.py --in hunts/kali_first.json --out fixtures/hunt_sample.json

Requirements:
- Replaces any home directory path and username with /home/user
- Keeps all HIGH and MEDIUM items
- Keeps a deterministic sample of 40 LOW items (seed 42)
- Preserves coverage counts
"""
from __future__ import annotations

import argparse
import json
import random
import re
import sys
from pathlib import Path
from typing import Any, Dict, List


def sanitize_string_paths(text: str) -> str:
    """Replace home directory paths and common user representations with /home/user."""
    if not isinstance(text, str):
        return text

    # Windows user paths: C:\Users\<username> or C:/Users/<username>
    text = re.sub(r"[A-Za-z]:[/\\]Users[/\\][^/\\\"'\s]+", "/home/user", text)
    # Unix user paths: /home/<username>
    text = re.sub(r"/home/[^/\\\"'\s]+", "/home/user", text)
    # Tilde paths: ~/
    text = re.sub(r"^~[/\\]", "/home/user/", text)
    text = re.sub(r"[\"'\s]~[/\\]", " /home/user/", text)

    return text


def sanitize_dict_paths(obj: Any) -> Any:
    """Recursively sanitize strings inside nested dicts/lists."""
    if isinstance(obj, str):
        return sanitize_string_paths(obj)
    elif isinstance(obj, list):
        return [sanitize_dict_paths(v) for v in obj]
    elif isinstance(obj, dict):
        return {k: sanitize_dict_paths(v) for k, v in obj.items()}
    return obj


def sanitize_hunt_data(data: Dict[str, Any], low_sample_size: int = 40, seed: int = 42) -> Dict[str, Any]:
    """Sanitize and downsample hunt report data."""
    # Deep copy and sanitize paths
    clean_data = sanitize_dict_paths(data)

    items: List[Dict[str, Any]] = clean_data.get("items", [])

    high_items = [it for it in items if str(it.get("severity", "")).upper() == "HIGH"]
    med_items = [it for it in items if str(it.get("severity", "")).upper() == "MEDIUM"]
    low_items = [it for it in items if str(it.get("severity", "")).upper() == "LOW"]
    other_items = [it for it in items if str(it.get("severity", "")).upper() not in ("HIGH", "MEDIUM", "LOW")]

    # Deterministic sampling of LOW items
    rng = random.Random(seed)
    # Sort first for deterministic order regardless of input dict ordering
    low_items_sorted = sorted(low_items, key=lambda x: (x.get("path", ""), x.get("reason", "")))
    if len(low_items_sorted) > low_sample_size:
        sampled_low = rng.sample(low_items_sorted, low_sample_size)
        # Sort sampled items back by priority descending
        sampled_low.sort(key=lambda x: x.get("priority", 0), reverse=True)
    else:
        sampled_low = low_items_sorted

    combined_items = high_items + med_items + sampled_low + other_items
    combined_items.sort(key=lambda x: x.get("priority", 0), reverse=True)

    clean_data["items"] = combined_items

    # Ensure coverage counts are preserved / present
    cov = clean_data.get("coverage", {})
    if "counts" not in cov:
        coverage_errors = cov.get("errors", [])
        dists_without = cov.get("dists_without_file_list", [])
        counts = {
            "skipped_too_large": sum(1 for e in coverage_errors if "skipped_too_large" in str(e).lower() or "skipped_py_too_large" in str(e).lower()),
            "missing_in_RECORD": sum(1 for e in coverage_errors if "missing file listed in record" in str(e).lower()),
            "inspection_timed_out": sum(1 for e in coverage_errors if "inspection_timed_out" in str(e).lower()),
            "file_list_unavailable": len(dists_without) + sum(1 for e in coverage_errors if "file_list_unavailable" in str(e).lower()),
            "entrypoint_ownership_unknown": sum(1 for e in coverage_errors if "entrypoint_ownership_unknown" in str(e).lower()),
        }
        cov["counts"] = counts
        clean_data["coverage"] = cov

    return clean_data


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sanitize and downsample SPIDER hunter report")
    parser.add_argument("--in", dest="input_file", required=True, help="Input hunt JSON path")
    parser.add_argument("--out", dest="output_file", required=True, help="Output sanitized JSON path")
    parser.add_argument("--low-sample", type=int, default=40, help="Number of LOW items to sample (default: 40)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for sampling (default: 42)")

    args = parser.parse_args(argv)

    inp = Path(args.input_file)
    if not inp.exists():
        sys.stderr.write(f"Error: Input file does not exist: {inp}\n")
        return 2

    try:
        raw_data = json.loads(inp.read_text(encoding="utf-8"))
    except Exception as e:
        sys.stderr.write(f"Error reading JSON from {inp}: {e}\n")
        return 2

    sanitized = sanitize_hunt_data(raw_data, low_sample_size=args.low_sample, seed=args.seed)

    out = Path(args.output_file)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sanitized, indent=2) + "\n", encoding="utf-8")
    print(f"Sanitized hunt report written to {out} ({len(sanitized.get('items', []))} items retained)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

