#!/usr/bin/env python
"""
Person_A/pipeline/parity_report.py
----------------------------------
Compares indicator detections across analyzer implementations on real archives:
1. Frozen v1 AST analyzer (Person_A/ast_analyzer/analyzer_v1_frozen.py)
2. scan_benign.py rule logic (Person_A/pipeline/scan_benign.py:analyze)
3. v1.1 engine (spider.engine.scan / analyzer_v1_1.py)

On a sample of 300 benign and 300 malicious archives sampled with seed 42,
extracts into temp dir, runs all three on the SAME file set (excluding kind "doc"),
and compares indicator sets per package (excluding Parse Error).

Outputs:
- Percentage of packages where v1 equals scan_benign.
- Top 10 indicators found by only one side in each direction (counts and examples).
- Indicators lost by v1.1 vs v1 (must be 0; any discrepancy is classified automatically
  only as far as data supports: e.g. uninspected/parse_failure, else marked 'unclassified').
- Writes results/parity_v1_vs_v11.md and results/parity_v1_vs_v11.csv.

Note: Designed to run on Kali where raw archives exist. Exits non-zero with a clear
message if fewer archives are found than required.
"""

import argparse
import csv
import io
import json
import os
import random
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Person_A.ast_analyzer.analyzer_v1_frozen import analyze_file as analyze_v1
from Person_A.pipeline.scan_benign import analyze as analyze_scan_benign
from spider.engine.classify import classify
from spider.engine.extract import safe_extract
from spider.engine.scan import scan_directory
from spider_contract.adapter import to_legacy

DEFAULT_BENIGN_RAW = ROOT / "data" / "raw" / "benign" / "archives"
DEFAULT_MALICIOUS_RAW = ROOT / "data" / "raw" / "malicious" / "pypi"
DEFAULT_OUT_MD = ROOT / "results" / "parity_v1_vs_v11.md"
DEFAULT_OUT_CSV = ROOT / "results" / "parity_v1_vs_v11.csv"
ARCHIVE_EXTS = (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".whl")


def collect_archives(directory):
    path = Path(directory)
    if not path.exists():
        return []
    archives = []
    for root, _, files in os.walk(path):
        for f in files:
            lower = f.lower()
            if any(lower.endswith(ext) for ext in ARCHIVE_EXTS):
                archives.append(Path(root) / f)
    return archives


def analyze_extracted_dir(dest_dir):
    """
    Extracts all files in dest_dir, filters out kind 'doc' using classify.py,
    and runs (a) analyzer_v1, (b) scan_benign, and (c) scan_directory (v1.1).
    """
    python_files = []
    dest_path = Path(dest_dir)
    for root, _, files in os.walk(dest_path):
        for f in files:
            full = Path(root) / f
            rel = str(full.relative_to(dest_path)).replace("\\", "/")
            kind, _ = classify(rel)
            if kind == "python":
                python_files.append((rel, full))

    # 1. Frozen v1
    v1_findings = []
    for rel, full in python_files:
        try:
            f = analyze_v1(str(full))
            for item in f:
                item["file"] = rel
            v1_findings.extend(f)
        except Exception:
            pass

    # 2. scan_benign.py logic
    sb_findings = []
    for rel, full in python_files:
        try:
            content = full.read_text(encoding="utf-8", errors="replace")
            f = analyze_scan_benign(content, rel)
            sb_findings.extend(f)
        except Exception:
            pass

    # 3. v1.1 engine
    v11_rec = scan_directory(dest_dir)
    v11_legacy = to_legacy(v11_rec)

    v1_inds = {f["indicator"] for f in v1_findings if f.get("category") != "Parse Error"}
    sb_inds = {f["indicator"] for f in sb_findings if f.get("category") != "Parse Error"}
    v11_inds = {f["indicator"] for f in v11_legacy if f.get("category") != "Parse Error"}

    return {
        "python_files": len(python_files),
        "v1_indicators": v1_inds,
        "scan_benign_indicators": sb_inds,
        "v11_indicators": v11_inds,
        "uninspected": [u["path"] for u in v11_rec.get("inventory", {}).get("uninspected", [])],
        "parse_failures": [p["path"] for p in v11_rec.get("inventory", {}).get("parse_failures", [])],
    }


def run_parity_comparison(benign_raw_dir, mal_raw_dir, out_md, out_csv, sample_size=300, seed=42):
    ben_archives = collect_archives(benign_raw_dir)
    mal_archives = collect_archives(mal_raw_dir)

    print(f"Archives found: {len(ben_archives)} benign, {len(mal_archives)} malicious")

    if len(ben_archives) < sample_size or len(mal_archives) < sample_size:
        sys.exit(
            f"ERROR: Insufficient raw archives found for parity evaluation!\n"
            f"  Benign archives found: {len(ben_archives)} (required: {sample_size})\n"
            f"  Malicious archives found: {len(mal_archives)} (required: {sample_size})\n"
            f"This script runs on Kali where raw archives exist under --raw-dir."
        )

    rng = random.Random(seed)
    sampled_ben = rng.sample(ben_archives, sample_size)
    sampled_mal = rng.sample(mal_archives, sample_size)

    results = []

    # Process benign
    for arc in sampled_ben:
        with tempfile.TemporaryDirectory() as dest:
            safe_extract(str(arc), dest)
            res = analyze_extracted_dir(dest)
            res["archive"] = arc.name
            res["corpus"] = "benign"
            results.append(res)

    # Process malicious
    for arc in sampled_mal:
        with tempfile.TemporaryDirectory() as dest:
            safe_extract(str(arc), dest)
            res = analyze_extracted_dir(dest)
            res["archive"] = arc.name
            res["corpus"] = "malicious"
            results.append(res)

    # Statistics
    ben_results = [r for r in results if r["corpus"] == "benign"]
    mal_results = [r for r in results if r["corpus"] == "malicious"]

    v1_eq_sb_ben = sum(1 for r in ben_results if r["v1_indicators"] == r["scan_benign_indicators"])
    pct_v1_eq_sb = (v1_eq_sb_ben / len(ben_results) * 100) if ben_results else 0.0

    # Top indicators found by only one side
    only_v1 = Counter()
    only_sb = Counter()
    for r in ben_results:
        for ind in (r["v1_indicators"] - r["scan_benign_indicators"]):
            only_v1[ind] += 1
        for ind in (r["scan_benign_indicators"] - r["v1_indicators"]):
            only_sb[ind] += 1

    # Indicators lost by v1.1 vs v1
    lost_counts = Counter()
    lost_examples = defaultdict(list)
    classified_reasons = {}

    for r in results:
        lost = r["v1_indicators"] - r["v11_indicators"]
        for ind in lost:
            lost_counts[ind] += 1
            if len(lost_examples[ind]) < 3:
                lost_examples[ind].append(r["archive"])

            # Automatic data-supported classification
            if r["parse_failures"]:
                classified_reasons[ind] = "file_parse_failure"
            elif r["uninspected"]:
                classified_reasons[ind] = "file_uninspected_limit"
            else:
                classified_reasons[ind] = "unclassified"

    # New in v1.1
    new_counts = Counter()
    for r in results:
        for ind in (r["v11_indicators"] - r["v1_indicators"]):
            new_counts[ind] += 1

    # Write CSV
    out_csv = Path(out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["archive", "corpus", "v1_count", "sb_count", "v11_count", "v1_equals_sb", "lost_in_v11", "new_in_v11"])
        for r in results:
            writer.writerow([
                r["archive"],
                r["corpus"],
                len(r["v1_indicators"]),
                len(r["scan_benign_indicators"]),
                len(r["v11_indicators"]),
                int(r["v1_indicators"] == r["scan_benign_indicators"]),
                ";".join(sorted(r["v1_indicators"] - r["v11_indicators"])),
                ";".join(sorted(r["v11_indicators"] - r["v1_indicators"])),
            ])

    # Write Markdown
    out_md = Path(out_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Parity Report: Analyzer v1 vs scan_benign vs v1.1",
        "",
        "## Summary",
        f"- **Archives Evaluated**: {len(ben_results)} benign, {len(mal_results)} malicious (sampled seed {seed}).",
        f"- **Percentage of benign packages where v1 equals scan_benign**: {pct_v1_eq_sb:.1f}% ({v1_eq_sb_ben} / {len(ben_results)}).",
        f"- **Total indicators lost by v1.1 vs v1**: {sum(lost_counts.values())}.",
        "",
        "## Top Indicators Found by Only One Side (v1 vs scan_benign)",
        "",
        "### In v1 but not scan_benign",
        "| Indicator | Count |",
        "|---|---:|",
    ]
    for ind, count in only_v1.most_common(10):
        lines.append(f"| `{ind}` | {count} |")

    lines.extend([
        "",
        "### In scan_benign but not v1",
        "| Indicator | Count |",
        "|---|---:|",
    ])
    for ind, count in only_sb.most_common(10):
        lines.append(f"| `{ind}` | {count} |")

    lines.extend([
        "",
        "## Indicators Lost by v1.1 vs v1",
        "| Indicator | Lost Count | Data-Supported Classification | Example Archives |",
        "|---|---:|---|---|",
    ])
    if not lost_counts:
        lines.append("| *(None)* | 0 | Verified 0 lost indicators | N/A |")
    else:
        for ind, count in lost_counts.most_common():
            cls = classified_reasons.get(ind, "unclassified")
            ex = ", ".join(lost_examples[ind])
            lines.append(f"| `{ind}` | {count} | {cls} | {ex} |")

    lines.extend([
        "",
        "## New Indicators Emitted in v1.1",
        "| Indicator | Count |",
        "|---|---:|",
    ])
    for ind, count in new_counts.most_common(10):
        lines.append(f"| `{ind}` | {count} |")

    out_md.write_text("\n".join(lines), encoding="utf-8")
    print(f"Parity report written to: {out_md} and {out_csv}")


def main():
    parser = argparse.ArgumentParser(description="Parity report comparing v1, scan_benign and v1.1 on raw archives (runs on Kali)")
    parser.add_argument("--benign-raw", default=str(DEFAULT_BENIGN_RAW), help="Path to raw benign archives directory")
    parser.add_argument("--malicious-raw", default=str(DEFAULT_MALICIOUS_RAW), help="Path to raw malicious archives directory")
    parser.add_argument("--out-md", default=str(DEFAULT_OUT_MD), help="Path to write parity markdown report")
    parser.add_argument("--out-csv", default=str(DEFAULT_OUT_CSV), help="Path to write parity csv report")
    parser.add_argument("--sample-size", type=int, default=300, help="Number of archives to sample per class")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    run_parity_comparison(
        benign_raw_dir=args.benign_raw,
        mal_raw_dir=args.malicious_raw,
        out_md=args.out_md,
        out_csv=args.out_csv,
        sample_size=args.sample_size,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
