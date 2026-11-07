#!/usr/bin/env python3
"""Summary script for v1.1 rescan corpora (Day 3 step 3.8).

Run:
    python Person_A/analysis/rescan_summary.py
"""
from __future__ import annotations

import gzip
import json
import statistics
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[2]
MAL_FILE = ROOT / "data/processed/malicious_v11.jsonl"
BEN_FILE = ROOT / "data/processed/benign_v11.jsonl.gz"
MAL_V1_FILE = ROOT / "data/processed/malicious_for_b.jsonl"
BEN_V1_FILE = ROOT / "data/processed/benign_for_b.jsonl.gz"
HOLDOUT_FILE = ROOT / "results/frozen_holdout_packages.csv"
OUT_FILE = ROOT / "results/rescan_v11_summary.md"


def load_package_ids(path: Path) -> Set[str]:
    if not path.exists():
        return set()
    ids = set()
    if path.suffix == ".csv":
        import csv
        with path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                pid = row.get("package_id")
                if pid:
                    ids.add(pid)
        return ids

    opener = gzip.open(path, "rt", encoding="utf-8") if str(path).endswith(".gz") else path.open("r", encoding="utf-8")
    with opener as f:
        for line in f:
            if line.strip():
                try:
                    data = json.loads(line)
                    pid = data.get("package_id")
                    if pid:
                        ids.add(pid)
                except Exception:
                    continue
    return ids


def check_coverage(
    v11_ids: Set[str],
    v1_path: Path,
    holdout_path: Path,
    filter_label: Optional[int] = None,
) -> Dict[str, Any]:
    v1_ids = load_package_ids(v1_path)
    all_holdout = load_package_ids(holdout_path)

    # If filter_label provided, filter holdout packages
    holdout_ids = set()
    if holdout_path.exists():
        import csv
        with holdout_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if filter_label is None or row.get("label") == str(filter_label):
                    pid = row.get("package_id")
                    if pid:
                        holdout_ids.add(pid)
    else:
        holdout_ids = all_holdout

    missing_v1 = sorted(list(v1_ids - v11_ids))
    missing_holdout = sorted(list(holdout_ids - v11_ids))

    return {
        "v1_total": len(v1_ids),
        "missing_v1_count": len(missing_v1),
        "missing_v1_sample": missing_v1[:10],
        "holdout_total": len(holdout_ids),
        "missing_holdout_count": len(missing_holdout),
        "missing_holdout_sample": missing_holdout[:10],
    }


def load_rows(path: Path) -> List[Dict[str, Any]]:
    rows = []
    if not path.exists():
        return rows
    opener = gzip.open(path, "rt", encoding="utf-8") if str(path).endswith(".gz") else path.open("r", encoding="utf-8")
    with opener as f:
        for line in f:
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    return rows


def compute_roc_auc(scores_and_labels: List[Tuple[float, int]]) -> float:
    """Compute ROC-AUC from a list of (score, label) pairs using trapezoidal rule/rank sum."""
    pos = [s for s, y in scores_and_labels if y == 1]
    neg = [s for s, y in scores_and_labels if y == 0]
    n_pos = len(pos)
    n_neg = len(neg)
    if n_pos == 0 or n_neg == 0:
        return 0.5

    # Count pairs (tie counts as 0.5)
    wins = 0.0
    for p in pos:
        for n in neg:
            if p > n:
                wins += 1.0
            elif p == n:
                wins += 0.5
    return wins / (n_pos * n_neg)


def summarize_class(name: str, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    n = len(rows)
    if n == 0:
        return {
            "name": name, "rows": 0, "pct_suspicious": 0.0, "pct_review": 0.0,
            "pct_unable": 0.0, "top_unable_reasons": [], "signal_rates": {},
            "s2_same_file_rate": 0.0, "small_suspicious_rate": 0.0,
            "large_suspicious_rate": 0.0, "median_py": 0.0,
        }

    n_susp = sum(1 for r in rows if r.get("verdict_outcome") == "suspicious")
    n_unable = sum(1 for r in rows if r.get("verdict_outcome") == "unable_to_assess")
    n_none = sum(1 for r in rows if r.get("verdict_outcome") == "none_detected_in_this_scan")

    # Review recommended among none_detected
    none_rows = [r for r in rows if r.get("verdict_outcome") == "none_detected_in_this_scan"]
    n_review = sum(1 for r in none_rows if r.get("review_recommended"))
    pct_review = (n_review / len(none_rows) * 100.0) if none_rows else 0.0

    # Top unable reasons
    unable_reasons = Counter()
    for r in rows:
        if r.get("verdict_outcome") == "unable_to_assess":
            for p in r.get("coverage_problems", []):
                unable_reasons[p.split(":")[0]] += 1

    # Signal rates S1 to S5
    signal_counts = Counter()
    for r in rows:
        for s in r.get("strong_signals", []):
            signal_counts[s] += 1

    signal_rates = {
        s: (signal_counts[s] / n * 100.0)
        for s in ("S1_install_command", "S2_dynamic_exec_plus", "S3_credential_net", "S4_env_post", "S5_decode_exec")
    }

    n_s2_same = sum(1 for r in rows if r.get("s2_same_file"))
    s2_same_rate = n_s2_same / n * 100.0

    # Small packages (<= 5 n_py_files) vs larger
    small_rows = [r for r in rows if r.get("n_py_files", 0) <= 5]
    large_rows = [r for r in rows if r.get("n_py_files", 0) > 5]

    small_susp = sum(1 for r in small_rows if r.get("verdict_outcome") == "suspicious")
    large_susp = sum(1 for r in large_rows if r.get("verdict_outcome") == "suspicious")

    small_rate = (small_susp / len(small_rows) * 100.0) if small_rows else 0.0
    large_rate = (large_susp / len(large_rows) * 100.0) if large_rows else 0.0

    py_counts = [r.get("n_py_files", 0) for r in rows]
    median_py = statistics.median(py_counts) if py_counts else 0.0

    return {
        "name": name,
        "rows": n,
        "pct_suspicious": (n_susp / n * 100.0),
        "pct_review": pct_review,
        "pct_unable": (n_unable / n * 100.0),
        "top_unable_reasons": unable_reasons.most_common(3),
        "signal_rates": signal_rates,
        "s2_same_file_rate": s2_same_rate,
        "small_suspicious_rate": small_rate,
        "large_suspicious_rate": large_rate,
        "median_py": median_py,
    }


def generate_summary() -> None:
    mal_rows = load_rows(MAL_FILE)
    ben_rows = load_rows(BEN_FILE)

    mal_sum = summarize_class("Malicious", mal_rows)
    ben_sum = summarize_class("Benign", ben_rows)

    # Compute ROC-AUC
    all_rows = [(r.get("n_py_files", 0), 1) for r in mal_rows] + [(r.get("n_py_files", 0), 0) for r in ben_rows]
    auc_size = compute_roc_auc(all_rows) if all_rows else 0.5

    all_findings = [(r.get("n_findings", 0), 1) for r in mal_rows] + [(r.get("n_findings", 0), 0) for r in ben_rows]
    auc_findings = compute_roc_auc(all_findings) if all_findings else 0.5

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUT_FILE.open("w", encoding="utf-8") as out:
        out.write("# python Person_A/analysis/rescan_summary.py\n\n")
        out.write("# SPIDER Corpora Rescan v1.1 Summary Report\n\n")
        out.write("This report provides a comparison of static signals and verdict distributions between the malicious and benign corpora under analyzer v1.1 and Verdict v2.\n\n")

        out.write("## Overview Metrics\n\n")
        out.write("| Metric | Malicious (`malicious_v11.jsonl`) | Benign (`benign_v11.jsonl.gz`) |\n")
        out.write("|---|---|---|\n")
        out.write(f"| **Total Packages** | {mal_sum['rows']} | {ben_sum['rows']} |\n")
        out.write(f"| **% Suspicious** | {mal_sum['pct_suspicious']:.1f}% | {ben_sum['pct_suspicious']:.1f}% |\n")
        out.write(f"| **% Review Recommended (among none detected)** | {mal_sum['pct_review']:.1f}% | {ben_sum['pct_review']:.1f}% |\n")
        out.write(f"| **% Unable to Assess** | {mal_sum['pct_unable']:.1f}% | {ben_sum['pct_unable']:.1f}% |\n")
        out.write(f"| **Median Analyzed `.py` Files** | {mal_sum['median_py']} | {ben_sum['median_py']} |\n")
        out.write(f"| **Suspicious Rate (Small Packages, $\\le$5 `.py`)** | {mal_sum['small_suspicious_rate']:.1f}% | {ben_sum['small_suspicious_rate']:.1f}% |\n")
        out.write(f"| **Suspicious Rate (Larger Packages, >5 `.py`)** | {mal_sum['large_suspicious_rate']:.1f}% | {ben_sum['large_suspicious_rate']:.1f}% |\n\n")

        out.write("## Strong Signals Distribution (S1 to S5)\n\n")
        out.write("| Signal ID | Description | Malicious % | Benign % |\n")
        out.write("|---|---|---|---|\n")
        s1_m = mal_sum["signal_rates"].get("S1_install_command", 0.0)
        s1_b = ben_sum["signal_rates"].get("S1_install_command", 0.0)
        out.write(f"| `S1_install_command` | Install hook override | {s1_m:.1f}% | {s1_b:.1f}% |\n")
        s2_m = mal_sum["signal_rates"].get("S2_dynamic_exec_plus", 0.0)
        s2_b = ben_sum["signal_rates"].get("S2_dynamic_exec_plus", 0.0)
        out.write(f"| `S2_dynamic_exec_plus` | Dynamic execution + network/obfuscation | {s2_m:.1f}% | {s2_b:.1f}% |\n")
        s3_m = mal_sum["signal_rates"].get("S3_credential_net", 0.0)
        s3_b = ben_sum["signal_rates"].get("S3_credential_net", 0.0)
        out.write(f"| `S3_credential_net` | Credential path + network activity | {s3_m:.1f}% | {s3_b:.1f}% |\n")
        s4_m = mal_sum["signal_rates"].get("S4_env_post", 0.0)
        s4_b = ben_sum["signal_rates"].get("S4_env_post", 0.0)
        out.write(f"| `S4_env_post` | `os.environ` + `requests.post` | {s4_m:.1f}% | {s4_b:.1f}% |\n")
        s5_m = mal_sum["signal_rates"].get("S5_decode_exec", 0.0)
        s5_b = ben_sum["signal_rates"].get("S5_decode_exec", 0.0)
        out.write(f"| `S5_decode_exec` | base64 decode + exec/eval | {s5_m:.1f}% | {s5_b:.1f}% |\n")
        out.write(f"| `s2_same_file` | Dynamic execution + net/obf in same file | {mal_sum['s2_same_file_rate']:.1f}% | {ben_sum['s2_same_file_rate']:.1f}% |\n\n")

        out.write("## Discriminative Power (ROC-AUC)\n\n")
        out.write(f"- **Package Size (`n_py_files`) ROC-AUC**: {auc_size:.4f}\n")
        out.write(f"- **Finding Count (`n_findings`) ROC-AUC**: {auc_findings:.4f}\n\n")

        out.write("## Top Unable-to-Assess Coverage Reasons\n\n")
        out.write(f"- **Malicious**: {mal_sum['top_unable_reasons']}\n")
        out.write(f"- **Benign**: {ben_sum['top_unable_reasons']}\n\n")

        # Coverage analysis vs v1 and frozen holdout
        mal_v11_ids = {r.get("package_id") for r in mal_rows if r.get("package_id")}
        ben_v11_ids = {r.get("package_id") for r in ben_rows if r.get("package_id")}

        cov_mal = check_coverage(mal_v11_ids, MAL_V1_FILE, HOLDOUT_FILE, filter_label=1)
        cov_ben = check_coverage(ben_v11_ids, BEN_V1_FILE, HOLDOUT_FILE, filter_label=0)

        out.write("## Corpus & Holdout Coverage\n\n")
        out.write("| Class | Total v1 Packages | Missing from v1.1 | Total Holdout Packages | Missing from Holdout |\n")
        out.write("|---|---|---|---|---|\n")
        out.write(f"| **Malicious** | {cov_mal['v1_total']} | {cov_mal['missing_v1_count']} | {cov_mal['holdout_total']} | {cov_mal['missing_holdout_count']} |\n")
        out.write(f"| **Benign** | {cov_ben['v1_total']} | {cov_ben['missing_v1_count']} | {cov_ben['holdout_total']} | {cov_ben['missing_holdout_count']} |\n\n")

        if cov_mal["missing_v1_sample"]:
            out.write(f"**First missing Malicious v1 IDs** (up to 10): {', '.join(cov_mal['missing_v1_sample'])}\n\n")
        if cov_mal["missing_holdout_sample"]:
            out.write(f"**First missing Malicious Holdout IDs** (up to 10): {', '.join(cov_mal['missing_holdout_sample'])}\n\n")
        if cov_ben["missing_v1_sample"]:
            out.write(f"**First missing Benign v1 IDs** (up to 10): {', '.join(cov_ben['missing_v1_sample'])}\n\n")
        if cov_ben["missing_holdout_sample"]:
            out.write(f"**First missing Benign Holdout IDs** (up to 10): {', '.join(cov_ben['missing_holdout_sample'])}\n\n")

        out.write("> [!NOTE]\n")
        out.write("> These rates represent static signal co-occurrence, not model accuracy. Excluding tests and doc directories directly mitigates benign inflation on dynamic and obfuscation rules.\n")

    print(f"Summary written to {OUT_FILE}")


if __name__ == "__main__":
    generate_summary()

