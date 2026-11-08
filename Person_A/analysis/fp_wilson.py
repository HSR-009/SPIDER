"""Wilson 95% confidence interval summary for FP check (Day 6 step 6.2 & brief 7.10).

Usage:
    python Person_A/analysis/fp_wilson.py \\
        --in results/fp_check_v11.csv \\
        --out results/fp_check_summary.md
"""
from __future__ import annotations

import argparse
import csv
import math
import sys
from pathlib import Path
from typing import Dict, List, Tuple


def wilson_95_ci(k: int, n: int) -> Tuple[float, float]:
    """Compute Wilson score 95% confidence interval for k successes in n trials.
    
    Formula from brief 7.10:
      p = k / n
      z = 1.96
      centre = (p + z^2 / (2 * n)) / (1 + z^2 / n)
      half = z * sqrt(p * (1 - p) / n + z^2 / (4 * n^2)) / (1 + z^2 / n)
      [centre - half, centre + half]
    Bound interval within [0.0, 1.0].
    """
    if n <= 0:
        return 0.0, 0.0

    p = float(k) / float(n)
    z = 1.96
    z_sq = z * z
    denom = 1.0 + z_sq / n

    centre = (p + z_sq / (2.0 * n)) / denom
    radicand = (p * (1.0 - p) / n) + (z_sq / (4.0 * n * n))
    half = z * math.sqrt(max(0.0, radicand)) / denom

    lower = max(0.0, centre - half)
    upper = min(1.0, centre + half)
    return lower, upper


def generate_wilson_summary(csv_path: Path, out_path: Path) -> int:
    if not csv_path.exists():
        sys.stderr.write(f"Input file not found: {csv_path}\n")
        return 2

    rows: List[Dict[str, str]] = []
    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)

    # Validation: refuse to run if any suspicious row has an empty triage_label or outside {true_positive, false_positive, unclear}
    suspicious_rows = [r for r in rows if r.get("verdict") == "suspicious"]
    invalid_rows = []

    for r in suspicious_rows:
        pkg_id = f"{r.get('name')}=={r.get('version')}"
        label = (r.get("triage_label") or "").strip().lower()
        if not label:
            invalid_rows.append(f"{pkg_id}: triage_label is empty")
        elif label not in ("true_positive", "false_positive", "unclear"):
            invalid_rows.append(f"{pkg_id}: invalid triage_label '{label}' (must be true_positive|false_positive|unclear)")

    if invalid_rows:
        sys.stderr.write("Refusing to run: unreviewed or invalid suspicious rows detected:\n")
        for err in invalid_rows:
            sys.stderr.write(f"  {err}\n")
        return 1

    total_n = len(rows)
    n_suspicious = len(suspicious_rows)
    n_unable = sum(1 for r in rows if r.get("verdict") == "unable_to_assess")
    n_review_rec = sum(1 for r in rows if str(r.get("review_recommended")).lower() in ("true", "1"))

    # Count labels for packages
    n_fp = sum(1 for r in suspicious_rows if r.get("triage_label", "").strip().lower() == "false_positive")
    n_tp = sum(1 for r in suspicious_rows if r.get("triage_label", "").strip().lower() == "true_positive")
    n_unclear = sum(1 for r in suspicious_rows if r.get("triage_label", "").strip().lower() == "unclear")

    # Intervals for package level
    ci_base_lower, ci_base_upper = wilson_95_ci(n_fp, total_n)
    # Upper bound treating unclear as FP
    ci_upper_lower, ci_upper_upper = wilson_95_ci(n_fp + n_unclear, total_n)
    # Lower bound treating unclear as TP
    ci_lower_lower, ci_lower_upper = wilson_95_ci(n_fp, total_n)

    # Family-level aggregation (count each family once)
    families: Dict[str, List[Dict[str, str]]] = {}
    for r in rows:
        fam = r.get("family") or (r.get("name", "").split("-")[0])
        families.setdefault(fam, []).append(r)

    total_fam = len(families)
    fam_fp = 0
    fam_tp = 0
    fam_unclear = 0
    fam_suspicious = 0

    for fam, f_rows in families.items():
        f_susp = [r for r in f_rows if r.get("verdict") == "suspicious"]
        if not f_susp:
            continue
        fam_suspicious += 1
        labels = {r.get("triage_label", "").strip().lower() for r in f_susp}
        if "false_positive" in labels:
            fam_fp += 1
        elif "unclear" in labels:
            fam_unclear += 1
        elif "true_positive" in labels:
            fam_tp += 1

    fam_ci_base_lower, fam_ci_base_upper = wilson_95_ci(fam_fp, total_fam)
    fam_ci_upper_lower, fam_ci_upper_upper = wilson_95_ci(fam_fp + fam_unclear, total_fam)
    fam_ci_lower_lower, fam_ci_lower_upper = wilson_95_ci(fam_fp, total_fam)

    # Generate Markdown summary
    pct_fp = (n_fp / total_n * 100) if total_n else 0.0
    fam_pct_fp = (fam_fp / total_fam * 100) if total_fam else 0.0

    unclear_clause = f" (plus {n_unclear} unclear)" if n_unclear else ""
    important_sentence = (
        f"> On a sample of {total_n} small, obscure PyPI packages, {n_suspicious} were flagged suspicious; "
        f"after manual review {n_fp} were false positives{unclear_clause} ({pct_fp:.1f}%, 95% CI [{ci_base_lower:.4f}, {ci_base_upper:.4f}]). "
        f"This evaluates precision on small, obscure PyPI packages and is not the false-positive rate of SPIDER in general."
    )

    lines = [
        "# False-Positive Evaluation Summary",
        "",
        "> [!IMPORTANT]",
        important_sentence,
        "",
        "## 1. Package-Level Results",
        "",
        f"- **Packages Scanned (n):** {total_n}",
        f"- **Flagged Suspicious:** {n_suspicious}",
        f"- **Unable to Assess:** {n_unable}",
        f"- **Review Recommended:** {n_review_rec}",
        "",
        "### Triage Breakdown",
        f"- **False Positives (FP):** {n_fp} ({pct_fp:.1f}%)",
        f"- **True Positives (TP):** {n_tp}",
        f"- **Unclear:** {n_unclear}",
        "",
        "### Wilson 95% Confidence Intervals",
        f"- **FP only (unclear counted as true positives):** [{ci_base_lower:.4f}, {ci_base_upper:.4f}] ({ci_base_lower*100:.1f}% – {ci_base_upper*100:.1f}%)",
        f"- **FP + unclear (unclear counted as false positives):** [{ci_upper_lower:.4f}, {ci_upper_upper:.4f}] ({ci_upper_lower*100:.1f}% – {ci_upper_upper*100:.1f}%)",
        "",
        "## 2. Family-Level Results",
        "",
        f"- **Distinct Package Families (n):** {total_fam}",
        f"- **Families Flagged Suspicious:** {fam_suspicious}",
        f"- **Family False Positives:** {fam_fp} ({fam_pct_fp:.1f}%)",
        f"- **Family True Positives:** {fam_tp}",
        f"- **Family Unclear:** {fam_unclear}",
        "",
        "### Family Wilson 95% Confidence Intervals",
        f"- **FP only (unclear counted as true positives):** [{fam_ci_base_lower:.4f}, {fam_ci_base_upper:.4f}] ({fam_ci_base_lower*100:.1f}% – {fam_ci_base_upper*100:.1f}%)",
        f"- **FP + unclear (unclear counted as false positives):** [{fam_ci_upper_lower:.4f}, {fam_ci_upper_upper:.4f}] ({fam_ci_upper_lower*100:.1f}% – {fam_ci_upper_upper*100:.1f}%)",
        "",
    ]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"FP summary written to: {out_path}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Wilson 95% confidence interval summary for FP check")
    parser.add_argument("--in", dest="input_file", default="results/fp_check_v11.csv", help="Input FP check CSV path")
    parser.add_argument("--out", dest="output_file", default="results/fp_check_summary.md", help="Output Markdown path")

    args = parser.parse_args(argv)

    return generate_wilson_summary(Path(args.input_file), Path(args.output_file))


if __name__ == "__main__":
    sys.exit(main())

