"""
evasion_table.py
-----------------
Official evaluation table for SPIDER Person C comparing:
- Baseline AST Analyzer (v1 frozen)
- Hardened AST Analyzer (v1.1)
- Defense: Baseline Analyzer with Source Normalization (v1 + normalize.py)
- Defense: Hardened Analyzer with Source Normalization (v1.1 + normalize.py)

Uses the official three-way classification logic:
  - recovered: Transformed sample produced at least one finding matching the
               original (category, indicator) of the baseline sample.
  - different_signal: Transformed sample produced finding(s), but none matching
                      the baseline's exact (category, indicator) (e.g. wrapper exec or obf).
  - missed: Transformed sample produced zero findings (complete evasion).

Outputs:
  - results/evasion_table_v1_vs_v11.json
  - results/evasion_table_v1_vs_v11.md
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Repo root
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Compatibility alias
try:
    import Person_c
    sys.modules.setdefault("person_c", Person_c)
except ImportError:
    pass

from Person_A.ast_analyzer.analyzer_v1_frozen import analyze_file as v1_analyze_file
from Person_A.ast_analyzer.analyzer_v1_1 import analyze_source as v11_analyze_source
from spider.normalize import normalize_source


def run_analyzer_v1(source_code: str) -> List[Dict[str, Any]]:
    """Runs frozen v1 AST analyzer on a source string via a temporary file."""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tmp:
        tmp.write(source_code)
        tmp_path = tmp.name

    try:
        raw = v1_analyze_file(tmp_path)
        # Filter out parse errors from security findings
        return [f for f in raw if f.get("category") != "Parse Error"]
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def run_analyzer_v11(source_code: str, filename: str = "<source>") -> List[Dict[str, Any]]:
    """Runs hardened v1.1 AST analyzer directly on source string."""
    findings, _parse_err = v11_analyze_source(source_code, filename)
    return findings or []


def union_findings(
    raw_findings: List[Dict[str, Any]],
    normalized_findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Union of a raw scan and a scan of the normalized source.

    Normalization must never drop a finding the raw scan already had.
    A finding already present in the raw list is kept as-is; normalized-only
    findings are appended. Identity is (category, indicator, file, line).
    """
    merged: List[Dict[str, Any]] = []
    seen = set()
    for finding in list(raw_findings) + list(normalized_findings):
        key = (
            finding.get("category"),
            finding.get("indicator"),
            finding.get("file"),
            finding.get("line"),
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(finding)
    return merged


def classify_outcome(baseline_findings: List[Dict[str, Any]], candidate_findings: List[Dict[str, Any]]) -> str:
    """Classifies outcome as recovered, different_signal, or missed."""
    if not candidate_findings:
        return "missed"

    baseline_signatures = {(f["category"], f["indicator"]) for f in baseline_findings}
    candidate_signatures = {(f["category"], f["indicator"]) for f in candidate_findings}

    if baseline_signatures & candidate_signatures:
        return "recovered"
    return "different_signal"


def build_evaluation_table(manifest_path: Path) -> Dict[str, Any]:
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    entries = manifest.get("entries", [])
    per_sample_results = []

    configs = ["v1", "v1_1", "v1_normalized", "v1_1_normalized"]
    totals = {c: {"recovered": 0, "different_signal": 0, "missed": 0} for c in configs}
    by_technique = {}

    for entry in entries:
        sample_id = entry["sample_id"]
        technique = entry["technique"]
        baseline_src = entry["baseline_source"]
        generated_code = entry["generated_code"]

        try:
            norm_code = normalize_source(generated_code)
        except Exception as e:
            norm_code = generated_code

        # Run analyzers on baseline
        b_findings_v1 = run_analyzer_v1(baseline_src)
        b_findings_v11 = run_analyzer_v11(baseline_src, sample_id)

        # Run analyzers on generated code
        f_v1 = run_analyzer_v1(generated_code)
        f_v11 = run_analyzer_v11(generated_code, sample_id)
        # v1 + normalize and v1.1 + normalize report the union. A rewrite that
        # drops a literal (for example base64.b64decode -> bytes) must not
        # erase the finding the raw scan already produced.
        f_v1_norm = union_findings(f_v1, run_analyzer_v1(norm_code))
        f_v11_norm = union_findings(f_v11, run_analyzer_v11(norm_code, sample_id))

        # Outomes
        out_v1 = classify_outcome(b_findings_v1, f_v1)
        out_v11 = classify_outcome(b_findings_v11, f_v11)
        out_v1_norm = classify_outcome(b_findings_v1, f_v1_norm)
        out_v11_norm = classify_outcome(b_findings_v11, f_v11_norm)

        sample_eval = {
            "sample_id": sample_id,
            "technique": technique,
            "description": entry.get("description", ""),
            "v1": {
                "outcome": out_v1,
                "findings": [(x["category"], x["indicator"]) for x in f_v1],
            },
            "v1_1": {
                "outcome": out_v11,
                "findings": [(x["category"], x["indicator"]) for x in f_v11],
            },
            "v1_normalized": {
                "outcome": out_v1_norm,
                "findings": [(x["category"], x["indicator"]) for x in f_v1_norm],
            },
            "v1_1_normalized": {
                "outcome": out_v11_norm,
                "findings": [(x["category"], x["indicator"]) for x in f_v11_norm],
            },
        }
        per_sample_results.append(sample_eval)

        # Update totals
        totals["v1"][out_v1] += 1
        totals["v1_1"][out_v11] += 1
        totals["v1_normalized"][out_v1_norm] += 1
        totals["v1_1_normalized"][out_v11_norm] += 1

        # By technique aggregation
        tech_bucket = by_technique.setdefault(technique, {c: {"recovered": 0, "different_signal": 0, "missed": 0} for c in configs})
        tech_bucket["v1"][out_v1] += 1
        tech_bucket["v1_1"][out_v11] += 1
        tech_bucket["v1_normalized"][out_v1_norm] += 1
        tech_bucket["v1_1_normalized"][out_v11_norm] += 1

    total_samples = len(entries)
    summary = {
        "manifest_hash_sha256": manifest.get("manifest_hash_sha256", ""),
        "total_samples": total_samples,
        "overall_counts": totals,
        "miss_rates_asr": {
            c: round((totals[c]["missed"] / total_samples) * 100, 2) if total_samples else 0.0
            for c in configs
        },
        "recovered_rates": {
            c: round((totals[c]["recovered"] / total_samples) * 100, 2) if total_samples else 0.0
            for c in configs
        },
    }

    return {
        "metadata": {
            "batch_name": manifest.get("batch_name", "adv-batch-v1"),
            "manifest_hash_sha256": manifest.get("manifest_hash_sha256", ""),
            "analyzer_v1": "Person_A/ast_analyzer/analyzer_v1_frozen.py",
            "analyzer_v1_1": "Person_A/ast_analyzer/analyzer_v1_1.py",
            "normalizer": "spider/normalize.py",
        },
        "summary": summary,
        "by_technique": by_technique,
        "per_sample": per_sample_results,
    }


def generate_markdown_report(report_data: Dict[str, Any]) -> str:
    summary = report_data["summary"]
    by_tech = report_data["by_technique"]
    per_sample = report_data["per_sample"]
    totals = summary["overall_counts"]
    asr = summary["miss_rates_asr"]
    rec = summary["recovered_rates"]

    md = []
    md.append("# SPIDER Evasion & Defense Comparison: AST v1 vs v1.1 vs Normalization")
    md.append("")
    md.append(f"**Frozen Adversarial Batch:** `{report_data['metadata']['batch_name']}`  ")
    md.append(f"**Manifest SHA-256:** `{report_data['metadata']['manifest_hash_sha256']}`  ")
    md.append(f"**Total Adversarial Samples:** {summary['total_samples']}  ")
    md.append("")
    md.append("---")
    md.append("")
    md.append("## 1. Executive Summary & Attack Success Rate (ASR)")
    md.append("")
    md.append("| Detector Pipeline | Recovered (Exact Match) | Different Signal (Partial) | Missed (Evaded) | Evasion Rate (ASR) |")
    md.append("| :--- | :---: | :---: | :---: | :---: |")

    names = {
        "v1": "Baseline AST Analyzer (`v1 frozen`)",
        "v1_1": "Hardened AST Analyzer (`v1.1`)",
        "v1_normalized": "AST `v1` + `normalize.py`",
        "v1_1_normalized": "AST `v1.1` + `normalize.py` (Full Defense)",
    }

    for c in ["v1", "v1_1", "v1_normalized", "v1_1_normalized"]:
        t = totals[c]
        md.append(f"| **{names[c]}** | {t['recovered']} ({rec[c]}%) | {t['different_signal']} | **{t['missed']}** | **{asr[c]}%** |")

    md.append("")
    md.append("---")
    md.append("")
    md.append("## 2. Per-Technique Breakdown")
    md.append("")
    md.append("| Technique | v1 (Rec/Diff/Miss) | v1.1 (Rec/Diff/Miss) | v1 + Norm (Rec/Diff/Miss) | v1.1 + Norm (Rec/Diff/Miss) |")
    md.append("| :--- | :---: | :---: | :---: | :---: |")

    for tech, counts in sorted(by_tech.items()):
        v1_s = f"{counts['v1']['recovered']}/{counts['v1']['different_signal']}/{counts['v1']['missed']}"
        v11_s = f"{counts['v1_1']['recovered']}/{counts['v1_1']['different_signal']}/{counts['v1_1']['missed']}"
        v1n_s = f"{counts['v1_normalized']['recovered']}/{counts['v1_normalized']['different_signal']}/{counts['v1_normalized']['missed']}"
        v11n_s = f"{counts['v1_1_normalized']['recovered']}/{counts['v1_1_normalized']['different_signal']}/{counts['v1_1_normalized']['missed']}"
        md.append(f"| `{tech}` | {v1_s} | {v11_s} | {v1n_s} | **{v11n_s}** |")

    md.append("")
    md.append("---")
    md.append("")
    md.append("## 3. Detailed Per-Sample Evaluation Log")
    md.append("")
    md.append("| ID | Technique | Description | v1 Outcome | v1.1 Outcome | v1.1+Norm Outcome |")
    md.append("| :--- | :--- | :--- | :---: | :---: | :---: |")

    for s in per_sample:
        v1_out = s["v1"]["outcome"]
        v11_out = s["v1_1"]["outcome"]
        v11n_out = s["v1_1_normalized"]["outcome"]
        md.append(f"| `{s['sample_id']}` | `{s['technique']}` | {s['description']} | `{v1_out}` | `{v11_out}` | **`{v11n_out}`** |")

    md.append("")
    md.append("---")
    md.append("")
    md.append("## 4. Key Security Findings")
    md.append(
        "- **Direct AST Bypasses in v1:** `getattr(os, ...)` and `__import__` reliably blind baseline "
        f"`v1` (ASR = {asr['v1']}%)."
    )
    md.append("- **Rule Hardening in v1.1:** `v1.1` successfully catches obfuscation indicators (`obf.fromhex`, `obf.chr_join`, `base64`), lowering pure miss rates and converting evasions to `different_signal`.")
    md.append("- **Defense Recovery via Normalization:** Adding deterministic AST normalization (`spider/normalize.py`) folds string concatenations, resolves import aliases, and converts 2-arg `getattr` into standard attribute calls, recovering original call signatures before rules fire.")
    md.append("")
    return "\n".join(md)


def main():
    manifest_path = Path(__file__).resolve().parent / "adv_batch" / "manifest.json"
    if not manifest_path.exists():
        print(f"Error: {manifest_path} not found. Run freeze_batch.py first.")
        sys.exit(1)

    table = build_evaluation_table(manifest_path)

    # Write JSON results
    out_json = REPO_ROOT / "results" / "evasion_table_v1_vs_v11.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(table, f, indent=2)

    # Write Markdown results
    md_content = generate_markdown_report(table)
    out_md = REPO_ROOT / "results" / "evasion_table_v1_vs_v11.md"
    with open(out_md, "w", encoding="utf-8") as f:
        f.write(md_content)

    # Remove mock file if it exists
    old_mock = REPO_ROOT / "results" / "evasion_table_day4_MOCK.json"
    if old_mock.exists():
        old_mock.unlink()

    # Print summary to console
    print("=" * 70)
    print("SPIDER EVASION EVALUATION: AST v1 vs v1.1 vs Normalization")
    print(f"Manifest Hash: {table['summary']['manifest_hash_sha256']}")
    print(f"Total Samples: {table['summary']['total_samples']}")
    print("=" * 70)
    for c, counts in table["summary"]["overall_counts"].items():
        asr = table["summary"]["miss_rates_asr"][c]
        rec = table["summary"]["recovered_rates"][c]
        print(f"{c:<20} -> Recovered: {counts['recovered']:2d} ({rec:5.1f}%) | Diff: {counts['different_signal']:2d} | Missed: {counts['missed']:2d} | ASR: {asr:5.1f}%")
    print("=" * 70)
    print(f"Wrote JSON table to: {out_json}")
    print(f"Wrote Markdown report to: {out_md}")


if __name__ == "__main__":
    main()
