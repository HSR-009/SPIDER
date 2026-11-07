#!/usr/bin/env python
"""
Person_A/pipeline/verify_adv_batch.py
------------------------------------
Verification of Person C's frozen adversarial batch (adv-batch-v1).

Arguments:
  --batch-dir : Path to directory containing manifest.json and samples/
  --c-table   : Path to C's results/evasion_table_v1_vs_v11.json
  --out       : Output markdown path (results/adv_batch_verification_by_A.md)

Functionality:
1. Manifest integrity:
   - Computes SHA-256 of manifest.json as raw bytes.
   - Computes SHA-256 of canonical JSON (sorted keys).
   - Computes SHA-256 of JSON excluding 'manifest_hash_sha256' key (C's freeze_batch method).
   - Compares with published target hash (bb7f4fe8...aaa3) and reports which matches.
   - Checks that each samples/adv_*.py file equals manifest's generated_code, reporting any differing samples.
2. Evaluates each sample against:
   - Frozen v1 analyzer (Person_A/ast_analyzer/analyzer_v1_frozen.py)
   - Real v1.1 engine (spider.engine.scan.scan_directory)
   - Evaluates baseline vs transformed sample using Person C's 3-outcome classification:
     * recovered: Transformed sample produced at least one finding matching (category, indicator)
       of the baseline source.
     * different_signal: Transformed sample produced findings, but none matching the baseline's
       exact (category, indicator).
     * missed: Transformed sample produced zero findings (complete evasion).
3. Evaluates real v1.1 engine verdict level:
   - Baseline verdict, adversarial verdict, reasons, review_recommended.
   - Summarizes counts of suspicious, review-kept, and silent adversarial samples.
4. Calling convention:
   - Always names finding-level percentages as "finding-level evasion rate" (with note that it is
     not a detection rate).
5. Disagreements:
   - Fully computed from data; no hardcoded claim paragraphs.
6. Appends an empty ## Interpretation (to be written by a human) section.
"""

import argparse
import hashlib
import json
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Person_A.ast_analyzer.analyzer_v1_frozen import analyze_file as v1_analyze_file
from spider.engine.scan import scan_directory
from spider_contract.adapter import to_legacy

DEFAULT_BATCH_DIR = ROOT / "person_c" / "adv_batch"
DEFAULT_C_TABLE = ROOT / "results" / "evasion_table_v1_vs_v11.json"
DEFAULT_OUT_MD = ROOT / "results" / "adv_batch_verification_by_A.md"
PUBLISHED_HASH = "bb7f4fe8676000ef1e2f06e08d8387738e8ee4a3c33ac68ade289ffd8875aaa3"


def compute_hashes(manifest_bytes: bytes, manifest_obj: dict):
    raw_sha = hashlib.sha256(manifest_bytes).hexdigest()

    canon_bytes = json.dumps(manifest_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    canon_sha = hashlib.sha256(canon_bytes).hexdigest()

    obj_without = dict(manifest_obj)
    obj_without.pop("manifest_hash_sha256", None)
    c_freeze_raw = json.dumps(obj_without, indent=2, sort_keys=True).encode("utf-8")
    c_freeze_sha = hashlib.sha256(c_freeze_raw).hexdigest()

    return {
        "raw_bytes": raw_sha,
        "canonical_json": canon_sha,
        "freeze_batch_method": c_freeze_sha,
    }


def run_analyzer_v1(source_code: str):
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tmp:
        tmp.write(source_code)
        tmp_path = tmp.name
    try:
        raw = v1_analyze_file(tmp_path)
        return [f for f in raw if f.get("category") != "Parse Error"]
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def run_v11_engine_scan(source_code: str):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "sample.py")
        with open(p, "w", encoding="utf-8") as f:
            f.write(source_code)
        rec = scan_directory(d)
        legacy = to_legacy(rec)
        findings = [f for f in legacy if f.get("category") != "Parse Error"]
        verdict = rec["verdict"]["outcome"]
        reasons = rec["verdict"].get("reasons", [])
        review_recommended = rec["verdict"].get("review_recommended", False)
        return {
            "findings": findings,
            "verdict": verdict,
            "reasons": reasons,
            "review_recommended": review_recommended,
            "record": rec,
        }


def classify_outcome(baseline_findings, candidate_findings):
    if not candidate_findings:
        return "missed"
    base_sig = {(f["category"], f["indicator"]) for f in baseline_findings}
    cand_sig = {(f["category"], f["indicator"]) for f in candidate_findings}
    if base_sig & cand_sig:
        return "recovered"
    return "different_signal"


def verify_batch(batch_dir, c_table_path, out_md_path):
    batch_dir = Path(batch_dir)
    manifest_file = batch_dir / "manifest.json"

    if not manifest_file.exists():
        sys.exit(f"ERROR: manifest.json not found in batch dir: {batch_dir}")

    manifest_bytes = manifest_file.read_bytes()
    manifest_obj = json.loads(manifest_bytes.decode("utf-8"))

    hashes = compute_hashes(manifest_bytes, manifest_obj)
    print("Computed Manifest SHA-256 Hashes:")
    print(f"  Raw bytes: {hashes['raw_bytes']}")
    print(f"  Canonical JSON: {hashes['canonical_json']}")
    print(f"  freeze_batch method: {hashes['freeze_batch_method']}")
    print(f"  Published target: {PUBLISHED_HASH}")

    matching_hash_method = None
    for method, h in hashes.items():
        if h == PUBLISHED_HASH:
            matching_hash_method = method
            break

    # Check sample files vs manifest generated_code
    differing_samples = []
    missing_samples = []
    entries = manifest_obj.get("entries", [])

    for entry in entries:
        sid = entry["sample_id"]
        rel_path = entry.get("source_file", f"samples/{sid}.py")
        sample_path = batch_dir / rel_path
        if not sample_path.exists():
            missing_samples.append(sid)
            continue
        file_content = sample_path.read_text(encoding="utf-8")
        if file_content != entry.get("generated_code"):
            differing_samples.append(sid)

    # Load C's published table if present
    c_table = None
    c_per_sample = {}
    c_table_p = Path(c_table_path)
    if c_table_p.exists():
        c_table = json.loads(c_table_p.read_text(encoding="utf-8"))
        for item in c_table.get("per_sample", []):
            c_per_sample[item["sample_id"]] = item

    results_rows = []
    summary_counts = {
        "v1": Counter(),
        "v1_1": Counter(),
    }
    verdict_counts = {
        "suspicious": 0,
        "review_recommended": 0,
        "silent": 0,
    }

    for entry in entries:
        sid = entry["sample_id"]
        tech = entry["technique"]
        base_src = entry["baseline_source"]
        gen_src = entry["generated_code"]

        # Run v1 finding-level
        base_v1 = run_analyzer_v1(base_src)
        gen_v1 = run_analyzer_v1(gen_src)
        outcome_v1 = classify_outcome(base_v1, gen_v1)
        summary_counts["v1"][outcome_v1] += 1

        # Run v1.1 engine finding-level & verdict-level
        base_v11_scan = run_v11_engine_scan(base_src)
        gen_v11_scan = run_v11_engine_scan(gen_src)

        outcome_v11 = classify_outcome(base_v11_scan["findings"], gen_v11_scan["findings"])
        summary_counts["v1_1"][outcome_v11] += 1

        # Verdict-level metrics
        adv_verd = gen_v11_scan["verdict"]
        adv_reasons = gen_v11_scan["reasons"]
        adv_review = gen_v11_scan["review_recommended"]
        base_verd = base_v11_scan["verdict"]

        if adv_verd == "suspicious":
            verdict_counts["suspicious"] += 1
        elif adv_review:
            verdict_counts["review_recommended"] += 1
        else:
            verdict_counts["silent"] += 1

        # Comparison with C table
        c_item = c_per_sample.get(sid, {})
        c_v1_out = c_item.get("v1", {}).get("outcome", "N/A")
        c_v11_out = c_item.get("v1_1", {}).get("outcome", "N/A")

        agree_v1 = (outcome_v1 == c_v1_out) if c_v1_out != "N/A" else None
        agree_v11 = (outcome_v11 == c_v11_out) if c_v11_out != "N/A" else None

        results_rows.append({
            "sample_id": sid,
            "technique": tech,
            "outcome_v1": outcome_v1,
            "c_v1": c_v1_out,
            "agree_v1": agree_v1,
            "outcome_v11": outcome_v11,
            "c_v11": c_v11_out,
            "agree_v11": agree_v11,
            "baseline_verdict": base_verd,
            "adversarial_verdict": adv_verd,
            "adversarial_reasons": adv_reasons,
            "review_recommended": adv_review,
        })

    # Prepare Markdown Report
    lines = [
        "# Adversarial Batch Verification Report (Person A)",
        "",
        "## 1. Manifest & File Integrity Verification",
        f"- **Published Manifest Hash**: `{PUBLISHED_HASH}`",
        f"- **Computed Raw Bytes Hash**: `{hashes['raw_bytes']}`",
        f"- **Computed Canonical JSON Hash**: `{hashes['canonical_json']}`",
        f"- **Computed Hash via `freeze_batch.py` Method**: `{hashes['freeze_batch_method']}`",
    ]

    if matching_hash_method:
        lines.append(f"- **Hash Match Status**: **MATCH** (matches via `{matching_hash_method}`).")
    else:
        lines.append("- **Hash Match Status**: **MISMATCH**.")

    lines.append(f"- **Sample Files Integrity Check** (matching `samples/adv_*.py` to manifest `generated_code`):")
    if missing_samples:
        lines.append(f"  - Missing sample files: {', '.join(missing_samples)}")
    if differing_samples:
        lines.append(f"  - Differing sample files: {', '.join(differing_samples)}")
    if not missing_samples and not differing_samples:
        lines.append(f"  - All {len(entries)} sample files in `samples/` exactly match manifest `generated_code`.")

    lines.extend([
        "",
        "## 2. Per-Sample Verification Table (Finding-Level and Engine Verdict-Level)",
        "",
        "| Sample ID | Technique | A v1 | C v1 | Agree v1 | A v1.1 | C v1.1 | Agree v1.1 | Baseline Verdict | Adv Verdict | Adv Reasons | Review Rec |",
        "|---|---|---|---|:---:|---|---|:---:|---|---|---|:---:|",
    ])

    disagreements = []
    for r in results_rows:
        ag_v1_str = "YES" if r["agree_v1"] else ("NO" if r["agree_v1"] is False else "N/A")
        ag_v11_str = "YES" if r["agree_v11"] else ("NO" if r["agree_v11"] is False else "N/A")
        if r["agree_v1"] is False:
            disagreements.append(f"{r['sample_id']} v1: A={r['outcome_v1']} vs C={r['c_v1']}")
        if r["agree_v11"] is False:
            disagreements.append(f"{r['sample_id']} v1.1: A={r['outcome_v11']} vs C={r['c_v11']}")

        reas_str = ", ".join(r["adversarial_reasons"]) or "none"
        rev_str = "True" if r["review_recommended"] else "False"

        lines.append(
            f"| `{r['sample_id']}` | `{r['technique']}` | `{r['outcome_v1']}` | `{r['c_v1']}` | {ag_v1_str} | `{r['outcome_v11']}` | `{r['c_v11']}` | {ag_v11_str} | `{r['baseline_verdict']}` | `{r['adversarial_verdict']}` | `{reas_str}` | {rev_str} |"
        )

    tot = len(results_rows) or 1
    v1_miss_cnt = summary_counts["v1"]["missed"]
    v1_miss_pct = (v1_miss_cnt / tot) * 100
    v11_miss_cnt = summary_counts["v1_1"]["missed"]
    v11_miss_pct = (v11_miss_cnt / tot) * 100

    lines.extend([
        "",
        "## 3. Finding-Level Summary",
        "",
        "> [!NOTE]",
        "> Note: Finding-level evasion rate measures whether the specific baseline indicator or an auxiliary finding fired; it is a feature-level metric, not a package detection rate.",
        "",
        "| Analyzer | Recovered | Different Signal | Missed (Evaded) | Finding-Level Evasion Rate |",
        "|---|---:|---:|---:|---:|",
        f"| **Frozen v1 (`analyzer_v1_frozen.py`)** | {summary_counts['v1']['recovered']} | {summary_counts['v1']['different_signal']} | {v1_miss_cnt} | **{v1_miss_pct:.2f}%** |",
        f"| **Hardened v1.1 (`spider.engine.scan`)** | {summary_counts['v1_1']['recovered']} | {summary_counts['v1_1']['different_signal']} | {v11_miss_cnt} | **{v11_miss_pct:.2f}%** |",
        "",
        "## 4. Real v1.1 Engine Verdict-Level Summary",
        "",
        "| Verdict Classification | Sample Count | Percentage of Batch |",
        "|---|---:|---:|",
        f"| **Suspicious** (strong signal triggered) | {verdict_counts['suspicious']} | {(verdict_counts['suspicious'] / tot * 100):.1f}% |",
        f"| **Review-Kept** (`none_detected_in_this_scan` with `review_recommended: true`) | {verdict_counts['review_recommended']} | {(verdict_counts['review_recommended'] / tot * 100):.1f}% |",
        f"| **Silent** (`none_detected_in_this_scan` without review) | {verdict_counts['silent']} | {(verdict_counts['silent'] / tot * 100):.1f}% |",
        "",
        "## 5. Comparison with Person C Published Data",
    ])

    lines.append(f"- **Measured v1 Misses**: {v1_miss_cnt} of {tot} samples ({v1_miss_pct:.2f}% finding-level evasion rate).")
    lines.append(f"- **Measured v1.1 Misses**: {v11_miss_cnt} of {tot} samples ({v11_miss_pct:.2f}% finding-level evasion rate).")

    if c_table:
        c_summary = c_table.get("summary", {})
        c_v1_counts = c_summary.get("overall_counts", {}).get("v1", {})
        c_v1_miss = c_v1_counts.get("missed")
        c_v1_rate = c_summary.get("miss_rates_asr", {}).get("v1")

        lines.append(f"- **Person C Published v1 Counts**: recovered={c_v1_counts.get('recovered')}, different_signal={c_v1_counts.get('different_signal')}, missed={c_v1_miss} (finding-level evasion rate: {c_v1_rate}%).")

        # Discrepancy checks from data
        if c_v1_miss is not None and c_v1_miss != v1_miss_cnt:
            lines.append(f"- **Discrepancy Detected**: Measured v1 missed count ({v1_miss_cnt}) differs from C table missed count ({c_v1_miss}).")
        else:
            lines.append("- **v1 Count Match**: Measured v1 counts exactly match C table summary.")

        if disagreements:
            lines.append(f"- **Sample-Level Disagreements**: {len(disagreements)} ({'; '.join(disagreements)}).")
        else:
            lines.append("- **Sample-Level Agreement**: 100% agreement between A's evaluation and C's published per-sample outcomes.")
    else:
        lines.append("- Person C published table file was not found; could not perform automated discrepancy comparison.")

    lines.extend([
        "",
        "## Interpretation (to be written by a human)",
        "",
        "<!-- TO BE WRITTEN BY HUMAN AFTER REVIEWING THE DATA -->",
    ])

    out_p = Path(out_md_path)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text("\n".join(lines), encoding="utf-8")
    print(f"Verification report written to: {out_p}")
    return results_rows, summary_counts, hashes, verdict_counts, differing_samples


def main():
    parser = argparse.ArgumentParser(description="Verify Person C frozen adv batch (adv-batch-v1)")
    parser.add_argument("--batch-dir", default=str(DEFAULT_BATCH_DIR))
    parser.add_argument("--c-table", default=str(DEFAULT_C_TABLE))
    parser.add_argument("--out", default=str(DEFAULT_OUT_MD))
    args = parser.parse_args()

    verify_batch(args.batch_dir, args.c_table, args.out)


if __name__ == "__main__":
    main()
