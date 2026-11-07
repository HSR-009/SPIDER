#!/usr/bin/env python
"""
Person_A/pipeline/evasion_check.py
----------------------------------
Adversarial evasion evaluation against the REAL v1.1 engine:

Part A: C's Seeds & Harness Evaluation
- Runs Person C's seeds (person_c/seeds) and harness transformations (T01 to T09)
  against the real v1.1 engine (spider.engine.scan / analyzer_v1_1.py + verdict_v2).
- Reports counts of recovered, different_signal, and missed per technique.
- Reads Person C's published baseline numbers directly from person_c/baseline_results.md
  and compares differences.

Part B: Real Package Targeted Evasion Evaluation (Runs on Kali)
- For 20 malicious and 20 benign packages with strong signals in the v11 tables (seed 42):
- Resolves raw archives from --benign-raw and --mal-raw.
- Applies ONLY T02 (base64), T03 (rot13), and T05 (delayed trigger) to the specific file(s)
  that hold the strong-signal findings from the original scan.
- Leaves all other files in the archive unchanged and never replaces a whole file with a generated snippet.
- Scores strictly by verdict and strong-signal IDs:
  - recovered: The same strong-signal ID(s) still fire.
  - different_signal: Verdict is still suspicious, but via different strong-signal IDs.
  - missed: Verdict is no longer suspicious.

Writes results/evasion_check_by_A.md containing Part A and Part B tables,
and an empty "## Interpretation (to be written by a human after reviewing the data)" section.
"""

import argparse
import gzip
import json
import os
import random
import re
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import person_c.disguises as disguises
import person_c.transformations_ext as transformations_ext
from spider.engine.extract import safe_extract
from spider.engine.scan import scan_directory

DEFAULT_BENIGN_TABLE = ROOT / "data" / "processed" / "benign_v11.jsonl.gz"
DEFAULT_MAL_TABLE = ROOT / "data" / "processed" / "malicious_v11.jsonl"
DEFAULT_BENIGN_RAW = ROOT / "data" / "raw" / "benign" / "archives"
DEFAULT_MAL_RAW = ROOT / "data" / "raw" / "malicious" / "pypi"
DEFAULT_OUT_MD = ROOT / "results" / "evasion_check_by_A.md"
C_BASELINE_FILE = ROOT / "person_c" / "baseline_results.md"


def read_c_baseline_results(baseline_path=C_BASELINE_FILE):
    """
    Parses Person C's baseline results from person_c/baseline_results.md.
    Returns {technique_name: {"total": int, "detected": int, "evaded": int, "evasion_rate": str}}.
    """
    p = Path(baseline_path)
    if not p.exists():
        return {}

    content = p.read_text(encoding="utf-8")
    table_rows = re.findall(r"\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|", content)

    results = defaultdict(lambda: {"total": 0, "detected": 0, "evaded": 0})
    for sample, tech, res in table_rows:
        sample = sample.strip()
        tech = tech.strip()
        res = res.strip()
        if sample.startswith("---") or sample.lower() == "sample":
            continue
        results[tech]["total"] += 1
        if "evasion" in res.lower() or "success" in res.lower():
            results[tech]["evaded"] += 1
        else:
            results[tech]["detected"] += 1

    summary = {}
    for tech, counts in results.items():
        tot = counts["total"]
        ev = counts["evaded"]
        rate = f"{(ev / tot * 100):.1f}%" if tot > 0 else "0.0%"
        summary[tech] = {
            "total": tot,
            "detected": counts["detected"],
            "evaded": ev,
            "evasion_rate": rate,
        }
    return summary


def score_verdict_and_signal(orig_verdict, orig_strong, trans_verdict, trans_strong):
    """
    Scoring strictly by verdict and strong-signal IDs:
    - recovered: The same strong-signal ID(s) still fire.
    - different_signal: Verdict is still suspicious, but via different strong-signal IDs.
    - missed: Verdict is no longer suspicious.
    """
    if trans_verdict != "suspicious":
        return "missed"

    if orig_strong and set(orig_strong).intersection(set(trans_strong)):
        return "recovered"
    else:
        return "different_signal"


def evaluate_part_a_seeds(seeds_dir=ROOT / "person_c" / "seeds"):
    """
    Part A: Runs Person C's seeds and T01-T09 transformations against the real v1.1 engine.
    """
    seeds_path = Path(seeds_dir)
    seed_files = sorted(seeds_path.glob("seed_*.py")) if seeds_path.exists() else []

    techniques = [
        ("T01_string_split", lambda c: "import os\nos.system(" + disguises.string_split_disguise('"whoami"') + ")\n" if "system" in c else c),
        ("T02_base64", disguises.base64_disguise),
        ("T03_rot13", disguises.rot13_disguise),
        ("T04_getattr", lambda c: disguises.getattr_disguise("os", "system", '"whoami"') if "system" in c else disguises.getattr_disguise("subprocess", "run", '["whoami"]')),
        ("T05_delay", lambda c: disguises.delay_disguise(c, 3)),
        ("T06_import_alias", lambda c: transformations_ext.import_alias_disguise("os", "system", '"whoami"', alias="_alias_os")),
        ("T07_dunder_import", lambda c: transformations_ext.dunder_import_disguise("os", "system", '"whoami"')),
        ("T08_chr_build", lambda c: "fn = " + transformations_ext.chr_build_disguise("system") + "\ngetattr(os, fn)('whoami')\n"),
        ("T09_hex_escape", lambda c: "fn = " + transformations_ext.hex_escape_disguise("system") + "\ngetattr(os, fn)('whoami')\n"),
    ]

    stats = {
        tid: {"recovered": 0, "different_signal": 0, "missed": 0, "total": 0}
        for tid, _ in techniques
    }

    for sf in seed_files:
        src = sf.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "seed.py").write_text(src, encoding="utf-8")
            base_rec = scan_directory(d)
            base_verd = base_rec["verdict"]["outcome"]
            base_reasons = base_rec["verdict"].get("reasons", [])

        for tid, trans_fn in techniques:
            try:
                trans_src = trans_fn(src)
            except Exception:
                trans_src = src

            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "trans.py").write_text(trans_src, encoding="utf-8")
                trans_rec = scan_directory(d)
                trans_verd = trans_rec["verdict"]["outcome"]
                trans_reasons = trans_rec["verdict"].get("reasons", [])

            outcome = score_verdict_and_signal(base_verd, base_reasons, trans_verd, trans_reasons)
            stats[tid][outcome] += 1
            stats[tid]["total"] += 1

    return stats


def load_packages_with_strong_signals(table_path):
    p = Path(table_path)
    if not p.exists():
        return []
    opener = gzip.open if p.suffix == ".gz" else open
    rows = []
    with opener(p, "rt", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                r = json.loads(line)
                if r.get("strong_signals"):
                    rows.append(r)
    return rows


def find_archive(raw_dir, pkg_name, ver, archive_used=None):
    raw_path = Path(raw_dir)
    if not raw_path.exists():
        return None

    if archive_used:
        cand = raw_path / Path(archive_used).name
        if cand.is_file():
            return cand
        parts = Path(archive_used).parts
        if "pypi" in parts:
            idx = parts.index("pypi")
            cand2 = raw_path.joinpath(*parts[idx + 1:])
            if cand2.is_file():
                return cand2

    for d in (raw_path / pkg_name / ver, raw_path / pkg_name, raw_path):
        if d.is_dir():
            for ext in (".tar.gz", ".tgz", ".zip", ".whl"):
                for cand in d.glob(f"*{ext}"):
                    if cand.is_file() and (pkg_name.lower() in cand.name.lower()):
                        return cand
    return None


def apply_part_b_transformations(archive_path, strong_findings_files, orig_strong):
    """
    Part B: Extracts archive into a temp directory.
    Applies ONLY T02, T03, and T05 to the specific file(s) that hold the
    strong-signal findings. Leaves all other files unchanged.
    """
    transforms = [
        ("T02_base64", disguises.base64_disguise),
        ("T03_rot13", disguises.rot13_disguise),
        ("T05_delay", lambda c: disguises.delay_disguise(c, 3)),
    ]

    results = {}

    for tid, trans_fn in transforms:
        with tempfile.TemporaryDirectory() as extract_dir:
            safe_extract(str(archive_path), extract_dir)
            extract_path = Path(extract_dir)

            # Locate the exact files holding the strong signal findings
            modified_any = False
            for rel_file in strong_findings_files:
                target_file = extract_path / rel_file
                if not target_file.is_file():
                    # Check without top folder
                    parts = Path(rel_file).parts
                    if len(parts) > 1:
                        target_file = extract_path.joinpath(*parts[1:])

                if target_file.is_file():
                    orig_code = target_file.read_text(encoding="utf-8", errors="replace")
                    trans_code = trans_fn(orig_code)
                    target_file.write_text(trans_code, encoding="utf-8")
                    modified_any = True

            # Rescan modified archive directory
            rec = scan_directory(extract_dir)
            trans_verd = rec["verdict"]["outcome"]
            trans_strong = rec["verdict"].get("reasons", [])

            if not modified_any:
                outcome = "missed"
            else:
                outcome = score_verdict_and_signal("suspicious", orig_strong, trans_verd, trans_strong)

            results[tid] = outcome

    return results


def run_evasion_check(
    benign_table=DEFAULT_BENIGN_TABLE,
    mal_table=DEFAULT_MAL_TABLE,
    benign_raw=DEFAULT_BENIGN_RAW,
    mal_raw=DEFAULT_MAL_RAW,
    out_md=DEFAULT_OUT_MD,
    seed=42,
    sample_size=20,
):
    # --- Part A: C's Seeds & Harness ---
    print("Running Part A: Evaluating Person C seeds against real v1.1 engine...")
    part_a_stats = evaluate_part_a_seeds()
    c_baseline = read_c_baseline_results()

    # --- Part B: Real Packages Targeted Evasion ---
    print(f"Running Part B: Sampling {sample_size} benign and {sample_size} malicious strong-signal packages...")
    ben_rows = load_packages_with_strong_signals(benign_table)
    mal_rows = load_packages_with_strong_signals(mal_table)

    rng = random.Random(seed)
    sampled_ben = rng.sample(ben_rows, min(sample_size, len(ben_rows))) if ben_rows else []
    sampled_mal = rng.sample(mal_rows, min(sample_size, len(mal_rows))) if mal_rows else []

    # Verify raw archives exist on Kali
    missing_ben = []
    resolved_ben = []
    for r in sampled_ben:
        arc = find_archive(benign_raw, r["package_name"], r["version"], r.get("archive_used"))
        if arc:
            resolved_ben.append((r, arc))
        else:
            missing_ben.append(r["package_id"])

    missing_mal = []
    resolved_mal = []
    for r in sampled_mal:
        arc = find_archive(mal_raw, r["package_name"], r["version"], r.get("archive_used"))
        if arc:
            resolved_mal.append((r, arc))
        else:
            missing_mal.append(r["package_id"])

    if len(resolved_ben) < sample_size or len(resolved_mal) < sample_size:
        sys.exit(
            f"ERROR: Insufficient raw archives found for Part B evasion check!\n"
            f"  Benign resolved: {len(resolved_ben)}/{sample_size} (missing: {len(missing_ben)})\n"
            f"  Malicious resolved: {len(resolved_mal)}/{sample_size} (missing: {len(missing_mal)})\n"
            f"This script runs on Kali where raw archives exist under --raw-dir."
        )

    part_b_stats = {
        tech: {"benign": Counter(), "malicious": Counter()}
        for tech in ("T02_base64", "T03_rot13", "T05_delay")
    }

    # Evaluate Benign
    for r, arc in resolved_ben:
        strong_files = {f["file"] for f in r.get("findings", []) if f.get("category") != "Parse Error"}
        res = apply_part_b_transformations(arc, strong_files, r.get("strong_signals", []))
        for tech, outcome in res.items():
            part_b_stats[tech]["benign"][outcome] += 1

    # Evaluate Malicious
    for r, arc in resolved_mal:
        strong_files = {f["file"] for f in r.get("findings", []) if f.get("category") != "Parse Error"}
        res = apply_part_b_transformations(arc, strong_files, r.get("strong_signals", []))
        for tech, outcome in res.items():
            part_b_stats[tech]["malicious"][outcome] += 1

    # --- Write Markdown Report ---
    out_path = Path(out_md)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Adversarial Evasion Check Report (Person A)",
        "",
        "## Part A — Evaluation of Person C's Seeds & Harness against v1.1 Engine",
        "",
        "Evaluated Person C's 20 seeds across T01–T09 using the real v1.1 engine (`spider.engine.scan` + `verdict_v2`).",
        "Comparison numbers from Person C's baseline are loaded directly from `person_c/baseline_results.md`.",
        "",
        "| Technique ID | Description | Total Tests | Recovered | Different Signal | Missed | v1.1 Missed % | Person C Published Missed % | Difference |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]

    c_name_map = {
        "T01_string_split": "String Split",
        "T02_base64": "Base64",
        "T03_rot13": "ROT13",
        "T04_getattr": "getattr",
        "T05_delay": "Delayed Trigger",
    }

    for tid, counts in sorted(part_a_stats.items()):
        tot = counts["total"]
        miss = counts["missed"]
        miss_rate = (miss / tot * 100) if tot > 0 else 0.0

        c_tech_key = c_name_map.get(tid)
        c_info = c_baseline.get(c_tech_key, {})
        c_rate_str = c_info.get("evasion_rate", "N/A")

        diff_str = "N/A"
        if "%" in c_rate_str:
            c_val = float(c_rate_str.replace("%", ""))
            diff_val = miss_rate - c_val
            diff_str = f"{diff_val:+.1f}%"

        lines.append(
            f"| **{tid.split('_')[0]}** | {tid} | {tot} | {counts['recovered']} | {counts['different_signal']} | {miss} | {miss_rate:.1f}% | {c_rate_str} | {diff_str} |"
        )

    lines.extend([
        "",
        "## Part B — Real Package Targeted Evasion (T02, T03, T05)",
        "",
        f"Evaluated on 20 benign and 20 malicious strong-signal packages sampled from v1.1 tables (seed {seed}).",
        "Transformations applied ONLY to the specific file(s) triggering the strong-signal findings.",
        "Scoring strictly by verdict and strong-signal IDs (recovered / different_signal / missed).",
        "",
        "| Technique ID | Benign (Rec / Diff / Miss) | Malicious (Rec / Diff / Miss) | Total Missed | Overall Missed % |",
        "|---|---|---|---:|---:|",
    ])

    for tech, classes in sorted(part_b_stats.items()):
        b_rec = classes["benign"]["recovered"]
        b_diff = classes["benign"]["different_signal"]
        b_miss = classes["benign"]["missed"]

        m_rec = classes["malicious"]["recovered"]
        m_diff = classes["malicious"]["different_signal"]
        m_miss = classes["malicious"]["missed"]

        tot_miss = b_miss + m_miss
        tot = (b_rec + b_diff + b_miss + m_rec + m_diff + m_miss) or 1
        pct = (tot_miss / tot) * 100

        lines.append(
            f"| **{tech}** | {b_rec} / {b_diff} / {b_miss} | {m_rec} / {m_diff} / {m_miss} | {tot_miss} | {pct:.1f}% |"
        )

    lines.extend([
        "",
        "## Interpretation (to be written by a human after reviewing the data)",
        "",
        "<!-- TO BE WRITTEN BY HUMAN AFTER REVIEWING THE DATA -->",
    ])

    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Evasion check report written to: {out_md}")


def main():
    parser = argparse.ArgumentParser(description="Adversarial Evasion Check (Part A seeds & Part B real archives, runs on Kali)")
    parser.add_argument("--benign-table", default=str(DEFAULT_BENIGN_TABLE))
    parser.add_argument("--mal-table", default=str(DEFAULT_MAL_TABLE))
    parser.add_argument("--benign-raw", default=str(DEFAULT_BENIGN_RAW))
    parser.add_argument("--mal-raw", default=str(DEFAULT_MAL_RAW))
    parser.add_argument("--out-md", default=str(DEFAULT_OUT_MD))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--sample-size", type=int, default=20)
    args = parser.parse_args()

    run_evasion_check(
        benign_table=args.benign_table,
        mal_table=args.mal_table,
        benign_raw=args.benign_raw,
        mal_raw=args.mal_raw,
        out_md=args.out_md,
        seed=args.seed,
        sample_size=args.sample_size,
    )


if __name__ == "__main__":
    main()
