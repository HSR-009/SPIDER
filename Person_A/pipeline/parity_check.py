#!/usr/bin/env python
"""Rule-parity check: re-scan a random sample of benign archives through the REAL scanner path
(run_malicious_scan.scan_version -> analyze_file) and compare with benign_for_b.jsonl. Read-only.
Works with a flat folder of archives (data/raw/benign/archives/*.tar.gz|*.whl|...) or name/version folders."""
import json, random, re, shutil, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BEN = ROOT / "data/processed/benign_for_b.jsonl"
RAW = ROOT / "data/raw/benign"
EXTS = (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tar", ".zip", ".whl")
N = 60

def norm(n): return re.sub(r"[-_.]+", "-", str(n).strip()).lower()

def parse(fn):
    low = fn.lower()
    for ext in EXTS:
        if low.endswith(ext):
            base = fn[: -len(ext)]
            if ext == ".whl":
                parts = base.split("-")
                return (norm(parts[0]), parts[1]) if len(parts) >= 2 else None
            name, _, ver = base.rpartition("-")
            return (norm(name), ver) if name else None
    return None

sys.path.insert(0, str(ROOT / "Person_A/pipeline"))
import run_malicious_scan as sc

files = {}
for p in RAW.rglob("*"):
    if p.is_file():
        k = parse(p.name)
        if k: files.setdefault(k, []).append(p)
ben = [json.loads(l) for l in open(BEN, encoding="utf-8") if l.strip()]
rows = [r for r in ben if (norm(r["package_name"]), r["version"]) in files]
print(f"archives indexed: {sum(len(v) for v in files.values())} | benign rows matched to an archive: {len(rows)} of {len(ben)}")
if len(rows) < 0.5 * len(ben):
    print("sample archive names:", [p.name for v in list(files.values())[:5] for p in v][:5])
    print("sample row keys:", [(r["package_name"], r["version"]) for r in ben[:5]])
    sys.exit("too few matches: send me these two lines")

random.seed(0)
same, diffs = 0, []
sample = random.sample(rows, min(N, len(rows)))
for r in sample:
    with tempfile.TemporaryDirectory(prefix="parity_") as t:
        d = Path(t)
        for a in files[(norm(r["package_name"]), r["version"])]:
            shutil.copy2(a, d / a.name)
        try:
            ref, _ = sc.scan_version(r["package_name"], r["version"], d, {})
        except Exception as e:
            sys.exit(f"reference scan failed: {type(e).__name__}: {e}")
    a = {f"{f['category']}::{f['indicator']}" for f in r["findings"]}
    b = {f"{f['category']}::{f['indicator']}" for f in ref["findings"] if f["category"] != "Parse Error"}
    if a == b: same += 1
    else: diffs.append((r["package_id"], sorted(a - b)[:5], sorted(b - a)[:5]))
print(f"\nidentical indicator sets: {same} of {len(sample)}")
for pid, only_file, only_ref in diffs[:15]:
    print(f"  {pid}\n     only in benign_for_b.jsonl:      {only_file}\n     only in real-analyzer re-scan:   {only_ref}")