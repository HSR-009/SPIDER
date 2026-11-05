#!/usr/bin/env python
"""Two checks before trusting the malicious-vs-benign comparison. Read-only.
 1) size strata + size-only AUC  (needs only the two *_for_b.jsonl files)
 2) rule parity: re-scan a random sample of benign packages with the real analyzer path and compare
    (needs data/raw/benign and Person_A/pipeline/run_malicious_scan.py)"""
import json, random, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAL = ROOT / "data/processed/malicious_for_b.jsonl"
BEN = ROOT / "data/processed/benign_for_b.jsonl"
ARCH = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar", ".zip", ".whl")
CATS = ["Install-Time / Package Execution", "Network Activity", "Command Execution",
        "Credential / Data Access", "Obfuscation", "Dynamic Code Execution"]

def norm(n): return re.sub(r"[-_.]+", "-", str(n).strip()).lower()
def load(p): return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
def pct(a, b): return f"{100 * a / b:5.1f}%" if b else "   n/a"

def auc(pos, neg):
    allv = sorted([(v, 1) for v in pos] + [(v, 0) for v in neg])
    ranks, i = [0] * len(allv), 0
    while i < len(allv):
        j = i
        while j + 1 < len(allv) and allv[j + 1][0] == allv[i][0]: j += 1
        for k in range(i, j + 1): ranks[k] = (i + j) / 2 + 1
        i = j + 1
    rp = sum(r for r, (_, l) in zip(ranks, allv) if l == 1)
    return (rp - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))

mal, ben = load(MAL), load(BEN)
print(f"rows: malicious {len(mal)}, benign {len(ben)}\n")
print("=== 1. SIZE CONFOUND ===")
for name, f in [("n_py_files", lambda r: r["n_py_files"]), ("failed_static_analysis", lambda r: r["failed_static_analysis"]),
                ("n_findings", lambda r: r["n_findings"])]:
    a = auc([f(r) for r in mal], [f(r) for r in ben])
    print(f"AUC of {name:24s} alone (malicious=positive): {a:.3f}  -> separability {max(a, 1 - a):.3f}")
med = lambda rows: sorted(r["n_py_files"] for r in rows)[len(rows) // 2]
print(f"median n_py_files: malicious {med(mal)}, benign {med(ben)}\n")
bins = [(0, 2), (3, 10), (11, 50), (51, 10**9)]
print("% of rows containing each category, by number of .py files (malicious/benign)")
print(f"{'category':34s}" + "".join(f"{f'{lo}-{hi if hi < 10**9 else chr(43)}':>16s}" for lo, hi in bins))
print(f"{'rows (M/B)':34s}" + "".join(
    f"{sum(lo <= r['n_py_files'] <= hi for r in mal):>8d}/{sum(lo <= r['n_py_files'] <= hi for r in ben):<7d}" for lo, hi in bins))
for c in CATS:
    cells = []
    for lo, hi in bins:
        m = [r for r in mal if lo <= r["n_py_files"] <= hi]; b = [r for r in ben if lo <= r["n_py_files"] <= hi]
        cells.append(f"{pct(sum(c in r['category_counts'] for r in m), len(m))}/{pct(sum(c in r['category_counts'] for r in b), len(b))}".replace(" ", ""))
    print(f"{c:34s}" + "".join(f"{x:>16s}" for x in cells))
ci = lambda r: any(f["indicator"] == "setuptools.command.install" for f in r["findings"])
cells = []
for lo, hi in bins:
    m = [r for r in mal if lo <= r["n_py_files"] <= hi]; b = [r for r in ben if lo <= r["n_py_files"] <= hi]
    cells.append(f"{pct(sum(map(ci, m)), len(m))}/{pct(sum(map(ci, b)), len(b))}".replace(" ", ""))
print(f"{'custom install command':34s}" + "".join(f"{x:>16s}" for x in cells))

print("\n=== 2. RULE PARITY (benign_for_b.jsonl vs re-scan through run_malicious_scan.scan_version) ===")
raw = ROOT / "data/raw/benign"
if not raw.exists():
    print("data/raw/benign not found: skipping"); sys.exit()
sys.path.insert(0, str(ROOT / "Person_A/pipeline"))
import run_malicious_scan as sc
dirs = {}
for p in raw.rglob("*"):
    if p.is_file() and p.name.lower().endswith(ARCH):
        dirs[(norm(p.parent.parent.name), p.parent.name)] = p.parent
rows = [r for r in ben if (r["package_name"], r["version"]) in dirs]
print(f"benign rows matched to a folder on disk: {len(rows)} of {len(ben)}")
if len(rows) < 0.5 * len(ben):
    print("layout not as expected, sample folders:", [str(v) for v in list(dirs.values())[:3]]); sys.exit()
random.seed(0)
same, diffs = 0, []
sample = random.sample(rows, min(60, len(rows)))
for r in sample:
    d = dirs[(r["package_name"], r["version"])]
    try:
        ref, _ = sc.scan_version(d.parent.name, d.name, d, {})
    except Exception as e:
        print("reference scan failed:", type(e).__name__, e); sys.exit()
    a = {f"{f['category']}::{f['indicator']}" for f in r["findings"]}
    b = {f"{f['category']}::{f['indicator']}" for f in ref["findings"] if f["category"] != "Parse Error"}
    if a == b: same += 1
    else: diffs.append((r["package_id"], sorted(a - b)[:4], sorted(b - a)[:4]))
print(f"identical indicator sets: {same} of {len(sample)}")
for pid, only_file, only_ref in diffs[:12]:
    print(f"  {pid}\n     only in benign_for_b.jsonl: {only_file}\n     only in real-analyzer re-scan: {only_ref}")