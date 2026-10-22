#!/usr/bin/env python
"""Slim, schema-compliant export of the malicious scan for Person B + Day 7 stats. Read-only on the scan."""
import json, re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "data/processed/malicious_scan.jsonl"
OUT = ROOT / "data/processed/malicious_for_b.jsonl"
ZERO = ROOT / "data/processed/zero_finding_packages.txt"
PYPI = ROOT / "data/raw/malicious/pypi"
SEV = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

def norm(n): return re.sub(r"[-_.]+", "-", str(n).strip()).lower()
def has_setup(r): return any(Path(x.get("file", "")).name == "setup.py" for x in r.get("results", []))

rows = [json.loads(l) for l in open(SRC, encoding="utf-8") if l.strip()]
n = len(rows)
ids = Counter()
cats, ind, zero = Counter(), Counter(), []
with open(OUT, "w", encoding="utf-8") as o:
    for r in rows:
        f = r.get("findings", [])
        pid = f"{norm(r['package_name'])}=={r['version']}"
        ids[pid] += 1
        ms = max((SEV.get(x.get("severity"), 0) for x in f), default=0)
        cats.update({x["category"] for x in f}); ind.update(x.get("indicator") for x in f)
        if not f: zero.append(pid)
        o.write(json.dumps({
            "package_id": pid, "package_name": norm(r["package_name"]), "version": r["version"],
            "label": 1, "source": r["source"], "in_index": r["in_index"], "index_annotated": r["index_annotated"],
            "n_py_files": r["files_attempted"], "n_findings": len(f), "category_counts": r["category_counts"],
            "max_severity": {0: None, 1: "LOW", 2: "MEDIUM", 3: "HIGH"}[ms],
            "parse_error_count": r["parse_error_count"], "failed_static_analysis": int(r["failed_static_analysis"]),
            "findings": [{k: x.get(k) for k in ("category", "indicator", "severity", "file", "line", "evidence")} for x in f],
        }) + "\n")
ZERO.write_text("\n".join(zero))

print(f"export: {OUT} ({OUT.stat().st_size/1e6:.1f} MB) | rows {n} | colliding ids after normalising: {sum(v>1 for v in ids.values())}")
print("not in index:", [r["package_id"] for r in rows if not r["in_index"]])
print(f"\nprevalence (denominator {n} package-versions):")
for c, k in cats.most_common(): print(f"  {c:36s}{k:5d} {100*k/n:5.1f}%")
print("with >=1 HIGH finding:", sum(1 for r in rows if any(x.get('severity') == 'HIGH' for x in r['findings'])))
print(f"zero findings: {len(zero)} ({100*len(zero)/n:.1f}%) -> {ZERO}")
print("top indicators:", ind.most_common(12))
print("most findings:", [(r["package_id"], r["findings_count"]) for r in sorted(rows, key=lambda r: -r["findings_count"])[:8]])

both = missing = 0; ex = []
for r in rows:
    d = PYPI / r["package"] / r["version"]
    if not d.is_dir(): continue
    names = [p.name for p in d.iterdir() if p.is_file()]
    if any(x.endswith(".whl") for x in names) and any(x.endswith((".tar.gz", ".tgz", ".tar.bz2", ".zip", ".tar")) for x in names):
        both += 1
        if not has_setup(r): missing += 1; ex.append(r["package_id"])
print(f"\nsetup.py scanned in {sum(has_setup(r) for r in rows)} rows")
print(f"versions with BOTH wheel and sdist: {both} | of those, setup.py NOT scanned: {missing} {ex[:5]}")
