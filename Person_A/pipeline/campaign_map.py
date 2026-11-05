#!/usr/bin/env python
"""Run on KALI (needs package_index.jsonl). Writes data/processed/malicious_campaign_map.csv:
for each malicious row, its campaign / typoTarget / injectionComponent / trigger / objective / obfuscation from the index.
USE FOR GROUPED SPLITS AND ANALYSIS ONLY. These are annotations, never model features."""
import csv, json, re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INDEX = ROOT / "data/raw/malicious/package_index.jsonl"
SRC = ROOT / "data/processed/malicious_for_b.jsonl"
OUT = ROOT / "data/processed/malicious_campaign_map.csv"
FIELDS = ["campaign", "typoTarget", "injectionComponent", "trigger", "objective", "obfuscation"]

def norm(n): return re.sub(r"[-_.]+", "-", str(n).strip()).lower()
def val(o, k):
    x = o.get(k)
    v = x.get("value") if isinstance(x, dict) and x.get("status") != "unknown" else None
    return "" if v is None else (json.dumps(v) if isinstance(v, (list, dict)) else str(v))

idx = {}
for line in open(INDEX, encoding="utf-8"):
    o = json.loads(line)
    purl = (o.get("purl") or {}).get("value") or ""
    if purl.startswith("pkg:pypi/"):
        name, _, ver = purl[9:].rpartition("@")
        idx[(norm(name), ver)] = o

rows = [json.loads(l) for l in open(SRC, encoding="utf-8") if l.strip()]
n_match = 0
with open(OUT, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["package_id", "package_name", "version"] + FIELDS)
    for r in rows:
        o = idx.get((norm(r["package_name"]), r["version"]))
        n_match += o is not None
        w.writerow([r["package_id"], r["package_name"], r["version"]] + [val(o, k) if o else "" for k in FIELDS])

camp = Counter()
for r in rows:
    o = idx.get((norm(r["package_name"]), r["version"]))
    c = val(o, "campaign") if o else ""
    camp[c or "(no campaign annotation)"] += 1
print(f"rows {len(rows)} | matched to index {n_match} | wrote {OUT}")
print("local rows per campaign (top 12):")
for c, k in camp.most_common(12): print(f"  {c:28s}{k:5d} {100 * k / len(rows):5.1f}%")
inj = Counter(val(idx.get((norm(r['package_name']), r['version'])), "injectionComponent") or "(none)" for r in rows if idx.get((norm(r['package_name']), r['version'])))
print("injectionComponent among local rows:", inj.most_common(6))