#!/usr/bin/env python
"""Which obfuscation techniques does analyzer v1 miss? Read-only; looks at annotated-obfuscated packages with no Obfuscation finding."""
import json, re, tarfile, zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCAN = ROOT / "data/processed/malicious_scan.jsonl"
INDEX = ROOT / "data/raw/malicious/package_index.jsonl"
PYPI = ROOT / "data/raw/malicious/pypi"
PATS = {
    "bytes.fromhex": r"fromhex", "chr() building": r"\bchr\(", "codecs": r"codecs\.", "reversed [::-1]": r"\[::-1\]",
    "\\x escape runs": r"(\\x[0-9a-fA-F]{2}){4,}", "zlib/gzip/bz2/lzma": r"zlib|gzip|bz2|lzma", "marshal/pickle": r"marshal|pickle",
    "base64 (any form)": r"base64|b64", "join(map/chr)": r"join\(\s*(map|chr)", "exec/eval": r"\b(exec|eval)\(",
    "compile()": r"(?<!re\.)\bcompile\(", "long encoded literal": r"['\"][A-Za-z0-9+/=]{200,}['\"]", "getattr": r"getattr\(",
    "__import__/importlib": r"__import__|importlib",
}

def norm(n): return re.sub(r"[-_.]+", "-", str(n).strip()).lower()
def fval(o, k):
    x = o.get(k); return x.get("value") if isinstance(x, dict) else x

def texts(r):
    out = []
    d = PYPI / r["package"] / r["version"]
    for a in sorted(d.iterdir()) if d.is_dir() else []:
        try:
            if zipfile.is_zipfile(a):
                with zipfile.ZipFile(a) as z:
                    out += [z.read(i).decode("utf-8", "replace") for i in z.infolist() if i.filename.endswith(".py") and not i.is_dir() and i.file_size < 1_000_000]
            elif a.name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar")):
                with tarfile.open(a, "r:*") as t:
                    for m in t:
                        if m.isfile() and m.name.endswith(".py") and m.size < 1_000_000:
                            f = t.extractfile(m)
                            if f: out.append(f.read().decode("utf-8", "replace"))
        except Exception:
            pass
    return out

idx = {}
for line in open(INDEX, encoding="utf-8"):
    o = json.loads(line); p = (o.get("purl") or {}).get("value") or ""
    if p.startswith("pkg:pypi/"):
        nm, _, v = p[9:].rpartition("@"); idx[(norm(nm), v)] = o
rows = [json.loads(l) for l in open(SCAN, encoding="utf-8") if l.strip()]
obf = [r for r in rows if r["index_annotated"] and idx.get((norm(r["package_name"]), r["version"])) is not None
       and str(fval(idx[(norm(r["package_name"]), r["version"])], "obfuscated")).lower() in ("true", "yes", "1")]
miss = [r for r in obf if "Obfuscation" not in r["category_counts"]]
print(f"annotated obfuscated: {len(obf)} | missed by analyzer: {len(miss)}\n")
tot, per = Counter(), {}
for r in miss:
    blob = "\n".join(texts(r))
    hit = [k for k, p in PATS.items() if re.search(p, blob)]
    per[r["package_id"]] = (len(blob), hit); tot.update(hit)
print("technique present in missed packages (of %d):" % len(miss))
for k, v in tot.most_common(): print(f"  {k:24s}{v:4d}")
print("\nmissed packages (py chars, techniques):")
for pid, (n, hit) in list(per.items())[:40]: print(f"  {pid:45s}{n:8d}  {', '.join(hit)}")
