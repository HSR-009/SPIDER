#!/usr/bin/env python
"""Read-only: print risky-keyword lines from one package version's .py files. Nothing is executed."""
import re, sys, tarfile, zipfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
PAT = re.compile(r"getattr|__import__|importlib|\beval\(|\bexec\(|(?<!re\.)compile\(|base64|marshal|zlib|pickle|ctypes|socket|subprocess|os\.system|urllib|requests|webbrowser|winreg|\.environ|chr\(|fromhex|decode\(")

def files(a):
    if zipfile.is_zipfile(a):
        with zipfile.ZipFile(a) as z:
            for i in z.infolist():
                if i.filename.endswith(".py") and not i.is_dir() and i.file_size < 1_000_000:
                    yield i.filename, z.read(i).decode("utf-8", "replace")
    else:
        with tarfile.open(a, "r:*") as t:
            for m in t:
                if m.isfile() and m.name.endswith(".py") and m.size < 1_000_000:
                    f = t.extractfile(m)
                    if f: yield m.name, f.read().decode("utf-8", "replace")

name, ver = sys.argv[1], sys.argv[2]
d = ROOT / "data/raw/malicious/pypi" / name / ver
for a in sorted(d.iterdir()):
    if not a.name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".zip", ".whl", ".tar")):
        continue
    print(f"\n##### {a.name}")
    for fn, text in files(a):
        hits = [(i, l) for i, l in enumerate(text.splitlines(), 1) if PAT.search(l)]
        if hits:
            print(f"--- {fn} ({len(hits)} hits)")
            for i, l in hits[:25]:
                print(f"{i:5d}: {l.strip()[:150]}")
