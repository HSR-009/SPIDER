import sys, tarfile, zipfile
from pathlib import Path
d = Path("data/raw/malicious/pypi") / sys.argv[1] / sys.argv[2]
for a in sorted(d.iterdir()):
    try:
        if zipfile.is_zipfile(a):
            z = zipfile.ZipFile(a); items = [(i.filename, z.read(i)) for i in z.infolist() if i.filename.endswith(".py") and i.file_size < 100000]
        elif a.name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar")):
            t = tarfile.open(a, "r:*"); items = [(m.name, t.extractfile(m).read()) for m in t if m.isfile() and m.name.endswith(".py") and m.size < 100000]
        else: continue
    except Exception as e: print(a.name, "ERR", e); continue
    for n, b in items:
        print(f"\n##### {a.name} :: {n}")
        for l in b.decode("utf-8", "replace").splitlines()[:40]: print(l[:200])
