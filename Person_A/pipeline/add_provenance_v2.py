"""Add provenance columns to the processed datasets (idempotent, read-then-rewrite).

Adds: group_id (PEP 503 normalised package name), analyzer_version, ruleset_version.
Optional: artifact_sha256 for benign rows, looked up in data/raw/benign/manifest.jsonl
when that file exists on this machine.

Usage (from the repository root):
    py Person_A/pipeline/add_provenance.py
    py Person_A/pipeline/add_provenance.py --analyzer-version analyzer-v1 --ruleset-version rules-v1
"""
import argparse
import gzip
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAL = ROOT / "data" / "processed" / "malicious_for_b.jsonl"
BEN = ROOT / "data" / "processed" / "benign_for_b.jsonl.gz"
MANIFEST = ROOT / "data" / "raw" / "benign" / "manifest.jsonl"


def make_group_id(name):
    return re.sub(r"[-_.]+", "-", str(name).strip()).lower()


def read_rows(path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_rows(path, rows):
    if path.suffix == ".gz":
        # mtime=0 keeps the gzip bytes identical between runs (clean git diffs)
        with open(path, "wb") as raw, gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, mtime=0
        ) as g:
            for r in rows:
                g.write((json.dumps(r, sort_keys=True) + "\n").encode("utf-8"))
    else:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            for r in rows:
                f.write(json.dumps(r, sort_keys=True) + "\n")


def load_manifest():
    hashes = {}
    if MANIFEST.exists():
        for line in MANIFEST.read_text(encoding="utf-8").splitlines():
            if line.strip():
                m = json.loads(line)
                hashes[(m["package_name"], m["version"])] = m["sha256"]
    return hashes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--analyzer-version", default="analyzer-v1")
    ap.add_argument("--ruleset-version", default="rules-v1")
    ap.add_argument("--mal", default=str(MAL))
    ap.add_argument("--ben", default=str(BEN))
    a = ap.parse_args()

    hashes = load_manifest()
    print("manifest hashes available:", len(hashes))
    for path in (Path(a.mal), Path(a.ben)):
        rows = read_rows(path)
        for r in rows:
            r["group_id"] = make_group_id(r["package_name"])
            r["analyzer_version"] = a.analyzer_version
            r["ruleset_version"] = a.ruleset_version
            h = hashes.get((r["package_name"], r["version"]))
            if h:
                r["artifact_sha256"] = h
        write_rows(path, rows)
        groups = {r["group_id"] for r in rows}
        print("%s: %d rows, %d groups" % (path.name, len(rows), len(groups)))
    # cross-file check: no group may appear in both tables (labels would be ambiguous)
    mal_groups = {r["group_id"] for r in read_rows(Path(a.mal))}
    ben_groups = {r["group_id"] for r in read_rows(Path(a.ben))}
    both = sorted(mal_groups & ben_groups)
    print("groups present in BOTH tables:", len(both), both[:5])
    if both:
        sys.exit("ERROR: some package names appear in both malicious and benign tables")


if __name__ == "__main__":
    main()
