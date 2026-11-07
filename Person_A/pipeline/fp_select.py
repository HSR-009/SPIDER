"""Select and download 100 obscure PyPI packages for FP evaluation (Day 4 step 4.8 & section 7.10)."""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
import tempfile
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from spider.fetch import fetch_package_archive, FetchError
from spider_contract.dataset import make_group_id

HUGOVK_TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
DEFAULT_OUT_DIR = ROOT / "fp_check"
DEFAULT_CSV = ROOT / "results/fp_check_selection.csv"
MAL_TABLE = ROOT / "data/processed/malicious_v11.jsonl"
BEN_TABLE = ROOT / "data/processed/benign_v11.jsonl.gz"


def load_corpus_groups() -> Set[str]:
    groups: Set[str] = set()
    for p in (MAL_TABLE, BEN_TABLE):
        if not p.exists():
            continue
        import gzip
        opener = gzip.open(p, "rt", encoding="utf-8") if str(p).endswith(".gz") else p.open("r", encoding="utf-8")
        with opener as f:
            for line in f:
                if line.strip():
                    try:
                        row = json.loads(line)
                        gid = row.get("group_id")
                        if gid:
                            groups.add(gid)
                    except Exception:
                        pass
    return groups


def fetch_top_packages(url: str = HUGOVK_TOP_URL) -> List[Dict[str, Any]]:
    req = urllib.request.Request(url, headers={"User-Agent": "SPIDER-fp-select/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("rows", [])


def select_candidates(
    rows: List[Dict[str, Any]],
    corpus_groups: Set[str],
    rank_start: int = 1500,
    rank_end: int = 15000,
    seed: int = 42,
) -> List[Tuple[int, str]]:
    """Select candidate packages ranked between rank_start and rank_end, excluding corpus groups."""
    candidates = []
    for rank, entry in enumerate(rows, 1):
        if rank < rank_start:
            continue
        if rank > rank_end:
            break
        project = entry.get("project")
        if not project:
            continue
        gid = make_group_id(project)
        if gid in corpus_groups:
            continue
        candidates.append((rank, project))

    rng = random.Random(seed)
    rng.shuffle(candidates)
    return candidates


def query_pypi_candidate(
    rank: int,
    project: str,
    max_sdist_bytes: int = 200 * 1024,
) -> Optional[Dict[str, Any]]:
    """Query PyPI JSON API for latest release sdist <= max_sdist_bytes."""
    url = f"https://pypi.org/pypi/{project}/json"
    req = urllib.request.Request(url, headers={"User-Agent": "SPIDER-fp-select/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None

    info = data.get("info", {})
    version = info.get("version")
    if not version:
        return None

    # Find sdist
    urls = data.get("urls", [])
    sdists = [u for u in urls if u.get("packagetype") == "sdist"]
    if not sdists:
        return None

    chosen = sdists[0]
    size = chosen.get("size", 0)
    sha256 = (chosen.get("digests") or {}).get("sha256", "").lower()

    if size > max_sdist_bytes:
        return None

    return {
        "name": project,
        "version": version,
        "rank": rank,
        "size": size,
        "sha256": sha256,
        "url": chosen.get("url"),
        "filename": chosen.get("filename"),
    }


def run_selection(
    count: int = 100,
    csv_out: Path = DEFAULT_CSV,
    seed: int = 42,
    rank_start: int = 1500,
    rank_end: int = 15000,
    custom_candidates: Optional[List[Tuple[int, str]]] = None,
) -> List[Dict[str, Any]]:
    """Select count packages and write to CSV."""
    if custom_candidates is None:
        rows = fetch_top_packages()
        corpus_groups = load_corpus_groups()
        candidates = select_candidates(rows, corpus_groups, rank_start=rank_start, rank_end=rank_end, seed=seed)
    else:
        candidates = custom_candidates

    selected = []
    for rank, project in candidates:
        match = query_pypi_candidate(rank, project)
        if match:
            selected.append(match)
            if len(selected) >= count:
                break

    csv_out.parent.mkdir(parents=True, exist_ok=True)
    with csv_out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "version", "rank", "size", "sha256"])
        writer.writeheader()
        for item in selected:
            writer.writerow({
                "name": item["name"],
                "version": item["version"],
                "rank": item["rank"],
                "size": item["size"],
                "sha256": item["sha256"],
            })

    print(f"Selection of {len(selected)} packages written to {csv_out}")
    return selected


def run_download(
    csv_file: Path = DEFAULT_CSV,
    out_dir: Path = DEFAULT_OUT_DIR,
    workers: int = 8,
) -> None:
    """Download archives listed in selection CSV using spider.fetch."""
    if not csv_file.exists():
        sys.exit(f"CSV file not found: {csv_file}")

    out_dir.mkdir(parents=True, exist_ok=True)
    items = []
    with csv_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            items.append(row)

    print(f"Downloading {len(items)} packages into {out_dir} with {workers} threads...")

    def _dl(item):
        name = item["name"]
        ver = item["version"]
        try:
            path, sha, verified = fetch_package_archive(name, ver, cache_dir=out_dir)
            return name, ver, True, verified, None
        except Exception as e:
            return name, ver, False, False, str(e)

    success_count = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_dl, item) for item in items]
        for fut in as_completed(futures):
            name, ver, ok, verified, err = fut.result()
            if ok:
                success_count += 1
            else:
                print(f"Failed {name}=={ver}: {err}")

    print(f"Download complete: {success_count}/{len(items)} downloaded successfully.")


def main() -> None:
    parser = argparse.ArgumentParser(description="SPIDER FP Package Selector and Downloader")
    subparsers = parser.add_subparsers(dest="subcommand")

    sel_p = subparsers.add_parser("select", help="Select 100 packages from PyPI and write selection CSV")
    sel_p.add_argument("--count", type=int, default=100)
    sel_p.add_argument("--csv", default=str(DEFAULT_CSV))
    sel_p.add_argument("--seed", type=int, default=42)

    dl_p = subparsers.add_parser("download", help="Download packages from selection CSV into fp_check/")
    dl_p.add_argument("--csv", default=str(DEFAULT_CSV))
    dl_p.add_argument("--out", default=str(DEFAULT_OUT_DIR))
    dl_p.add_argument("--workers", type=int, default=8)

    args = parser.parse_args()

    if args.subcommand == "select":
        run_selection(count=args.count, csv_out=Path(args.csv), seed=args.seed)
    elif args.subcommand == "download":
        run_download(csv_file=Path(args.csv), out_dir=Path(args.out), workers=args.workers)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

