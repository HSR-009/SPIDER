"""Select and download 100 obscure PyPI packages for FP evaluation (Day 4 step 4.8 & section 7.10)."""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
import time
import urllib.request
import zipfile
import tarfile
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
FP_CHECK_CSV = ROOT / "fp_check/selection.csv"
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
    rank_start: int = 5000,
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


def archive_has_py_file(archive_path: Path) -> bool:
    """Check if archive contains at least one .py file without extracting/executing."""
    path_str = str(archive_path).lower()
    try:
        if path_str.endswith(".zip") or path_str.endswith(".whl"):
            with zipfile.ZipFile(archive_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".py") and not name.endswith("/"):
                        return True
            return False
        elif (
            path_str.endswith(".tar.gz")
            or path_str.endswith(".tgz")
            or path_str.endswith(".tar.bz2")
            or path_str.endswith(".tar.xz")
            or path_str.endswith(".tar")
        ):
            with tarfile.open(archive_path, "r:*") as tf:
                for member in tf.getmembers():
                    if member.name.endswith(".py") and member.isfile():
                        return True
            return False
    except Exception:
        return False
    return False


def run_selection(
    count: int = 150,
    csv_out: Path = DEFAULT_CSV,
    seed: int = 42,
    rank_start: int = 5000,
    rank_end: int = 15000,
    custom_candidates: Optional[List[Tuple[int, str]]] = None,
    delay_sec: float = 1.0,
) -> List[Dict[str, Any]]:
    """Select count packages (default 150 candidates to allow filtering) and write to CSV."""
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
        if delay_sec > 0:
            time.sleep(delay_sec)

    # Write primary CSV (e.g. results/fp_check_selection.csv)
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

    # Also write fp_check/selection.csv as the brief says
    try:
        FP_CHECK_CSV.parent.mkdir(parents=True, exist_ok=True)
        with FP_CHECK_CSV.open("w", newline="", encoding="utf-8") as f:
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
    except Exception as e:
        print(f"Warning: could not write {FP_CHECK_CSV}: {e}")

    print(f"Selection of {len(selected)} packages written to {csv_out} and {FP_CHECK_CSV}")
    return selected


def run_download(
    csv_file: Path = DEFAULT_CSV,
    out_dir: Path = DEFAULT_OUT_DIR,
    target_count: int = 100,
    workers: int = 8,
) -> List[Dict[str, Any]]:
    """Download archives listed in selection CSV using spider.fetch, stopping at target_count that have >= 1 .py file."""
    if not csv_file.exists():
        sys.exit(f"CSV file not found: {csv_file}")

    out_dir.mkdir(parents=True, exist_ok=True)
    items = []
    with csv_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            items.append(row)

    print(f"Processing candidate list of {len(items)} packages into {out_dir} (stopping at {target_count} valid)...")

    accepted_packages: List[Dict[str, Any]] = []
    skipped_no_py: List[Dict[str, Any]] = []
    failed_downloads: List[Dict[str, Any]] = []

    # Process items in order to respect rank/selection order
    for item in items:
        if len(accepted_packages) >= target_count:
            break
        name = item["name"]
        ver = item["version"]
        try:
            archive_path, sha, verified = fetch_package_archive(name, ver, cache_dir=out_dir)
            if not archive_has_py_file(archive_path):
                print(f"Skipping {name}=={ver}: no .py file inside archive")
                skipped_no_py.append(item)
                # Remove non-compliant archive to keep fp_check clean
                try:
                    archive_path.unlink()
                except Exception:
                    pass
                continue
            
            accepted_packages.append(item)
            print(f"Accepted [{len(accepted_packages)}/{target_count}] {name}=={ver}")
        except Exception as e:
            print(f"Failed {name}=={ver}: {e}")
            failed_downloads.append({"item": item, "error": str(e)})

    # Record skipped/accepted in fp_check log
    summary_file = out_dir / "download_summary.json"
    try:
        summary_file.write_text(
            json.dumps({
                "target_count": target_count,
                "accepted_count": len(accepted_packages),
                "skipped_no_py_count": len(skipped_no_py),
                "failed_count": len(failed_downloads),
                "skipped_no_py": skipped_no_py,
            }, indent=2),
            encoding="utf-8"
        )
    except Exception:
        pass

    print(f"Download complete: {len(accepted_packages)} accepted, {len(skipped_no_py)} skipped (no .py), {len(failed_downloads)} failed.")
    return accepted_packages


def main() -> None:
    parser = argparse.ArgumentParser(description="SPIDER FP Package Selector and Downloader")
    subparsers = parser.add_subparsers(dest="subcommand")

    sel_p = subparsers.add_parser("select", help="Select candidates from PyPI and write selection CSV")
    sel_p.add_argument("--count", type=int, default=150)
    sel_p.add_argument("--csv", default=str(DEFAULT_CSV))
    sel_p.add_argument("--seed", type=int, default=42)
    sel_p.add_argument("--rank-start", type=int, default=5000)
    sel_p.add_argument("--rank-end", type=int, default=15000)
    sel_p.add_argument("--throttle", type=float, default=1.0)

    dl_p = subparsers.add_parser("download", help="Download packages from selection CSV into fp_check/")
    dl_p.add_argument("--csv", default=str(DEFAULT_CSV))
    dl_p.add_argument("--out", default=str(DEFAULT_OUT_DIR))
    dl_p.add_argument("--target-count", type=int, default=100)
    dl_p.add_argument("--workers", type=int, default=8)

    args = parser.parse_args()

    if args.subcommand == "select":
        run_selection(
            count=args.count,
            csv_out=Path(args.csv),
            seed=args.seed,
            rank_start=args.rank_start,
            rank_end=args.rank_end,
            delay_sec=args.throttle,
        )
    elif args.subcommand == "download":
        run_download(
            csv_file=Path(args.csv),
            out_dir=Path(args.out),
            target_count=args.target_count,
            workers=args.workers,
        )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
