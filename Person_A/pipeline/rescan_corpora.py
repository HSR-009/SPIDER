"""Bulk rescan driver for malicious and benign corpora (Day 3 step 3.3)."""
from __future__ import annotations

import argparse
import gzip
import json
import multiprocessing
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from spider.engine.extract import safe_extract
from spider.engine.scan import scan_directory
from spider_contract.adapter import to_legacy
from spider_contract.dataset import make_group_id
from spider_contract.verdict import coverage_problems
from spider_contract.verdict_v2 import decide, strong_signals

# Windows/Linux guards for limits and alarm
HAVE_RESOURCE = False
try:
    import resource
    HAVE_RESOURCE = True
except ImportError:
    pass

try:
    import signal
except ImportError:
    signal = None

ARCHIVE_SUFFIXES = (
    ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz",
    ".tar", ".zip", ".whl",
)

ANNOTATION_FIELDS = {
    "details", "objective", "trigger", "injectioncomponent",
    "typotarget", "targetedos", "obfuscated", "obfuscation",
    "condition", "conditional",
}


def normalize(value: Any) -> str:
    return re.sub(r"[-_.]+", "-", str(value).strip()).lower()


def make_id(name: str, version: str) -> str:
    return f"{normalize(name)}@{version}"


def annotation_present(item: Dict[str, Any]) -> bool:
    """True only when a behavioral field has an actual annotated value."""
    for key in ANNOTATION_FIELDS:
        field = item.get(key)
        if not isinstance(field, dict):
            continue
        status = str(field.get("status", "")).lower()
        value = field.get("value")
        if status == "manually set" and value is not None:
            if value != "" and value != [] and value != {}:
                return True
    return False


def load_index(index_path: Path) -> Dict[str, List[Dict[str, Any]]]:
    index: Dict[str, List[Dict[str, Any]]] = {}
    if not index_path.exists():
        return index

    with index_path.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                item = json.loads(line)
                purl = (item.get("purl") or {}).get("value", "")
                if not purl.startswith("pkg:pypi/"):
                    continue
                identity = unquote(purl[len("pkg:pypi/"):])
                name, sep, version = identity.partition("@")
                if not name or not sep or not version:
                    continue
                pid = make_id(name, version)
                index.setdefault(pid, []).append(item)
            except Exception:
                continue
    return index


def artifact_priority(path: Path) -> int:
    name = path.name.lower()
    if name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
        return 0
    if name.endswith(".zip") and not name.endswith(".whl"):
        return 1
    return 2


def _worker_init() -> None:
    if sys.platform != "win32":
        if signal and hasattr(signal, "SIGINT"):
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        if HAVE_RESOURCE:
            try:
                # 2 GiB address space
                resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))
            except Exception:
                pass
            try:
                # 120s CPU time
                resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
            except Exception:
                pass


def _alarm_handler(signum, frame):
    raise TimeoutError("Archive scan timed out (60s limit)")


def get_temp_root() -> Path:
    # Use /dev/shm when free space >= 2 GB, else system temp
    if sys.platform != "win32":
        shm = Path("/dev/shm")
        if shm.exists() and os.access(shm, os.W_OK):
            try:
                usage = shutil.disk_usage(shm)
                if usage.free >= 2 * (1024 ** 3):
                    return shm
            except Exception:
                pass
    return Path(tempfile.gettempdir())


def check_s2_same_file(scan_record: Dict[str, Any]) -> bool:
    """True if any single file has exec/eval/compile together with an Obfuscation or Network finding."""
    file_findings: Dict[str, List[Dict[str, Any]]] = {}
    for f in scan_record.get("findings", []):
        file_findings.setdefault(f.get("file", ""), []).append(f)

    for path, f_list in file_findings.items():
        inds = {f.get("indicator") for f in f_list}
        cats = {f.get("category") for f in f_list}
        has_exec = bool(inds & {"exec", "eval", "compile"})
        has_obf_or_net = bool({"obfuscation", "network_activity", "Obfuscation", "Network Activity"} & cats)
        if has_exec and has_obf_or_net:
            return True
    return False


def scan_single_archive_task(task_args: Dict[str, Any]) -> Dict[str, Any]:
    """Worker task scanning a single package archive."""
    archive_path = Path(task_args["archive_path"])
    pkg_name = task_args["package_name"]
    version = task_args["version"]
    label = task_args["label"]
    source = task_args["source"]
    group_id = task_args["group_id"]
    pid = task_args["package_id"]
    in_index = task_args.get("in_index")
    index_annotated = task_args.get("index_annotated")
    manifest_sha256 = task_args.get("artifact_sha256")

    # Set 60s per-archive alarm on Linux
    alarm_set = False
    if sys.platform != "win32" and signal and hasattr(signal, "alarm"):
        try:
            signal.signal(signal.SIGALRM, _alarm_handler)
            signal.alarm(60)
            alarm_set = True
        except Exception:
            pass

    t0 = time.time()
    temp_dir = None
    try:
        temp_root = get_temp_root()
        temp_dir = Path(tempfile.mkdtemp(prefix="spider_worker_", dir=temp_root))

        ext_res = safe_extract(archive_path, temp_dir)
        # If extraction failed completely with unreadable archive, record coverage problem
        has_unreadable = any(str(r.get("reason", "")).startswith("unreadable_archive") for r in ext_res.get("rejected", []))
        if has_unreadable:
            raise RuntimeError("unreadable_archive")

        record = scan_directory(temp_dir, name=pkg_name, version=version)

        # Wire extraction rejections and limits into record inventory
        for rej in ext_res.get("rejected", []):
            record["inventory"]["uninspected"].append({"path": rej.get("name", "unknown"), "reason": rej.get("reason", "rejected")})
        for lim in ext_res.get("limits_hit", []):
            if lim not in record["inventory"]["limits_hit"]:
                record["inventory"]["limits_hit"].append(lim)

        # Recompute coverage problems & verdict
        cov_probs = coverage_problems(record)
        findings_legacy = to_legacy(record)
        # Note: findings_legacy contains legacy findings including converted parse errors as Parse Error category
        outcome, s_signals, review_rec = decide(findings_legacy, cov_probs)

        # Determine n_py_files: files inspected that are python and not doc
        n_py_files = sum(
            1 for f in record.get("files", [])
            if f.get("kind") == "python"
        )
        # n_py_files_all: all .py files including those classified doc
        n_py_files_all = sum(
            1 for f in record.get("files", [])
            if f.get("path", "").lower().endswith((".py", ".pyw"))
        )

        n_findings = len(record.get("findings", []))
        n_parse_failures = len(record.get("inventory", {}).get("parse_failures", []))

        category_counts: Dict[str, int] = {}
        for f in findings_legacy:
            if f.get("category") == "Parse Error":
                continue
            cat = f.get("category", "Uncategorized")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Max severity
        severities = [f.get("severity", "").upper() for f in record.get("findings", [])]
        max_severity = None
        if "HIGH" in severities:
            max_severity = "HIGH"
        elif "MEDIUM" in severities:
            max_severity = "MEDIUM"
        elif "LOW" in severities:
            max_severity = "LOW"

        s2_same = check_s2_same_file(record)
        elapsed = time.time() - t0

        row = {
            "package_id": pid,
            "package_name": pkg_name,
            "version": version,
            "group_id": group_id,
            "label": label,
            "source": source,
            "analyzer_version": "analyzer-v1.1",
            "ruleset_version": "rules-v1.1",
            "in_index": in_index,
            "index_annotated": index_annotated,
            "n_py_files": n_py_files,
            "n_py_files_all": n_py_files_all,
            "n_findings": n_findings,
            "category_counts": category_counts,
            "parse_error_count": n_parse_failures,
            "failed_static_analysis": 1 if n_parse_failures > 0 else 0,
            "max_severity": max_severity,
            "findings": findings_legacy,
            "strong_signals": s_signals,
            "review_recommended": review_rec,
            "verdict_outcome": outcome,
            "coverage_problems": cov_probs,
            "n_parse_failures": n_parse_failures,
            "limits_hit": record.get("inventory", {}).get("limits_hit", []),
            "s2_same_file": s2_same,
            "archive_used": str(archive_path),
            "scan_seconds": round(elapsed, 4),
        }
        if manifest_sha256 is not None:
            row["artifact_sha256"] = manifest_sha256

        return row

    except Exception as exc:
        elapsed = time.time() - t0
        exc_type = type(exc).__name__
        cov_probs = [f"worker_error:{exc_type}"]
        row = {
            "package_id": pid,
            "package_name": pkg_name,
            "version": version,
            "group_id": group_id,
            "label": label,
            "source": source,
            "analyzer_version": "analyzer-v1.1",
            "ruleset_version": "rules-v1.1",
            "in_index": in_index,
            "index_annotated": index_annotated,
            "n_py_files": 0,
            "n_py_files_all": 0,
            "n_findings": 0,
            "category_counts": {},
            "parse_error_count": 0,
            "failed_static_analysis": 1,
            "max_severity": None,
            "findings": [],
            "strong_signals": [],
            "review_recommended": False,
            "verdict_outcome": "unable_to_assess",
            "coverage_problems": cov_probs,
            "n_parse_failures": 0,
            "limits_hit": [],
            "s2_same_file": False,
            "archive_used": str(archive_path),
            "scan_seconds": round(elapsed, 4),
        }
        if manifest_sha256 is not None:
            row["artifact_sha256"] = manifest_sha256
        return row

    finally:
        if alarm_set and signal and hasattr(signal, "alarm"):
            try:
                signal.alarm(0)
            except Exception:
                pass
        if temp_dir and temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)


def build_malicious_tasks(src_dir: Path, index: Dict[str, List[Dict[str, Any]]], limit: Optional[int] = None) -> List[Dict[str, Any]]:
    pypi_root = src_dir if (src_dir / "pypi").exists() is False and src_dir.name == "pypi" else (src_dir / "pypi" if (src_dir / "pypi").exists() else src_dir)
    tasks = []

    if not pypi_root.exists():
        return tasks

    # Package folders
    pkg_dirs = sorted([d for d in pypi_root.iterdir() if d.is_dir()], key=lambda d: d.name)
    for pkg_d in pkg_dirs:
        package_name = pkg_d.name
        ver_dirs = sorted([v for v in pkg_d.iterdir() if v.is_dir()], key=lambda v: v.name)
        for ver_d in ver_dirs:
            version = ver_d.name
            archives = sorted(
                (p for p in ver_d.iterdir() if p.is_file() and p.name.lower().endswith(ARCHIVE_SUFFIXES)),
                key=lambda p: (artifact_priority(p), p.name.lower()),
            )
            if not archives:
                continue

            chosen_archive = archives[0]
            index_pid = make_id(package_name, version)
            pid = f"{package_name}=={version}"
            meta = index.get(index_pid, [])

            tasks.append({
                "package_id": pid,
                "package_name": package_name,
                "version": version,
                "group_id": make_group_id(package_name),
                "label": 1,
                "source": "Backstabber's Knife Collection",
                "in_index": bool(meta),
                "index_annotated": any(annotation_present(item) for item in meta),
                "archive_path": str(chosen_archive),
            })
            if limit and len(tasks) >= limit:
                return tasks

    return tasks


def build_benign_tasks(manifest_path: Path, limit: Optional[int] = None) -> Tuple[List[Dict[str, Any]], int]:
    tasks = []
    missing_count = 0

    if not manifest_path.exists():
        return tasks, missing_count

    seen_versions: Dict[str, int] = {}

    with manifest_path.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            entry = json.loads(line)
            pkg_name = entry.get("package_name") or entry.get("name")
            version = entry.get("version")
            arc_rel = entry.get("archive_path")
            sha = entry.get("sha256")

            # Skip .whl for benign
            if arc_rel.lower().endswith(".whl"):
                continue

            # Up to 2 versions per package
            norm_name = make_group_id(pkg_name)
            if seen_versions.get(norm_name, 0) >= 2:
                continue

            archive_path = Path(arc_rel)
            if not archive_path.is_absolute():
                archive_path = ROOT / archive_path

            if not archive_path.exists():
                missing_count += 1
                continue

            seen_versions[norm_name] = seen_versions.get(norm_name, 0) + 1
            pid = f"{pkg_name}=={version}"

            tasks.append({
                "package_id": pid,
                "package_name": pkg_name,
                "version": version,
                "group_id": norm_name,
                "label": 0,
                "source": entry.get("source", "popular PyPI projects; assumed benign, not verified"),
                "in_index": None,
                "index_annotated": None,
                "archive_path": str(archive_path),
                "artifact_sha256": sha,
            })
            if limit and len(tasks) >= limit:
                break

    return tasks, missing_count


def run_rescan(
    kind: str,
    out_path: Path,
    src_dir: Optional[Path] = None,
    manifest_path: Optional[Path] = None,
    workers: int = 1,
    limit: Optional[int] = None,
    resume: bool = False,
) -> None:
    is_gz = str(out_path).endswith(".gz")
    partial_path = Path(str(out_path) + ".partial" if not is_gz else str(out_path)[:-3] + ".partial")

    done_ids: Set[str] = set()
    if resume and partial_path.exists():
        with partial_path.open(encoding="utf-8") as f:
            for line in f:
                try:
                    row = json.loads(line)
                    if "package_id" in row:
                        done_ids.add(row["package_id"])
                except Exception:
                    continue
        print(f"Resuming: found {len(done_ids)} packages already in {partial_path}")

    # Build tasks
    if kind == "malicious":
        src = src_dir or (ROOT / "data/raw/malicious")
        idx_file = ROOT / "data/raw/malicious/package_index.jsonl"
        index = load_index(idx_file)
        tasks = build_malicious_tasks(src, index, limit)
    elif kind == "benign":
        m_file = manifest_path or (ROOT / "data/raw/benign/manifest.jsonl")
        tasks, missing = build_benign_tasks(m_file, limit)
        if missing > 0:
            print(f"Skipped {missing} missing benign archive files listed in manifest")
    else:
        raise ValueError(f"Unknown kind: {kind}")

    tasks_to_run = [t for t in tasks if t["package_id"] not in done_ids]
    total = len(tasks_to_run)
    print(f"Total tasks to scan: {total} (workers: {workers})")

    out_file_mode = "a" if (resume and partial_path.exists()) else "w"
    partial_path.parent.mkdir(parents=True, exist_ok=True)

    t_start = time.time()
    completed = 0

    with partial_path.open(out_file_mode, encoding="utf-8") as out_stream:
        if workers <= 1:
            for task in tasks_to_run:
                row = scan_single_archive_task(task)
                out_stream.write(json.dumps(row) + "\n")
                out_stream.flush()
                completed += 1
                if completed % 100 == 0 or completed == total:
                    elapsed = time.time() - t_start
                    rate = completed / max(1e-5, elapsed)
                    rem = (total - completed) / max(1e-5, rate)
                    print(f"[{completed}/{total}] {rate:.2f} items/s | ETA: {rem:.1f}s")
        else:
            with multiprocessing.Pool(
                processes=workers,
                initializer=_worker_init,
                maxtasksperchild=100,
            ) as pool:
                for row in pool.imap_unordered(scan_single_archive_task, tasks_to_run, chunksize=1):
                    out_stream.write(json.dumps(row) + "\n")
                    out_stream.flush()
                    completed += 1
                    if completed % 100 == 0 or completed == total:
                        elapsed = time.time() - t_start
                        rate = completed / max(1e-5, elapsed)
                        rem = (total - completed) / max(1e-5, rate)
                        print(f"[{completed}/{total}] {rate:.2f} items/s | ETA: {rem:.1f}s")

    # Sort rows by package_id before writing final file for deterministic reproducibility
    rows = []
    if partial_path.exists():
        with partial_path.open(encoding="utf-8") as f_in:
            for line in f_in:
                if line.strip():
                    try:
                        rows.append(json.loads(line))
                    except Exception:
                        continue

    rows.sort(key=lambda r: r.get("package_id", ""))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    if is_gz:
        # Deterministic gzip with mtime=0
        with gzip.GzipFile(str(out_path), "wb", mtime=0.0) as f_out:
            for r in rows:
                f_out.write((json.dumps(r) + "\n").encode("utf-8"))
        if partial_path.exists():
            partial_path.unlink()
    else:
        if out_path.exists():
            out_path.unlink()
        with out_path.open("w", encoding="utf-8") as f_out:
            for r in rows:
                f_out.write(json.dumps(r) + "\n")
        if partial_path.exists():
            partial_path.unlink()

    print(f"Rescan completed successfully. Output written to {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="SPIDER Corpora Rescan Driver")
    parser.add_argument("--kind", choices=["malicious", "benign"], required=True)
    parser.add_argument("--out", required=True)
    default_workers = 1 if sys.platform == "win32" else max(1, os.cpu_count() - 1)
    parser.add_argument("--workers", type=int, default=default_workers)
    parser.add_argument("--src")
    parser.add_argument("--manifest")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--resume", action="store_true")

    args = parser.parse_args()

    run_rescan(
        kind=args.kind,
        out_path=Path(args.out),
        src_dir=Path(args.src) if args.src else None,
        manifest_path=Path(args.manifest) if args.manifest else None,
        workers=args.workers,
        limit=args.limit,
        resume=args.resume,
    )


if __name__ == "__main__":
    main()
