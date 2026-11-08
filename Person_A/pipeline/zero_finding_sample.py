"""Sample 30 malicious packages with zero findings across archive-size terciles (brief 6.3).

Usage:
    python Person_A/pipeline/zero_finding_sample.py \\
        --table data/processed/malicious_v11.jsonl \\
        --raw-dir data/raw/malicious/pypi \\
        --out results/zero_finding_review.csv \\
        --context zero_review/context.md
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from spider.engine.extract import safe_extract
from spider.engine.sanitize import sanitize_snippet

ARCHIVE_SUFFIXES = (
    ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz",
    ".tar", ".zip", ".whl",
)

ALLOWED_MISS_REASONS = {
    "non_python_payload",
    "data_file_payload",
    "obfuscation_not_detected",
    "api_not_in_ruleset",
    "install_via_other_mechanism",
    "actually_benign_label",
    "empty_or_stub",
    "other",
}


def artifact_priority(path: Path) -> int:
    name = path.name.lower()
    if name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
        return 0
    if name.endswith(".zip") and not name.endswith(".whl"):
        return 1
    return 2


def locate_archive(raw_dir: Path, package_name: str, version: str, pypi_cache: Optional[Dict[str, Path]] = None) -> Optional[Path]:
    """Locate package archive under raw_dir using standard precedence."""
    pypi_root = raw_dir if (raw_dir / "pypi").exists() is False and raw_dir.name == "pypi" else (raw_dir / "pypi" if (raw_dir / "pypi").exists() else raw_dir)
    ver_dir = pypi_root / package_name / version
    if not ver_dir.exists():
        # Try finding case-insensitively using cached pypi map if available
        pkg_lower = package_name.lower()
        if pypi_cache is not None:
            cand_pkg_dir = pypi_cache.get(pkg_lower)
        else:
            cand_pkg = [d for d in pypi_root.iterdir() if d.is_dir() and d.name.lower() == pkg_lower]
            cand_pkg_dir = cand_pkg[0] if cand_pkg else None

        if cand_pkg_dir and cand_pkg_dir.is_dir():
            ver_lower = version.lower()
            cand_ver = [v for v in cand_pkg_dir.iterdir() if v.is_dir() and v.name.lower() == ver_lower]
            if cand_ver:
                ver_dir = cand_ver[0]

    if not ver_dir.exists():
        return None

    archives = sorted(
        (p for p in ver_dir.iterdir() if p.is_file() and p.name.lower().endswith(ARCHIVE_SUFFIXES)),
        key=lambda p: (artifact_priority(p), p.name.lower()),
    )
    return archives[0] if archives else None


def load_zero_finding_candidates(table_path: Path, raw_dir: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Find rows with n_findings == 0 and locate their raw archives."""
    candidates = []
    missing_archives = []

    if not table_path.exists():
        return candidates, missing_archives

    pypi_root = raw_dir if (raw_dir / "pypi").exists() is False and raw_dir.name == "pypi" else (raw_dir / "pypi" if (raw_dir / "pypi").exists() else raw_dir)
    pypi_cache: Optional[Dict[str, Path]] = None
    if pypi_root.exists() and pypi_root.is_dir():
        try:
            pypi_cache = {d.name.lower(): d for d in pypi_root.iterdir() if d.is_dir()}
        except Exception:
            pypi_cache = None

    with table_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue

            # Accept label in (1, "1", "malicious", True) as malicious and nothing else
            label = row.get("label")
            if label not in (1, "1", "malicious", True):
                continue
            if row.get("n_findings", 0) != 0:
                continue

            pkg_id = row.get("package_id", "")
            pkg_name = row.get("package_name") or (pkg_id.split("==")[0] if "==" in pkg_id else "")
            version = row.get("version") or (pkg_id.split("==")[1] if "==" in pkg_id else "")

            # If archive_used is stored in the row, check it first
            arc_path = None
            if row.get("archive_used"):
                cand = Path(row["archive_used"])
                if cand.exists():
                    arc_path = cand

            if arc_path is None:
                arc_path = locate_archive(raw_dir, pkg_name, version, pypi_cache=pypi_cache)

            if arc_path and arc_path.exists():
                size_bytes = arc_path.stat().st_size
                candidates.append({
                    "row": row,
                    "package_id": pkg_id,
                    "package_name": pkg_name,
                    "version": version,
                    "archive_path": arc_path,
                    "size_bytes": size_bytes,
                    "n_py_files": row.get("n_py_files", 0),
                    "n_files_all": row.get("n_files_all", 0),
                })
            else:
                missing_archives.append(pkg_id)

    return candidates, missing_archives


def stratify_into_terciles(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sort candidates by size_bytes and assign terciles (low, mid, high)."""
    if not candidates:
        return []

    sorted_cands = sorted(candidates, key=lambda c: (c["size_bytes"], c["package_id"]))
    n = len(sorted_cands)
    t1_end = n // 3
    t2_end = (2 * n) // 3

    for i, c in enumerate(sorted_cands):
        if i < t1_end:
            c["tercile"] = "low"
        elif i < t2_end:
            c["tercile"] = "mid"
        else:
            c["tercile"] = "high"

    return sorted_cands


def sample_zero_findings(
    candidates: List[Dict[str, Any]],
    per_tercile: int = 10,
    seed: int = 42,
) -> List[Dict[str, Any]]:
    """Sample per_tercile packages per tercile using deterministic RNG."""
    tercile_groups: Dict[str, List[Dict[str, Any]]] = {"low": [], "mid": [], "high": []}
    for c in candidates:
        tercile_groups[c["tercile"]].append(c)

    rng = random.Random(seed)
    sampled: List[Dict[str, Any]] = []

    for tercile in ("low", "mid", "high"):
        group = tercile_groups[tercile]
        # Sort group before sampling to ensure determinism
        group_sorted = sorted(group, key=lambda x: (x["package_id"], x["size_bytes"]))
        if len(group_sorted) <= per_tercile:
            print(f"Tercile {tercile} has {len(group_sorted)} candidates <= {per_tercile}; taking all.")
            sampled.extend(group_sorted)
        else:
            taken = rng.sample(group_sorted, per_tercile)
            # Sort taken items
            taken.sort(key=lambda x: x["package_id"])
            sampled.extend(taken)

    # Sort final sample deterministically by package_id
    sampled.sort(key=lambda x: x["package_id"])
    return sampled


def inspect_package_context(archive_path: Path) -> Dict[str, Any]:
    """Safe-extract and inspect files for context.md generation."""
    temp_dir = tempfile.mkdtemp(prefix="spider_zero_ctx_")
    try:
        ext_res = safe_extract(archive_path, Path(temp_dir))
        extracted_root = Path(temp_dir)

        files_info = []
        for p in sorted(extracted_root.rglob("*")):
            if p.is_file():
                rel_path = str(p.relative_to(extracted_root)).replace("\\", "/")
                files_info.append({
                    "path": rel_path,
                    "size": p.stat().st_size,
                    "is_py": rel_path.lower().endswith(".py"),
                    "abs_path": p,
                })

        # Capture first 40 lines of setup.py, pyproject.toml, and __init__.py files
        snippets: Dict[str, str] = {}
        for fi in files_info:
            p_name = Path(fi["path"]).name.lower()
            if p_name in ("setup.py", "pyproject.toml") or p_name == "__init__.py":
                try:
                    raw_text = fi["abs_path"].read_text(encoding="utf-8", errors="replace")
                    lines = raw_text.splitlines()[:40]
                    content_40 = "\n".join(lines)
                    sanitized = sanitize_snippet(content_40) or ""
                    snippets[fi["path"]] = sanitized
                except Exception as e:
                    snippets[fi["path"]] = f"# Error reading file: {e}"

        return {
            "files": files_info,
            "snippets": snippets,
            "total_files": len(files_info),
            "py_files": sum(1 for f in files_info if f["is_py"]),
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def run_zero_finding_sampling(
    table_path: Path,
    raw_dir: Path,
    out_csv: Path,
    context_md: Path,
    seed: int = 42,
) -> int:
    candidates, missing = load_zero_finding_candidates(table_path, raw_dir)

    if missing:
        print(f"Warning: {len(missing)} zero-finding packages had missing archives and were excluded:")
        for m in missing[:10]:
            print(f"  {m}")

    if not candidates:
        sys.stderr.write("No candidate zero-finding packages found with available archives.\n")
        return 2

    stratified = stratify_into_terciles(candidates)
    sampled = sample_zero_findings(stratified, per_tercile=10, seed=seed)

    print(f"Sampled {len(sampled)} zero-finding malicious packages across size terciles.")

    # Write results/zero_finding_review.csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "package_id",
        "size_bytes",
        "tercile",
        "n_py_files",
        "n_files_all",
        "miss_reason",
        "miss_note",
    ]

    context_lines = [
        "# Zero-Finding Malicious Review Context",
        "",
        "> Reading aid for manual review of zero-finding malicious packages.",
        "> Contains sanitized excerpts of package manifests and code stubs.",
        "",
    ]

    with out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for s in sampled:
            ctx = inspect_package_context(s["archive_path"])
            n_py = ctx["py_files"]
            n_all = ctx["total_files"]

            writer.writerow({
                "package_id": s["package_id"],
                "size_bytes": s["size_bytes"],
                "tercile": s["tercile"],
                "n_py_files": n_py,
                "n_files_all": n_all,
                "miss_reason": "",
                "miss_note": "",
            })

            # Append context
            context_lines.append(f"## Package: `{s['package_id']}` (tercile: {s['tercile']}, size: {s['size_bytes']} bytes)")
            context_lines.append(f"- **Archive:** `{s['archive_path'].name}`")
            context_lines.append(f"- **Total Files:** {n_all} ({n_py} Python files)")
            context_lines.append("")
            context_lines.append("### File Inventory")
            for fi in ctx["files"]:
                flag = " [Python]" if fi["is_py"] else ""
                context_lines.append(f"- `{fi['path']}` ({fi['size']} bytes){flag}")
            context_lines.append("")

            if ctx["snippets"]:
                context_lines.append("### Key File Excerpts (first 40 lines, sanitized)")
                for path, snip in ctx["snippets"].items():
                    context_lines.append(f"#### `{path}`")
                    context_lines.append("```python")
                    context_lines.append(snip)
                    context_lines.append("```")
                    context_lines.append("")

    context_md.parent.mkdir(parents=True, exist_ok=True)
    context_md.write_text("\n".join(context_lines) + "\n", encoding="utf-8")
    print(f"Review CSV written to: {out_csv}")
    print(f"Context Markdown written to: {context_md}")

    if missing:
        print(f"Candidates without locatable archive: {len(missing)}")
        for m in missing[:10]:
            print(f"  {m}")
    else:
        print("Candidates without locatable archive: 0")

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sample zero-finding malicious packages for manual triage")
    parser.add_argument("--table", default="data/processed/malicious_v11.jsonl", help="Path to malicious_v11.jsonl")
    parser.add_argument("--raw-dir", default="data/raw/malicious/pypi", help="Path to raw malicious archive folder")
    parser.add_argument("--out", default="results/zero_finding_review.csv", help="Path to output review CSV")
    parser.add_argument("--context", default="zero_review/context.md", help="Path to output context markdown")
    parser.add_argument("--seed", type=int, default=42, help="Sampling seed (default 42)")

    args = parser.parse_args(argv)

    return run_zero_finding_sampling(
        table_path=Path(args.table),
        raw_dir=Path(args.raw_dir),
        out_csv=Path(args.out),
        context_md=Path(args.context),
        seed=args.seed,
    )


if __name__ == "__main__":
    sys.exit(main())

