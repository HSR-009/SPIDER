"""Hunter-lite scanning engine (brief section 5.2, 5.6 and spec 7.9).

Never import or execute any scanned package; read files only.
Flags install-time persistence artifacts:
- .pth files with executable lines (starting with import or import\t)
- sitecustomize.py and usercustomize.py
- console_scripts and gui_scripts pointing outside the distribution's own package
- Per-distribution scan of install-relevant files
- Tamper check when RECORD has hashes
- Fallback for missing RECORD with file_list_unavailable coverage note
"""
from __future__ import annotations

import base64
import csv
import configparser
import hashlib
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import spider
from spider.engine.scan import analyze_source
from spider.hunter.inventory import iter_distributions, list_environments
from spider.hunter.store import HunterStore
from spider_contract.verdict_v2 import decide

# Keywords in executable .pth lines that escalate severity to HIGH
PTH_HIGH_KEYWORDS = {
    "exec", "eval", "os.system", "subprocess", "base64",
    "socket", "urllib", "http", "compile", "__import__"
}

DISCLAIMER = "Static inspection of installed files only; a clean hunt does not mean the machine is clean."


def sha256_of_file(file_path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest().lower()
    except Exception:
        return ""


def urlsafe_b64_sha256(data: bytes) -> str:
    """Return urlsafe base64 sha256 without padding (as used in RECORD files)."""
    digest = hashlib.sha256(data).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def calculate_priority(severity: str, artifact: str, new_since_last: bool, allowlisted: bool) -> int:
    """Compute priority according to spec 7.9:
    HIGH=100, MEDIUM=50, LOW=10;
    +30 if new since last scan;
    +20 for .pth or startup hooks;
    allowlisted by sha256 -> priority 0 and hidden by default.
    """
    if allowlisted:
        return 0

    base = {"HIGH": 100, "MEDIUM": 50, "LOW": 10}.get(severity.upper(), 10)
    if new_since_last:
        base += 30
    if artifact in ("pth", "startup"):
        base += 20
    return base


def sanitize_path(path_str: str) -> str:
    """Replace user home directory with ~."""
    try:
        home = str(Path.home())
        if path_str.startswith(home):
            return "~" + path_str[len(home):]
    except Exception:
        pass
    return path_str


def inspect_pth_files(root: Path) -> List[Dict[str, Any]]:
    """Inspect .pth files directly under root for executable lines."""
    items = []
    try:
        for pth in root.glob("*.pth"):
            if not pth.is_file():
                continue
            sha = sha256_of_file(pth)
            try:
                content = pth.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for idx, line in enumerate(content.splitlines(), 1):
                raw = line.strip()
                if line.startswith("import ") or line.startswith("import\t"):
                    # Executable line detected!
                    has_high = any(re.search(r"\b" + re.escape(kw) + r"\b", line) for kw in PTH_HIGH_KEYWORDS)
                    severity = "HIGH" if has_high else "MEDIUM"
                    reason = f"Executable code in .pth line {idx}: {raw[:80]}"
                    items.append({
                        "dist": "",
                        "version": "",
                        "artifact": "pth",
                        "path": str(pth),
                        "sha256": sha,
                        "severity": severity,
                        "reason": reason,
                        "evidence_snippet": raw[:160],
                    })
    except Exception:
        pass
    return items


def inspect_custom_startup_hooks(root: Path) -> List[Dict[str, Any]]:
    """Inspect sitecustomize.py and usercustomize.py directly under root."""
    items = []
    for name in ("sitecustomize.py", "usercustomize.py"):
        hook_path = root / name
        if not hook_path.is_file():
            continue

        sha = sha256_of_file(hook_path)
        try:
            content = hook_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        findings, parse_error = analyze_source(content, path=name)
        if parse_error:
            # Parse error on startup hook is at least medium
            items.append({
                "dist": "",
                "version": "",
                "artifact": "startup",
                "path": str(hook_path),
                "sha256": sha,
                "severity": "MEDIUM",
                "reason": f"Startup hook {name} parse error: {parse_error}",
                "evidence_snippet": content[:160],
            })
            continue

        # Evaluate verdict v2
        outcome, strong_signals, review_rec = decide(findings)

        if strong_signals:
            severity = "HIGH"
            reason = f"Startup hook {name} contains strong signals: {', '.join(strong_signals)}"
        elif findings:
            severity = "MEDIUM"
            ind_names = [f.get("indicator") for f in findings if f.get("indicator")]
            reason = f"Startup hook {name} contains suspicious findings: {', '.join(ind_names[:3])}"
        else:
            severity = "LOW"
            reason = f"Startup hook {name} present"

        items.append({
            "dist": "",
            "version": "",
            "artifact": "startup",
            "path": str(hook_path),
            "sha256": sha,
            "severity": severity,
            "reason": reason,
            "evidence_snippet": content[:160],
        })
    return items


def find_top_level_packages(dist_dir: Path) -> Set[str]:
    """Identify top-level packages owned by distribution from top_level.txt or dist-info name."""
    top_levels = set()
    top_txt = dist_dir / "top_level.txt"
    if top_txt.is_file():
        try:
            for line in top_txt.read_text(encoding="utf-8", errors="replace").splitlines():
                t = line.strip()
                if t:
                    top_levels.add(t)
        except Exception:
            pass

    # From directory name (e.g. foo-1.0.dist-info -> foo)
    folder_name = dist_dir.name
    if ".dist-info" in folder_name:
        base = folder_name.split(".dist-info")[0]
        name = base.split("-")[0].replace("-", "_").lower()
        top_levels.add(name)
    elif ".egg-info" in folder_name:
        base = folder_name.split(".egg-info")[0]
        name = base.split("-")[0].replace("-", "_").lower()
        top_levels.add(name)

    return top_levels


def inspect_entry_points(dist_dir: Path, dist_name: str, dist_version: str, top_levels: Set[str]) -> List[Dict[str, Any]]:
    """Check console_scripts and gui_scripts for entry points outside own package."""
    items = []
    ep_file = dist_dir / "entry_points.txt"
    if not ep_file.is_file():
        return items

    sha = sha256_of_file(ep_file)
    cp = configparser.ConfigParser()
    try:
        cp.read(ep_file, encoding="utf-8")
    except Exception:
        return items

    normalized_top = {t.lower().replace("-", "_") for t in top_levels}
    if dist_name:
        normalized_top.add(dist_name.lower().replace("-", "_"))

    for section in ("console_scripts", "gui_scripts"):
        if not cp.has_section(section):
            continue
        for name, target in cp.items(section):
            # Target format: module:func or module
            mod_part = target.split(":")[0].strip()
            top_mod = mod_part.split(".")[0].strip().lower().replace("-", "_")
            if top_mod and top_mod not in normalized_top:
                items.append({
                    "dist": dist_name,
                    "version": dist_version,
                    "artifact": "entrypoint",
                    "path": str(ep_file),
                    "sha256": sha,
                    "severity": "MEDIUM",
                    "reason": f"Entry point '{name} = {target}' targets '{top_mod}' outside package ownership",
                    "evidence_snippet": f"[{section}] {name} = {target}",
                })
    return items


def inspect_distribution(
    root: Path,
    dist_info: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], Optional[str], List[str]]:
    """Inspect an individual distribution:
    - Tamper check (RECORD)
    - File list resolution (RECORD, installed-files.txt, top_level.txt, directory listing)
    - Entry points outside own package
    - Per-distribution scan of install-relevant files (max 200)
    """
    items: List[Dict[str, Any]] = []
    coverage_problem: Optional[str] = None
    errors: List[str] = []

    dist_name = dist_info.get("name") or ""
    dist_version = dist_info.get("version") or ""
    meta_path_str = dist_info.get("metadata_path")
    meta_dir = Path(meta_path_str) if meta_path_str else None

    if not meta_dir or not meta_dir.exists():
        return items, "file_list_unavailable", errors

    top_levels = find_top_level_packages(meta_dir)

    # 1. Entry point check
    items.extend(inspect_entry_points(meta_dir, dist_name, dist_version, top_levels))

    # 2. File list & tamper check
    record_file = meta_dir / "RECORD"
    installed_files_txt = meta_dir / "installed-files.txt"
    files_to_scan: List[Path] = []

    if record_file.is_file():
        # Check hashes in RECORD
        try:
            with record_file.open("r", encoding="utf-8", errors="replace") as rf:
                reader = csv.reader(rf)
                for row in reader:
                    if not row:
                        continue
                    rel_p = row[0].strip()
                    if not rel_p or rel_p.endswith(".dist-info/RECORD"):
                        continue
                    
                    target_p = (meta_dir.parent / rel_p).resolve()
                    if not target_p.exists():
                        coverage_problem = f"Missing file listed in RECORD: {rel_p}"
                        continue

                    # Check tamper hash if provided
                    if len(row) >= 2 and row[1]:
                        expected_hash_entry = row[1].strip()
                        if expected_hash_entry.startswith("sha256="):
                            exp_sha = expected_hash_entry.split("sha256=")[1].strip()
                            try:
                                file_bytes = target_p.read_bytes()
                                actual_sha = urlsafe_b64_sha256(file_bytes)
                                if actual_sha != exp_sha:
                                    items.append({
                                        "dist": dist_name,
                                        "version": dist_version,
                                        "artifact": "tamper",
                                        "path": str(target_p),
                                        "sha256": hashlib.sha256(file_bytes).hexdigest().lower(),
                                        "severity": "MEDIUM",
                                        "reason": "File modified after install (hash mismatch with RECORD)",
                                        "evidence_snippet": f"Expected sha256={exp_sha}, got {actual_sha}",
                                    })
                            except Exception as e:
                                errors.append(f"Cannot read {target_p} for tamper check: {e}")

                    if target_p.suffix == ".py":
                        files_to_scan.append(target_p)
        except Exception as e:
            errors.append(f"Failed to read RECORD for {dist_name}: {e}")
    elif installed_files_txt.is_file():
        try:
            for line in installed_files_txt.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line:
                    p = (meta_dir / line).resolve()
                    if p.is_file() and p.suffix == ".py":
                        files_to_scan.append(p)
        except Exception:
            pass
    else:
        # Fallback to directory listing using top_level.txt
        found_any = False
        for tl in top_levels:
            cand_dir = root / tl
            cand_py = root / f"{tl}.py"
            if cand_dir.is_dir():
                found_any = True
                for p in cand_dir.rglob("*.py"):
                    if p.is_file():
                        files_to_scan.append(p)
            elif cand_py.is_file():
                found_any = True
                files_to_scan.append(cand_py)

        if not found_any:
            coverage_problem = "file_list_unavailable"

    # 3. Per-distribution scan of install-relevant files (max 200)
    # Install relevant: top-level modules, __init__.py, __main__.py, etc.
    relevant_files: List[Path] = []
    for p in files_to_scan:
        name = p.name
        if name in ("__init__.py", "__main__.py", "setup.py") or p.parent == root:
            relevant_files.append(p)
        elif len(relevant_files) < 200:
            relevant_files.append(p)

    relevant_files = relevant_files[:200]

    all_dist_findings = []
    for fpath in relevant_files:
        try:
            code = fpath.read_text(encoding="utf-8", errors="replace")
            f_findings, parse_err = analyze_source(code, path=fpath.name)
            if f_findings:
                for f in f_findings:
                    f["file_obj_path"] = str(fpath)
                    all_dist_findings.append(f)
        except Exception:
            pass

    if all_dist_findings:
        outcome, strong, review_recommended = decide(all_dist_findings)
        if strong:
            for s in strong:
                # Find finding corresponding to this reason
                first_f = all_dist_findings[0]
                p_path = first_f.get("file_obj_path", str(relevant_files[0]))
                items.append({
                    "dist": dist_name,
                    "version": dist_version,
                    "artifact": "dist_scan",
                    "path": p_path,
                    "sha256": sha256_of_file(Path(p_path)),
                    "severity": "HIGH",
                    "reason": f"Distribution contains strong signal {s}",
                    "evidence_snippet": f"Strong signal triggered: {s}",
                })
        elif review_recommended:
            first_f = all_dist_findings[0]
            p_path = first_f.get("file_obj_path", str(relevant_files[0]))
            items.append({
                "dist": dist_name,
                "version": dist_version,
                "artifact": "dist_scan",
                "path": p_path,
                "sha256": sha256_of_file(Path(p_path)),
                "severity": "LOW",
                "reason": "Distribution inspection triggered review_recommended",
                "evidence_snippet": f"Indicators: {first_f.get('indicator')}",
            })

    return items, coverage_problem, errors


def run_hunt(
    extra_site_packages: Optional[List[str | Path]] = None,
    db_path: Optional[str | Path] = None,
    include_system_defaults: bool = True,
) -> Dict[str, Any]:
    """Execute hunter scan across environment roots."""
    scan_id = f"hunt_{uuid.uuid4().hex[:12]}"
    created_at = datetime.now(timezone.utc).isoformat()
    roots = list_environments(
        extra_site_packages=extra_site_packages,
        include_system_defaults=include_system_defaults,
    )

    store = HunterStore(db_path=db_path)
    allowlist = store.get_allowlist()
    prev_items = store.get_previous_scan_items()

    all_raw_items: List[Dict[str, Any]] = []
    coverage_dists_without_file_list: List[str] = []
    coverage_errors: List[str] = []
    total_distributions = 0

    for root in roots:
        root_path = Path(root).resolve()
        if not root_path.exists():
            continue

        # 1. .pth files
        all_raw_items.extend(inspect_pth_files(root_path))

        # 2. startup hooks
        all_raw_items.extend(inspect_custom_startup_hooks(root_path))

        # 3. Distributions
        for dist in iter_distributions(root_path):
            total_distributions += 1
            dist_items, cov_prob, errs = inspect_distribution(root_path, dist)
            all_raw_items.extend(dist_items)
            if cov_prob:
                if cov_prob == "file_list_unavailable":
                    coverage_dists_without_file_list.append(dist.get("name") or "unknown")
                else:
                    coverage_errors.append(f"{dist.get('name')}: {cov_prob}")
            if errs:
                coverage_errors.extend(errs)

    # Process items with new_since_last and priority
    processed_items: List[Dict[str, Any]] = []
    for item in all_raw_items:
        dist_key = item.get("dist", "")
        art_key = item.get("artifact", "")
        sha_key = (item.get("sha256") or "").lower()

        # Check allowlist
        is_allowed = sha_key in allowlist and bool(sha_key)

        # "New since last scan" = items whose (dist, artifact, sha256) were absent in previous scan
        new_since_last = (dist_key, art_key, sha_key) not in prev_items

        priority = calculate_priority(
            severity=item.get("severity", "LOW"),
            artifact=art_key,
            new_since_last=new_since_last,
            allowlisted=is_allowed,
        )

        item_out = dict(item)
        item_out["priority"] = priority
        item_out["new_since_last"] = new_since_last
        item_out["allowlisted"] = is_allowed
        processed_items.append(item_out)

    # Sort items by priority descending
    processed_items.sort(key=lambda x: x["priority"], reverse=True)

    # Record scan in SQLite store
    store.record_scan(
        scan_id=scan_id,
        roots_count=len(roots),
        items=processed_items,
        ts=created_at,
    )

    return {
        "hunt_id": scan_id,
        "created_at": created_at,
        "spider_version": getattr(spider, "__version__", "1.1"),
        "roots": [str(r) for r in roots],
        "distributions_count": total_distributions,
        "items": processed_items,
        "coverage": {
            "dists_without_file_list": coverage_dists_without_file_list,
            "errors": coverage_errors,
        },
        "limitations": [DISCLAIMER],
    }
