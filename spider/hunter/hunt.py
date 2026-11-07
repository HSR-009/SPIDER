"""Hunter-lite scanning engine (brief section 5.2, 5.6 and spec 7.9).

Never import or execute any scanned package; read files only.
Flags install-time persistence artifacts:
- .pth files with executable lines (starting with import or import\t)
- sitecustomize.py and usercustomize.py
- console_scripts and gui_scripts pointing outside the distribution's own package
- Per-distribution scan of install-relevant files (one file at a time, per-file decide())
- Tamper check when RECORD has hashes (skipping bin/ and Scripts/)
- Fallback for missing RECORD with file_list_unavailable coverage note
- Safety checks: regular files only, size caps (20MB hash, 1MB py AST), per-dist time limits
"""
from __future__ import annotations

import base64
import configparser
import csv
import hashlib
import os
import re
import stat
import sys
import time
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

MAX_HASH_FILE_BYTES = 20 * 1024 * 1024  # 20 MB
MAX_PY_SCAN_BYTES = 1 * 1024 * 1024     # 1 MB
DIST_TIMEOUT_SECONDS = 10.0             # 10 s per distribution


def is_regular_file(path: Path) -> bool:
    """Return True only if path is a regular file (not directory, symlink, fifo, socket, device)."""
    try:
        # Use lstat to check file type without following symlinks into FIFOs/devices
        st = os.lstat(path)
        return stat.S_ISREG(st.st_mode)
    except Exception:
        return False


def is_regular_dir(path: Path) -> bool:
    """Return True only if path is a regular directory (not a symlink to a dir)."""
    try:
        st = os.lstat(path)
        return stat.S_ISDIR(st.st_mode)
    except Exception:
        return False


def check_filesystem_module_ownership(site_dir: Path, top_mod: str) -> bool:
    """Check if top_mod exists in site_dir as a regular directory or file without following symlinks outside.
    
    Checks:
    - <site_dir>/<top_mod>/ exists as a directory (not symlink pointing outside)
    - <site_dir>/<top_mod>.py exists as a regular file
    - <site_dir>/<top_mod>.*.so or <top_mod>.*.pyd exists as a regular file
    """
    if not top_mod:
        return False

    cand_dir = site_dir / top_mod
    try:
        if cand_dir.exists():
            # Check lstat: if directory, ensure it doesn't resolve outside site_dir
            st = os.lstat(cand_dir)
            if stat.S_ISLNK(st.st_mode):
                # Symlink: must resolve to a directory within site_dir
                target = cand_dir.resolve()
                try:
                    target.relative_to(site_dir.resolve())
                    if target.is_dir():
                        return True
                except ValueError:
                    return False
            elif stat.S_ISDIR(st.st_mode):
                return True
    except Exception:
        pass

    cand_py = site_dir / f"{top_mod}.py"
    if is_regular_file(cand_py):
        return True

    # Check .so / .pyd / .dll C extensions next to metadata dir
    try:
        prefix = f"{top_mod}."
        for item in site_dir.iterdir():
            name = item.name.lower()
            if name.startswith(prefix.lower()) and any(name.endswith(ext) for ext in (".so", ".pyd", ".dll")):
                if is_regular_file(item):
                    return True
    except Exception:
        pass

    return False


def sha256_of_file(file_path: Path, max_bytes: int = MAX_HASH_FILE_BYTES) -> Tuple[str, Optional[str]]:
    """Stream hash of a regular file up to max_bytes.
    
    Returns (sha256_hex, skip_note).
    If file exceeds max_bytes, returns ('', 'skipped_too_large').
    If file is not a regular file or cannot be opened, returns ('', 'skipped_not_regular_file').
    """
    if not is_regular_file(file_path):
        return "", "skipped_not_regular_file"

    try:
        size = os.path.getsize(file_path)
        if size > max_bytes:
            return "", "skipped_too_large"
    except Exception:
        return "", "file_stat_failed"

    h = hashlib.sha256()
    read_bytes = 0
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                read_bytes += len(chunk)
                if read_bytes > max_bytes:
                    return "", "skipped_too_large"
                h.update(chunk)
        return h.hexdigest().lower(), None
    except Exception:
        return "", "file_read_error"


def urlsafe_b64_sha256_stream(file_path: Path, max_bytes: int = MAX_HASH_FILE_BYTES) -> Tuple[str, Optional[str]]:
    """Return urlsafe base64 sha256 without padding (as used in RECORD files)."""
    if not is_regular_file(file_path):
        return "", "skipped_not_regular_file"

    try:
        size = os.path.getsize(file_path)
        if size > max_bytes:
            return "", "skipped_too_large"
    except Exception:
        return "", "file_stat_failed"

    h = hashlib.sha256()
    read_bytes = 0
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                read_bytes += len(chunk)
                if read_bytes > max_bytes:
                    return "", "skipped_too_large"
                h.update(chunk)
        digest = h.digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="), None
    except Exception:
        return "", "file_read_error"


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


def inspect_pth_files(root: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Inspect .pth files directly under root for executable lines."""
    items = []
    coverage_notes = []
    try:
        for pth in root.glob("*.pth"):
            if not is_regular_file(pth):
                continue
            sha, skip_note = sha256_of_file(pth)
            if skip_note:
                coverage_notes.append(f"{pth}: {skip_note}")
                if skip_note == "skipped_too_large":
                    continue

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
    return items, coverage_notes


def inspect_custom_startup_hooks(root: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Inspect sitecustomize.py and usercustomize.py directly under root."""
    items = []
    coverage_notes = []
    for name in ("sitecustomize.py", "usercustomize.py"):
        hook_path = root / name
        if not is_regular_file(hook_path):
            continue

        sha, skip_note = sha256_of_file(hook_path)
        if skip_note:
            coverage_notes.append(f"{hook_path}: {skip_note}")
            if skip_note == "skipped_too_large":
                continue

        try:
            sz = os.path.getsize(hook_path)
            if sz > MAX_PY_SCAN_BYTES:
                coverage_notes.append(f"{hook_path}: skipped_py_too_large ({sz} bytes)")
                continue
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
    return items, coverage_notes


def find_top_level_packages(dist_dir: Path, record_file: Optional[Path] = None) -> Set[str]:
    """Identify top-level packages owned by distribution from:
    - RECORD (the first path component of each listed file, ignoring '..' and the metadata folder)
    - top_level.txt if present
    - the normalised dist name
    """
    top_levels: Set[str] = set()

    # From RECORD
    if record_file and is_regular_file(record_file):
        try:
            with record_file.open("r", encoding="utf-8", errors="replace") as rf:
                reader = csv.reader(rf)
                for row in reader:
                    if not row:
                        continue
                    rel_p = row[0].strip().replace("\\", "/").strip("/")
                    if not rel_p or rel_p.startswith("..") or "/.." in rel_p:
                        continue
                    parts = rel_p.split("/")
                    first = parts[0]
                    # Ignore metadata folders (.dist-info, .egg-info)
                    if not first.endswith(".dist-info") and not first.endswith(".egg-info"):
                        if first.endswith(".py"):
                            first = first[:-3]
                        if first:
                            top_levels.add(first.replace("-", "_").lower())
        except Exception:
            pass

    # From top_level.txt
    top_txt = dist_dir / "top_level.txt"
    if is_regular_file(top_txt):
        try:
            for line in top_txt.read_text(encoding="utf-8", errors="replace").splitlines():
                t = line.strip()
                if t:
                    top_levels.add(t.replace("-", "_").lower())
        except Exception:
            pass

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


def get_entry_points_modules(ep_file: Path) -> Tuple[Set[str], List[Dict[str, Any]]]:
    """Parse entry_points.txt and return targeted module names and raw items."""
    targeted_modules: Set[str] = set()
    raw_entries: List[Dict[str, Any]] = []
    if not is_regular_file(ep_file):
        return targeted_modules, raw_entries

    cp = configparser.ConfigParser()
    try:
        cp.read(ep_file, encoding="utf-8")
    except Exception:
        return targeted_modules, raw_entries

    for section in ("console_scripts", "gui_scripts"):
        if not cp.has_section(section):
            continue
        for name, target in cp.items(section):
            # Target format: module:func or module
            mod_part = target.split(":")[0].strip()
            if mod_part:
                targeted_modules.add(mod_part)
            raw_entries.append({
                "section": section,
                "name": name,
                "target": target,
                "module": mod_part,
            })
    return targeted_modules, raw_entries


def inspect_distribution(
    root: Path,
    dist_info: Dict[str, Any],
    timeout_sec: float = DIST_TIMEOUT_SECONDS,
) -> Tuple[List[Dict[str, Any]], Optional[str], List[str]]:
    """Inspect an individual distribution:
    - Checks regular files only (no FIFOs or devices)
    - Tamper check (RECORD), skipping bin/ and Scripts/, remaining at MEDIUM
    - Entry points outside own package
    - Scan only install-relevant files:
      * top-level modules
      * __init__.py and __main__.py of the package
      * leftover setup.py
      * modules targeted by console_scripts / gui_scripts
    - Runs decide() once per file. Emit HIGH only for strong signals within that single file,
      reporting that file's path and hash. Other findings downgraded to LOW.
    - Time limit per distribution (recording coverage error instead of hanging).
    """
    items: List[Dict[str, Any]] = []
    coverage_problem: Optional[str] = None
    errors: List[str] = []

    start_time = time.monotonic()

    dist_name = dist_info.get("name") or ""
    dist_version = dist_info.get("version") or ""
    meta_path_str = dist_info.get("metadata_path")
    meta_dir = Path(meta_path_str) if meta_path_str else None

    if not meta_dir or not meta_dir.exists():
        return items, "file_list_unavailable", errors

    record_file = meta_dir / "RECORD"
    installed_files_txt = meta_dir / "installed-files.txt"

    top_levels = find_top_level_packages(meta_dir, record_file=record_file)

    # 1. Entry point check and targeted modules
    ep_file = meta_dir / "entry_points.txt"
    targeted_ep_modules, raw_ep_entries = get_entry_points_modules(ep_file)

    has_record = is_regular_file(record_file)
    has_top_level = is_regular_file(meta_dir / "top_level.txt")
    site_dir = meta_dir.parent

    if raw_ep_entries:
        ep_sha, ep_skip = sha256_of_file(ep_file)
        if ep_skip:
            errors.append(f"{ep_file}: {ep_skip}")
        normalized_top = {t.lower().replace("-", "_") for t in top_levels}
        if dist_name:
            normalized_top.add(dist_name.lower().replace("-", "_"))

        for ep in raw_ep_entries:
            mod_part = ep["module"]
            top_mod = mod_part.split(".")[0].strip().lower().replace("-", "_")
            if not top_mod:
                continue

            # 1. Already in normalized_top (from RECORD, top_level.txt, or dist name)
            if top_mod in normalized_top:
                continue

            # 2. Ownership by filesystem:
            # <metadata_dir>/../<top_mod>/ exists as a directory, or <top_mod>.py or <top_mod>.*.so exists next to metadata_dir.
            # (stays inside site_dir, regular files/dirs only, no symlink following outside)
            if check_filesystem_module_ownership(site_dir, top_mod):
                # Owned via filesystem!
                continue

            # 3. Ownership could not be established:
            if not has_record and not has_top_level:
                # BOTH RECORD and top_level.txt are missing -> LOW with unknown ownership
                items.append({
                    "dist": dist_name,
                    "version": dist_version,
                    "artifact": "entrypoint",
                    "path": str(ep_file),
                    "sha256": ep_sha,
                    "severity": "LOW",
                    "reason": f"Entry point '{ep['name']} = {ep['target']}' ownership unknown (no RECORD/top_level.txt)",
                    "evidence_snippet": f"[{ep['section']}] {ep['name']} = {ep['target']}",
                })
                errors.append(f"{dist_name}: entrypoint_ownership_unknown ({ep['name']} -> {top_mod})")
            else:
                # Dist has RECORD (or top_level.txt) that does not list it, and module not on disk -> MEDIUM
                items.append({
                    "dist": dist_name,
                    "version": dist_version,
                    "artifact": "entrypoint",
                    "path": str(ep_file),
                    "sha256": ep_sha,
                    "severity": "MEDIUM",
                    "reason": f"Entry point '{ep['name']} = {ep['target']}' targets '{top_mod}' outside package ownership",
                    "evidence_snippet": f"[{ep['section']}] {ep['name']} = {ep['target']}",
                })

    all_dist_py_files: List[Path] = []

    if is_regular_file(record_file):
        try:
            with record_file.open("r", encoding="utf-8", errors="replace") as rf:
                reader = csv.reader(rf)
                for row in reader:
                    # Timeout check during RECORD parsing
                    if (time.monotonic() - start_time) > timeout_sec:
                        errors.append(f"{dist_name}: inspection_timed_out (exceeded {timeout_sec}s)")
                        return items, coverage_problem, errors

                    if not row:
                        continue
                    rel_p = row[0].strip()
                    if not rel_p or rel_p.endswith(".dist-info/RECORD"):
                        continue

                    # Normalize path separators
                    normalized_rel = rel_p.replace("\\", "/").strip("/")

                    # Tamper check: skip entries under bin/ and Scripts/
                    is_bin_script = (
                        normalized_rel.startswith("bin/")
                        or normalized_rel.startswith("Scripts/")
                        or "/bin/" in normalized_rel
                        or "/Scripts/" in normalized_rel
                    )

                    target_p = (meta_dir.parent / rel_p).resolve()
                    if not target_p.exists():
                        coverage_problem = f"Missing file listed in RECORD: {rel_p}"
                        continue

                    if not is_regular_file(target_p):
                        errors.append(f"{target_p}: skipped_not_regular_file")
                        continue

                    if len(row) >= 2 and row[1]:
                        expected_hash_entry = row[1].strip()
                        if expected_hash_entry.startswith("sha256="):
                            if not is_bin_script:
                                exp_digest = expected_hash_entry.split("sha256=")[1].strip()
                                # Determine digest format: 64-char hex or base64
                                is_hex = (len(exp_digest) == 64 and all(c in "0123456789abcdefABCDEF" for c in exp_digest))
                                digest_fmt = "hex" if is_hex else "base64"

                                if is_hex:
                                    actual_hex, skip_note = sha256_of_file(target_p)
                                    match = (actual_hex.lower() == exp_digest.lower())
                                    actual_display = actual_hex
                                else:
                                    actual_b64, skip_note = urlsafe_b64_sha256_stream(target_p)
                                    match = (actual_b64 == exp_digest)
                                    actual_display = actual_b64

                                if skip_note:
                                    errors.append(f"{target_p}: {skip_note}")
                                elif not match:
                                    f_sha, _ = sha256_of_file(target_p)
                                    items.append({
                                        "dist": dist_name,
                                        "version": dist_version,
                                        "artifact": "tamper",
                                        "path": str(target_p),
                                        "sha256": f_sha,
                                        "severity": "MEDIUM",
                                        "digest_format": digest_fmt,
                                        "reason": f"File modified after install (hash mismatch with RECORD; digest format: {digest_fmt})",
                                        "evidence_snippet": f"Expected sha256={exp_digest}, got {actual_display}",
                                    })

                    if target_p.suffix == ".py":
                        all_dist_py_files.append(target_p)
        except Exception as e:
            errors.append(f"Failed to read RECORD for {dist_name}: {e}")
    elif is_regular_file(installed_files_txt):
        try:
            for line in installed_files_txt.read_text(encoding="utf-8", errors="replace").splitlines():
                if (time.monotonic() - start_time) > timeout_sec:
                    errors.append(f"{dist_name}: inspection_timed_out (exceeded {timeout_sec}s)")
                    return items, coverage_problem, errors

                line = line.strip()
                if line:
                    p = (meta_dir / line).resolve()
                    if is_regular_file(p) and p.suffix == ".py":
                        all_dist_py_files.append(p)
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
                    if is_regular_file(p):
                        all_dist_py_files.append(p)
            elif is_regular_file(cand_py):
                found_any = True
                all_dist_py_files.append(cand_py)

        if not found_any:
            coverage_problem = "file_list_unavailable"

    # 3. Filter to install-relevant files only:
    # - Top-level modules (parent == root or immediate root file)
    # - __init__.py and __main__.py of the package
    # - Leftover setup.py
    # - Modules that console_scripts and gui_scripts entry points target
    # Build relative paths for matching targeted entry points
    relevant_files: List[Path] = []
    
    # Precompute targeted relative file paths (e.g. "pkg/cli.py" for module "pkg.cli")
    targeted_rel_paths = set()
    for mod in targeted_ep_modules:
        mod_rel = mod.replace(".", "/") + ".py"
        targeted_rel_paths.add(mod_rel.lower())
        targeted_rel_paths.add(mod.replace(".", "/") + "/__init__.py".lower())

    for p in all_dist_py_files:
        if not is_regular_file(p):
            continue
        p_name = p.name
        is_relevant = False

        if p_name in ("__init__.py", "__main__.py", "setup.py"):
            is_relevant = True
        elif p.parent == root:
            # Top-level module
            is_relevant = True
        else:
            # Check if this matches a targeted entry point module
            try:
                rel_to_root = str(p.relative_to(root)).replace("\\", "/").lower()
                if rel_to_root in targeted_rel_paths or any(rel_to_root.endswith("/" + target) for target in targeted_rel_paths):
                    is_relevant = True
            except Exception:
                pass

        if is_relevant and p not in relevant_files:
            relevant_files.append(p)

    # 4. Per-file AST scan and per-file decide()
    for fpath in relevant_files:
        if (time.monotonic() - start_time) > timeout_sec:
            errors.append(f"{dist_name}: inspection_timed_out (exceeded {timeout_sec}s)")
            break

        try:
            sz = os.path.getsize(fpath)
            if sz > MAX_PY_SCAN_BYTES:
                errors.append(f"{fpath}: skipped_py_too_large ({sz} bytes)")
                continue

            code = fpath.read_text(encoding="utf-8", errors="replace")
            f_findings, parse_err = analyze_source(code, path=fpath.name)
            if parse_err:
                errors.append(f"{fpath}: parse_error ({parse_err})")
                continue

            if not f_findings:
                continue

            # Run decide() strictly on THIS file's findings alone!
            outcome, strong, review_rec = decide(f_findings)
            f_sha, skip_note = sha256_of_file(fpath)
            if skip_note:
                errors.append(f"{fpath}: {skip_note}")

            if strong:
                # Strong signal found within a single file -> HIGH
                for s in strong:
                    items.append({
                        "dist": dist_name,
                        "version": dist_version,
                        "artifact": "dist_scan",
                        "path": str(fpath),
                        "sha256": f_sha,
                        "severity": "HIGH",
                        "reason": f"File {fpath.name} contains strong signal {s}",
                        "evidence_snippet": f"Strong signal triggered: {s}",
                    })
            elif review_rec or f_findings:
                # Any other finding downgraded to LOW
                first_f = f_findings[0]
                items.append({
                    "dist": dist_name,
                    "version": dist_version,
                    "artifact": "dist_scan",
                    "path": str(fpath),
                    "sha256": f_sha,
                    "severity": "LOW",
                    "reason": f"File {fpath.name} findings downgraded to LOW ({first_f.get('indicator')})",
                    "evidence_snippet": f"Indicator: {first_f.get('indicator')}",
                })
        except Exception as e:
            errors.append(f"Error scanning {fpath}: {e}")

    return items, coverage_problem, errors


def run_hunt(
    extra_site_packages: Optional[List[str | Path]] = None,
    db_path: Optional[str | Path] = None,
    include_system_defaults: bool = True,
    dist_timeout: float = DIST_TIMEOUT_SECONDS,
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
        pth_items, pth_notes = inspect_pth_files(root_path)
        all_raw_items.extend(pth_items)
        if pth_notes:
            coverage_errors.extend(pth_notes)

        # 2. startup hooks
        startup_items, startup_notes = inspect_custom_startup_hooks(root_path)
        all_raw_items.extend(startup_items)
        if startup_notes:
            coverage_errors.extend(startup_notes)

        # 3. Distributions
        for dist in iter_distributions(root_path):
            total_distributions += 1
            dist_items, cov_prob, errs = inspect_distribution(root_path, dist, timeout_sec=dist_timeout)
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

    # Calculate coverage counts per kind
    coverage_counts = {
        "skipped_too_large": 0,
        "missing_in_RECORD": 0,
        "inspection_timed_out": 0,
        "file_list_unavailable": len(coverage_dists_without_file_list),
        "entrypoint_ownership_unknown": 0,
    }

    for err in coverage_errors:
        err_lower = err.lower()
        if "skipped_too_large" in err_lower or "skipped_py_too_large" in err_lower:
            coverage_counts["skipped_too_large"] += 1
        elif "missing file listed in record" in err_lower:
            coverage_counts["missing_in_RECORD"] += 1
        elif "inspection_timed_out" in err_lower:
            coverage_counts["inspection_timed_out"] += 1
        elif "file_list_unavailable" in err_lower:
            coverage_counts["file_list_unavailable"] += 1
        elif "entrypoint_ownership_unknown" in err_lower:
            coverage_counts["entrypoint_ownership_unknown"] += 1

    return {
        "hunt_id": scan_id,
        "created_at": created_at,
        "spider_version": getattr(spider, "__version__", "1.1"),
        "roots": [str(r) for r in roots],
        "distributions_count": total_distributions,
        "items": processed_items,
        "coverage": {
            "counts": coverage_counts,
            "dists_without_file_list": coverage_dists_without_file_list,
            "errors": coverage_errors,
        },
        "limitations": [DISCLAIMER],
    }
