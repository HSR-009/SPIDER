"""Engine scanner: scan_directory (section 2.4)."""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Set

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

from spider_contract.hashing import sha256_bytes, sha256_file
from spider_contract.verdict import coverage_problems, derive_verdict
from spider_contract.adapter import normalize_category
from Person_A.ast_analyzer.analyzer_v1_1 import analyze_source
from spider.engine.limits import Limits
from spider.engine.classify import classify, EXCLUDE_DIRS, VENDORED_DIRS
from spider.engine.phase import trigger_phase
from spider.engine.records import build_finding, build_relations

KNOWN_BACKENDS = {
    "setuptools.build_meta",
    "setuptools.build_meta:__legacy__",
    "flit_core.buildapi",
    "hatchling.build",
    "poetry.core.masonry.api",
    "pdm.backend",
    "maturin",
    "scikit_build_core.build",
    "mesonpy",
}


def scan_directory(
    path: str | Path,
    *,
    name: Optional[str] = None,
    version: Optional[str] = None,
    scan_id: Optional[str] = None,
    exclude_dirs: Set[str] = EXCLUDE_DIRS,
    limits: Optional[Limits] = None,
    analyzer_version: str = "analyzer-v1.1",
    ruleset_version: str = "rules-v1.1",
    spider_version: str = "0.1.0-dev",
) -> Dict[str, Any]:
    if limits is None:
        limits = Limits()

    root_path = Path(path).resolve()
    pkg_name = name or root_path.name
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sid = scan_id or str(uuid.uuid4())

    limits_hit = []
    uninspected = []
    parse_failures = []
    vendored_paths = set()
    files_entries = []
    raw_findings = []

    total_files_count = 0
    total_bytes_count = 0
    coverage_known = True

    # 1. Walk with os.scandir recursion
    def walk_dir(current_dir: Path, depth: int):
        nonlocal total_files_count, total_bytes_count, coverage_known

        if depth > limits.max_depth:
            if "max_depth" not in limits_hit:
                limits_hit.append("max_depth")
            return

        try:
            entries = sorted(os.scandir(current_dir), key=lambda e: e.name)
        except OSError as e:
            coverage_known = False
            return

        for entry in entries:
            try:
                if entry.is_symlink():
                    rel = str(PurePosixPath(Path(entry.path).relative_to(root_path)))
                    uninspected.append({"path": rel, "reason": "symlink_skipped"})
                    continue

                if entry.is_dir():
                    if entry.name == "__pycache__":
                        continue
                    walk_dir(Path(entry.path), depth + 1)
                elif entry.is_file():
                    total_files_count += 1
                    if total_files_count > limits.max_files:
                        if "max_files" not in limits_hit:
                            limits_hit.append("max_files")
                        return

                    file_stat = entry.stat()
                    file_size = file_stat.st_size

                    if total_bytes_count + file_size > limits.max_total_bytes:
                        if "max_total_bytes" not in limits_hit:
                            limits_hit.append("max_total_bytes")
                        return

                    total_bytes_count += file_size
                    rel = str(PurePosixPath(Path(entry.path).relative_to(root_path)))

                    kind, roles = classify(rel)

                    # Track vendored paths
                    if "vendored" in roles:
                        # Collect the directory
                        parent_rel = str(PurePosixPath(Path(entry.path).parent.relative_to(root_path)))
                        # Find the top vendored folder relative to root
                        parts = PurePosixPath(rel).parts
                        for i, part in enumerate(parts[:-1]):
                            if part.lower() in VENDORED_DIRS:
                                v_dir = "/".join(parts[: i + 1])
                                vendored_paths.add(v_dir)
                                break

                    if file_size > limits.max_file_bytes:
                        uninspected.append({"path": rel, "reason": "too_large"})
                        files_entries.append({
                            "path": rel,
                            "kind": kind,
                            "sha256": None,
                            "lines": None,
                            "inspected": False,
                            "roles": roles,
                        })
                        continue

                    file_hash = sha256_file(entry.path)

                    if kind == "binary":
                        uninspected.append({"path": rel, "reason": "binary_not_analyzed"})
                        files_entries.append({
                            "path": rel,
                            "kind": kind,
                            "sha256": file_hash,
                            "lines": None,
                            "inspected": False,
                            "roles": roles,
                        })
                        continue

                    if kind == "doc":
                        # Not analyzed, but inspected = False, no uninspected reason (per doc rules)
                        files_entries.append({
                            "path": rel,
                            "kind": kind,
                            "sha256": file_hash,
                            "lines": None,
                            "inspected": False,
                            "roles": roles,
                        })
                        continue

                    if kind == "build_config":
                        # Parse pyproject.toml / setup.cfg
                        inspected = False
                        lines_count = None
                        try:
                            content_bytes = Path(entry.path).read_bytes()
                            text = content_bytes.decode("utf-8", errors="replace")
                            lines_count = len(text.splitlines())
                        except Exception:
                            text = ""

                        if entry.name.lower() == "pyproject.toml":
                            if tomllib is None:
                                uninspected.append({"path": rel, "reason": "toml_parser_unavailable"})
                            else:
                                try:
                                    data = tomllib.loads(text)
                                    inspected = True
                                    build_sys = data.get("build-system", {})
                                    backend = build_sys.get("build-backend")
                                    backend_path = build_sys.get("backend-path")
                                    if (backend and backend not in KNOWN_BACKENDS) or backend_path:
                                        raw_findings.append({
                                            "raw": {
                                                "category": "Install-Time / Package Execution",
                                                "indicator": "custom_build_backend",
                                                "severity": "MEDIUM",
                                                "rule_id": "inst.custom_build_backend",
                                                "evidence": f"custom build backend: {backend}",
                                                "line": 1,
                                                "col": None,
                                                "end_line": None,
                                                "end_col": None,
                                                "snippet": f"build-backend = '{backend}'",
                                                "enclosing_function": None,
                                                "scope": "module",
                                                "in_main_guard": False,
                                                "confidence": "medium",
                                            },
                                            "file": rel,
                                            "roles": roles,
                                            "in_vendored": "vendored" in roles,
                                        })
                                except Exception as err:
                                    uninspected.append({"path": rel, "reason": f"toml_parse_error: {err}"})
                        elif entry.name.lower() == "setup.cfg":
                            inspected = True
                            if "[cmdclass]" in text:
                                raw_findings.append({
                                    "raw": {
                                        "category": "Install-Time / Package Execution",
                                        "indicator": "setup_cfg_cmdclass",
                                        "severity": "MEDIUM",
                                        "rule_id": "inst.cmdclass",
                                        "evidence": "setup.cfg overrides cmdclass",
                                        "line": 1,
                                        "col": None,
                                        "end_line": None,
                                        "end_col": None,
                                        "snippet": "[cmdclass]",
                                        "enclosing_function": None,
                                        "scope": "module",
                                        "in_main_guard": False,
                                        "confidence": "medium",
                                    },
                                    "file": rel,
                                    "roles": roles,
                                    "in_vendored": "vendored" in roles,
                                })
                        else:
                            inspected = True

                        files_entries.append({
                            "path": rel,
                            "kind": kind,
                            "sha256": file_hash,
                            "lines": lines_count,
                            "inspected": inspected,
                            "roles": roles,
                        })
                        continue

                    if kind == "python":
                        try:
                            content_bytes = Path(entry.path).read_bytes()
                            src = content_bytes.decode("utf-8", errors="replace")
                            lines_count = len(src.splitlines())
                        except Exception as e:
                            parse_failures.append({"path": rel, "error": f"read error: {e}"})
                            files_entries.append({
                                "path": rel,
                                "kind": kind,
                                "sha256": file_hash,
                                "lines": None,
                                "inspected": False,
                                "roles": roles,
                            })
                            continue

                        f_list, p_err = analyze_source(src, rel)
                        if p_err:
                            parse_failures.append({"path": rel, "error": p_err.get("error", "syntax error")})
                            files_entries.append({
                                "path": rel,
                                "kind": kind,
                                "sha256": file_hash,
                                "lines": lines_count,
                                "inspected": False,
                                "roles": roles,
                            })
                        else:
                            files_entries.append({
                                "path": rel,
                                "kind": kind,
                                "sha256": file_hash,
                                "lines": lines_count,
                                "inspected": True,
                                "roles": roles,
                            })
                            for f in f_list:
                                raw_findings.append({
                                    "raw": f,
                                    "file": rel,
                                    "roles": roles,
                                    "in_vendored": "vendored" in roles,
                                })
                        continue

                    # metadata or other
                    if kind == "other":
                        if file_size > 0:
                            uninspected.append({"path": rel, "reason": "unknown_type"})
                        files_entries.append({
                            "path": rel,
                            "kind": kind,
                            "sha256": file_hash,
                            "lines": None,
                            "inspected": False,
                            "roles": roles,
                        })
                    else:
                        files_entries.append({
                            "path": rel,
                            "kind": kind,
                            "sha256": file_hash,
                            "lines": None,
                            "inspected": True,
                            "roles": roles,
                        })
            except OSError:
                continue

    if root_path.exists():
        walk_dir(root_path, 0)
    else:
        coverage_known = False

    # Sort files by path for deterministic order
    files_entries.sort(key=lambda x: x["path"])

    # Order raw_findings by (file, line)
    raw_findings.sort(key=lambda item: (item["file"], item["raw"].get("line") or 0))

    # Build scan_record findings
    findings = []
    raw_map = {}
    for idx, item in enumerate(raw_findings, start=1):
        fid = f"F{idx:03d}"
        t_phase = trigger_phase(item["raw"], item["roles"])
        f_entry = build_finding(fid, item["raw"], item["file"], t_phase, item["in_vendored"])
        findings.append(f_entry)
        raw_map[fid] = item["raw"]

    # Relations
    relations = build_relations(findings, raw_map)

    # Compute inventory counts
    files_total = len(files_entries)
    python_files = sum(1 for f in files_entries if f["kind"] == "python")
    files_inspected = sum(1 for f in files_entries if f["inspected"])

    # Compute target.artifact.sha256 from the per-file hashes already collected
    # Lines "<relpath>\0<file sha256>\n" sorted by relpath
    # Files over max_file_bytes appear as "<relpath>\0too_large\n"
    too_large_paths = {u["path"] for u in uninspected if u["reason"] == "too_large"}
    hash_lines = []
    for f in sorted(files_entries, key=lambda x: x["path"]):
        if f["sha256"] is not None:
            hash_lines.append(f"{f['path']}\0{f['sha256']}\n")
        elif f["path"] in too_large_paths:
            hash_lines.append(f"{f['path']}\0too_large\n")
    artifact_hash = sha256_bytes("".join(hash_lines).encode("utf-8")) if hash_lines else None

    record: Dict[str, Any] = {
        "schema_version": "0.1",
        "scan_id": sid,
        "created_at": created_at,
        "record_origin": "analyzer",
        "tool": {
            "spider_version": spider_version,
            "analyzer_version": analyzer_version,
            "ruleset_version": ruleset_version,
        },
        "target": {
            "kind": "directory",
            "name": pkg_name,
            "version": version,
            "artifact": {
                "filename": None,
                "sha256": artifact_hash,
                "size_bytes": total_bytes_count,
                "format": "dir",
            },
            "hash_verified": None,
        },
        "inventory": {
            "coverage_known": coverage_known,
            "files_total": files_total,
            "python_files": python_files,
            "files_inspected": files_inspected,
            "uninspected": uninspected,
            "parse_failures": parse_failures,
            "vendored_paths": sorted(list(vendored_paths)),
            "limits_hit": limits_hit,
        },
        "files": files_entries,
        "findings": findings,
        "relations": relations,
        "model_assessment": {
            "status": "not_run",
            "model_name": None,
            "model_version": None,
            "label": None,
            "score": None,
            "calibrated": False,
            "illustrative": False,
            "top_features": [],
            "note": None,
        },
        "verdict": {
            "outcome": "none_detected_in_this_scan",
            "reasons": [],
            "limitations": ["Static analysis only: 'none detected in this scan' does not mean the package is safe."],
        },
        "timings_ms": {
            "acquire": None,
            "extract": None,
            "analyze": None,
            "features": None,
            "model": None,
        },
    }

    # Derive verdict
    v_dict = derive_verdict(record)
    record["verdict"]["outcome"] = v_dict["outcome"]
    record["verdict"]["reasons"] = v_dict["reasons"]
    if "review_recommended" in v_dict:
        record["verdict"]["review_recommended"] = v_dict["review_recommended"]

    # Copy derive_verdict()'s limitations / coverage problems and keep the static-analysis sentence
    limitations = ["Static analysis only: 'none detected in this scan' does not mean the package is safe."]
    cov_probs = coverage_problems(record)
    for p in cov_probs:
        limitations.append(f"Coverage problem: {p}")
    record["verdict"]["limitations"] = limitations

    return record
