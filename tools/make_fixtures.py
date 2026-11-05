#!/usr/bin/env python3
"""Generate the five contract fixtures.

Writes:
  fixtures/src/<package>/...      tiny synthetic, HARMLESS source trees
  fixtures/records/<NN_name>.json hand-written scan records describing them

IMPORTANT: the records are *contract examples* written by hand (record_origin =
"hand_written_fixture"). They are NOT analyzer output. Spans and snippets are
computed from the real source text so they are exact; severities, phases and
model values are illustrative. Level 1 golden tests = run the real analyzer on
fixtures/src and diff against these records after Person A reviews them.

Run from anywhere:  python tools/make_fixtures.py
"""
from __future__ import annotations

import ast
import base64
import json
import shutil
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from spider_contract.hashing import sha256_bytes, tree_sha256  # noqa: E402
from spider_contract.verdict import coverage_problems, derive_verdict  # noqa: E402

SRC_DIR = ROOT / "fixtures" / "src"
REC_DIR = ROOT / "fixtures" / "records"
CREATED_AT = "2026-11-01T00:00:00Z"
NONE_DETECTED_NOTE = "Static analysis only: 'none detected in this scan' does not mean the package is safe."

Source = Any  # str or bytes


# --------------------------------------------------------------------------- helpers
def to_bytes(content: Source) -> bytes:
    return content if isinstance(content, bytes) else content.encode("utf-8")


def span_of(text: str, needle: str, nth: int = 1) -> Dict[str, int]:
    assert "\n" not in needle, "needle must be a single line"
    idx = -1
    for _ in range(nth):
        idx = text.index(needle, idx + 1)  # raises ValueError if absent
    line = text.count("\n", 0, idx) + 1
    col = idx - (text.rfind("\n", 0, idx) + 1)
    return {"start_line": line, "start_col": col, "end_line": line, "end_col": col + len(needle)}


def make_finding(
    sources: Dict[str, Source], fid: str, rule_id: str, category: str, indicator: str,
    severity: str, confidence: str, file: str, needle: str, explanation: str, phase: str,
    func: Optional[str] = None, after_norm: bool = False, vendored: bool = False,
    nth: int = 1, limitations: Optional[List[str]] = None,
) -> Dict[str, Any]:
    text = sources[file]
    assert isinstance(text, str)
    return {
        "id": fid,
        "rule_id": rule_id,
        "category": category,
        "indicator": indicator,
        "severity": severity,
        "confidence": confidence,
        "file": file,
        "span": span_of(text, needle, nth),
        "snippet": needle,
        "explanation": explanation,
        "trigger_phase": phase,
        "context": {"enclosing_function": func, "after_normalization": after_norm, "in_vendored_path": vendored},
        "evidence_class": "static_indicator",
        "limitations": limitations or ["Static estimate: does not prove the code executed."],
    }


def classify(path: str) -> str:
    if path.endswith(".py"):
        return "python"
    if path in ("pyproject.toml", "setup.cfg"):
        return "build_config"
    if path.endswith((".so", ".pyd", ".dll", ".dylib")):
        return "binary"
    if path.endswith((".md", ".rst", ".txt")):
        return "doc"
    return "other"


def roles_for(path: str, vendored_paths: List[str]) -> List[str]:
    roles = []  # type: List[str]
    if path == "setup.py":
        roles.append("install_hook")
    if path == "pyproject.toml":
        roles.append("build_config")
    if path.endswith("/__init__.py") and path.count("/") == 1:
        roles.append("package_init")
    if any(path == v or path.startswith(v + "/") for v in vendored_paths):
        roles.append("vendored")
    return roles


def describe_problem(code: str) -> str:
    if code.startswith("parse_failure_ratio"):
        return "More than 20%% of Python files could not be parsed (ratio %s)." % code.split(":", 1)[1]
    if code.startswith("uninspected_ratio"):
        return "More than half of the code-bearing files were not inspected (%s)." % code.split(":", 1)[1]
    if code.startswith("limits_hit"):
        return "A safety limit was reached: %s." % code.split(":", 1)[1]
    return {
        "coverage_unknown": "File coverage could not be established.",
        "hash_mismatch": "The artifact hash does not match the published hash.",
        "nothing_inspected": "No file could be inspected.",
    }.get(code, code)


MODEL_NOT_RUN = {
    "status": "not_run", "model_name": None, "model_version": None, "label": None, "score": None,
    "calibrated": False, "illustrative": False, "top_features": [], "note": "Model not run.",
}


def build_record(
    name: str, version: str, sources: Dict[str, Source], findings: List[Dict[str, Any]],
    relations: List[Dict[str, Any]], model: Dict[str, Any], timings: Dict[str, Any],
    parse_failures: Optional[List[Dict[str, str]]] = None, vendored_paths: Optional[List[str]] = None,
    limits_hit: Optional[List[str]] = None, extra_limitations: Optional[List[str]] = None,
) -> Dict[str, Any]:
    parse_failures = parse_failures or []
    vendored_paths = vendored_paths or []
    failed = {p["path"] for p in parse_failures}

    # write the synthetic tree
    pkg_dir = SRC_DIR / name
    for rel, content in sources.items():
        target = pkg_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(to_bytes(content))

    files, uninspected = [], []
    for rel in sorted(sources):
        data = to_bytes(sources[rel])
        kind = classify(rel)
        if kind == "python":
            inspected = rel not in failed
            if inspected:
                ast.parse(sources[rel])  # fixtures must really parse
            else:
                try:
                    ast.parse(sources[rel])
                except SyntaxError:
                    pass
                else:
                    raise AssertionError("%s is listed as a parse failure but parses fine" % rel)
        elif kind == "build_config":
            inspected = True
        else:
            inspected = False
        if not inspected and kind not in ("doc", "python"):
            uninspected.append(
                {"path": rel, "reason": "binary file: not analysed" if kind == "binary" else "unsupported file type"}
            )
        files.append(
            {
                "path": rel,
                "kind": kind,
                "sha256": sha256_bytes(data),
                "lines": None if kind == "binary" else len(data.decode("utf-8").splitlines()),
                "inspected": inspected,
                "roles": roles_for(rel, vendored_paths),
            }
        )

    record = {
        "schema_version": "0.1",
        "scan_id": str(uuid.uuid5(uuid.NAMESPACE_URL, "spider-fixture/" + name)),
        "created_at": CREATED_AT,
        "record_origin": "hand_written_fixture",
        "tool": {"spider_version": "fixture", "analyzer_version": "fixture", "ruleset_version": "fixture"},
        "target": {
            "kind": "directory",
            "name": name,
            "version": version,
            "artifact": {
                "filename": None,
                "sha256": tree_sha256(pkg_dir),
                "size_bytes": sum(len(to_bytes(c)) for c in sources.values()),
                "format": "dir",
            },
            "hash_verified": None,
        },
        "inventory": {
            "coverage_known": True,
            "files_total": len(files),
            "python_files": sum(1 for f in files if f["kind"] == "python"),
            "files_inspected": sum(1 for f in files if f["inspected"]),
            "uninspected": uninspected,
            "parse_failures": parse_failures,
            "vendored_paths": vendored_paths,
            "limits_hit": limits_hit or [],
        },
        "files": files,
        "findings": findings,
        "relations": relations,
        "model_assessment": model,
        "verdict": {"outcome": "unable_to_assess", "reasons": [], "limitations": []},
        "timings_ms": timings,
    }
    derived = derive_verdict(record)
    limitations = [describe_problem(c) for c in coverage_problems(record)]
    if derived["outcome"] == "none_detected_in_this_scan":
        limitations.append(NONE_DETECTED_NOTE)
    limitations.extend(extra_limitations or [])
    verdict_dict = {"outcome": derived["outcome"], "reasons": derived["reasons"], "limitations": limitations}
    if "review_recommended" in derived:
        verdict_dict["review_recommended"] = derived["review_recommended"]
    record["verdict"] = verdict_dict
    return record


# --------------------------------------------------------------------------- fixtures
def fx_clean() -> Dict[str, Any]:
    src = {
        "pyproject.toml": '[build-system]\nrequires = ["setuptools>=61"]\nbuild-backend = "setuptools.build_meta"\n\n'
        '[project]\nname = "demo-httpclient"\nversion = "1.0.0"\n',
        "README.md": "# demo-httpclient\n\nSynthetic SPIDER contract fixture. Harmless.\n",
        "demo_httpclient/__init__.py": '"""Tiny demo HTTP helper (synthetic fixture, harmless)."""\n'
        "import socket\n\n__version__ = \"1.0.0\"\n\n\n"
        "def can_connect(host, port, timeout=1.0):\n"
        '    """Return True if a TCP connection succeeds."""\n'
        "    with socket.create_connection((host, port), timeout=timeout):\n"
        "        return True\n",
    }
    findings = [
        make_finding(
            src, "F001", "SPD-NET-001", "network_activity", "socket.create_connection", "low", "medium",
            "demo_httpclient/__init__.py", "socket.create_connection((host, port), timeout=timeout)",
            "Opens a TCP connection inside a function; it runs only when can_connect() is called.",
            "call", func="can_connect",
        )
    ]
    return build_record(
        "demo-httpclient", "1.0.0", src, findings, [], dict(MODEL_NOT_RUN),
        {"acquire": 0, "extract": 2, "analyze": 14, "features": 3, "model": None},
    )


def fx_install_hook() -> Dict[str, Any]:
    src = {
        "setup.py": '"""Synthetic fixture: harmless custom install command."""\n'
        "import os\nfrom setuptools import setup\nfrom setuptools.command.install import install\n\n\n"
        "class PostInstall(install):\n"
        "    def run(self):\n"
        "        install.run(self)\n"
        '        os.system("echo SPIDER-FIXTURE install hook ran")\n\n\n'
        'setup(\n    name="demo-installhook",\n    version="0.1.0",\n'
        '    packages=["demo_installhook"],\n    cmdclass={"install": PostInstall},\n)\n',
        "demo_installhook/__init__.py": '__version__ = "0.1.0"\n',
    }
    f1 = make_finding(
        src, "F001", "SPD-INS-002", "install_time", "setuptools.command.install", "medium", "high",
        "setup.py", "class PostInstall(install):",
        "Custom install command class: code inside it runs during `pip install` of a source distribution.",
        "install",
    )
    f2 = make_finding(
        src, "F002", "SPD-CMD-001", "command_execution", "os.system", "high", "high",
        "setup.py", 'os.system("echo SPIDER-FIXTURE install hook ran")',
        "Shell command executed from the custom install command.", "install", func="PostInstall.run",
    )
    rel = [
        {
            "id": "R001", "from": "F001", "to": "F002", "type": "co_occurrence",
            "basis": "F002 sits inside the class flagged by F001 (PostInstall.run).", "confidence": "high",
        }
    ]
    model = dict(
        MODEL_NOT_RUN, status="abstained", illustrative=True,
        note="Illustrative: the model abstained (low confidence). Not a real model output.",
    )
    return build_record(
        "demo-installhook", "0.1.0", src, [f1, f2], rel, model,
        {"acquire": 0, "extract": 2, "analyze": 11, "features": 3, "model": 6},
    )


def fx_obfuscated() -> Dict[str, Any]:
    payload = base64.b64encode(b"print('SPIDER-MARKER')").decode()
    src = {
        "demo_obfuscated/__init__.py": '"""Synthetic SPIDER fixture: harmless encoded-marker pattern."""\n'
        "import base64\nimport os\n\n"
        'PAYLOAD = "%s"  # decodes to a harmless print\n\n' % payload
        + "blob = base64.b64decode(PAYLOAD).decode()\nexec(blob)\n\n\n"
        "def helper():\n"
        '    fn = getattr(os, "sys" + "tem")\n'
        '    return fn("echo SPIDER-FIXTURE")\n',
    }
    path = "demo_obfuscated/__init__.py"
    f1 = make_finding(
        src, "F001", "SPD-OBF-001", "obfuscation", "base64.b64decode", "medium", "high", path,
        "base64.b64decode(PAYLOAD).decode()",
        "Decodes an embedded string at module level, so it runs on import.", "import",
    )
    f2 = make_finding(
        src, "F002", "SPD-DYN-001", "dynamic_execution", "exec", "high", "high", path, "exec(blob)",
        "Executes a dynamically built string at module level.", "import",
    )
    f3 = make_finding(
        src, "F003", "SPD-CMD-INDIRECT-001", "command_execution", "os.system", "medium", "medium", path,
        'getattr(os, "sys" + "tem")',
        "Indirect call to os.system built from concatenated strings; visible only after string-constant folding.",
        "call", func="helper", after_norm=True,
    )
    rel = [
        {
            "id": "R001", "from": "F001", "to": "F002", "type": "possible_flow",
            "basis": "`blob` is assigned from the decode expression (line %d) and passed to exec (line %d) in the "
            "same scope. v0.1 tracks only straight-line assignment, so this is not marked confirmed."
            % (f1["span"]["start_line"], f2["span"]["start_line"]),
            "confidence": "medium",
        },
        {
            "id": "R002", "from": "F003", "to": "F002", "type": "co_occurrence",
            "basis": "Both findings are in the same file.", "confidence": "low",
        },
    ]
    model = {
        "status": "ok", "model_name": "illustrative_model", "model_version": "none", "label": "malicious",
        "score": 0.93, "calibrated": False, "illustrative": True,
        "top_features": [
            {"name": "exec_at_import", "value": 1, "contribution": 0.31},
            {"name": "base64_decode_count", "value": 1, "contribution": 0.18},
            {"name": "indirect_call_after_normalization", "value": 1, "contribution": 0.11},
        ],
        "note": "Illustrative values for UI development; not from a trained model.",
    }
    return build_record(
        "demo-obfuscated", "0.2.0", src, [f1, f2, f3], rel, model,
        {"acquire": 0, "extract": 1, "analyze": 19, "features": 4, "model": 7},
    )


def fx_unable() -> Dict[str, Any]:
    src = {
        "pyproject.toml": '[build-system]\nrequires = ["setuptools>=61"]\nbuild-backend = "setuptools.build_meta"\n',
        "demo_nativeonly/__init__.py": '"""Synthetic fixture."""\n__version__ = "2.0.0"\n',
        "demo_nativeonly/broken.py": "def broken(:\n    pass\n",
        "demo_nativeonly/_core.so": b"SPIDER-FIXTURE-NOT-A-REAL-BINARY\x00",
        "demo_nativeonly/_helper.pyd": b"SPIDER-FIXTURE-NOT-A-REAL-BINARY-2\x00",
    }
    failures = [{"path": "demo_nativeonly/broken.py", "error": "SyntaxError: invalid syntax (line 1)"}]
    return build_record(
        "demo-nativeonly", "2.0.0", src, [], [], dict(MODEL_NOT_RUN),
        {"acquire": 0, "extract": 1, "analyze": 6, "features": 1, "model": None},
        parse_failures=failures,
        extra_limitations=["Binary extension modules (.so/.pyd) are not analysed by SPIDER v0.1."],
    )


def fx_vendored() -> Dict[str, Any]:
    src = {
        "setup.py": '"""Synthetic fixture: standard setup() call, no custom install command."""\n'
        "from setuptools import find_packages, setup\n\n"
        'setup(name="demo-vendored", version="3.1.0", packages=find_packages())\n',
        "README.md": "# demo-vendored\n\nSynthetic vendored-heavy fixture. Harmless.\n",
        "demo_vendored/__init__.py": '"""Own code of the synthetic vendored-heavy package."""\n'
        "import urllib.request\n\n\n"
        "def fetch_status(url):\n"
        "    with urllib.request.urlopen(url, timeout=2) as resp:\n"
        "        return resp.status\n",
        "demo_vendored/_vendor/__init__.py": "",
    }
    for li in range(12):
        src["demo_vendored/_vendor/lib%02d/__init__.py" % li] = ""
        for mi in range(10):
            src["demo_vendored/_vendor/lib%02d/mod%02d.py" % (li, mi)] = (
                '"""Vendored module %d.%d (synthetic)."""\n\n\ndef compute(x):\n    return x + %d\n'
                % (li, mi, li * 10 + mi)
            )
    v1 = "demo_vendored/_vendor/lib03/mod02.py"
    v2 = "demo_vendored/_vendor/lib07/mod05.py"
    v3 = "demo_vendored/_vendor/lib09/mod01.py"
    src[v1] += "\n\nimport socket\n\n\ndef ping():\n    return socket.socket()\n"
    src[v2] += '\n\nimport subprocess\n\n\ndef version():\n    return subprocess.run(["echo", "vendored"], capture_output=True)\n'
    src[v3] += "\n\nimport socket\n\n\ndef host():\n    return socket.gethostname()\n"

    f1 = make_finding(
        src, "F001", "SPD-INS-001", "install_time", "setuptools.setup", "low", "high", "setup.py",
        'setup(name="demo-vendored", version="3.1.0", packages=find_packages())',
        "Standard setup() call. Common in benign packages; not a discriminative signal on its own.", "install",
        limitations=["Plain setup() is expected in most packages (see Day 7 analysis); shown for completeness."],
    )
    f2 = make_finding(
        src, "F002", "SPD-NET-002", "network_activity", "urllib.request.urlopen", "medium", "medium",
        "demo_vendored/__init__.py", "urllib.request.urlopen(url, timeout=2)",
        "Opens a URL inside a function; runs only when fetch_status() is called.", "call", func="fetch_status",
    )
    f3 = make_finding(
        src, "F003", "SPD-NET-001", "network_activity", "socket.socket", "low", "medium", v1, "socket.socket()",
        "Creates a socket inside a vendored function.", "call", func="ping", vendored=True,
    )
    f4 = make_finding(
        src, "F004", "SPD-CMD-002", "command_execution", "subprocess.run", "low", "medium", v2,
        'subprocess.run(["echo", "vendored"], capture_output=True)',
        "Runs a subprocess inside a vendored function.", "call", func="version", vendored=True,
    )
    f5 = make_finding(
        src, "F005", "SPD-NET-003", "network_activity", "socket.gethostname", "low", "medium", v3,
        "socket.gethostname()", "Reads the local hostname inside a vendored function.", "call", func="host",
        vendored=True,
    )
    return build_record(
        "demo-vendored", "3.1.0", src, [f1, f2, f3, f4, f5], [], dict(MODEL_NOT_RUN),
        {"acquire": 0, "extract": 5, "analyze": 88, "features": 12, "model": None},
        vendored_paths=["demo_vendored/_vendor"],
        extra_limitations=[
            "Findings under demo_vendored/_vendor are listed but not suppressed: bundled code is a known hiding place."
        ],
    )


def clean_dir(d: Path) -> None:
    if not d.exists():
        d.mkdir(parents=True)
        return
    for item in d.iterdir():
        if item.is_file():
            try:
                item.unlink()
            except Exception:
                pass
        elif item.is_dir():
            shutil.rmtree(item, ignore_errors=True)


def main() -> None:
    for d in (SRC_DIR, REC_DIR):
        clean_dir(d)
    records = [
        ("01_clean_network_in_function", fx_clean()),
        ("02_install_hook", fx_install_hook()),
        ("03_obfuscated_chain", fx_obfuscated()),
        ("04_unable_to_assess", fx_unable()),
        ("05_vendored_heavy", fx_vendored()),
    ]
    for stem, rec in records:
        (REC_DIR / (stem + ".json")).write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
        print("wrote %s  [%s]" % (stem, rec["verdict"]["outcome"]))


if __name__ == "__main__":
    main()
