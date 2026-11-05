"""Bridge between the OLD 5-field analyzer findings and scan_record v0.1.

Old shape (from shared/ interface doc):
    {"category": "Command Execution", "indicator": "os.system",
     "file": "sample.py", "line": 4, "evidence": "os.system() call detected"}
    Real analyzer output also carries "severity" ("HIGH"/"MEDIUM", upper-case).

Rules:
  * "Parse Error" is NOT a finding. It becomes inventory.parse_failures.
  * Fields the old format cannot supply stay "unknown"/null; nothing is invented.
  * coverage_known is False, so a converted record can never say
    "none_detected_in_this_scan" (it says unable_to_assess instead).
  * to_legacy() lets Person B keep the old shape until B migrates.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from .verdict import derive_verdict


class AdapterError(ValueError):
    pass


# --- category names ---------------------------------------------------------
# Normalised legacy label -> v0.1 enum. Add aliases here if the analyzer uses
# other spellings. Normalisation: lowercase, non-alphanumerics -> "_".
CATEGORY_ALIASES = {
    "command_execution": "command_execution",
    "dynamic_execution": "dynamic_execution",
    "dynamic_code_execution": "dynamic_execution",
    "credential_data_access": "credential_access",
    "credential_or_data_access": "credential_access",
    "credential_access": "credential_access",
    "network_activity": "network_activity",
    "obfuscation": "obfuscation",
    "install_time_behavior": "install_time",
    "install_time_behaviour": "install_time",
    "install_time": "install_time",
    "install_time_package_execution": "install_time",
    "supply_chain_abuse": "supply_chain_abuse",
}

# v0.1 enum -> legacy display label used by to_legacy().
# CONFIRMED against Person_A/ast_analyzer/analyzer.py (Antigravity report,
# 2026-11-03). "Supply-Chain Abuse" is defined in security_categories.py but the
# analyzer never emits it; the schema keeps it reserved.
LEGACY_CATEGORY_LABELS = {
    "command_execution": "Command Execution",
    "dynamic_execution": "Dynamic Code Execution",
    "credential_access": "Credential / Data Access",
    "network_activity": "Network Activity",
    "obfuscation": "Obfuscation",
    "install_time": "Install-Time / Package Execution",
    "supply_chain_abuse": "Supply-Chain Abuse",
}

# The real analyzer marks every plain setuptools setup() call HIGH, and 53.2% of
# the benign corpus contains one. Under the verdict policy a HIGH finding means
# "suspicious", so converted records would flag half of all benign packages.
# Install-time findings with one of these indicators are therefore converted to
# severity "low". Person A: replace the guesses below with the exact indicator
# strings the analyzer emits for a plain setup() call (see v1_1_rule_spec.md).
PLAIN_SETUP_INDICATORS = frozenset(
    {"setup", "setuptools.setup", "distutils.core.setup", "setuptools.setup()"}
)

PARSE_ERROR_LABEL = "Parse Error"
_SEVERITIES = ("low", "medium", "high")


def _key(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", label.strip().lower()).strip("_")


def normalize_category(label: str) -> str:
    key = _key(label)
    if key == "parse_error":
        return "parse_error"
    if key not in CATEGORY_ALIASES:
        raise AdapterError(
            "Unknown legacy category %r. Add it to CATEGORY_ALIASES in "
            "spider_contract/adapter.py (and tell the team: categories are fixed "
            "by the schema)." % label
        )
    return CATEGORY_ALIASES[key]


def _file_kind(path: str) -> str:
    return "python" if path.endswith(".py") else "other"


def convert_legacy_scan(
    legacy_findings: Iterable[Dict[str, Any]],
    *,
    name: str,
    version: Optional[str] = None,
    analyzer_version: str = "unknown",
    ruleset_version: str = "unknown",
    spider_version: str = "0.0.0-dev",
    scan_id: Optional[str] = None,
    created_at: Optional[str] = None,
) -> Dict[str, Any]:
    findings = []  # type: List[Dict[str, Any]]
    parse_failures = []  # type: List[Dict[str, str]]
    paths = []  # type: List[str]

    def remember(path: str) -> None:
        if path not in paths:
            paths.append(path)

    for item in legacy_findings:
        for required in ("category", "indicator", "file", "line"):
            if required not in item:
                raise AdapterError("legacy finding is missing %r: %r" % (required, item))
        category = normalize_category(str(item["category"]))
        path = str(item["file"])
        remember(path)
        if category == "parse_error":
            parse_failures.append(
                {"path": path, "error": str(item.get("evidence") or "parse error")}
            )
            continue
        severity = str(item.get("severity", "unknown")).lower()
        if severity not in _SEVERITIES:
            severity = "unknown"
        limitations = [
            "Converted from the legacy format: columns, snippet, "
            "confidence and trigger phase are unavailable."
        ]
        if category == "install_time" and str(item["indicator"]) in PLAIN_SETUP_INDICATORS:
            severity = "low"
            limitations.append(
                "A plain setup() call is routine packaging; legacy severity HIGH "
                "was lowered to low so it does not trigger a suspicious verdict."
            )
        findings.append(
            {
                "id": "F%03d" % (len(findings) + 1),
                "rule_id": "legacy:%s" % item["indicator"],
                "category": category,
                "indicator": str(item["indicator"]),
                "severity": severity,
                "confidence": "unknown",
                "file": path,
                "span": {
                    "start_line": int(item["line"]),
                    "start_col": None,
                    "end_line": None,
                    "end_col": None,
                },
                "snippet": None,
                "explanation": str(item.get("evidence") or ""),
                "trigger_phase": "unknown",
                "context": {
                    "enclosing_function": None,
                    "after_normalization": False,
                    "in_vendored_path": False,
                },
                "evidence_class": "static_indicator",
                "limitations": limitations,
            }
        )

    failed = {p["path"] for p in parse_failures}
    files = [
        {
            "path": p,
            "kind": _file_kind(p),
            "sha256": None,
            "lines": None,
            "inspected": p not in failed,
            "roles": [],
        }
        for p in paths
    ]
    record = {
        "schema_version": "0.1",
        "scan_id": scan_id or str(uuid.uuid4()),
        "created_at": created_at
        or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "record_origin": "legacy_conversion",
        "tool": {
            "spider_version": spider_version,
            "analyzer_version": analyzer_version,
            "ruleset_version": ruleset_version,
        },
        "target": {
            "kind": "directory",
            "name": name,
            "version": version,
            "artifact": {"filename": None, "sha256": None, "size_bytes": None, "format": "other"},
            "hash_verified": None,
        },
        "inventory": {
            "coverage_known": False,
            "files_total": len(files),
            "python_files": sum(1 for f in files if f["kind"] == "python"),
            "files_inspected": sum(1 for f in files if f["inspected"]),
            "uninspected": [],
            "parse_failures": parse_failures,
            "vendored_paths": [],
            "limits_hit": [],
        },
        "files": files,
        "findings": findings,
        "relations": [],
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
        "verdict": {"outcome": "unable_to_assess", "reasons": [], "limitations": []},
        "timings_ms": {"acquire": None, "extract": None, "analyze": None, "features": None, "model": None},
    }
    verdict = derive_verdict(record)
    record["verdict"] = {
        "outcome": verdict["outcome"],
        "reasons": verdict["reasons"],
        "limitations": [
            "Converted from legacy findings: file coverage is unknown, so this "
            "record cannot support a 'none detected' conclusion."
        ],
    }
    return record


def to_legacy(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    """v0.1 record -> old 5-field list (for Person B until B migrates)."""
    out = []  # type: List[Dict[str, Any]]
    for f in record["findings"]:
        item = {
            "category": LEGACY_CATEGORY_LABELS[f["category"]],
            "indicator": f["indicator"],
            "file": f["file"],
            "line": f["span"]["start_line"],
            "evidence": f["explanation"],
        }
        if f["severity"] in _SEVERITIES:  # real analyzer uses upper-case HIGH/MEDIUM
            item["severity"] = f["severity"].upper()
        out.append(item)
    for p in record["inventory"]["parse_failures"]:
        out.append(
            {
                "category": PARSE_ERROR_LABEL,
                "indicator": "SyntaxError",
                "severity": "MEDIUM",
                "file": p["path"],
                "line": 0,
                "evidence": p["error"],
            }
        )
    return out


def failed_static_analysis(record: Dict[str, Any]) -> int:
    """The ML feature B was asked to build: 1 if any file failed to parse."""
    return 1 if record["inventory"]["parse_failures"] else 0
