"""Package-level feature extraction from the supplied static-analysis JSONL records.

This module never executes package code and does not make network requests.
"""
import re
from collections import Counter

CATEGORY_KEYS = {
    "network_activity": "Network Activity",
    "credential_data_access": "Credential / Data Access",
    "command_execution": "Command Execution",
    "obfuscation": "Obfuscation",
    "install_time": "Install-Time / Package Execution",
    "dynamic_code_execution": "Dynamic Code Execution",
}
INDICATOR_PATTERNS = {
    "eval": ("eval",),
    "exec": ("exec",),
    "compile": ("compile",),
    "os_system": ("os.system",),
    "subprocess": ("subprocess.", "subprocess"),
    "http_post": ("requests.post", "httpx.post"),
    "urlopen": ("urlopen",),
    "socket": ("socket.", "create_connection"),
    "base64": ("base64.", "b64decode", "b64encode"),
    "pickle": ("pickle.", "dill."),
    "environment_access": ("os.environ", "getenv"),
}

def _normalise(value):
    return re.sub(r"[^a-z0-9_.]+", "", str(value or "").lower())

def extract_record_features(record):
    """Convert one package-version JSONL record into numeric ML features."""
    findings = record.get("findings") or []
    if not isinstance(findings, list):
        findings = []
    indicators = [_normalise(f.get("indicator", "")) for f in findings if isinstance(f, dict)]
    categories = [str(f.get("category", "")) for f in findings if isinstance(f, dict)]
    severities = [str(f.get("severity", "")).upper() for f in findings if isinstance(f, dict)]
    n_files = max(int(record.get("n_py_files") or 0), 1)
    out = {}
    category_counts = Counter(categories)
    for key, category in CATEGORY_KEYS.items():
        count = category_counts[category]
        out[f"behavior_{key}_count"] = count
        out[f"behavior_{key}_per_file"] = count / n_files
        out[f"behavior_{key}_present"] = int(count > 0)
    for key, patterns in INDICATOR_PATTERNS.items():
        count = sum(1 for indicator in indicators if any(p in indicator for p in patterns))
        out[f"behavior_{key}_count"] = count
        out[f"behavior_{key}_per_file"] = count / n_files
    for severity in ("HIGH", "MEDIUM", "LOW"):
        count = sum(s == severity for s in severities)
        out[f"behavior_severity_{severity.lower()}_count"] = count
        out[f"behavior_severity_{severity.lower()}_per_file"] = count / n_files
    out["behavior_unique_indicator_count"] = len(set(i for i in indicators if i))
    out["behavior_unique_indicator_per_file"] = out["behavior_unique_indicator_count"] / n_files
    # Diagnostic/ablation columns: not included in the behavior-only model.
    out["n_py_files"] = int(record.get("n_py_files") or 0)
    out["n_findings"] = int(record.get("n_findings") or len(findings))
    out["parse_error_count"] = int(record.get("parse_error_count") or 0)
    out["failed_static_analysis"] = int(record.get("failed_static_analysis") or 0)
    return out

BEHAVIOR_FEATURE_COLS = (
    [f"behavior_{key}_{suffix}" for key in CATEGORY_KEYS for suffix in ("count", "per_file", "present")]
    + [f"behavior_{key}_{suffix}" for key in INDICATOR_PATTERNS for suffix in ("count", "per_file")]
    + [f"behavior_severity_{level}_{suffix}" for level in ("high", "medium", "low") for suffix in ("count", "per_file")]
    + ["behavior_unique_indicator_count", "behavior_unique_indicator_per_file"]
)
DIAGNOSTIC_FEATURE_COLS = ["n_py_files", "n_findings", "parse_error_count", "failed_static_analysis"]

def extract_code_features(file_path=None, findings=None):
    """Backward-compatible adapter for older callers; package records are preferred."""
    return extract_record_features({"findings": findings or []})
