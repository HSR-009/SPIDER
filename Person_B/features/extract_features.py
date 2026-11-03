"""Feature extraction for SPIDER's package-version records (static findings only)."""
import re
from collections import Counter

SECURITY_CATEGORIES = (
    "Network Activity",
    "Credential / Data Access",
    "Command Execution",
    "Obfuscation",
    "Install-Time / Package Execution",
    "Dynamic Code Execution",
    "File System Access",
)

def normalize_package_name(name):
    return re.sub(r"[-_.]+", "-", str(name or "").strip().lower())

def clean_indicator(value):
    return str(value or "").strip()

def extract_record_features(record, indicator_vocabulary=()):
    findings = record.get("findings") or []
    if not isinstance(findings, list):
        findings = []
    valid = [f for f in findings if isinstance(f, dict) and f.get("category") != "Parse Error"]
    category_counts = Counter(str(f.get("category", "")) for f in valid)
    indicators = {clean_indicator(f.get("indicator")) for f in valid if clean_indicator(f.get("indicator"))}
    out = {}
    for category in SECURITY_CATEGORIES:
        key = re.sub(r"[^a-z0-9]+", "_", category.lower()).strip("_")
        out[f"category_count__{key}"] = int(category_counts[category])
        out[f"category_present__{key}"] = int(category_counts[category] > 0)
    for indicator in indicator_vocabulary:
        out[f"indicator_present__{indicator}"] = int(indicator in indicators)
    out["n_py_files"] = int(record.get("n_py_files", record.get("files_attempted", 0)) or 0)
    out["n_findings"] = int(record.get("n_findings", len(valid)) or 0)
    out["parse_error_count"] = int(record.get("parse_error_count", 0) or 0)
    out["failed_static_analysis"] = int(bool(record.get("failed_static_analysis", 0)))
    return out

def top_indicator_vocabulary(records, limit=40):
    # Package-presence frequency, not raw finding frequency.
    counts = Counter()
    for record in records:
        findings = record.get("findings") or []
        counts.update({clean_indicator(f.get("indicator")) for f in findings
                       if isinstance(f, dict) and f.get("category") != "Parse Error"
                       and clean_indicator(f.get("indicator"))})
    return [name for name, _ in sorted(counts.items(), key=lambda x: (-x[1], x[0]))[:limit]]

def feature_columns(indicator_vocabulary=()):
    cats = []
    for category in SECURITY_CATEGORIES:
        key = re.sub(r"[^a-z0-9]+", "_", category.lower()).strip("_")
        cats.extend([f"category_count__{key}", f"category_present__{key}"])
    return cats + [f"indicator_present__{name}" for name in indicator_vocabulary]

DIAGNOSTIC_COLUMNS = ["n_py_files", "n_findings", "parse_error_count", "failed_static_analysis"]
