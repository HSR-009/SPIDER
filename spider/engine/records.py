"""Helpers for constructing scan_record entries."""
from typing import Any, Dict, List, Optional
from spider_contract.adapter import normalize_category


def build_finding(
    fid: str,
    raw_finding: Dict[str, Any],
    relpath: str,
    trigger_phase_val: str,
    in_vendored: bool
) -> Dict[str, Any]:
    cat = normalize_category(raw_finding["category"])
    rule_id = raw_finding.get("rule_id", "unknown")
    sev = str(raw_finding.get("severity", "unknown")).lower()
    conf = str(raw_finding.get("confidence", "high")).lower()

    limitations = ["Static pattern match; no execution was performed."]
    if in_vendored:
        limitations.append("in vendored path")
        conf = "medium"

    return {
        "id": fid,
        "rule_id": rule_id,
        "category": cat,
        "indicator": str(raw_finding["indicator"]),
        "severity": sev,
        "confidence": conf,
        "file": relpath,
        "span": {
            "start_line": int(raw_finding.get("line") or 1),
            "start_col": raw_finding.get("col"),
            "end_line": raw_finding.get("end_line"),
            "end_col": raw_finding.get("end_col"),
        },
        "snippet": raw_finding.get("snippet"),
        "explanation": str(raw_finding.get("evidence") or ""),
        "trigger_phase": trigger_phase_val,
        "context": {
            "enclosing_function": raw_finding.get("enclosing_function"),
            "after_normalization": False,
            "in_vendored_path": in_vendored,
        },
        "evidence_class": "static_indicator",
        "limitations": limitations,
    }


def build_relations(findings: List[Dict[str, Any]], raw_findings_map: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build relations between findings (co_occurrence and possible_flow)."""
    relations = []
    rid_counter = 1

    for i in range(len(findings)):
        f1 = findings[i]
        rf1 = raw_findings_map.get(f1["id"], {})
        for j in range(i + 1, len(findings)):
            f2 = findings[j]
            rf2 = raw_findings_map.get(f2["id"], {})

            # Same file co_occurrence
            if f1["file"] == f2["file"]:
                fn1 = rf1.get("enclosing_function")
                fn2 = rf2.get("enclosing_function")
                same_func = (fn1 is not None and fn1 == fn2)

                basis = "co-occur in same function" if same_func else "co-occur in same file"
                rel_type = "co_occurrence"

                # Check for possible_flow:
                # credential + network in same function, or obfuscation decode + exec/eval in same function
                is_cred_net = (
                    (f1["category"] == "credential_access" and f2["category"] == "network_activity") or
                    (f2["category"] == "credential_access" and f1["category"] == "network_activity")
                )
                is_decode_exec = (
                    ("base64" in f1["indicator"] and f2["indicator"] in ("exec", "eval")) or
                    ("base64" in f2["indicator"] and f1["indicator"] in ("exec", "eval"))
                )

                if same_func and (is_cred_net or is_decode_exec):
                    rel_type = "possible_flow"
                    basis = "potential data flow in same function"

                relations.append({
                    "id": f"R{rid_counter:03d}",
                    "from": f1["id"],
                    "to": f2["id"],
                    "type": rel_type,
                    "basis": basis,
                    "confidence": "medium",
                })
                rid_counter += 1

    return relations
