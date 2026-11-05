from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any, Optional

@dataclass
class Finding:
    category: str
    indicator: str
    severity: str
    file: str
    line: Optional[int] = None
    evidence: str = ""
    col_offset: Optional[int] = None
    end_lineno: Optional[int] = None
    end_col_offset: Optional[int] = None
    snippet: Optional[str] = None
    rule_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Drop None optional fields for legacy parity if needed
        return {k: v for k, v in d.items() if v is not None}

@dataclass
class ScanRecord:
    schema_version: str = "0.1.0"
    package_name: str = ""
    version: str = ""
    package_id: str = ""
    group_id: str = ""
    analyzer_version: str = "v1.0.0"
    verdict: str = "unable_to_assess"  # suspicious | none_detected_in_this_scan | unable_to_assess
    review_recommended: bool = False
    findings: List[Dict[str, Any]] = field(default_factory=list)
    category_counts: Dict[str, int] = field(default_factory=dict)
    n_findings: int = 0
    n_py_files: int = 0
    parse_error_count: int = 0
    failed_static_analysis: int = 0
    record_origin: str = "scan"  # scan | replay | fixture | legacy
    inventory: Dict[str, Any] = field(default_factory=lambda: {
        "inspected_files": [],
        "parse_failures": [],
        "uninspected_files": [],
        "vendored_paths": [],
        "limits_hit": []
    })

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
