import math
from collections import Counter

def calculate_shannon_entropy(data: str) -> float:
    """Calculates randomness of strings (Base64/obfuscation detector)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)

def extract_row(raw_findings: dict, total_calls: int = 1) -> dict:
    """Normalizes raw analyzer findings into ML feature numbers."""
    total = max(total_calls, 1)
    return {
        "feat_eval_ratio": raw_findings.get("eval_calls", 0) / total,
        "feat_exec_ratio": raw_findings.get("exec_calls", 0) / total,
        "feat_system_call_ratio": raw_findings.get("system_calls", 0) / total,
        "feat_subprocess_ratio": raw_findings.get("subprocess_calls", 0) / total,
        "feat_max_entropy": max([calculate_shannon_entropy(s) for s in raw_findings.get("strings", [])], default=0.0),
        "feat_ast_parse_failed": 1 if raw_findings.get("parse_failed") else 0,
    }

if __name__ == "__main__":
    # Sanity test
    test_data = {"eval_calls": 2, "system_calls": 1, "strings": ["aGVsbG8gd29ybGQ="], "parse_failed": False}
    print("Features extracted:", extract_row(test_data, total_calls=10))