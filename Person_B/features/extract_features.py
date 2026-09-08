import math
from collections import Counter


def compute_shannon_entropy(text: str) -> float:
    """Calculates Shannon Entropy (randomness) of a string.

    Higher values indicate obfuscation, encryption, or Base64 encoding.
    """
    if not text:
        return 0.0

    length = len(text)
    counts = Counter(text)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def extract_code_features(ast_summary: dict) -> dict:
    """Normalizes AST counts against total function calls and measures string entropy."""
    total_calls = ast_summary.get("total_calls", 0)

    # Prevent division by zero: if total_calls == 0, safe default is 1 for ratio calculations
    denom = total_calls if total_calls > 0 else 1

    eval_calls = ast_summary.get("eval_calls", 0)
    exec_calls = ast_summary.get("exec_calls", 0)
    system_calls = ast_summary.get("system_calls", 0)
    subprocess_calls = ast_summary.get("subprocess_calls", 0)

    # String entropy calculations
    strings = ast_summary.get("strings", [])
    if strings:
        entropies = [compute_shannon_entropy(s) for s in strings]
        max_entropy = max(entropies)
        avg_entropy = sum(entropies) / len(entropies)
    else:
        max_entropy = 0.0
        avg_entropy = 0.0

    return {
        "feat_total_calls": total_calls,
        "feat_eval_ratio": round(eval_calls / denom, 4),
        "feat_exec_ratio": round(exec_calls / denom, 4),
        "feat_system_call_ratio": round(system_calls / denom, 4),
        "feat_subprocess_ratio": round(subprocess_calls / denom, 4),
        "feat_max_entropy": round(max_entropy, 4),
        "feat_avg_entropy": round(avg_entropy, 4),
        "feat_parse_failed": int(ast_summary.get("parse_failed", 0)),
    }


if __name__ == "__main__":
    sample = {
        "total_calls": 10,
        "eval_calls": 2,
        "exec_calls": 1,
        "system_calls": 1,
        "subprocess_calls": 0,
        "strings": ["aW1wb3J0IG9zCnN5c3RlbSgnaGFjaycp", "normal_string"],
        "parse_failed": 0,
    }
    print("Test extract_code_features:")
    print(extract_code_features(sample))