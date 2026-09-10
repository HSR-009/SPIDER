import ast
import math
from collections import Counter

def compute_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy to detect packed/obfuscated strings."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = Counter(text)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def extract_code_features(file_path: str, findings: list) -> dict:
    """
    Translates Person A's security findings into ML numerical features.
    Also calculates file-level metrics (entropy, total calls) for normalization.
    """
    # 1. Initialize base metrics
    features = {
        "feat_total_calls": 0,
        "feat_eval_ratio": 0.0,
        "feat_exec_ratio": 0.0,
        "feat_system_call_ratio": 0.0,
        "feat_subprocess_ratio": 0.0,
        "feat_max_entropy": 0.0,
        "feat_avg_entropy": 0.0,
        "feat_parse_failed": 0
    }

    raw_counts = {"eval": 0, "exec": 0, "system": 0, "subprocess": 0}

    # 2. Map Person A's findings
    for finding in findings:
        cat = finding.get("category")
        ind = finding.get("indicator", "")

        # Handle Person A's parse error flag
        if cat == "Parse Error" or ind == "SyntaxError":
            features["feat_parse_failed"] = 1
            return features  # Stop here if unparsable

        # Tally dangerous indicators
        if ind == "eval":
            raw_counts["eval"] += 1
        elif ind in ["exec", "compile"]:
            raw_counts["exec"] += 1
        elif ind == "os.system":
            raw_counts["system"] += 1
        elif ind.startswith("subprocess."):
            raw_counts["subprocess"] += 1

    # 3. Extract our own file-level features (Entropy & Total Calls)
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
            
        # Compute Shannon Entropy per line to find obfuscation blocks
        lines = source.split('\n')
        entropies = [compute_shannon_entropy(line) for line in lines if line.strip()]
        if entropies:
            features["feat_max_entropy"] = max(entropies)
            features["feat_avg_entropy"] = sum(entropies) / len(entropies)

        # Count total calls for our ML ratio denominators
        tree = ast.parse(source)
        features["feat_total_calls"] = sum(1 for node in ast.walk(tree) if isinstance(node, ast.Call))

    except Exception:
        # Failsafe if the file is utterly broken
        features["feat_parse_failed"] = 1

    # 4. Compute Final ML Ratios
    total = features["feat_total_calls"]
    if total > 0:
        features["feat_eval_ratio"] = raw_counts["eval"] / total
        features["feat_exec_ratio"] = raw_counts["exec"] / total
        features["feat_system_call_ratio"] = raw_counts["system"] / total
        features["feat_subprocess_ratio"] = raw_counts["subprocess"] / total

    return features

if __name__ == "__main__":
    # Quick sanity check on how our adapter handles Person A's output format
    mock_findings = [
        {"category": "Command Execution", "indicator": "os.system", "line": 4},
        {"category": "Dynamic Code Execution", "indicator": "eval", "line": 10}
    ]
    
    # We will test this against a real file once we wire up the full loop
    print("[+] Feature extraction adapter ready for Person A's output schema.")