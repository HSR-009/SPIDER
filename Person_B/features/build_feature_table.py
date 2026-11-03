#!/usr/bin/env python
"""
Builds the package-level feature table from processed datasets (malicious_for_b.jsonl and benign_for_b.jsonl.gz).
Produces data/processed/feature_table_v1.csv conforming to the Day 1 requirements:
- one row per package_id
- group_id (PEP 503 name)
- counts per category
- presence of the top 40 indicators
- n_findings, parse_error_count, failed_static_analysis
- n_py_files in its own column
- label (0 or 1)
"""

import gzip
import json
import re
import sys
from collections import Counter
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from spider_contract.dataset import make_group_id

CATEGORIES = [
    "Command Execution",
    "Dynamic Code Execution",
    "Credential / Data Access",
    "Network Activity",
    "Obfuscation",
    "Install-Time / Package Execution",
]

def clean_col_name(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]+", "_", text.lower()).strip("_")

def get_top_40_indicators(file_paths):
    counts = Counter()
    for fp in file_paths:
        opener = gzip.open if str(fp).endswith(".gz") else open
        with opener(fp, "rt", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line.strip():
                    continue
                row = json.loads(line)
                seen = set(f.get("indicator") for f in row.get("findings", []) if f.get("indicator"))
                for ind in seen:
                    counts[ind] += 1
    return [ind for ind, _ in counts.most_common(40)]

def extract_row_features(row, top_indicators):
    findings = row.get("findings", [])
    cat_counts = row.get("category_counts", {})
    
    # Category counts
    feat = {}
    for cat in CATEGORIES:
        feat[f"cat_count_{clean_col_name(cat)}"] = cat_counts.get(cat, 0)
        
    # Top 40 indicator presence
    indicators_in_row = set(f.get("indicator") for f in findings if f.get("indicator"))
    for ind in top_indicators:
        feat[f"ind_{clean_col_name(ind)}"] = 1 if ind in indicators_in_row else 0
        
    # Package-level stats
    feat["n_findings"] = int(row.get("n_findings", len(findings)))
    feat["parse_error_count"] = int(row.get("parse_error_count", 0))
    feat["failed_static_analysis"] = int(row.get("failed_static_analysis", 0))
    feat["n_py_files"] = int(row.get("n_py_files", 0))
    
    return feat

def build_table(output_csv: Path = PROJECT_ROOT / "data" / "processed" / "feature_table_v1.csv"):
    mal_path = PROJECT_ROOT / "data" / "processed" / "malicious_for_b.jsonl"
    ben_path = PROJECT_ROOT / "data" / "processed" / "benign_for_b.jsonl.gz"
    
    print("[*] Determining top 40 indicators across corpora...")
    top_indicators = get_top_40_indicators([mal_path, ben_path])
    
    records = []
    for fp, default_label in [(mal_path, 1), (ben_path, 0)]:
        print(f"[*] Extracting features from {fp}...")
        opener = gzip.open if str(fp).endswith(".gz") else open
        with opener(fp, "rt", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line.strip():
                    continue
                row = json.loads(line)
                pkg_name = row.get("package_name", "")
                version = row.get("version", "")
                pkg_id = row.get("package_id", f"{pkg_name}=={version}")
                gid = row.get("group_id", make_group_id(pkg_name))
                label = int(row.get("label", default_label))
                
                feats = extract_row_features(row, top_indicators)
                record = {
                    "package_id": pkg_id,
                    "package_name": pkg_name,
                    "group_id": gid,
                    "label": label,
                    **feats
                }
                records.append(record)
                
    df = pd.DataFrame(records)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_csv, index=False)
    print(f"[+] Feature table built successfully: {len(df)} rows, {len(df.columns)} columns.")
    print(f"[+] Saved to: {output_csv}")
    return df

if __name__ == "__main__":
    build_table()
