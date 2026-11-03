<<<<<<< HEAD
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
=======
import os
import sys
import pandas as pd
from pathlib import Path

# Ensure root folder (SPIDER) is available in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# 1. Import Person A's real AST parser
from Person_A.ast_analyzer.analyzer import analyze_file

# 2. Import Person B's feature extractors
from Person_B.features.extract_features import extract_code_features
from Person_B.features.metadata_features import fetch_pypi_metadata, compute_typosquat_distance
from Person_B.models.baseline_model import FEATURE_COLS

# Mock top packages for Typosquatting checks
TOP_PACKAGES = ["requests", "urllib3", "numpy", "pandas", "tensorflow", "colorama", "setuptools"]

def process_toy_samples(samples_dir: str):
    """
    Crawls the toy_samples directory, runs Person A's analyzer, 
    and builds the final ML-ready feature table.
    """
    records = []
    
    # data/toy_samples contains 'clean', 'malicious', 'edge_cases'
    for label_dir in os.listdir(samples_dir):
        label_path = os.path.join(samples_dir, label_dir)
        if not os.path.isdir(label_path):
            continue
            
        # 1 means malicious, 0 means benign (edge cases default to benign for toy testing)
        is_malicious = 1 if label_dir == "malicious" else 0
        
        for file_name in os.listdir(label_path):
            if not file_name.endswith(".py"):
                continue
                
            file_path = os.path.join(label_path, file_name)
            # Derive a mock package name from the filename
            package_name = file_name.replace(".py", "").split("_")[0] 
            
            print(f"[*] Processing: {file_path}")
            
            # --- PHASE A: Person A's Static Analysis ---
            findings = analyze_file(file_path)
            
            # --- PHASE B: Person B's ML Code Feature Translation ---
            code_features = extract_code_features(file_path, findings)
            
            # --- PHASE C: Person B's Metadata Features ---
            typosquat_features = compute_typosquat_distance(package_name)
            metadata = fetch_pypi_metadata(package_name)
            
            # --- PHASE D: Merge All Features ---
            row = {
                "package_name": package_name,
                "label": is_malicious
            }
            row.update(code_features)
            row.update(typosquat_features)
            row.update(metadata)
            
            records.append(row)
            
    return pd.DataFrame(records)

if __name__ == "__main__":
    samples_dir = os.path.join(BASE_DIR, "data", "benchmark_dataset")
    output_csv = os.path.join(BASE_DIR, "data", "processed", "feature_table.csv")
    
    if not os.path.exists(samples_dir):
        print(f"[!] Cannot find toy samples at {samples_dir}. Did the merge succeed?")
        sys.exit(1)
        
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    
    print("[*] Starting end-to-end feature extraction pipeline...")
    df = process_toy_samples(samples_dir)
    
    # Ensure all expected columns exist (fill missing with 0)
    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0
            
    # Reorder columns to exactly match our ML model's expected schema
    final_cols = ["package_name"] + FEATURE_COLS + ["label"]
    df = df[final_cols]
    
    df.to_csv(output_csv, index=False)
    print(f"\n[+] Successfully built feature table with {len(df)} packages.")
    print(f"[+] Saved to: {output_csv}")
>>>>>>> origin/person-a-security
