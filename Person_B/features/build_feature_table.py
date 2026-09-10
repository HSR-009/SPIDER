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
    samples_dir = os.path.join(BASE_DIR, "data", "toy_samples")
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