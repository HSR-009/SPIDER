# SPIDER Baseline v1.1 Report

**Dataset Version:** v1.1 (`malicious_v11.jsonl`, `benign_v11.jsonl.gz`)  
**Date:** November 6, 2026  
**Role:** Person B (Machine Learning)  
**Evaluation Protocol:** 5-fold StratifiedGroupKFold on development set (3,957 packages) + frozen grouped holdout (991 packages, strictly preserved).  
**Positive Class:** Malicious (`label = 1`).  

## 1. Overall Frozen Holdout Results

| Experiment | Model | PR-AUC | ROC-AUC | Precision | Recall | F1 | FPR | TN | FP | FN | TP |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| behavior_without_size | random_forest | 0.8745 | 0.8988 | 0.8685 | 0.6944 | 0.7717 | 0.0739 | 539 | 43 | 125 | 284 |
| behavior_without_size | xgboost | 0.8468 | 0.8661 | 0.8576 | 0.6773 | 0.7568 | 0.0790 | 536 | 46 | 132 | 277 |
| behavior_with_size | random_forest | 0.9064 | 0.9218 | 0.8665 | 0.7457 | 0.8016 | 0.0808 | 535 | 47 | 104 | 305 |
| behavior_with_size | xgboost | 0.8826 | 0.8804 | 0.8035 | 0.7897 | 0.7965 | 0.1357 | 503 | 79 | 86 | 323 |
| size_only | random_forest | 0.6464 | 0.7504 | 0.6638 | 0.7531 | 0.7056 | 0.2680 | 426 | 156 | 101 | 308 |
| size_only | xgboost | 0.6509 | 0.7506 | 0.6726 | 0.7335 | 0.7018 | 0.2509 | 436 | 146 | 109 | 300 |

## 2. 5-Fold Grouped Cross-Validation (Development Set)

| Experiment | Model | CV PR-AUC | CV ROC-AUC | CV Precision | CV Recall | CV F1 | CV FPR |
|---|---|---:|---:|---:|---:|---:|---:|
| behavior_without_size | random_forest | 0.8539 ± 0.0198 | 0.8784 ± 0.0219 | 0.8588 ± 0.0318 | 0.6730 ± 0.0485 | 0.7530 ± 0.0201 | 0.0791 ± 0.0253 |
| behavior_without_size | xgboost | 0.8629 ± 0.0233 | 0.8833 ± 0.0265 | 0.8531 ± 0.0354 | 0.6939 ± 0.0433 | 0.7643 ± 0.0281 | 0.0847 ± 0.0248 |
| behavior_with_size | random_forest | 0.9132 ± 0.0139 | 0.9238 ± 0.0185 | 0.8495 ± 0.0160 | 0.7933 ± 0.0445 | 0.8197 ± 0.0219 | 0.0988 ± 0.0154 |
| behavior_with_size | xgboost | 0.9165 ± 0.0119 | 0.9270 ± 0.0126 | 0.8098 ± 0.0185 | 0.8399 ± 0.0253 | 0.8241 ± 0.0070 | 0.1388 ± 0.0195 |
| size_only | random_forest | 0.7043 ± 0.0282 | 0.8060 ± 0.0202 | 0.6549 ± 0.0342 | 0.7436 ± 0.0450 | 0.6948 ± 0.0103 | 0.2780 ± 0.0596 |
| size_only | xgboost | 0.7103 ± 0.0288 | 0.8081 ± 0.0188 | 0.6679 ± 0.0268 | 0.7411 ± 0.0450 | 0.7013 ± 0.0113 | 0.2604 ± 0.0467 |

## 3. Size-Stratified Frozen Holdout Evaluation

| Experiment | Model | Size Stratum | Total | Benign | Malicious | PR-AUC | ROC-AUC | Precision | Recall | F1 | FPR |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| behavior_without_size | random_forest | 1-5_files | 497 | 178 | 319 | 0.9322 | 0.8966 | 0.9469 | 0.7273 | 0.8227 | 0.0730 |
| behavior_without_size | random_forest | 6-20_files | 199 | 164 | 35 | 0.7737 | 0.9043 | 0.6744 | 0.8286 | 0.7436 | 0.0854 |
| behavior_without_size | random_forest | >20_files | 270 | 231 | 39 | 0.6308 | 0.8959 | 0.5897 | 0.5897 | 0.5897 | 0.0693 |
| behavior_without_size | random_forest | 0_files | 25 | 9 | 16 | 0.6957 | 0.6111 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| behavior_without_size | random_forest | all_packages | 991 | 582 | 409 | 0.8745 | 0.8988 | 0.8685 | 0.6944 | 0.7717 | 0.0739 |
| behavior_without_size | xgboost | 1-5_files | 497 | 178 | 319 | 0.9347 | 0.8966 | 0.9488 | 0.7555 | 0.8412 | 0.0730 |
| behavior_without_size | xgboost | 6-20_files | 199 | 164 | 35 | 0.7989 | 0.9111 | 0.6327 | 0.8857 | 0.7381 | 0.1098 |
| behavior_without_size | xgboost | >20_files | 270 | 231 | 39 | 0.2818 | 0.6717 | 0.2500 | 0.1282 | 0.1695 | 0.0649 |
| behavior_without_size | xgboost | 0_files | 25 | 9 | 16 | 0.6957 | 0.6111 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| behavior_without_size | xgboost | all_packages | 991 | 582 | 409 | 0.8468 | 0.8661 | 0.8576 | 0.6773 | 0.7568 | 0.0790 |
| behavior_with_size | random_forest | 1-5_files | 497 | 178 | 319 | 0.9476 | 0.9043 | 0.8607 | 0.8715 | 0.8660 | 0.2528 |
| behavior_with_size | random_forest | 6-20_files | 199 | 164 | 35 | 0.8834 | 0.9554 | 0.9231 | 0.6857 | 0.7869 | 0.0122 |
| behavior_with_size | random_forest | >20_files | 270 | 231 | 39 | 0.5999 | 0.9035 | 1.0000 | 0.0769 | 0.1429 | 0.0000 |
| behavior_with_size | random_forest | 0_files | 25 | 9 | 16 | 0.6957 | 0.6111 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| behavior_with_size | random_forest | all_packages | 991 | 582 | 409 | 0.9064 | 0.9218 | 0.8665 | 0.7457 | 0.8016 | 0.0808 |
| behavior_with_size | xgboost | 1-5_files | 497 | 178 | 319 | 0.9471 | 0.9042 | 0.8037 | 0.9498 | 0.8707 | 0.4157 |
| behavior_with_size | xgboost | 6-20_files | 199 | 164 | 35 | 0.8287 | 0.9425 | 0.8500 | 0.4857 | 0.6182 | 0.0183 |
| behavior_with_size | xgboost | >20_files | 270 | 231 | 39 | 0.2816 | 0.5659 | 0.6000 | 0.0769 | 0.1364 | 0.0087 |
| behavior_with_size | xgboost | 0_files | 25 | 9 | 16 | 0.6957 | 0.6111 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| behavior_with_size | xgboost | all_packages | 991 | 582 | 409 | 0.8826 | 0.8804 | 0.8035 | 0.7897 | 0.7965 | 0.1357 |
| size_only | random_forest | 1-5_files | 497 | 178 | 319 | 0.6966 | 0.5981 | 0.6742 | 0.9404 | 0.7853 | 0.8146 |
| size_only | random_forest | 6-20_files | 199 | 164 | 35 | 0.3381 | 0.6242 | 0.6364 | 0.2000 | 0.3043 | 0.0244 |
| size_only | random_forest | >20_files | 270 | 231 | 39 | 0.1385 | 0.3273 | 0.1250 | 0.0256 | 0.0426 | 0.0303 |
| size_only | random_forest | 0_files | 25 | 9 | 16 | 0.6400 | 0.5000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| size_only | random_forest | all_packages | 991 | 582 | 409 | 0.6464 | 0.7504 | 0.6638 | 0.7531 | 0.7056 | 0.2680 |
| size_only | xgboost | 1-5_files | 497 | 178 | 319 | 0.6966 | 0.5981 | 0.6742 | 0.9404 | 0.7853 | 0.8146 |
| size_only | xgboost | 6-20_files | 199 | 164 | 35 | 0.3407 | 0.6305 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| size_only | xgboost | >20_files | 270 | 231 | 39 | 0.1598 | 0.4149 | 0.0000 | 0.0000 | 0.0000 | 0.0043 |
| size_only | xgboost | 0_files | 25 | 9 | 16 | 0.6400 | 0.5000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| size_only | xgboost | all_packages | 991 | 582 | 409 | 0.6509 | 0.7506 | 0.6726 | 0.7335 | 0.7018 | 0.2509 |

## 4. Size Confound & Diagnostic Analysis

As established in `results/rescan_v11_summary.md`, package size (`n_py_files`) is an artificial dataset confound rather than legitimate malicious behavior:
- In the v1.1 corpus, malicious packages have a median of 2 analyzed `.py` files, whereas benign libraries have a median of 12.
- In `size_only`, models achieve an apparent overall ROC-AUC of ~0.78, but this is entirely an artifact of classifying small packages as malicious. On packages with 1–5 files, `size_only` produces an extreme false-positive rate, while failing completely on larger malicious packages.
- In `behavior_with_size`, tree models heavily split on `n_py_files`, driving small-package FPR dramatically higher compared to `behavior_without_size`.
- Therefore, `behavior_without_size` remains the authoritative production model: it relies strictly on AST behavioral signals and avoids learning size shortcuts.

## 5. Provenance & Leakage Notes
- Grouping is strictly by `group_id` (PEP 503 normalized package name). 0 group overlap between dev and holdout.
- Frozen holdout packages (`results/frozen_holdout_packages.csv`) were strictly excluded from training, validation, and top-indicator vocabulary selection.
- All forbidden columns (`strong_signals`, `verdict_outcome`, `review_recommended`, `s2_same_file`, diagnostics, identifiers) are blocked by explicit allowlisting and runtime leakage guards.
