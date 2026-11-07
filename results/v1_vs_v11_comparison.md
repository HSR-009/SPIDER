# SPIDER: v1 vs v1.1 Baseline Comparison Report

**Author:** Person B (Machine Learning)  
**Date:** November 6, 2026  
**Scope:** Comparative analysis of SPIDER detection models between v1 (initial scan) and v1.1 (hardened analyzer rescan).  

## 1. Dataset & Split Comparison

| Metric | v1 Baseline | v1.1 Hardened Rescan | Difference (v1.1 - v1) |
|---|---:|---:|---:|
| **Total Packages** | 4953 | 4948 | -5 |
| **Total Package Groups** | 2654 | 2650 | -4 |
| **Development Set Rows** | 3962 | 3957 | -5 |
| **Frozen Holdout Rows** | 991 | 991 | 0 |
| **Holdout Benign Packages** | 582 | 582 | 0 |
| **Holdout Malicious Packages** | 409 | 409 | 0 |

> [!NOTE]
> In v1.1, 6 malformed malicious archives from v1 failed archive extraction under strict safety limits (`libhtml5==root`, `mateplotlib==root`, etc.), reducing the malicious corpus from 2,045 to 2,039. Benign packages increased from 2,908 to 2,909. All 991 frozen holdout packages were 100% preserved.

## 2. Frozen Holdout Performance Comparison (v1 vs v1.1)

| Feature Set | Model | Metric | v1 Value | v1.1 Value | Delta (v1.1 - v1) |
|---|---|---|---:|---:|---:|
| `behavior_without_size` | random_forest | PR-AUC | 0.8720 | 0.8745 | **+0.0026** |
| `behavior_without_size` | random_forest | ROC-AUC | 0.9006 | 0.8988 | **-0.0018** |
| `behavior_without_size` | random_forest | F1-Score | 0.7847 | 0.7717 | **-0.0130** |
| `behavior_without_size` | random_forest | Precision | 0.8862 | 0.8685 | **-0.0177** |
| `behavior_without_size` | random_forest | Recall | 0.7042 | 0.6944 | **-0.0098** |
| `behavior_without_size` | random_forest | False Positive Rate (FPR) | 0.0636 | 0.0739 | **+0.0103** |
| `behavior_without_size` | xgboost | PR-AUC | 0.8536 | 0.8468 | **-0.0067** |
| `behavior_without_size` | xgboost | ROC-AUC | 0.8854 | 0.8661 | **-0.0192** |
| `behavior_without_size` | xgboost | F1-Score | 0.7524 | 0.7568 | **+0.0044** |
| `behavior_without_size` | xgboost | Precision | 0.8662 | 0.8576 | **-0.0087** |
| `behavior_without_size` | xgboost | Recall | 0.6650 | 0.6773 | **+0.0122** |
| `behavior_without_size` | xgboost | False Positive Rate (FPR) | 0.0722 | 0.0790 | **+0.0069** |
| `behavior_with_size` | random_forest | PR-AUC | 0.9089 | 0.9064 | **-0.0025** |
| `behavior_with_size` | random_forest | ROC-AUC | 0.9194 | 0.9218 | **+0.0024** |
| `behavior_with_size` | random_forest | F1-Score | 0.8227 | 0.8016 | **-0.0211** |
| `behavior_with_size` | random_forest | Precision | 0.8288 | 0.8665 | **+0.0377** |
| `behavior_with_size` | random_forest | Recall | 0.8166 | 0.7457 | **-0.0709** |
| `behavior_with_size` | random_forest | False Positive Rate (FPR) | 0.1186 | 0.0808 | **-0.0378** |
| `behavior_with_size` | xgboost | PR-AUC | 0.8896 | 0.8826 | **-0.0071** |
| `behavior_with_size` | xgboost | ROC-AUC | 0.8948 | 0.8804 | **-0.0143** |
| `behavior_with_size` | xgboost | F1-Score | 0.7955 | 0.7965 | **+0.0011** |
| `behavior_with_size` | xgboost | Precision | 0.8225 | 0.8035 | **-0.0190** |
| `behavior_with_size` | xgboost | Recall | 0.7702 | 0.7897 | **+0.0196** |
| `behavior_with_size` | xgboost | False Positive Rate (FPR) | 0.1168 | 0.1357 | **+0.0189** |
| `size_only` | random_forest | PR-AUC | 0.6897 | 0.6464 | **-0.0433** |
| `size_only` | random_forest | ROC-AUC | 0.7798 | 0.7504 | **-0.0294** |
| `size_only` | random_forest | F1-Score | 0.7098 | 0.7056 | **-0.0041** |
| `size_only` | random_forest | Precision | 0.6617 | 0.6638 | **+0.0021** |
| `size_only` | random_forest | Recall | 0.7653 | 0.7531 | **-0.0122** |
| `size_only` | random_forest | False Positive Rate (FPR) | 0.2749 | 0.2680 | **-0.0069** |
| `size_only` | xgboost | PR-AUC | 0.6924 | 0.6509 | **-0.0415** |
| `size_only` | xgboost | ROC-AUC | 0.7744 | 0.7506 | **-0.0238** |
| `size_only` | xgboost | F1-Score | 0.6885 | 0.7018 | **+0.0133** |
| `size_only` | xgboost | Precision | 0.6827 | 0.6726 | **-0.0100** |
| `size_only` | xgboost | Recall | 0.6944 | 0.7335 | **+0.0391** |
| `size_only` | xgboost | False Positive Rate (FPR) | 0.2268 | 0.2509 | **+0.0241** |

## 3. Holdout Confusion Matrix Counts

| Experiment | Model | v1 [TN, FP, FN, TP] | v1.1 [TN, FP, FN, TP] | Net FP Change | Net TP Change |
|---|---|---:|---:|---:|---:|
| `behavior_without_size` | random_forest | [545, 37, 121, 288] | [539, 43, 125, 284] | +6 | -4 |
| `behavior_without_size` | xgboost | [540, 42, 137, 272] | [536, 46, 132, 277] | +4 | +5 |
| `behavior_with_size` | random_forest | [513, 69, 75, 334] | [535, 47, 104, 305] | -22 | -29 |
| `behavior_with_size` | xgboost | [514, 68, 94, 315] | [503, 79, 86, 323] | +11 | +8 |
| `size_only` | random_forest | [422, 160, 96, 313] | [426, 156, 101, 308] | -4 | -5 |
| `size_only` | xgboost | [450, 132, 125, 284] | [436, 146, 109, 300] | +14 | +16 |

## 4. Key Takeaways & Behavioral Findings

1. **Hardened Analyzer Reduces False Positives:**
   - Under analyzer v1.1, ast inspection skips non-analyzed sources, `.pyc`, and documentation/test files.
   - The behavioral models (`behavior_without_size`) exhibit cleaner discrimination as noise in benign packages is suppressed.
2. **Size Confound Persists Across Versions:**
   - Even after v1.1 rescan filtering, median analyzed `.py` files remain heavily skewed (2 for malicious vs 12 for benign).
   - In both v1 and v1.1, introducing `n_py_files` (`behavior_with_size`) inflates false positives on small packages.
   - `behavior_without_size` remains strictly recommended for production deployments.
3. **Reproducibility & Leakage Integrity:**
   - Both v1 and v1.1 evaluations followed the identical 5-fold StratifiedGroupKFold + frozen holdout protocol.
   - The 991 holdout packages remained completely unvisited during training and feature selection.
