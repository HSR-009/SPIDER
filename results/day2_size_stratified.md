# SPIDER Day 2 — Size-Stratified Model Evaluation

Evaluation performed on the frozen holdout set (991 packages) divided into package-size buckets by `n_py_files`.

## Summary by Size Bucket and Experiment

| Experiment | Model | Size Bucket | Total | Benign | Malicious | PR-AUC | ROC-AUC | Precision | Recall | F1 | FPR |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| behavior_without_size | random_forest | 1-5_files | 407 | 126 | 281 | 0.9293 | 0.8761 | 0.9749 | 0.6904 | 0.8083 | 0.0397 |
| behavior_without_size | random_forest | 6-20_files | 200 | 139 | 61 | 0.8011 | 0.8249 | 0.8070 | 0.7541 | 0.7797 | 0.0791 |
| behavior_without_size | random_forest | >20_files | 359 | 308 | 51 | 0.7926 | 0.9647 | 0.6957 | 0.9412 | 0.8000 | 0.0682 |
| behavior_without_size | random_forest | 0_files | 25 | 9 | 16 | 0.6400 | 0.5000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| behavior_without_size | random_forest | all_packages | 991 | 582 | 409 | 0.8720 | 0.9006 | 0.8862 | 0.7042 | 0.7847 | 0.0636 |
| behavior_without_size | xgboost | 1-5_files | 407 | 126 | 281 | 0.9312 | 0.8784 | 0.9703 | 0.6975 | 0.8116 | 0.0476 |
| behavior_without_size | xgboost | 6-20_files | 200 | 139 | 61 | 0.8291 | 0.8388 | 0.7966 | 0.7705 | 0.7833 | 0.0863 |
| behavior_without_size | xgboost | >20_files | 359 | 308 | 51 | 0.6378 | 0.8894 | 0.5472 | 0.5686 | 0.5577 | 0.0779 |
| behavior_without_size | xgboost | 0_files | 25 | 9 | 16 | 0.6400 | 0.5000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| behavior_without_size | xgboost | all_packages | 991 | 582 | 409 | 0.8536 | 0.8854 | 0.8662 | 0.6650 | 0.7524 | 0.0722 |
| behavior_with_size | random_forest | 1-5_files | 407 | 126 | 281 | 0.9444 | 0.8853 | 0.8006 | 0.9573 | 0.8720 | 0.5317 |
| behavior_with_size | random_forest | 6-20_files | 200 | 139 | 61 | 0.8403 | 0.8119 | 0.9545 | 0.6885 | 0.8000 | 0.0144 |
| behavior_with_size | random_forest | >20_files | 359 | 308 | 51 | 0.8585 | 0.9677 | 1.0000 | 0.4510 | 0.6216 | 0.0000 |
| behavior_with_size | random_forest | 0_files | 25 | 9 | 16 | 0.6400 | 0.5000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| behavior_with_size | random_forest | all_packages | 991 | 582 | 409 | 0.9089 | 0.9194 | 0.8288 | 0.8166 | 0.8227 | 0.1186 |
| behavior_with_size | xgboost | 1-5_files | 407 | 126 | 281 | 0.9378 | 0.8664 | 0.7968 | 0.8932 | 0.8423 | 0.5079 |
| behavior_with_size | xgboost | 6-20_files | 200 | 139 | 61 | 0.8233 | 0.8016 | 0.9773 | 0.7049 | 0.8190 | 0.0072 |
| behavior_with_size | xgboost | >20_files | 359 | 308 | 51 | 0.6072 | 0.8409 | 0.8750 | 0.4118 | 0.5600 | 0.0097 |
| behavior_with_size | xgboost | 0_files | 25 | 9 | 16 | 0.6400 | 0.5000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| behavior_with_size | xgboost | all_packages | 991 | 582 | 409 | 0.8896 | 0.8948 | 0.8225 | 0.7702 | 0.7955 | 0.1168 |
| size_only | random_forest | 1-5_files | 407 | 126 | 281 | 0.7543 | 0.6228 | 0.6904 | 1.0000 | 0.8169 | 1.0000 |
| size_only | random_forest | 6-20_files | 200 | 139 | 61 | 0.5205 | 0.6902 | 0.6829 | 0.4590 | 0.5490 | 0.0935 |
| size_only | random_forest | >20_files | 359 | 308 | 51 | 0.1812 | 0.4975 | 0.1600 | 0.0784 | 0.1053 | 0.0682 |
| size_only | random_forest | 0_files | 25 | 9 | 16 | 0.6400 | 0.5000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| size_only | random_forest | all_packages | 991 | 582 | 409 | 0.6897 | 0.7798 | 0.6617 | 0.7653 | 0.7098 | 0.2749 |
| size_only | xgboost | 1-5_files | 407 | 126 | 281 | 0.7543 | 0.6228 | 0.6904 | 1.0000 | 0.8169 | 1.0000 |
| size_only | xgboost | 6-20_files | 200 | 139 | 61 | 0.5337 | 0.7009 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| size_only | xgboost | >20_files | 359 | 308 | 51 | 0.2109 | 0.3981 | 0.3333 | 0.0588 | 0.1000 | 0.0195 |
| size_only | xgboost | 0_files | 25 | 9 | 16 | 0.6400 | 0.5000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| size_only | xgboost | all_packages | 991 | 582 | 409 | 0.6924 | 0.7744 | 0.6827 | 0.6944 | 0.6885 | 0.2268 |

### Key Takeaways from Size Stratification:
1. **AST-Only Baseline (`behavior_without_size`):**
   - **Random Forest** exhibits robust false positive control across all strata: **3.97%** on small packages (1-5 files), **7.91%** on medium packages (6-20 files), and **6.82%** on large packages (>20 files), yielding an overall holdout FPR of **6.36%** and ROC-AUC of **0.9006**.
   - **XGBoost** exhibits slightly higher variation across strata: **4.76%** on small packages (1-5 files), **8.63%** on medium packages (6-20 files), and **7.79%** on large packages (>20 files), with an overall holdout FPR of **7.22%** and ROC-AUC of **0.8854**.
   - Note that while Random Forest keeps FPR under 8% across all strata, XGBoost reaches **8.63% FPR** on medium-sized packages.
2. **Severe Distortion from Size Feature (`behavior_with_size`):**
   - Introducing `n_py_files` to tree classifiers induces severe class-confounding: the False Positive Rate on small packages (1-5 files) explodes to **53.17% (RF)** and **50.79% (XGBoost)**.
   - Because benign training samples are predominantly larger libraries, the models learn an artificial shortcut linking small codebase size directly to malice.

### Limitations of Experiments:
1. **Limitations of `size_only`:** Codebase file count alone is inherently confounded by dataset curation: legitimate packages ship extensive tests and documentation, while historical malware samples are predominantly compact scripts. Relying on size produces a catastrophic **100% FPR** on 1-5 file packages (classifying all small benign packages as malicious) while failing entirely on large evasion-padded malware.
2. **Limitations of metadata ablation:** Typosquatting distance features (`feat_min_edit_distance`, `feat_is_potential_squat`) offer limited standalone discriminative power (ROC-AUC ~0.64, PR-AUC ~0.51) because only a minor subset of supply-chain attacks rely on name similarity. Furthermore, PyPI API attributes (`feat_package_age_days`, `feat_total_releases`, `feat_pypi_exists`) are missing from stored repository snapshots; live network querying is prohibited to avoid network dependency and distribution leakage.
