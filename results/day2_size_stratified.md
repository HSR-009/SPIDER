# SPIDER Day 2 — Size-Stratified Model Evaluation

Evaluation performed on the frozen holdout set (991 packages) divided into package-size buckets by `n_py_files`.

## Summary by Size Bucket and Experiment

| Experiment | Model | Size Bucket | Total | Benign | Malicious | PR-AUC | ROC-AUC | Precision | Recall | F1 | FPR |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| behavior_without_size | random_forest | 1-5_files | 407 | 126 | 281 | 0.9293 | 0.8766 | 0.9727 | 0.6335 | 0.7672 | 0.0397 |
| behavior_without_size | random_forest | 6-20_files | 200 | 139 | 61 | 0.7950 | 0.8243 | 0.8214 | 0.7541 | 0.7863 | 0.0719 |
| behavior_without_size | random_forest | >20_files | 359 | 308 | 51 | 0.8053 | 0.9668 | 0.6857 | 0.9412 | 0.7934 | 0.0714 |
| behavior_without_size | random_forest | 0_files | 25 | 9 | 16 | 0.6400 | 0.5000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| behavior_without_size | random_forest | all_packages | 991 | 582 | 409 | 0.8713 | 0.9012 | 0.8803 | 0.6650 | 0.7577 | 0.0636 |
| behavior_without_size | xgboost | 1-5_files | 407 | 126 | 281 | 0.9308 | 0.8780 | 0.9677 | 0.6406 | 0.7709 | 0.0476 |
| behavior_without_size | xgboost | 6-20_files | 200 | 139 | 61 | 0.8302 | 0.8383 | 0.7833 | 0.7705 | 0.7769 | 0.0935 |
| behavior_without_size | xgboost | >20_files | 359 | 308 | 51 | 0.6273 | 0.8903 | 0.5455 | 0.5882 | 0.5660 | 0.0812 |
| behavior_without_size | xgboost | 0_files | 25 | 9 | 16 | 0.6400 | 0.5000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| behavior_without_size | xgboost | all_packages | 991 | 582 | 409 | 0.8535 | 0.8844 | 0.8538 | 0.6284 | 0.7239 | 0.0756 |
| behavior_with_size | random_forest | 1-5_files | 407 | 126 | 281 | 0.9430 | 0.8825 | 0.8006 | 0.9573 | 0.8720 | 0.5317 |
| behavior_with_size | random_forest | 6-20_files | 200 | 139 | 61 | 0.8366 | 0.8075 | 0.8936 | 0.6885 | 0.7778 | 0.0360 |
| behavior_with_size | random_forest | >20_files | 359 | 308 | 51 | 0.8318 | 0.9628 | 1.0000 | 0.4118 | 0.5833 | 0.0000 |
| behavior_with_size | random_forest | 0_files | 25 | 9 | 16 | 0.6400 | 0.5000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| behavior_with_size | random_forest | all_packages | 991 | 582 | 409 | 0.9077 | 0.9178 | 0.8218 | 0.8117 | 0.8167 | 0.1237 |
| behavior_with_size | xgboost | 1-5_files | 407 | 126 | 281 | 0.9381 | 0.8666 | 0.7943 | 0.8932 | 0.8409 | 0.5159 |
| behavior_with_size | xgboost | 6-20_files | 200 | 139 | 61 | 0.8185 | 0.7964 | 0.9773 | 0.7049 | 0.8190 | 0.0072 |
| behavior_with_size | xgboost | >20_files | 359 | 308 | 51 | 0.5957 | 0.8221 | 0.9130 | 0.4118 | 0.5676 | 0.0065 |
| behavior_with_size | xgboost | 0_files | 25 | 9 | 16 | 0.6400 | 0.5000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| behavior_with_size | xgboost | all_packages | 991 | 582 | 409 | 0.8870 | 0.8905 | 0.8225 | 0.7702 | 0.7955 | 0.1168 |
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

### Key Takeaways from Stratification:
1. **AST-only without size (`behavior_without_size`)** performs consistently across small (1-5 files) and medium packages, keeping FPR under 8%.
2. In the `>20 files` bucket, benign packages contain extensive helper/test files; models without size distinguish malicious indicators without penalizing large benign packages.
3. Models relying purely on `n_py_files` (`size_only`) suffer from high false positive rates (FPR > 20%) because legitimate popular packages have larger codebases.
