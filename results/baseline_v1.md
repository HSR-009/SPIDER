# SPIDER baseline v1

Positive class: malicious (label 1). Holdout is not used for tuning.

| Experiment | Model | PR-AUC | ROC-AUC | Precision | Recall | F1 | FPR | TN | FP | FN | TP |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| behavior_without_size | random_forest | 0.8713 | 0.9012 | 0.8803 | 0.6650 | 0.7577 | 0.0636 | 545 | 37 | 137 | 272 |
| behavior_without_size | xgboost | 0.8535 | 0.8844 | 0.8538 | 0.6284 | 0.7239 | 0.0756 | 538 | 44 | 152 | 257 |
| behavior_with_size | random_forest | 0.9077 | 0.9178 | 0.8218 | 0.8117 | 0.8167 | 0.1237 | 510 | 72 | 77 | 332 |
| behavior_with_size | xgboost | 0.8870 | 0.8905 | 0.8225 | 0.7702 | 0.7955 | 0.1168 | 514 | 68 | 94 | 315 |
| size_only | random_forest | 0.6897 | 0.7798 | 0.6617 | 0.7653 | 0.7098 | 0.2749 | 422 | 160 | 96 | 313 |
| size_only | xgboost | 0.6924 | 0.7744 | 0.6827 | 0.6944 | 0.6885 | 0.2268 | 450 | 132 | 125 | 284 |

Provenance notes: group_id is normalized package name; analyzer_version is null because the current source export does not provide it.
n_findings, parse-error count and failed-analysis status are diagnostics, excluded from model inputs.
Top-40 indicator vocabulary is selected by package-presence frequency without labels.
Benign labels are assumed-benign as documented in the shared dataset schema.
