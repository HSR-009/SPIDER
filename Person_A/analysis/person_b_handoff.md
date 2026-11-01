# SPIDER — Person A to Person B Handoff

## 1. Purpose

This handoff provides the datasets and security-analysis findings for Person B's machine-learning pipeline in SPIDER (Supply Chain Packages Intelligence for Detection, Evasion and Resilience).

**Person A:** Static analysis, malicious-package research, threat modeling, and indicator analysis.  
**Person B:** Feature engineering, baseline ML models, evaluation, and explainability.  
**Person C:** Adversarial evasion testing and dashboard.

The goal is to detect malicious PyPI packages using behavioral, metadata, and supply-chain signals while avoiding data leakage and misleading evaluation.

## 2. Dataset Files

Use the following committed files from the repository root:

| Dataset | Path | Rows | Label |
|---|---|---:|---:|
| Malicious | `data/processed/malicious_for_b.jsonl` | 2,045 | `1` |
| Benign | `data/processed/benign_for_b.jsonl.gz` | 2,908 | `0` |

The benign dataset is compressed with gzip. Read it using Python's `gzip` module; do not assume it is a plain JSONL file.

### Dataset summary

| Property | Malicious | Benign |
|---|---:|---:|
| Package-version rows | 2,045 | 2,908 |
| Unique package names | 1,186 | 1,468 |
| Rows with Python files | 2,027 | 2,862 |
| Rows with at least one finding | 1,879 | 2,445 |
| Rows with failed static analysis | 38 | 171 |

Each row represents a **package version**, not necessarily a unique package. Multiple versions of the same package may appear.

The benign set consists of popular PyPI packages assumed benign for this study; it has not been independently verified as completely malware-free. Treat results as a research baseline, not a definitive estimate of real-world performance.

## 3. Critical: Prevent Data Leakage

**Do not use the following fields as model input features:**

- `label` — the target being predicted.
- `malicious_evidence` — label-supporting documentation, not a feature.
- `in_index` and `index_annotated` — these reflect how the datasets were collected and can reveal the label.
- `source` — the source field separates the classes by construction in the current exports.
- `package_id` — identifier that contains package/version information; do not use it as a raw predictive feature.
- `version` — exclude as a raw feature unless a carefully justified, leakage-safe transformation is designed.

### Package size and collection bias

The two datasets differ substantially in package size:

- Median Python files: **3 malicious versus 20 benign**.
- A size-only model using `n_py_files` produced an AUC of **0.197** when malicious was the positive class. Reversing the score direction gives a separability of approximately **0.803**.
- `n_findings` alone had an AUC of **0.509**.
- `failed_static_analysis` alone had an AUC of **0.480**.

The size result is an important warning: package size alone separates the classes substantially in this dataset. The AUC of 0.197 does not mean a model is performing at 19.7% accuracy; AUC measures ranking, and a value below 0.5 can indicate that the score tends to rank the positive class in the opposite direction.

**Required evaluation:**
1. Report a size-only baseline beside every main model result.
2. Evaluate performance within Python-file-count buckets, where sample counts permit.
3. Compare results with and without size-related features.
4. Treat `n_py_files`, `n_findings`, and `failed_static_analysis` cautiously because they can reflect collection and scanning differences as well as package behavior.

## 4. Split Strategy

Prevent related package versions from appearing across both training and test sets.

- At minimum, split by normalized `package_name`, keeping every version of a package in one partition.
- Do not randomly split individual package-version rows.
- Near-duplicates can use different names. Examples found during analysis include `maratlib` / `maratlib1` and `chia-pool-reference` / `cat-admin-tool`.
- Where reliable campaign or near-duplicate groupings are available, consider a stricter grouped evaluation and document the method.

The malicious source index is campaign-heavy: campaign IDs 30 and 47 account for 1,524 of 2,627 campaign-annotated PyPI index records. These are **index-wide counts**, not confirmed counts for the locally scanned dataset. Person A's scan covered 2,040 of 6,428 PyPI index records, approximately **31.7%**.

Do not use campaign annotations as predictive features in the primary behavioral baseline. They are useful for grouping, stratified analysis, and investigating dataset bias.

## 5. Static Analyzer Output

Person A's analyzer is located at:

`Person_A/ast_analyzer/analyzer.py`

The export contains package-level features and categorized findings. The main AST-detectable behavior categories are:

- Command Execution
- Dynamic Code Execution
- Credential / Data Access
- Network Activity
- Obfuscation
- Install-Time / Package Execution

Supply-chain abuse, such as typosquatting, depends substantially on names or metadata and is not fully detectable from Python AST analysis alone.

### Parse errors

`Parse Error` is a **status, not a security behavior category**.

Represent scanning failures using `failed_static_analysis`. Do not count `Parse Error` as a behavioral finding or as evidence that a package is malicious.

### Findings are indicators, not verdicts

The analyzer uses static rules. A finding does not prove malicious intent, and a package with no findings is not necessarily safe.

Examples of signals that require context:

- `setuptools.setup()` is common in legitimate packages and should not be treated as a strong malicious signal by itself.
- `subprocess`, `eval`, `exec`, environment-variable access, and Base64 operations can occur in benign software.
- Network activity and custom installation behavior can be informative but are not conclusive independently.

Use combinations of signals and evaluate their contribution empirically.

## 6. Baseline Indicator Results

The current indicator-discrimination report compares prevalence across 2,045 malicious and 2,908 benign package-version rows. These are **prevalence comparisons, not model accuracy or detection rates**.

| Category | Malicious | Benign | Prevalence ratio |
|---|---:|---:|---:|
| Network Activity | 43.77% | 17.54% | 2.50× |
| Command Execution | 39.90% | 25.79% | 1.55× |
| Install-Time / Package Execution | 69.88% | 53.27% | 1.31× |
| Obfuscation | 21.96% | 24.90% | 0.88× |
| Credential / Data Access | 25.97% | 50.48% | 0.51× |
| Dynamic Code Execution | 10.71% | 25.93% | 0.41× |

Important individual signals:

- `setuptools.command.install`: 19.32% malicious versus 0.76% benign.
- `requests.post`: 17.75% malicious versus 3.61% benign.
- `os.system`: 10.22% malicious versus 3.82% benign.
- `setuptools.setup()`: 69.34% malicious versus 53.20% benign; weak on its own.
- `os.environ`: 23.72% malicious versus 48.11% benign, likely affected by the larger benign packages and their codebases.

Use the complete report at `Person_A/analysis/indicator_discrimination.md` for the full indicator-level comparison. Interpret individual ratios alongside their counts and denominators; very small counts can produce unstable ratios.

## 7. Important Dataset Limitations

1. **Size imbalance:** Benign packages have more Python files on average, which can distort feature prevalence and model performance.
2. **Placeholder packages:** Some malicious package versions contain little or no meaningful Python code. For example, `matplatlib-plus@1.1` was observed as an empty placeholder. Such cases may require package-name similarity and metadata features.
3. **Static-analysis blind spots:** Compiled `.so` binaries, `.pth` files, and behavior hidden through complex dynamic loading may not be fully represented by AST findings.
4. **Obfuscation:** The source index marks 1,010 of 1,024 annotated records as obfuscated, while the analyzer reports Obfuscation findings in approximately 22% of locally scanned malicious package versions. These numbers have different denominators and annotation scopes; do not interpret the difference directly as a measured false-negative rate.
5. **Dataset coverage:** The locally scanned records represent approximately 31.7% of the PyPI records in the malicious source index.
6. **Label caveat:** A package-version can be labeled malicious because it belongs to a malicious package or campaign even when that particular version has little detectable payload.

## 8. Recommended ML Workflow

1. Load the two JSONL datasets, decompressing `benign_for_b.jsonl.gz`.
2. Validate row counts, labels, schema, and missing values.
3. Exclude the leakage fields listed in Section 3.
4. Establish simple baselines, including a size-only baseline.
5. Use package-grouped train/validation/test splits.
6. Train the planned Random Forest and XGBoost models.
7. Evaluate overall performance and performance by package-size bucket.
8. Report precision, recall, F1-score, ROC-AUC, and the confusion matrix; include class balance and split methodology.
9. Use SHAP or another explainability method to examine the features driving predictions.
10. Compare behavioral-only features against behavioral-plus-metadata features, clearly documenting the difference.

Do not present a high score as proof of generalization unless leakage, package overlap, and size-related confounding have been addressed.

## 9. Relevant Person A Files

- `Person_A/ast_analyzer/analyzer.py` — frozen analyzer v1 baseline.
- `Person_A/analysis/indicator_discrimination.md` — malicious-versus-benign indicator prevalence.
- `Person_A/analysis/supply_chain_facts.md` — source-index and campaign observations.
- `Person_A/analysis/analyzer_v1_real_data_gaps.md` — observed analyzer limitations and examples.
- `Person_A/analysis/v1_1_rule_spec.md` — proposed improvements; analyzer v1 itself remains unchanged.
- `Person_A/pipeline/indicator_lift.py` — generates indicator-prevalence comparisons.
- `Person_A/pipeline/sanity_checks.py` — dataset-size and diagnostic checks.

## 10. Handoff Checklist

- [ ] Load both committed datasets successfully.
- [ ] Confirm the benign gzip file decompresses and has 2,908 rows.
- [ ] Exclude leakage-prone fields.
- [ ] Split by normalized package name at minimum.
- [ ] Include a size-only baseline.
- [ ] Report metrics overall and by size bucket.
- [ ] Document limitations and the exact evaluation methodology.

**Core principle:** SPIDER should learn meaningful behavioral and supply-chain signals—not dataset provenance, package identity, or differences in package size and collection method.