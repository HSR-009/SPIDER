# SPIDER Day 5 — Adversarial Resilience Table & Three-Way Comparison

**Date:** 2026-11-08  
**Author:** Person B (Machine Learning)  
**Batch:** `adv-batch-v1` | **Manifest Hash:** `bb7f4fe8676000ef1e2f06e08d8387738e8ee4a3c33ac68ade289ffd8875aaa3`  
**Verification:** 100% verified against published release (12 samples, 0 mismatches)  

---

## 1. Overall Three-Way Comparison Table (Denominator: 12 Samples)

| Detection Pipeline | Recovered (Exact Match) | Different Signal | Missed (Evaded) | Finding-Level Evasion Rate | RF Detection Rate (P≥0.5) | XGB Detection Rate (P≥0.5) |
|---|---:|---:|---:|---:|---:|---:|
| **A. Baseline (AST v1)** | 2 (16.67%) | 2 (16.67%) | **8** | **66.67%** | 4/12 (33.33%) | 3/12 (25.0%) |
| **B. Normalized (v1 + Normalize)** | 5 (41.67%) | 2 (16.67%) | **5** | **41.67%** | 7/12 (58.33%) | 6/12 (50.0%) |
| **C. Hardened (AST v1.1)** | 4 (33.33%) | 8 (66.67%) | **0** | **0.0%** | 7/12 (58.33%) | 6/12 (50.0%) |
| **D. Hardened + Normalized** | 5 (41.67%) | 6 (50.0%) | **1** | **8.33%** | 9/12 (75.0%) | 8/12 (66.67%) |

> [!IMPORTANT]
> **Finding-Level vs Package-Level Distinction:** Finding-level evasion rate measures whether the exact baseline indicator or an auxiliary finding fired; it is a feature-level syntactic metric, **not a package detection rate**. As established in Person A's verification, emitting `different_signal` does not imply detection by the engine verdict.

## 2. Hardened Engine Verdict-Level Breakdown (v1.1)

| Pipeline | Suspicious (Strong Signal) | Review-Kept (`review_recommended: true`) | Silent (`none_detected`, No Review) | Review Recommendation Rate |
|---|---:|---:|---:|---:|
| **Hardened v1.1** | 1 (8.33%) | 5 (41.67%) | 6 (50.0%) | **45.45%** (5/11 non-suspicious) |
| **Hardened v1.1 + Normalize** | 1 (8.33%) | 7 (58.33%) | 4 (33.33%) | **63.64%** (7/11 non-suspicious) |

### Verdict Observations:
- Only **1 of 12 samples** (`adv_001`, Base64 dynamic execution) triggers a `suspicious` verdict under Verdict v2 (via strong signals `S2_dynamic_exec_plus` and `S5_decode_exec`).
- **5 of 12 samples** are review-kept (`adv_002` ROT13, `adv_004` Delay-7, `adv_005` Delay-3, `adv_006` Import Alias, `adv_010` Alias + Getattr).
- **6 of 12 samples** evade both suspicious verdict and review recommendation (silent): String split (`adv_000`), Getattr (`adv_003`), Dunder import (`adv_007`), Chr build (`adv_008`), Hex escape (`adv_009`), and Combo (`adv_011`).

## 3. Per-Technique Resilience Breakdown

| Technique ID | Description | v1 Finding Level | v1 + Normalize | v1.1 Hardened | v1.1 Verdict Outcome |
|---|---|---|---|---|---|
| `T01_string_split` | String concatenation split on function attribute name | `missed` | `recovered` | `different_signal` | `silent` (`none_detected_in_this_scan`) |
| `T02_base64` | Base64 encoded payload with dynamic execution | `different_signal` | `different_signal` | `different_signal` | `suspicious` (`suspicious`) |
| `T03_rot13` | ROT13 encoded payload with dynamic execution | `different_signal` | `different_signal` | `different_signal` | `review_kept` (`none_detected_in_this_scan`) |
| `T04_getattr` | Dynamic function resolution via getattr with split name | `missed` | `missed` | `different_signal` | `silent` (`none_detected_in_this_scan`) |
| `T05_delay` | Delayed execution trigger with counter threshold = 7 | `recovered` | `recovered` | `recovered` | `review_kept` (`none_detected_in_this_scan`) |
| `T05_delay` | Delayed execution trigger with counter threshold = 3 | `recovered` | `recovered` | `recovered` | `review_kept` (`none_detected_in_this_scan`) |
| `T06_import_alias` | Module import aliasing concealing os.popen | `missed` | `missed` | `recovered` | `review_kept` (`none_detected_in_this_scan`) |
| `T07_dunder_import` | Dynamic import resolution via __import__ and dynamic string arg | `missed` | `missed` | `different_signal` | `silent` (`none_detected_in_this_scan`) |
| `T08_chr_build` | Attribute name constructed via chr() joins and resolved with getattr | `missed` | `missed` | `different_signal` | `silent` (`none_detected_in_this_scan`) |
| `T09_hex_escape` | Attribute name hex-decoded via bytes.fromhex and resolved with getattr | `missed` | `missed` | `different_signal` | `silent` (`none_detected_in_this_scan`) |
| `T06_import_alias+T04_getattr` | Combination: aliased import followed by 2-arg getattr call | `missed` | `recovered` | `recovered` | `review_kept` (`none_detected_in_this_scan`) |
| `T06_import_alias+T01_string_split+T04_getattr` | Combination: aliased import, string split function name, and getattr call | `missed` | `recovered` | `different_signal` | `silent` (`none_detected_in_this_scan`) |

## 4. Normalization Adapter Findings & Limitations

1. **AST Rewriting Scope:** Person C's `spider.normalize` implements 4 specific AST transformations (constant string concat folding, `import as` alias resolution, literal base64 decoding, and 2-arg `getattr` rewriting).
2. **Effective Recoveries:** Normalization successfully recovers 3 additional techniques that evaded v1 AST analysis: String split (`adv_000`), Import alias + Getattr (`adv_010`), and Import alias + String split + Getattr (`adv_011`).
3. **Uncovered Techniques:** Normalization has zero effect on ROT13 (`adv_002`), Delay counters (`adv_004`, `adv_005`), `__import__` dunder calls (`adv_007`), `chr()` joins (`adv_008`), or `bytes.fromhex()` escapes (`adv_009`).
4. **Module Status:** The docstring in `spider/normalize.py` explicitly notes that it is a placeholder/best-guess module built outside the repository layout. Its results are treated as a research defense prototype.

## 5. Machine Learning Evaluation on Adversarial Batch

Person B's production models (`behavior_without_size`, trained on the v1.1 dev set without `n_py_files` as a direct feature) were evaluated on the adversarial batch. Residual size correlation is not ruled out. Person A's verification did not independently verify the normalization columns or RF/XGBoost detection rates below; treat them as reported experimental results:
- **Random Forest:** Detects **7 of 12 samples** (58.33%) under Hardened v1.1 features, rising to **9 of 12 samples** (75.00%) under Hardened v1.1 + Normalization ($P(\text{malicious}) \ge 0.5$). It captures auxiliary behavioral patterns (`Dynamic Code Execution`, `Obfuscation`) even when the primary command execution indicator was obfuscated.
- **XGBoost:** Detects **6 of 12 samples** (50.00%) under Hardened v1.1 features, rising to **8 of 12 samples** (66.67%) under Hardened v1.1 + Normalization.
- **Integrity Guard:** The frozen adversarial batch was **never used for model training, tuning, threshold selection, or isotonic probability calibration**.
