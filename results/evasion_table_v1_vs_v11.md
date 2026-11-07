# SPIDER Evasion & Defense Comparison: AST v1 vs v1.1 vs Normalization

**Frozen Adversarial Batch:** `adv-batch-v1`  
**Manifest SHA-256:** `bb7f4fe8676000ef1e2f06e08d8387738e8ee4a3c33ac68ade289ffd8875aaa3`  
**Total Adversarial Samples:** 12  

---

## 1. Executive Summary & Attack Success Rate (ASR)

| Detector Pipeline | Recovered (Exact Match) | Different Signal (Partial) | Missed (Evaded) | Evasion Rate (ASR) |
| :--- | :---: | :---: | :---: | :---: |
| **Baseline AST Analyzer (`v1 frozen`)** | 2 (16.67%) | 2 | **8** | **66.67%** |
| **Hardened AST Analyzer (`v1.1`)** | 4 (33.33%) | 8 | **0** | **0.0%** |
| **AST `v1` + `normalize.py`** | 5 (41.67%) | 2 | **5** | **41.67%** |
| **AST `v1.1` + `normalize.py` (Full Defense)** | 6 (50.0%) | 5 | **1** | **8.33%** |

---

## 2. Per-Technique Breakdown

| Technique | v1 (Rec/Diff/Miss) | v1.1 (Rec/Diff/Miss) | v1 + Norm (Rec/Diff/Miss) | v1.1 + Norm (Rec/Diff/Miss) |
| :--- | :---: | :---: | :---: | :---: |
| `T01_string_split` | 0/0/1 | 0/1/0 | 1/0/0 | **1/0/0** |
| `T02_base64` | 0/1/0 | 0/1/0 | 0/1/0 | **0/1/0** |
| `T03_rot13` | 0/1/0 | 0/1/0 | 0/1/0 | **0/1/0** |
| `T04_getattr` | 0/0/1 | 0/1/0 | 0/0/1 | **0/1/0** |
| `T05_delay` | 2/0/0 | 2/0/0 | 2/0/0 | **2/0/0** |
| `T06_import_alias` | 0/0/1 | 1/0/0 | 0/0/1 | **1/0/0** |
| `T06_import_alias+T01_string_split+T04_getattr` | 0/0/1 | 0/1/0 | 1/0/0 | **1/0/0** |
| `T06_import_alias+T04_getattr` | 0/0/1 | 1/0/0 | 1/0/0 | **1/0/0** |
| `T07_dunder_import` | 0/0/1 | 0/1/0 | 0/0/1 | **0/0/1** |
| `T08_chr_build` | 0/0/1 | 0/1/0 | 0/0/1 | **0/1/0** |
| `T09_hex_escape` | 0/0/1 | 0/1/0 | 0/0/1 | **0/1/0** |

---

## 3. Detailed Per-Sample Evaluation Log

| ID | Technique | Description | v1 Outcome | v1.1 Outcome | v1.1+Norm Outcome |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `adv_000` | `T01_string_split` | String concatenation split on function attribute name | `missed` | `different_signal` | **`recovered`** |
| `adv_001` | `T02_base64` | Base64 encoded payload with dynamic execution | `different_signal` | `different_signal` | **`different_signal`** |
| `adv_002` | `T03_rot13` | ROT13 encoded payload with dynamic execution | `different_signal` | `different_signal` | **`different_signal`** |
| `adv_003` | `T04_getattr` | Dynamic function resolution via getattr with split name | `missed` | `different_signal` | **`different_signal`** |
| `adv_004` | `T05_delay` | Delayed execution trigger with counter threshold = 7 | `recovered` | `recovered` | **`recovered`** |
| `adv_005` | `T05_delay` | Delayed execution trigger with counter threshold = 3 | `recovered` | `recovered` | **`recovered`** |
| `adv_006` | `T06_import_alias` | Module import aliasing concealing os.popen | `missed` | `recovered` | **`recovered`** |
| `adv_007` | `T07_dunder_import` | Dynamic import resolution via __import__ and dynamic string arg | `missed` | `different_signal` | **`missed`** |
| `adv_008` | `T08_chr_build` | Attribute name constructed via chr() joins and resolved with getattr | `missed` | `different_signal` | **`different_signal`** |
| `adv_009` | `T09_hex_escape` | Attribute name hex-decoded via bytes.fromhex and resolved with getattr | `missed` | `different_signal` | **`different_signal`** |
| `adv_010` | `T06_import_alias+T04_getattr` | Combination: aliased import followed by 2-arg getattr call | `missed` | `recovered` | **`recovered`** |
| `adv_011` | `T06_import_alias+T01_string_split+T04_getattr` | Combination: aliased import, string split function name, and getattr call | `missed` | `different_signal` | **`recovered`** |

---

## 4. Key Security Findings
- **Direct AST Bypasses in v1:** `getattr(os, ...)` and `__import__` reliably blind baseline `v1` (ASR = 50.0%).
- **Rule Hardening in v1.1:** `v1.1` successfully catches obfuscation indicators (`obf.fromhex`, `obf.chr_join`, `base64`), lowering pure miss rates and converting evasions to `different_signal`.
- **Defense Recovery via Normalization:** Adding deterministic AST normalization (`spider/normalize.py`) folds string concatenations, resolves import aliases, and converts 2-arg `getattr` into standard attribute calls, recovering original call signatures before rules fire.
