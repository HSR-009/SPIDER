# Day 4 — Person C Deliverables: AST Normalization Defense, Frozen Adversarial Batch & Evasion Evaluation

**Author:** Person C (Jeet Dave — Evasion, Defense & Dashboard)  
**Status:** Completed & Verified against Real Analyzers  
**Frozen Batch Tag:** `adv-batch-v1`  
**Manifest SHA-256:** `bb7f4fe8676000ef1e2f06e08d8387738e8ee4a3c33ac68ade289ffd8875aaa3`

---

## 1. Overview & Research Paradigm

Following the core SPIDER research loop:
```
DETECT → ATTACK/EVASION → DEFEND → RE-TEST
```
Day 4 establishes the defense layer (`spider/normalize.py`) and evaluates its effectiveness against an adversarial test batch across both the frozen baseline AST analyzer (`analyzer_v1_frozen`) and the hardened analyzer (`analyzer_v1_1`).

---

## 2. Deliverables Summary

### A. AST Normalization Defense (`spider/normalize.py`)
Deterministic source-to-source AST normalization that reverses obfuscation patterns prior to security rule inspection. Never executes code; parses, transforms, and unparses AST only.
- **Rule 1 (`ConstantFoldStringConcat`):** Folds chains of constant string additions (`"sys" + "tem"` → `"system"`).
- **Rule 2 (`ResolveImportAliases`):** Resolves aliased imports (`import os as x; x.system(...)` → `os.system(...)`).
- **Rule 3 (`DecodeLiteralBase64`):** Statically decodes constant base64 literals (`base64.b64decode("...")` → decoded bytes literal).
- **Rule 4 (`GetattrToAttribute`):** Rewrites 2-argument constant getattr calls (`getattr(os, "system")` → `os.system`).
- **Tests (`tests/test_normalize.py`):** 12/12 unit tests passing, covering individual rules and combined composition.

### B. Frozen Adversarial Evaluation Batch (`Person_c/adv_batch/`)
- **Manifest:** `Person_c/adv_batch/manifest.json`
- **Total Samples:** 12 syntactically verified samples spanning T01–T09 and multi-technique combinations (`T06+T04`, `T06+T01+T04`).
- **Integrity Hash (SHA-256):** `bb7f4fe8676000ef1e2f06e08d8387738e8ee4a3c33ac68ade289ffd8875aaa3`
- **Guaranteed Real Disguises:** `real_disguises_used: true`. All samples built using verified disguise functions from `Person_c/disguises.py` and `Person_c/transformations_ext.py`.
- **Standalone Sample Files:** Saved to `Person_c/adv_batch/samples/adv_000.py` through `adv_011.py` for direct inspection.

### C. Real Evasion & Defense Evaluation (`Person_c/evasion_table.py`)
Evaluates the adversarial batch across 4 analyzer configurations using the official three-way classification logic (`recovered`, `different_signal`, `missed`):
1. **Baseline AST Analyzer (`v1 frozen`)**
2. **Hardened AST Analyzer (`v1.1`)**
3. **AST `v1` + `normalize.py`**
4. **AST `v1.1` + `normalize.py` (Full Defense)**

Results written to:
- `results/evasion_table_v1_vs_v11.json`
- `results/evasion_table_v1_vs_v11.md`

#### Results Summary:
| Detector Pipeline | Recovered (Exact Match) | Different Signal (Partial) | Missed (Evaded) | Evasion Rate (ASR) |
| :--- | :---: | :---: | :---: | :---: |
| **Baseline AST Analyzer (`v1 frozen`)** | 2 (16.67%) | 2 | **8** | **66.67%** |
| **Hardened AST Analyzer (`v1.1`)** | 4 (33.33%) | 8 | **0** | **0.0%** |
| **AST `v1` + `normalize.py`** | 5 (41.67%) | 2 | **5** | **41.67%** |
| **AST `v1.1` + `normalize.py` (Full Defense)** | **6 (50.0%)** | 5 | **1** | **8.33%** |

### D. Scan Record Loader (`Person_c/load_replay_records.py`)
Loads real scan records from `fixtures/replay` (or `fixtures/records` fallback). Adheres strictly to honesty rules: preserves genuine `record_origin` tags and returns an empty list gracefully if the directory does not exist yet.

---

## 3. Verification & Test Commands

To verify all Person C deliverables locally:
```powershell
# 1. Run normalization unit tests
python -m unittest tests/test_normalize.py

# 2. Run evasion & catalog tests
python -m unittest Person_c/test_evasion_and_catalog.py

# 3. Run harness safety test suite
python -m unittest Person_c/test_harness_safety.py

# 4. Re-freeze batch & verify hash
python Person_c/adv_batch/freeze_batch.py

# 5. Run full v1 vs v1.1 evasion table
python Person_c/evasion_table.py
```
