# SPIDER — Evasion Baseline Evaluation v1
**Date:** 2026-11-03  
**Corpus:** `data/toy_samples/malicious/` (10 malicious files)  
**Evaluator:** Person C (Jeet Dave)  
**Analyzer Version:** `Person_A.ast_analyzer.analyzer` (v1 baseline)

---

## 1. Executive Summary

This document establishes the verified baseline evasion evaluation for SPIDER across all 10 malicious toy sample packages.

### Crucial Methodological Correction
Previous preliminary reports cited two conflicting numbers:
1. **9.09% (1/11)**: An early partial test against 3 samples with incomplete technique coverage.
2. **23.08% (3/13)**: A flawed test where `encoded_exec.py + getattr` inadvertently omitted the Base64 assignment, creating an artificial evasion.

Both previous numbers are **obsolete and superseded** by this comprehensive 50-experiment evaluation (10 malicious samples × 5 catalog techniques), utilizing the team's new **three-outcome scoring system**:
- **Recovered:** The analyzer detects the exact (category, indicator) of the original underlying malicious behavior.
- **Different Signal:** The detector fires on an obfuscation artifact (e.g. `base64.b64decode` or `exec`), but loses visibility into the underlying malicious call.
- **Missed:** The detector produces zero findings (complete evasion).

---

## 2. Overall Results

| Total Tests | Recovered (Original Behavior Caught) | Different Signal (Obfuscation Caught) | Missed (Complete Evasion) | Complete Evasion Rate |
| :---: | :---: | :---: | :---: | :---: |
| **50** | **26** (52.0%) | **16** (32.0%) | **8** (16.0%) | **16.0%** |

---

## 3. Results by Technique

| Technique ID | Technique Name | Total | Recovered | Different Signal | Missed (Evaded) | Missed Rate |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **T01** | String Splitting | 10 | 10 | 0 | 0 | 0.0% |
| **T02** | Base64 Encoding | 10 | 2 | 8 | 0 | 0.0% |
| **T03** | ROT13 Encoding | 10 | 2 | 8 | 0 | 0.0% |
| **T04** | getattr Indirection | 10 | 2 | 0 | 8 | 80.0% |
| **T05** | Delayed Trigger | 10 | 10 | 0 | 0 | 0.0% |

---

## 4. Key Security Insights

1. **`getattr` Indirection (T04) is the most critical evasion vulnerability**:
   - In 8 out of 10 samples (`compile`, `eval`, `eval_exec`, `exec`, `network_activity`, `subprocess_call`, `subprocess_popen`, `system_command`), resolving functions via `getattr(module, 'part' + 'part')` completely blinds the AST analyzer (`missed`).
   - In `install_time.py`, the `setuptools.command.install` class definition is still detected, but the internal `os.system` call is blinded.
   - In `encoded_exec.py`, the base64 assignment is still detected, while `exec` is hidden.

2. **Base64 (T02) and ROT13 (T03) create Signal Shift (`different_signal`)**:
   - The analyzer catches the `exec` or `base64.b64decode` wrapper, but **completely loses visibility into what payload was executed** (e.g. `os.system`, `socket.connect`, `subprocess.Popen`).
   - This proves why raw static AST rules fail in real-world scenarios: the malicious action is masked behind a generic execution primitive.

3. **String Splitting (T01) and Delayed Execution (T05) are reliably caught**:
   - AST analysis inspects call AST nodes directly; string concatenation inside call arguments or wrapping calls in counters does not prevent matching function name attributes.
