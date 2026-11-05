# SPIDER Evasion Catalog (T01–T05)
**Author:** Person C (Jeet Dave)  
**Role:** Evasion, Defense & Dashboard  
**Status:** Active Sprint Standard (7-Day Sprint Plan, Day 1)  
**Baseline Evaluation Reference:** [`results/evasion_baseline_v1.md`](../results/evasion_baseline_v1.md)

---

## 1. Overview and Core Research Objective

In SPIDER, malicious package detection is evaluated under the paradigm:
```
DETECT → ATTACK/EVASION → DEFEND → RE-TEST
```
The goal of this evasion catalog is not merely to alter source code appearance, but to systematically test whether controlled static transformations cause our AST-based analyzer (`analyzer.py`) to lose visibility into known malicious primitives.

### Strict Safety Boundaries
- **No Malicious Execution:** Transformed samples are analyzed as static source text or parsed via Python AST. Untrusted code is never executed directly.
- **Harmless Markers in Equivalence Tests:** Any functional testing uses benign marker prints (`print("MARKER_...")`), with zero network, filesystem, or process spawning.
- **AST Pre-flight:** An AST validator rejects any dangerous calls before subprocess testing.

---

## 2. Three-Outcome Detection Scoring

Each transformation applied to a known malicious sample produces one of three distinct outcomes against the detector:

1. **`recovered`**: The detector identifies the exact same `(category, indicator)` as the baseline sample.
2. **`different_signal`**: The detector fires on an obfuscation/wrapper artifact (e.g. `base64.b64decode` or `exec`), but loses visibility into the underlying malicious call.
3. **`missed`**: The detector produces zero security findings (`[]`), representing a complete evasion.

---

## 3. The Catalog: Techniques T01–T05

### T01: String Splitting / Concatenation
- **Stable ID:** `T01`
- **Name:** String Splitting and Concatenation
- **Implementation:** `Person_c/disguises.py::string_split_disguise(sensitive_word, seed=42)`
- **Target Behavior It Hides:** Conceals sensitive literal strings (e.g., `"whoami"`, `"os.system"`, hostnames, file paths) from naive regex, string grep, or keyword search.
- **Harmless Source Example:**
  ```python
  import os
  os.system("whoami")
  ```
- **Transformed Code:**
  ```python
  import os
  os.system('w' + 'ho' + 'a' + 'mi')
  ```
- **Expected Analyzer Behavior:**
  - `recovered`: Person A's AST analyzer inspects `Call.func` (`os.system`) directly, rather than matching on string arguments. The AST call structure remains intact, so `os.system` is reliably detected.
- **Empirical Baseline Result:** 10 / 10 Recovered (0% Missed).
- **Limitations:** Does not bypass AST call-node rules unless the function identifier itself is split and resolved dynamically (see T04).

---

### T02: Base64 Payload Encoding
- **Stable ID:** `T02`
- **Name:** Base64 Payload Encoding and Dynamic Execution
- **Implementation:** `Person_c/disguises.py::base64_disguise(payload_code)`
- **Target Behavior It Hides:** Hides arbitrary command execution, socket connections, or environment access inside an opaque base64 string literal.
- **Harmless Source Example:**
  ```python
  import os
  os.system("whoami")
  ```
- **Transformed Code:**
  ```python
  import base64
  encoded_data = 'aW1wb3J0IG9zCgpvcy5zeXN0ZW0oIndob2FtaSIp'
  decoded_code = base64.b64decode(encoded_data)
  exec(decoded_code)
  ```
- **Expected Analyzer Behavior:**
  - `different_signal`: The analyzer detects `base64.b64decode` (Obfuscation) and `exec` (Dynamic Code Execution). However, it **loses visibility** into the underlying `os.system` (Command Execution).
- **Empirical Baseline Result:** 8 / 10 Different Signal, 2 / 10 Recovered (0% Missed, 80% Signal Shift).
- **Limitations:** Introduces explicit high-entropy indicator calls (`base64.b64decode`, `exec`) that flag the sample as suspicious or obfuscated.

---

### T03: ROT13 Payload Encoding
- **Stable ID:** `T03`
- **Name:** ROT13 Encoding and Dynamic Execution
- **Implementation:** `Person_c/disguises.py::rot13_disguise(payload_code)`
- **Target Behavior It Hides:** Reversible substitution cipher masking payload source text without standard binary encoding headers.
- **Harmless Source Example:**
  ```python
  import subprocess
  subprocess.run(["whoami"])
  ```
- **Transformed Code:**
  ```python
  import codecs
  encoded_data = 'vzcbeg fhocebprff\n\nfhocebprff.eha(["jxbav"])'
  decoded_code = codecs.decode(encoded_data, 'rot_13')
  exec(decoded_code)
  ```
- **Expected Analyzer Behavior:**
  - `different_signal`: The baseline analyzer detects `exec` (Dynamic Code Execution), but does not detect `subprocess.run`.
- **Empirical Baseline Result:** 8 / 10 Different Signal, 2 / 10 Recovered (0% Missed, 80% Signal Shift).
- **Limitations:** Calls `exec()`, which is a high-severity indicator in SPIDER's taxonomy.

---

### T04: `getattr` Dynamic Indirection
- **Stable ID:** `T04`
- **Name:** Dynamic Attribute Access via `getattr()`
- **Implementation:** `Person_c/disguises.py::getattr_disguise(module, func_name, args_code)`
- **Target Behavior It Hides:** Conceals direct function calls (`os.system`, `subprocess.run`, `socket.socket`, `exec`, `eval`) from AST call-attribute matchers.
- **Harmless Source Example:**
  ```python
  import os
  os.system("whoami")
  ```
- **Transformed Code:**
  ```python
  import os
  function_name = 'sy' + 'st' + 'em'
  getattr(os, function_name)("whoami")
  ```
- **Expected Analyzer Behavior:**
  - `missed`: Because `node.func` is a `getattr` Call node rather than an `Attribute` node matching `node.func.attr == 'system'`, the baseline analyzer fails to match the rule and emits zero findings.
- **Empirical Baseline Result:** 8 / 10 Missed (80% Evasion Success Rate).
- **Defense Implication:** Directly motivates the Day 4 normalization defense (`spider/normalize.py`) to resolve `getattr(obj, "literal")` into attribute access prior to AST rule evaluation.

---

### T05: Delayed / Conditional Trigger Execution
- **Stable ID:** `T05`
- **Name:** Counter-Based Delayed Trigger Execution
- **Implementation:** `Person_c/disguises.py::delay_disguise(payload_code, trigger_count=3)`
- **Target Behavior It Hides:** Intended to evade dynamic sandboxes by executing only after multiple invocations or specific runtime environmental checks.
- **Harmless Source Example:**
  ```python
  import os
  os.system("whoami")
  ```
- **Transformed Code:**
  ```python
  counter = 0
  counter += 1
  if counter >= 3:
      import os
      os.system("whoami")
  ```
- **Expected Analyzer Behavior:**
  - `recovered`: Static AST traversal walks all nodes inside `If` bodies regardless of condition values. The underlying `os.system` call is located and detected identically to baseline.
- **Empirical Baseline Result:** 10 / 10 Recovered (0% Missed).
- **Limitations:** Ineffective against static AST analysis; primarily targets dynamic analysis sandboxes.

---

## 4. Summary Matrix across 10 Baseline Malicious Samples

| Technique | Recovered (Original Caught) | Different Signal (Obfuscation Caught) | Missed (Evaded) | Primary Defense Opportunity |
| :--- | :---: | :---: | :---: | :--- |
| **T01 String Split** | 100% | 0% | 0% | Constant folding |
| **T02 Base64** | 20% | 80% | 0% | Static base64 decoding |
| **T03 ROT13** | 20% | 80% | 0% | Static decode folding |
| **T04 getattr** | 20% | 0% | **80%** | `getattr` attribute normalization |
| **T05 Delayed** | 100% | 0% | 0% | Static control-flow inspection |
