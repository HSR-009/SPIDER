# SPIDER Evasion Catalog (v1 Baseline)

This document formalizes the evasion techniques developed in the Adversarial Evasion Laboratory (Person C). Each technique is assigned a stable identifier (T01–T05) and documents the syntax transformation, underlying target behavior, and detection visibility against the AST analyzer.

---

## Catalog Index

| ID | Technique Name | Target Behavior Hidden | Visibility in Analyzer v1 |
|---|---|---|---|
| **T01** | String Splitting | Sensitive API / module / command string literals | **Visible** (Direct call remains intact; only argument string is split) |
| **T02** | Base64 Encoding | Entire executable code payload | **Wrapper Visible** (Wrapper's `b64decode` + `exec` flagged; payload unseen) |
| **T03** | ROT13 Encoding | Entire executable code payload | **Wrapper Visible** (Wrapper's `exec` flagged; payload unseen) |
| **T04** | `getattr` Dynamic Invocation | Function / method dispatch (`os.system`, `subprocess.run`) | **EVADED** (0% detected; AST rule only matches direct attribute calls) |
| **T05** | Delayed / Conditional Trigger | Deferred execution flow via counters / conditions | **Visible** (Syntax remains standard Python calls within blocks) |

---

## Detailed Specifications

### T01 — String Splitting
- **Mechanism**: Splits a sensitive string literal into random substrings of 1–3 characters and joins them via binary string addition (`+`).
- **Implementation**: `string_split_disguise(sensitive_word, seed=42)`
- **Example**:
  ```python
  # Original
  os.system("whoami")
  # Transformed
  os.system("wh" + "oa" + "mi")
  ```
- **Analysis Impact**: If the analyzer matches function names directly (e.g. `os.system`), this transform does not evade. It only hides argument-based sensitive paths or commands.

### T02 — Base64 Encoding
- **Mechanism**: Encodes the entire payload into standard Base64 ascii text, wrapping it in `base64.b64decode(...)` followed by `exec(...)`.
- **Implementation**: `base64_disguise(payload_code)`
- **Example**:
  ```python
  import base64
  encoded_data = 'aW1wb3J0IG9zOyBvcy5zeXN0ZW0oIndob2FtaSIp'
  decoded_code = base64.b64decode(encoded_data)
  exec(decoded_code)
  ```
- **Analysis Impact**: The analyzer flags the wrapper (`base64.b64decode` and `exec`), but the underlying malicious action (`os.system`) is completely masked from static AST inspection without normalization.

### T03 — ROT13 Encoding
- **Mechanism**: Encodes the payload using codecs ROT-13 reversible substitution, executed via `exec(codecs.decode(..., 'rot_13'))`.
- **Implementation**: `rot13_disguise(payload_code)`
- **Analysis Impact**: Flags the wrapper `exec`, but obfuscated payload is hidden from keyword and indicator matchers.

### T04 — `getattr` Dynamic Dispatch (Critical Gap)
- **Mechanism**: Reconstructs the target function name dynamically using fragmented string literals and accesses the module method via Python's built-in `getattr(module, function_name)`.
- **Implementation**: `getattr_disguise(module, func_name, args_code)`
- **Example**:
  ```python
  import os
  function_name = 'sy' + 'st' + 'em'
  getattr(os, function_name)("whoami")
  ```
- **Analysis Impact**: **100% Evasion Success against Analyzer v1.** The AST pattern `node.func.attr == "system"` fails because `node.func` is a `Call` to `getattr`, not an `Attribute`. Motivates the need for AST constant-folding and normalization in v1.1.

### T05 — Delayed / Conditional Trigger
- **Mechanism**: Wraps the target payload inside an iteration counter or deferred conditional block (`if counter >= 3:`).
- **Implementation**: `delay_disguise(payload_code, trigger_count=3)`
- **Analysis Impact**: The AST analyzer continues to flag AST nodes regardless of their control flow nesting level.
