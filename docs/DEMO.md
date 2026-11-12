# SPIDER Live Demonstration Guide

This guide walks through evaluating SPIDER end-to-end using real fixtures, CLI commands, and the interactive web interface.

---

## 1. Setup & Environment Verification

Verify dependencies and run the complete test suite:

```bash
# Activate your environment
source .venv/bin/activate  # Or on Windows: .venv\Scripts\Activate.ps1

# Run offline unit test discover
python -m unittest discover -s tests
```
*Expected: 240+ tests run cleanly without network access.*

---

## 2. CLI Demonstrations

### Scenario A: Suspicious Install Hook Override (Malicious Package)
Scan a sample package that overrides `setuptools.command.install` to execute arbitrary shell commands:

```bash
python -m spider scan fixtures/src/demo-installhook
```
*Expected Output:*
- Verdict: `suspicious`
- Triggered signals: `S1_install_command`
- Exit Code: `10`

### Scenario B: Benign HTTP Client Package
Scan a standard HTTP client library implementation:

```bash
python -m spider scan fixtures/src/demo-httpclient
```
*Expected Output:*
- Verdict: `none_detected_in_this_scan`
- Exit Code: `0`
- Reminder: *"Static analysis only: 'none detected in this scan' does not mean the package is safe."*

### Scenario C: Uninspectable Target Handling
Scan an empty directory or invalid non-Python folder:

```bash
python -m spider scan fixtures/empty_dir
```
*Expected Output:*
- Verdict: `unable_to_assess`
- Reason: `nothing_inspected`
- Exit Code: `20`

### Scenario D: Missing Environment Argument Error Handling
Test clean error handling when targeting a non-existent site-packages folder:

```bash
python -m spider hunt --site-packages /path/that/does/not/exist
```
*Expected Output:*
- Clean single-line error message (no stack trace)
- Exit Code: `2`

---

## 3. Interactive UI Demonstration

Launch the local web dashboard:

```bash
python -m spider serve
```
Navigate to `http://127.0.0.1:8000`:

1. **Welcome Screen (`/`)**: Overview of SPIDER philosophy, 3-way verdict policy, and 3D architectural canvas.
2. **Tool Hub (`/hub`)**: Quick access to Scanner, Hunter, History, Research Lab, and Red Team benches.
3. **Scan Execution (`/scanner/scan`)**:
   - Drag and drop any archive (`.tar.gz`, `.zip`, `.whl`) or specify a local path.
   - Click Scan to observe live extraction and AST rule evaluation.
4. **Scan Evidence (`/scanner/evidence`)**: Inspect the line-by-line syntax spans, category tags, and context evidence.
5. **Score Page (`/scanner/score`)**: Review the model connection status and roadmap notes.
6. **Hunter Report (`/hunter/report`)**:
   - View inspected environments and detected persistence artifacts (`.pth` files, entry point mismatches).
   - High-severity items appear expanded; low-severity items are collapsed with package counts.
7. **Research Results (`/research`)**: Review verified corpus statistics, Wilson confidence intervals, and known engine limits.

