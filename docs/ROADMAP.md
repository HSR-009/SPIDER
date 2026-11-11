# SPIDER Roadmap & Future Work

This document outlines planned development milestones, feature backlogs, and future architectural expansions for SPIDER beyond v1.0.

---

## 1. Machine Learning Model Integration

While SPIDER v1 relies strictly on frozen deterministic AST rules (`analyzer-v1.1`), the research pipeline developed in `Person_B/` establishes the foundations for ML integration:

- **Calibrated Malicious Probability**:
  - Integration of isotonic regression to calibrate raw booster probabilities.
  - Separate reporting with and without package file count (`n_py_files`) to control for size confounding (AUC ~0.79).
- **SHAP Explanation Visualizations**:
  - Exposing local TreeSHAP explanations alongside AST indicators in the UI (`/scanner/score`).
- **Ensemble Decision Thresholds**:
  - Dual-tier arbitration where strong AST rules (`S1`–`S5`) override model predictions to ensure high-precision detection.

---

## 2. Dynamic Analysis & Sandboxed Execution

Static analysis fundamentally cannot assess payloads whose behavior depends on dynamic imports, C extensions, or runtime environment variables:

- **Isolated Ephemeral Sandboxing**:
  - Integration with lightweight virtualization (e.g. gVisor, Firecracker, or Docker sandboxes) to safely trace package installation (`pip install --dry-run` and install hook traces).
- **Network Call Interception**:
  - Dynamic tracing of DNS requests and outbound HTTP traffic during package import.
- **System Call Auditing**:
  - Auditd / eBPF monitoring of filesystem modifications and process execution spawned from setup scripts.

---

## 3. Supply Chain Ecosystem Expansion

- **Dependency Graph Resolution**:
  - Recursive scanning of transitive dependencies declared in `requirements.txt`, `pyproject.toml`, and lockfiles (`poetry.lock`, `Pipfile.lock`).
- **PyPI Live Feed Monitoring**:
  - Continuous streaming consumer for new PyPI releases and index changelogs to flag newly registered suspicious packages in real time.
- **Typosquatting & Name-Squat Detection**:
  - Integration of Levenshtein string distance against top 5,000 PyPI packages to flag potential impersonation attacks.

---

## 4. Red Team & Prompt Injection Defense

- **MCP Tool Description Auditing**:
  - Static evaluation of docstrings and descriptions designed for LLM agent integration (MCP servers, LangChain tools) to detect indirect prompt injection and unauthorized command execution directives.
- **Expanded Obfuscation Deobfuscation**:
  - Automated normalization passes for dynamic `getattr`, `__import__` resolution, and layered string building before AST parsing.

