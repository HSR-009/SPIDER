# SPIDER Shared Interfaces

## Purpose

This document defines the interfaces between the security analysis,
machine learning, and adversarial testing components.

---

## A → B: Security Analyzer Output

Person A's AST analyzer produces categorized security findings from Python
source code.

Each finding should contain:

- `category` — security category
- `indicator` — specific security indicator detected
- `file` — source file where it was detected
- `line` — line number of the finding
- `evidence` — short description of what was detected

Example:

```text
category: Command Execution
indicator: os.system
file: sample.py
line: 4
evidence: os.system() call detected