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

## Parse Errors

`Parse Error` is not a security category.

If the AST analyzer cannot parse a Python file, it produces a `Parse Error`
finding so the analyzer does not crash.

Person B must not count `Parse Error` as a security-category finding.

Instead, it should be represented separately as:

`failed_static_analysis = 1`

when building ML features.

The normal security categories remain the seven categories defined in the
security taxonomy.