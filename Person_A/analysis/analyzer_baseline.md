# SPIDER AST Analyzer — Baseline for Adversarial Testing

## Purpose

This document defines the baseline behavior of Person A's AST analyzer
before adversarial/evasion transformations are applied.

Person C should use this baseline when testing whether defined evasion
techniques cause security indicators to disappear.

## Analyzer Input

Python source files.

## Analyzer Output

Each detected finding contains:

- category
- indicator
- severity
- file
- line
- evidence

## Current Security Categories

- Command Execution
- Dynamic Code Execution
- Credential / Data Access
- Network Activity
- Obfuscation
- Install-Time / Package Execution
- Supply-Chain Abuse

## Baseline Toy Samples

Malicious samples currently available:

- `system_command.py`
- `subprocess_call.py`
- `subprocess_popen.py`
- `eval.py`
- `exec.py`
- `compile.py`
- `eval_exec.py`
- `encoded_exec.py`
- `network_activity.py`
- `install_time.py`

Clean samples currently available:

- `calculator.py`
- `file_reader.py`
- `hello.py`
- `legitimate_base64.py`
- `legitimate_subprocess.py`

Edge-case analyzer fixtures are stored separately under:

`data/toy_samples/edge_cases/`

## Important Testing Rule

Person C should preserve the original malicious sample identifier when
creating an adversarial version.

The expected malicious label remains:

`1 = malicious`

The purpose of adversarial testing is to determine whether the same
underlying malicious behavior becomes less visible to the AST analyzer.

## Current Baseline Limitations

The analyzer performs:

- Python AST parsing
- security-rule matching
- categorized findings

It does not perform:

- sandbox execution
- bytecode analysis
- symbolic execution