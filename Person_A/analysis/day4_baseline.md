# Day 4 — A ↔ C Baseline Test

## Original Sample

`encoded_exec.py`

## Baseline Analyzer Findings

| Category | Indicator | Severity |
|---|---|---|
| Obfuscation | base64.b64decode | MEDIUM |
| Dynamic Code Execution | exec | HIGH |

## Purpose

This baseline will be used by Person C when applying defined evasion
techniques to the sample.

C should compare the modified sample against this original result and
record which indicators remain detectable and which disappear.

## Expected Label

Malicious (`1`)