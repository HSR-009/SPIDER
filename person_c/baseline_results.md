# SPIDER Person C — Baseline Evasion Results (Historical / Superseded)

> [!NOTE]
> **SUPERSEDED BY OFFICIAL SPRINT BASELINE:**  
> The preliminary 9.09% (1/11) and 23.08% (3/13) exploratory numbers are obsolete.  
> The official, verified baseline evaluation across all 10 malicious samples using the team's three-outcome scoring system (`recovered`, `different_signal`, `missed`) is documented in:
> - [`results/evasion_baseline_v1.md`](../results/evasion_baseline_v1.md)
> - [`results/evasion_baseline_v1.json`](../results/evasion_baseline_v1.json)

---

## Historical Experiment (Exploratory / Week 1)

Static source transformations were applied to selected malicious toy samples and the transformed source was analyzed using Person A's AST analyzer.

No malicious sample was executed.

## Results (Preliminary 11-Test Matrix)

| Sample | Technique | Result |
|---|---|---|
| system_command.py | Base64 | Detected |
| system_command.py | ROT13 | Detected |
| system_command.py | getattr | Evasion Success |
| system_command.py | Delayed Trigger | Detected |
| system_command.py | String Split | Detected |
| subprocess_call.py | Base64 | Detected |
| subprocess_call.py | ROT13 | Detected |
| subprocess_call.py | Delayed Trigger | Detected |
| encoded_exec.py | Base64 | Detected |
| encoded_exec.py | ROT13 | Detected |
| encoded_exec.py | Delayed Trigger | Detected |

## Summary

- Applicable experiments: 11
- Evasion successes: 1
- Preliminary evasion rate: 9.09% (Superseded by `results/evasion_baseline_v1.md`)

## Key Finding

The `getattr`-based transformation bypassed the baseline AST detection rules in the tested case, while the other tested transformations remained detectable.

## Research Note

This result motivates a defense layer for indirect or dynamically reconstructed function calls. The baseline analyzer is retained unchanged so that robustness can be compared fairly after defense.
