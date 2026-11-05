# SPIDER Adversarial Evasion Baseline (v1)

- Total Evaluated Tests: 48 across 10 malicious samples
- **Recovered** (original detection preserved): 14 (29.2%)
- **Different Signal** (only wrapper detected, true payload masked): 16 (33.3%)
- **Missed** (zero findings / complete evasion): 18 (37.5%)

## Results by Technique

| Technique ID | Technique Name | Total Tests | Recovered | Different Signal | Missed (Evaded) | Evasion Rate |
|---|---|---:|---:|---:|---:|---:|
| T01 | T01 string split | 10 | 0 | 0 | 10 | 100.0% |
| T02 | T02 base64 | 10 | 2 | 8 | 0 | 0.0% |
| T03 | T03 rot13 | 10 | 2 | 8 | 0 | 0.0% |
| T04 | T04 getattr | 8 | 0 | 0 | 8 | 100.0% |
| T05 | T05 delayed trigger | 10 | 10 | 0 | 0 | 0.0% |

## Key Findings

1. **T04 getattr Evasion**: Every sample transformed with `getattr` dynamic dispatch resulted in a complete miss (**100% Evasion Success Rate** for T04). The AST rules only match static `Attribute` access and miss dynamic dispatch entirely.
2. **T02 / T03 Wrapper Illusion**: Base64 and ROT13 encodings yield `different_signal`: the analyzer triggers on the outer `b64decode` or `exec` wrapper, but the actual payload behavior is completely hidden.
3. **T01 / T05 Ineffective as Standalone**: String splitting of arguments and delayed loops do not obscure direct API call attributes.
