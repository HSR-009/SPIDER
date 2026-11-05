# SPIDER v1.1 Rule Specification — Evidence-Driven Draft

## Status

Proposal only. Analyzer v1 remains frozen. No rule changes are authorized by this document.

## Evidence from the current baseline

The current benign corpus contains 2,908 package-version rows from 1,468 package names. The malicious export contains 2,045 package-version rows from 1,186 package names.

| Indicator | Malicious prevalence | Benign prevalence | Prevalence ratio |
|---|---:|---:|---:|
| setuptools.command.install | 19.32% | 0.76% | 25.53x |
| requests.post | 17.75% | 3.61% | 4.92x |
| os.system | 10.22% | 3.82% | 2.68x |
| os.environ | 23.72% | 48.11% | 0.49x |
| eval | 3.33% | 11.93% | 0.28x |

These are baseline prevalence comparisons, not accuracy estimates. The benign corpus is assumed benign based on selection and has not been independently audited.

## Proposed changes to investigate

1. Treat plain setuptools.setup() as informational context, not an independent high-risk signal.
2. Preserve custom install-command detection as a separate, higher-value indicator.
3. Do not treat os.environ access, eval, exec, compile, Base64, or network access alone as proof of malicious intent.
4. Reduce duplicate-finding inflation in downstream features by distinguishing indicator presence per package version from raw occurrence counts.
5. Investigate context-sensitive combinations, such as credential access plus outbound network activity, rather than raising risk from a single broad API.
6. Add separate lightweight metadata features for package-name similarity, encoded-string characteristics, empty packages, and non-Python artifacts. Clearly label these as outside the AST analyzer.
7. Keep parse failure as an analysis-status feature, not a malicious behavior category.

## Required validation before implementation

- Verify severity constants and rule parity between analyzer.py and scan_benign.py.
- Manually review high-signal benign examples and representative malicious examples.
- Report malicious and benign denominators for every indicator.
- Measure benign false-positive rates on an independently reviewed subset before choosing thresholds.
- Evaluate with package-name-grouped splits to prevent version leakage.

## Known limitations

The current AST rules can miss indirect calls such as getattr and __import__, constructed strings using chr, encoded payloads, and behavior hidden in compiled or non-Python artifacts. These are investigation targets, not claims that a proposed rule already detects them.
