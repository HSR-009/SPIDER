# SPIDER — Day 6 Dataset Note

## Dataset and scan

The local malicious PyPI corpus was previously measured at 4,336 files across 2,046 package-version folders. The completed scan output contains 2045 package-version records and 2045 unique package IDs.

- PyPI index records: 6,428
- Scan records marked in-index: 2040 (99.8% of scan output, where applicable)
- Scan records not matched to index: 5
- Python files attempted / scanned: 28171 / 28171
- Total findings: 25299
- Records with zero findings: 156
- Records marked failed: 0
- Records marked index-annotated: 154

## Output integrity

The completed checks found unique package IDs and consistent finding totals. All 28171 attempted Python files are accounted for as scanned. No rows were marked as failed static analysis.

## Coverage caveat

The scan is based on the locally available corpus. It does not cover all 6,428 PyPI index records, and the 5 local-only output records should not be counted as index matches. No claim about detection specificity or false-positive rate can be made from a malicious-only scan.

## Day 6: Manual Spot-Check Results

Four additional read-only package tests were completed.

| Package | Findings | In index | Index annotated | Static analysis failed |
|---|---:|---|---|---|
| 7miners@2.33.0 | 151 | Yes | No | No |
| 1000pip-climber-system-free-download@1000pip climber system free download-1 | 0 | Yes | No | No |
| 10cent11@999.0.4 | 3 | Yes | Yes | No |
| libhtml5@root | 0 | No | No | No |

Previously checked packages: pillwo, 10cent10, aadhaarcrypt.

### Observed limitations
- The 7miners result includes many network and credential-access indicators in library and test files. These are static indicators and do not establish malicious intent; potential false positives require further evaluation.
- A zero-finding result does not establish that a package is benign.
- libhtml5@root was not matched to the package index. Its zero-finding result should not be interpreted as a safety verdict.
- These package tests ran in read-only mode and did not modify the full-scan output.

### Day 6 status
Full scan, output integrity checks, documentation, and seven package spot-checks completed. Spot-check results were not merged into the full-scan JSONL.
