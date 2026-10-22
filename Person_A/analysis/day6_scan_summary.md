# SPIDER — Real Malicious Dataset Scan Summary

Generated: 2026-10-20 09:25

## Denominators and scan totals

- Output package-version records: 2045
- Unique package IDs: 2045
- Records with at least one scanned Python file: 2027
- Records with zero findings: 156 (7.6%)
- Records marked `failed_static_analysis`: 0
- Records matched to the index: 2040 (99.8%)
- Records marked index-annotated: 154
- Python files scanned / attempted: 28171 / 28171
- Total findings: 25299

## Package-versions showing each category

| Category | Package-versions | % of output records | Finding instances |
|---|---:|---:|---:|
| Install-Time / Package Execution | 1429 | 69.9% | 1848 |
| Network Activity | 895 | 43.8% | 9905 |
| Command Execution | 815 | 39.9% | 5078 |
| Credential / Data Access | 531 | 26.0% | 6299 |
| Obfuscation | 449 | 22.0% | 1641 |
| Dynamic Code Execution | 219 | 10.7% | 462 |
| Parse Error | 37 | 1.8% | 66 |

## Top indicators

| Indicator | Finding instances |
|---|---:|
| os.environ | 4960 |
| requests.post | 4704 |
| requests.get | 4308 |
| subprocess.run | 2926 |
| os.system | 1493 |
| setuptools.setup | 1453 |
| .env | 1151 |
| base64.b64decode | 886 |
| subprocess.Popen | 659 |
| base64.b64encode | 571 |
| urllib.request.urlopen | 501 |
| setuptools.command.install | 395 |
| socket | 345 |
| exec | 208 |
| eval | 195 |

## Severity split

| Severity | Finding instances |
|---|---:|
| HIGH | 13687 |
| MEDIUM | 11612 |

## Interpretation and limitations

- This scan covers the available local malicious PyPI corpus, not every PyPI index entry.
- The index contains 6,428 PyPI records; output records marked in-index are a subset of that corpus.
- Five output records were previously found not to match the index. They may be local-only packages.
- This is a malicious-only corpus. These results do not establish benign-versus-malicious discrimination or false-positive rates.
- Zero recorded analysis failures means no failures were recorded by this run; it does not independently prove every index entry or every possible payload was covered.
- Category percentages use output package-version records as the denominator. A package-version is counted once per category even if it has multiple findings in that category.
