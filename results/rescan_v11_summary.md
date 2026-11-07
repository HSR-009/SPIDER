# SPIDER Corpora Rescan v1.1 Summary Report

This report provides a comparison of static signals and verdict distributions between the malicious and benign corpora under analyzer v1.1 and Verdict v2.

## Overview Metrics

| Metric | Malicious (`malicious_v11.jsonl`) | Benign (`benign_v11.jsonl.gz`) |
|---|---|---|
| **Total Packages** | 2039 | 2909 |
| **% Suspicious** | 32.6% | 12.0% |
| **% Review Recommended (among none detected)** | 55.9% | 44.1% |
| **% Unable to Assess** | 2.1% | 6.3% |
| **Median Analyzed `.py` Files** | 2 | 12 |
| **Suspicious Rate (Small Packages, $\le$5 `.py`)** | 30.6% | 1.2% |
| **Suspicious Rate (Larger Packages, >5 `.py`)** | 41.5% | 17.1% |

## Strong Signals Distribution (S1 to S5)

| Signal ID | Description | Malicious % | Benign % |
|---|---|---|---|
| `S1_install_command` | Install hook override | 19.4% | 0.9% |
| `S2_dynamic_exec_plus` | Dynamic execution + network/obfuscation | 8.1% | 9.6% |
| `S3_credential_net` | Credential path + network activity | 2.8% | 1.8% |
| `S4_env_post` | `os.environ` + `requests.post` | 6.2% | 2.4% |
| `S5_decode_exec` | base64 decode + exec/eval | 4.6% | 6.1% |
| `s2_same_file` | Dynamic execution + net/obf in same file | 7.1% | 1.7% |

## Discriminative Power (ROC-AUC)

- **Package Size (`n_py_files`) ROC-AUC**: 0.2094
- **Finding Count (`n_findings`) ROC-AUC**: 0.5635

## Top Unable-to-Assess Coverage Reasons

- **Malicious**: [('uninspected_ratio', 29), ('parse_failure_ratio', 14)]
- **Benign**: [('uninspected_ratio', 161), ('parse_failure_ratio', 25), ('limits_hit', 1)]

## Corpus & Holdout Coverage

| Class | Total v1 Packages | Missing from v1.1 | Total Holdout Packages | Missing from Holdout |
|---|---|---|---|---|
| **Malicious** | 2045 | 6 | 409 | 0 |
| **Benign** | 2908 | 0 | 582 | 0 |

**First missing Malicious v1 IDs** (up to 10): libhtml5==root, mateplotlib==root, nmap-python==root, numipy-openvc==aaa.bbb.ccc, numipy==root, openvc==root

> [!NOTE]
> These rates represent static signal co-occurrence, not model accuracy. Size remains a confound: size-only AUC is 0.2094, i.e. about 0.79 read in the other direction (median analyzed .py files: 2 malicious vs 12 benign). Excluding tests/docs did not remove it, so report ML metrics with and without n_py_files. S2 and S5 fire as often on benign as on malicious.
