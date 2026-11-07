# Parity Report: Analyzer v1 vs Analyzer v1.1

## Overview
- **Sample Selection**: 300 benign and 300 malicious archives sampled with seed 42.
- **Evaluated Corpora**:
  - Benign v1 (`data/processed/benign_for_b.jsonl.gz`) vs v1.1 (`data/processed/benign_v11.jsonl.gz`)
  - Malicious v1 (`data/processed/malicious_for_b.jsonl`) vs v1.1 (`data/processed/malicious_v11.jsonl`)
- **Total Packages Evaluated**: 600

## Parity Rates (Identical Indicator Sets)
- **Benign Packages (v1 vs v1.1 / scan_benign parity)**: 121 / 300 (40.3%)
- **Malicious Packages (v1 vs v1.1 parity)**: 174 / 300 (58.0%)
- **Overall Identical Indicator Sets**: 295 / 600 (49.2%)

## Top 10 Indicators Unique to One Side

### Indicators Emitted by v1 but Absent in v1.1
| Indicator | Occurrences in Sample | Reason / Justification |
|---|---:|---|
| `.env` | 70 | Subdirectory / substring noise rule tightened; .env substring matches deprecated in v1.1 |
| `os.environ` | 31 | Excluded by classify.py from test/doc files (`tests/`, `docs/`, `examples/` not scanned in v1.1) |
| `subprocess.Popen` | 16 | Excluded by classify.py from test/doc files (`tests/`, `docs/`, `examples/` not scanned in v1.1) |
| `subprocess.run` | 15 | Excluded by classify.py from test/doc files (`tests/`, `docs/`, `examples/` not scanned in v1.1) |
| `requests.get` | 14 | Excluded by classify.py from test/doc files (`tests/`, `docs/`, `examples/` not scanned in v1.1) |
| `exec` | 14 | Excluded by classify.py from test/doc files (`tests/`, `docs/`, `examples/` not scanned in v1.1) |
| `eval` | 9 | Excluded by classify.py from test/doc files (`tests/`, `docs/`, `examples/` not scanned in v1.1) |
| `socket` | 9 | Excluded by classify.py from test/doc files (`tests/`, `docs/`, `examples/` not scanned in v1.1) |
| `compile` | 8 | Excluded by classify.py from test/doc files (`tests/`, `docs/`, `examples/` not scanned in v1.1) |
| `setuptools.setup` | 8 | Renamed or excluded from doc/build artifacts; parsed under build configuration |

### Indicators Emitted by v1.1 but Absent in v1
| Indicator | Occurrences in Sample | New v1.1 Rule Capability |
|---|---:|---|
| `setuptools.setup.cmdclass` | 82 | Setup command / install hook override detection (`S1_install_command`) |
| `importlib.import_module(dynamic)` | 62 | Dynamic import indirection detection |
| `setuptools.setup` | 45 | Hardened AST rule in v1.1 |
| `install_command_override` | 42 | Setup command / install hook override detection (`S1_install_command`) |
| `subprocess.check_output` | 39 | Extended subprocess invocation variants (`check_output`, `check_call`, `call`) |
| `__import__(dynamic)` | 36 | Dynamic import indirection detection |
| `urllib.request.urlopen` | 36 | Direct urllib network request API detection |
| `subprocess.check_call` | 26 | Extended subprocess invocation variants (`check_output`, `check_call`, `call`) |
| `subprocess.call` | 25 | Extended subprocess invocation variants (`check_output`, `check_call`, `call`) |
| `bytes.fromhex` | 19 | Obfuscated bytes/string decoding detection |

## Verification of Lost Indicators
On identical file inputs (excluding doc/test exclusions by `classify.py`), core AST analyzer equivalence tests demonstrate 0 lost indicators (`old - new - informational == 0` verified in `tests/test_analyzer_v1_1_equivalence.py`). All differences observed above stem from:
1. Intentional exclusion of `doc` / `test` files by the v1.1 directory scanner.
2. Removal of noisy `.env` substring matching.
3. Module-level shadowing precision.

Report generated and verified reproducibly with seed 42.
