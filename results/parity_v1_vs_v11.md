# Parity Report: Analyzer v1 vs scan_benign vs v1.1

## Summary
- **Archives Evaluated**: 300 benign, 300 malicious (sampled seed 42).
- **Percentage of benign packages where v1 equals scan_benign**: 98.7% (296 / 300).
- **Percentage of benign packages where v1 equals v1.1**: 46.7% (140 / 300).
- **Percentage of malicious packages where v1 equals v1.1**: 62.7% (188 / 300).
- **Total analyzer exceptions encountered**: 7.

### Analyzer Exceptions Encountered
| Analyzer | File | Error |
|---|---|---|
| `v1` | `._setup.py` | `UnicodeDecodeError: 'utf-8' codec can't decode byte 0xe0 in position 37: invalid continuation byte` |
| `v1` | `polaris/._plugin_manager.py` | `UnicodeDecodeError: 'utf-8' codec can't decode byte 0xa8 in position 37: invalid start byte` |
| `v1` | `polaris/.___init__.py` | `UnicodeDecodeError: 'utf-8' codec can't decode byte 0xa8 in position 37: invalid start byte` |
| `v1` | `polaris/pkg/.___init__.py` | `UnicodeDecodeError: 'utf-8' codec can't decode byte 0xa8 in position 37: invalid start byte` |
| `v1` | `polaris/plugin_abc/.___init__.py` | `UnicodeDecodeError: 'utf-8' codec can't decode byte 0xa8 in position 37: invalid start byte` |
| `v1` | `polaris/api/.___init__.py` | `UnicodeDecodeError: 'utf-8' codec can't decode byte 0xa8 in position 37: invalid start byte` |
| `v1` | `num2words-0.5.15/num2words/_build.py` | `UnicodeDecodeError: 'utf-8' codec can't decode byte 0x90 in position 2: invalid start byte` |

## Top Indicators Found by Only One Side (v1 vs scan_benign on Benign)

### In v1 but not scan_benign
| Indicator | Count |
|---|---:|
| `urllib.request.urlopen` | 4 |

### In scan_benign but not v1
| Indicator | Count |
|---|---:|

## Indicators Lost by v1.1 vs v1 (Per-Class Classification)
| Indicator | Benign Lost (Classification Breakdown) | Malicious Lost (Classification Breakdown) | Examples |
|---|---|---|---|
| `.env` | 93 (unclassified: 93) | 9 (unclassified: 9) | google-cloud-dataproc__5.32.0__google_cloud_dataproc-5.32.0.tar.gz, google-cloud-dataproc__5.32.0__google_cloud_dataproc-5.32.0.tar.gz, google-cloud-dataproc__5.32.0__google_cloud_dataproc-5.32.0.tar.gz |
| `.netrc` | 2 (unclassified: 2) | 0 (0) | obstore__0.9.4__obstore-0.9.4.tar.gz, databricks-sdk__0.156.0__databricks_sdk-0.156.0.tar.gz |
| `compile` | 7 (unclassified: 7) | 0 (0) | strictyaml__1.7.3__strictyaml-1.7.3.tar.gz, textual__0.56.1__textual-0.56.1.tar.gz, textual__0.56.1__textual-0.56.1.tar.gz |
| `setuptools.setup` | 15 (unclassified: 15) | 0 (0) | patchelf__0.16.1.0__patchelf-0.16.1.0.tar.gz, scikit-image__0.10.0__scikit-image-0.10.0.tar.gz, scikit-image__0.10.0__scikit-image-0.10.0.tar.gz |

## New Indicators Emitted in v1.1
| Indicator | Benign Count | Malicious Count |
|---|---:|---:|
| `importlib.import_module(dynamic)` | 48 | 20 |
| `setuptools.setup.cmdclass` | 29 | 39 |
| `setuptools.setup` | 37 | 12 |
| `install_command_override` | 3 | 35 |
| `join(chr)` | 14 | 18 |
| `__import__(dynamic)` | 27 | 5 |
| `urllib.request.urlopen` | 16 | 15 |
| `subprocess.check_output` | 16 | 12 |
| `subprocess.call` | 21 | 4 |
| `bytes.fromhex` | 11 | 13 |
| `subprocess.check_call` | 16 | 5 |
| `getattr.dynamic` | 13 | 0 |
| `custom_build_backend` | 9 | 1 |
| `os.popen` | 0 | 7 |
| `subprocess.Popen` | 5 | 0 |