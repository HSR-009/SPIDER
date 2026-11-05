# Indicator Discrimination — SPIDER

## Dataset scope

- Malicious package-version rows: 2045
- Benign package-version rows: 2908
- Unique malicious package names: 1186
- Unique benign package names: 1468
- Unit of analysis: package-version row; an indicator counts once per row.
- These are baseline prevalence comparisons, not accuracy or causal evidence.

## Category prevalence

| Category | Malicious rows | Malicious % | Benign rows | Benign % | Prevalence ratio |
|---|---:|---:|---:|---:|---:|
| Command Execution | 816 | 39.90% | 750 | 25.79% | 1.55x |
| Credential / Data Access | 531 | 25.97% | 1468 | 50.48% | 0.51x |
| Dynamic Code Execution | 219 | 10.71% | 754 | 25.93% | 0.41x |
| Install-Time / Package Execution | 1429 | 69.88% | 1549 | 53.27% | 1.31x |
| Network Activity | 895 | 43.77% | 510 | 17.54% | 2.50x |
| Obfuscation | 449 | 21.96% | 724 | 24.90% | 0.88x |

## Static-analysis status

| Dataset | Package-version rows | Rows marked failed_static_analysis | Rows with parse errors |
|---|---:|---:|---:|
| Malicious | 2045 | 38 | 38 |
| Benign | 2908 | 171 | 171 |

Parse errors are analysis-status information, not behavioral indicators.
Rows with parse errors may still contain findings from other files.

## Indicator prevalence

| Category :: Indicator | Malicious rows | Malicious % | Benign rows | Benign % | Prevalence ratio |
|---|---:|---:|---:|---:|---:|
| Command Execution :: os.system | 209 | 10.22% | 111 | 3.82% | 2.68x |
| Command Execution :: subprocess.Popen | 413 | 20.20% | 449 | 15.44% | 1.31x |
| Command Execution :: subprocess.run | 349 | 17.07% | 403 | 13.86% | 1.23x |
| Credential / Data Access :: .aws/credentials | 30 | 1.47% | 15 | 0.52% | 2.84x |
| Credential / Data Access :: .env | 209 | 10.22% | 475 | 16.33% | 0.63x |
| Credential / Data Access :: .netrc | 32 | 1.56% | 36 | 1.24% | 1.26x |
| Credential / Data Access :: .ssh/ | 29 | 1.42% | 52 | 1.79% | 0.79x |
| Credential / Data Access :: os.environ | 485 | 23.72% | 1399 | 48.11% | 0.49x |
| Dynamic Code Execution :: compile | 41 | 2.00% | 289 | 9.94% | 0.20x |
| Dynamic Code Execution :: eval | 68 | 3.33% | 347 | 11.93% | 0.28x |
| Dynamic Code Execution :: exec | 156 | 7.63% | 545 | 18.74% | 0.41x |
| Install-Time / Package Execution :: setuptools.command.install | 395 | 19.32% | 22 | 0.76% | 25.53x |
| Install-Time / Package Execution :: setuptools.setup | 1418 | 69.34% | 1547 | 53.20% | 1.30x |
| Network Activity :: requests.get | 458 | 22.40% | 247 | 8.49% | 2.64x |
| Network Activity :: requests.post | 363 | 17.75% | 105 | 3.61% | 4.92x |
| Network Activity :: requests.request | 27 | 1.32% | 36 | 1.24% | 1.07x |
| Network Activity :: socket | 117 | 5.72% | 309 | 10.63% | 0.54x |
| Network Activity :: urllib.request.urlopen | 278 | 13.59% | 0 | 0.00% | infinite (zero benign rows) |
| Obfuscation :: base64.a85decode | 0 | 0.00% | 3 | 0.10% | 0.00x |
| Obfuscation :: base64.a85encode | 0 | 0.00% | 4 | 0.14% | 0.00x |
| Obfuscation :: base64.b16decode | 1 | 0.05% | 16 | 0.55% | 0.09x |
| Obfuscation :: base64.b16encode | 0 | 0.00% | 17 | 0.58% | 0.00x |
| Obfuscation :: base64.b32decode | 7 | 0.34% | 12 | 0.41% | 0.83x |
| Obfuscation :: base64.b32encode | 14 | 0.68% | 22 | 0.76% | 0.90x |
| Obfuscation :: base64.b32hexdecode | 0 | 0.00% | 1 | 0.03% | 0.00x |
| Obfuscation :: base64.b32hexencode | 0 | 0.00% | 1 | 0.03% | 0.00x |
| Obfuscation :: base64.b64decode | 318 | 15.55% | 435 | 14.96% | 1.04x |
| Obfuscation :: base64.b64encode | 226 | 11.05% | 533 | 18.33% | 0.60x |
| Obfuscation :: base64.b85decode | 9 | 0.44% | 5 | 0.17% | 2.56x |
| Obfuscation :: base64.b85encode | 0 | 0.00% | 4 | 0.14% | 0.00x |
| Obfuscation :: base64.decode | 0 | 0.00% | 1 | 0.03% | 0.00x |
| Obfuscation :: base64.decodebytes | 0 | 0.00% | 44 | 1.51% | 0.00x |
| Obfuscation :: base64.decodestring | 0 | 0.00% | 20 | 0.69% | 0.00x |
| Obfuscation :: base64.encode | 0 | 0.00% | 3 | 0.10% | 0.00x |
| Obfuscation :: base64.encodebytes | 3 | 0.15% | 51 | 1.75% | 0.08x |
| Obfuscation :: base64.encodestring | 2 | 0.10% | 27 | 0.93% | 0.11x |
| Obfuscation :: base64.standard_b64decode | 0 | 0.00% | 27 | 0.93% | 0.00x |
| Obfuscation :: base64.standard_b64encode | 0 | 0.00% | 44 | 1.51% | 0.00x |
| Obfuscation :: base64.urlsafe_b64decode | 26 | 1.27% | 104 | 3.58% | 0.36x |
| Obfuscation :: base64.urlsafe_b64encode | 32 | 1.56% | 170 | 5.85% | 0.27x |
| Obfuscation :: base64.z85decode | 1 | 0.05% | 0 | 0.00% | infinite (zero benign rows) |

## Install indicators

| Indicator | Malicious rows | Benign rows |
|---|---:|---:|
| Plain setuptools.setup() | 1418 | 1547 |
| Custom install indicator | 395 | 22 |

## Benign HIGH-severity review queue

These are candidates for manual false-positive review, not confirmed false positives.

| Package | Version | Findings | Categories |
|---|---|---:|---|
| gevent | 26.9.0 | 2977 | Command Execution, Credential / Data Access, Dynamic Code Execution, Install-Time / Package Execution, Network Activity, Obfuscation |
| gevent | 1.3.2 | 1740 | Command Execution, Credential / Data Access, Dynamic Code Execution, Install-Time / Package Execution, Network Activity, Obfuscation |
| google-cloud-compute | 1.19.0 | 1512 | Credential / Data Access |
| Django | 5.2.18 | 1051 | Command Execution, Credential / Data Access, Dynamic Code Execution, Install-Time / Package Execution, Network Activity, Obfuscation |
| Django | 2.2.13 | 1015 | Command Execution, Credential / Data Access, Dynamic Code Execution, Install-Time / Package Execution, Network Activity, Obfuscation |
| google-ai-generativelanguage | 0.12.1 | 727 | Credential / Data Access |
| azure-ai-projects | 2.2.0 | 726 | Command Execution, Credential / Data Access, Obfuscation |
| numpy | 1.26.3 | 670 | Command Execution, Credential / Data Access, Dynamic Code Execution, Install-Time / Package Execution, Obfuscation |
| ddtrace | 2.3.5 | 600 | Command Execution, Credential / Data Access, Dynamic Code Execution, Install-Time / Package Execution, Network Activity, Obfuscation |
| moto | 5.2.4 | 564 | Credential / Data Access, Install-Time / Package Execution, Network Activity, Obfuscation |
| openai | 3.37.0 | 555 | Command Execution, Credential / Data Access, Dynamic Code Execution, Install-Time / Package Execution, Network Activity, Obfuscation |
| ansible | 2.7.1 | 536 | Command Execution, Credential / Data Access, Dynamic Code Execution, Install-Time / Package Execution, Network Activity, Obfuscation |
| mlflow-skinny | 3.17.2 | 526 | Command Execution, Credential / Data Access, Dynamic Code Execution, Install-Time / Package Execution, Network Activity, Obfuscation |
| mlflow | 3.17.2 | 525 | Command Execution, Credential / Data Access, Dynamic Code Execution, Network Activity, Obfuscation |
| pipenv | 2026.10.2 | 495 | Command Execution, Credential / Data Access, Dynamic Code Execution, Network Activity, Obfuscation |
| hatch | 1.18.1 | 486 | Command Execution, Credential / Data Access, Dynamic Code Execution, Obfuscation |
| google-ai-generativelanguage | 0.6.4 | 448 | Credential / Data Access |
| typer-slim | 0.16.1 | 446 | Command Execution, Credential / Data Access |
| typer | 0.27.3 | 440 | Command Execution, Credential / Data Access |
| datamodel-code-generator | 0.86.0 | 436 | Command Execution, Credential / Data Access, Dynamic Code Execution, Network Activity, Obfuscation |
| ansible | 2.9.27 | 432 | Command Execution, Credential / Data Access, Dynamic Code Execution, Install-Time / Package Execution, Network Activity, Obfuscation |
| anthropic | 2.2.0 | 423 | Command Execution, Credential / Data Access, Dynamic Code Execution, Install-Time / Package Execution, Obfuscation |
| typer | 0.13.1 | 423 | Command Execution, Credential / Data Access |
| azure-identity | 1.26.0 | 421 | Command Execution, Credential / Data Access, Obfuscation |
| moto | 5.0.1.dev18 | 414 | Credential / Data Access, Network Activity, Obfuscation |
| pymongo | 4.19.0 | 407 | Command Execution, Credential / Data Access, Dynamic Code Execution, Install-Time / Package Execution, Network Activity, Obfuscation |
| meson | 1.12.1 | 404 | Command Execution, Credential / Data Access, Dynamic Code Execution, Install-Time / Package Execution, Obfuscation |
| google-cloud-compute | 1.56.0 | 395 | Credential / Data Access |
| langchain-community | 0.3.16 | 378 | Command Execution, Credential / Data Access, Dynamic Code Execution, Network Activity, Obfuscation |
| ansible-core | 2.22.0rc1 | 362 | Command Execution, Credential / Data Access, Dynamic Code Execution, Install-Time / Package Execution, Network Activity, Obfuscation |

## Interpretation and limitations

- Plain `setuptools.setup()` is informational and should not independently drive risk.
- A broad indicator such as `os.environ` access or network activity is not proof of malicious intent.
- Finding totals are not independent events; prevalence counts each indicator once per package-version row.
- Benign packages were assumed benign based on corpus selection, not independently audited.
- Collection limits and differences between the datasets may bias the comparison.
- Do not treat prevalence ratios as model accuracy or use them alone to choose thresholds.
- Verify scanner-rule parity against frozen analyzer v1 before interpreting results.
- Split ML evaluation by normalized `package_name` to prevent version leakage.

