# SPIDER Threat Model

## 1. Objective

SPIDER detects potentially malicious PyPI packages using static Python AST analysis, package metadata, machine-learning features, and adversarial evaluation. The goal is to identify suspicious package behavior before it causes harm, while understanding the limitations of static detection.

## 2. Threat Actors and Capabilities

Potential attackers may publish malicious packages, impersonate legitimate packages, compromise legitimate packages, or hide malicious behavior through obfuscation.

Attacker capabilities may include:
- Publishing packages with names similar to popular packages.
- Executing code during installation, import, or runtime.
- Accessing environment variables, sensitive files, or credentials.
- Sending collected data to external infrastructure.
- Hiding behavior through encoded strings, indirect calls, dynamic imports, or reconstructed code.
- Distributing different package versions with different behavior.

## 3. Attack Surface

| Attack surface | Potential behavior | SPIDER coverage |
|---|---|---|
| Package naming and metadata | Typosquatting and package impersonation | Requires metadata/name-analysis features |
| Installation | Custom install commands or setup-related behavior | Partially covered by AST rules |
| Import and runtime | Command execution, environment access, network activity | Partially covered by AST rules |
| Dynamic execution | `eval`, `exec`, `compile`, indirect execution | Direct calls partially covered |
| Obfuscation | Base64 and encoded payloads | Some Base64 operations covered |
| Non-Python artifacts | Compiled extensions or other hidden payloads | Limited or out of scope for AST-only analysis |

## 4. Scope

### In scope
- Static analysis of Python source using AST.
- Detection of the existing analyzer v1 indicators.
- Comparison of malicious and assumed-benign package-version datasets.
- Feature engineering, explainability, and adversarial robustness evaluation.
- Identification of false positives and known detection gaps.

### Out of scope or limited
- Executing package code to observe runtime behavior.
- Proving that a package is safe or malicious from one indicator.
- Complete analysis of compiled binaries, `.so`, `.pyc`, `.pth`, or build-system hooks.
- Guaranteeing detection of all obfuscated or dynamically constructed behavior.
- Treating package-name similarity alone as proof of maliciousness.

## 5. Assumptions and Limitations

- The malicious dataset contains known reported samples and may not represent every type of malicious package.
- The benign corpus was selected from popular PyPI projects but has not been independently verified as entirely benign.
- Different package versions may contain repeated or changed code; train/test splitting must group by normalized package name.
- AST rules detect syntactic patterns, not intent.
- A finding's severity is a rule-assigned label, not a calibrated probability of maliciousness.
- Parse errors indicate incomplete static analysis, not malicious behavior by themselves.

## 6. Known Detection Gaps

- Indirect calls through `getattr`.
- Dynamic imports through `__import__`.
- Strings reconstructed with `chr` or concatenation.
- Encoded or encrypted payloads that are not directly recognized by existing rules.
- Credential access followed by exfiltration through APIs not currently covered.
- Name-confusion attacks without suspicious source-code indicators.
- Malicious behavior hidden in non-Python artifacts or build configuration.

These are known or suspected gaps for investigation; they are not claims that every such technique is currently present in the dataset.

## 7. Risk Interpretation

Broad indicators such as `os.environ`, network APIs, `eval`, `exec`, Base64, and `setuptools.setup()` can occur in legitimate software. SPIDER should evaluate combinations and context rather than treating individual findings as conclusive evidence.

The current baseline indicates that `setuptools.command.install` is more discriminative than plain `setuptools.setup()` in the collected datasets. This is a preliminary prevalence result, not a final accuracy measurement.

## 8. Data Handling and Evaluation

- Treat raw malicious package archives as untrusted; do not install or execute them.
- Keep raw datasets local and excluded from Git.
- Commit analysis code and safe reports, not raw malicious archives or generated scan dumps.
- Report dataset sizes, annotation coverage, and collection limitations.
- Use package-name-grouped train/test splits to reduce version leakage.
- Measure false positives using reviewed benign examples before selecting thresholds.

## 9. Planned Improvements

1. Separate plain setup detection from custom install-command detection.
2. Add metadata-based name-similarity features.
3. Evaluate lightweight encoded-string and artifact-presence features.
4. Investigate combinations of credential access and outbound communication.
5. Validate candidate v1.1 rules against benign and malicious examples before implementation.

## 10. Current Status

Analyzer v1 remains frozen. This document records the current threat model and evidence-based improvement areas; proposed v1.1 changes require separate validation.

## Evidence-Based Threats and Analysis Limitations

### Obfuscation and Execution Evasion

Day 7 testing found limited agreement between analyzer v1's Obfuscation findings and the reviewed annotations: 21 of 59 reviewed cases agreed (35.6%). Observed examples included `maratlib`, which used dynamic import and obfuscated execution, and `amazon-boto`, which contained credential-exfiltration behavior. Compiled `.so` payloads and `.pth` files are additional analysis surfaces that require handling beyond ordinary Python AST inspection. These observations motivate future detection improvements; analyzer v1 remains frozen.

### Dataset Coverage and Campaign Bias

The local scan covered 2,040 of 6,428 indexed PyPI records (31.7%). Of 2,627 records with campaign annotations, campaign IDs 30 and 47 account for 1,524 combined. Models may therefore learn campaign-specific or collection-specific patterns. Evaluation should use package-name-grouped splits at minimum, investigate near-duplicate packages under different names, and report performance on appropriately separated data.

### Limits of Obfuscation Labels

The index marks 1,010 of 1,024 obfuscation-annotated PyPI records as obfuscated, whereas analyzer v1 flags Obfuscation in approximately 22% of locally scanned malicious package-version rows. Annotation presence is not equivalent to locally detectable source behavior. Missing source, compiled payloads, unsupported transformations, and analyzer limitations may contribute to the difference; the figures should not be presented as a directly measured false-negative rate.
