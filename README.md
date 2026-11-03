# 🕷️ SPIDER

**SPIDER** (**S**upply Chain **P**ackages **I**ntelligence for **D**etection, **E**vasion and **R**esilience) is an open-source, evidence-driven local security toolkit designed to detect malicious Python packages on PyPI, hunt for post-installation persistence artifacts, and rigorously stress-test its own detection rules against adversarial evasion techniques.

Unlike black-box classifiers that produce opaque risk scores, SPIDER is built on an **evidence-first** architecture: every alert links directly to concrete source code lines, syntax trees, and indicators. The system emits honest three-way verdicts: `suspicious`, `none detected in this scan`, or `unable to assess` — and never declares a package "safe."

---

## 📁 Repository Structure

```text
SPIDER/
├── Person_A/                 # Core engine, AST analysis, security taxonomy & dataset pipelines
│   ├── ast_analyzer/         # Static AST analyzer (v1 baseline & v1.1 rules)
│   ├── analysis/             # Technical gap analyses, prevalence & discrimination reports
│   ├── pipeline/             # Data ingestion, benign fetcher, provenance & rescan scripts
│   └── threat_model/         # Attack surface, taxonomy, and threat model specifications
├── Person_B/                 # Machine learning pipeline, feature engineering & explainability
│   ├── features/             # AST call ratios, Shannon entropy, and metadata features
│   ├── models/               # Group-safe splitting, baseline RF/XGBoost, and SHAP explainability
│   └── results/              # Frozen baseline and resilience evaluation metrics (JSON/Markdown)
├── person_c/                 # Adversarial evasion laboratory & investigation dashboard
│   ├── dashboard/            # Streamlit interactive application & HTML mockups
│   ├── evasion/              # Disguise generators (T01-T05: string split, base64, ROT13, getattr, delay)
│   └── day3_evidence/        # Empirical evasion experiment results on malicious samples
├── data/                     # Dataset corpora and test fixtures
│   ├── processed/            # Canonical JSONL datasets (malicious_for_b, benign_for_b with group_id)
│   ├── raw/                  # Source manifests (benign manifest.jsonl) and quarantined archives
│   └── toy_samples/          # Clean, malicious, and edge-case Python scripts for verification
├── spider_contract/          # Shared evidence schema, models, leakage guards & validators
├── tests/                    # Automated unittest test suite
├── requirements.txt          # Python dependencies
└── roadmap.yaml              # Dynamic roadmap and feature progression (Levels 0–8)
```

---

## ⚡ Quick Start

### 1. Installation

Ensure Python 3.10+ is installed (tested on Python 3.13):

```bash
# Clone the repository
git clone https://github.com/HSR-009/SPIDER.git
cd SPIDER

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Automated Tests

Run the official test suite to verify analyzer behavior, schema contracts, and leakage guards:

```bash
python -m unittest discover -s tests
```

### 3. Validate Dataset Contracts

Validate dataset integrity, PEP 503 `group_id` normalization, and required provenance fields:

```bash
python -m spider_contract.dataset_check
```

### 4. Run the Static Analyzer on a File

Analyze any Python file using Person A's AST analyzer:

```python
from Person_A.ast_analyzer.analyzer import analyze_file

findings = analyze_file("data/toy_samples/malicious/encoded_exec.py")
for finding in findings:
    print(f"[{finding['severity']}] {finding['category']} :: {finding['indicator']} (Line {finding['line']})")
```

### 5. Launch the Investigation Dashboard

Run the Streamlit investigation interface:

```bash
streamlit run person_c/dashboard/app.py
```

---

## 🛡️ Core Security Categories

SPIDER detects indicators across six primary behavioral categories (plus an explicit status category for unparsable code):

1. **Command Execution** (`HIGH`): `os.system`, `subprocess.run`, `subprocess.Popen`
2. **Dynamic Code Execution** (`HIGH`): `eval`, `exec`, `compile`
3. **Credential / Data Access** (`HIGH`): `os.environ`, `.aws/credentials`, `.ssh/`, `.netrc`, `.env`
4. **Network Activity** (`MEDIUM`): `socket`, `requests.get/post`, `urllib.request.urlopen`
5. **Obfuscation** (`MEDIUM`): `base64` decoders, dynamic string reconstructions
6. **Install-Time Execution** (`HIGH`): Custom `setuptools.command.install`, `setup.py` hooks
7. **Parse Error** (`MEDIUM` status): Tracks `SyntaxError` and unparsable files as explicit coverage gaps, never as malicious behavior.

---

## 🔬 Research & Anti-Leakage Discipline

- **Group-Safe Splitting**: Cross-validation and test splits are strictly grouped by package name (`group_id`), ensuring versions of the same package never leak across splits.
- **Leakage Guards**: Banned feature columns (`label`, `source`, `in_index`, `index_annotated`, `package_id`) are programmatically blocked via `assert_no_leaky_columns`.
- **Size-Bias Control**: Evaluation explicitly reports size-only baselines and evaluates performance across package-size buckets to prevent models from taking shortcuts based on package file counts.
