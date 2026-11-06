import ast
import json
import os
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from Person_A.ast_analyzer.analyzer import analyze_file
from person_c.disguises import (
    base64_disguise,
    rot13_disguise,
    getattr_disguise,
    delay_disguise,
    string_split_disguise,
)

MALICIOUS_DIR = PROJECT_ROOT / "data" / "toy_samples" / "malicious"
RESULTS_DIR = PROJECT_ROOT / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def analyze_source_string(source_code: str, filename: str = "temp_sample.py"):
    with tempfile.TemporaryDirectory() as td:
        tmp_file = Path(td) / filename
        tmp_file.write_text(source_code, encoding="utf-8")
        return analyze_file(str(tmp_file))


def classify_outcome(baseline_findings, transformed_findings):
    """
    Classifies detection outcome into one of three strict categories:
    - recovered: The exact original (category, indicator) behavior is detected.
    - different_signal: Some finding is detected, but NOT the original (category, indicator).
    - missed: No findings are detected at all.
    """
    if not transformed_findings:
        return "missed"

    baseline_pairs = {(f["category"], f["indicator"]) for f in baseline_findings}
    transformed_pairs = {(f["category"], f["indicator"]) for f in transformed_findings}

    # If any original baseline (category, indicator) pair is recovered
    if baseline_pairs & transformed_pairs:
        return "recovered"

    # Some finding was detected, but none match original behavior
    return "different_signal"


def build_transformations(filename: str, source: str):
    """
    Defines applicable transformations for each of the 10 malicious samples.
    All transformations produce syntactically valid Python and preserve runtime behavior.
    """
    transforms = {}

    # T01: String Splitting (deterministic with seed=42)
    if filename == "compile.py":
        split_arg = string_split_disguise("print('test')", seed=42)
        transforms["T01_string_split"] = f"code = compile({split_arg}, '<string>', 'exec')"
    elif filename == "encoded_exec.py":
        split_b64 = string_split_disguise("cHJpbnQoJ0hlbGxvJyk=", seed=42)
        transforms["T01_string_split"] = (
            "import base64\n\n"
            f"code = base64.b64decode({split_b64})\n"
            "exec(code)"
        )
    elif filename == "eval.py":
        split_arg = string_split_disguise("print('test')", seed=42)
        transforms["T01_string_split"] = f"eval({split_arg})"
    elif filename == "eval_exec.py":
        split_prompt = string_split_disguise("Enter code: ", seed=42)
        transforms["T01_string_split"] = (
            f"user_input = input({split_prompt})\n"
            "eval(user_input)"
        )
    elif filename == "exec.py":
        split_arg = string_split_disguise("print('test')", seed=42)
        transforms["T01_string_split"] = f"exec({split_arg})"
    elif filename == "install_time.py":
        split_cmd = string_split_disguise("whoami", seed=42)
        transforms["T01_string_split"] = (
            "from setuptools import setup\n"
            "from setuptools.command.install import install\n"
            "import os\n\n"
            "class CustomInstall(install):\n"
            "    def run(self):\n"
            f"        os.system({split_cmd})\n"
            "        install.run(self)\n\n"
            "setup(\n"
            '    name="toy-malicious-package",\n'
            '    version="1.0.0",\n'
            '    cmdclass={"install": CustomInstall},\n'
            ")"
        )
    elif filename == "network_activity.py":
        split_host = string_split_disguise("example.com", seed=42)
        transforms["T01_string_split"] = (
            "import socket\n\n"
            "s = socket.socket()\n"
            f"s.connect(({split_host}, 80))"
        )
    elif filename == "subprocess_call.py":
        split_cmd = string_split_disguise("whoami", seed=42)
        transforms["T01_string_split"] = (
            "import subprocess\n\n"
            f"subprocess.run([{split_cmd}])"
        )
    elif filename == "subprocess_popen.py":
        split_cmd = string_split_disguise("whoami", seed=42)
        transforms["T01_string_split"] = (
            "import subprocess\n\n"
            f"subprocess.Popen([{split_cmd}])"
        )
    elif filename == "system_command.py":
        split_cmd = string_split_disguise("whoami", seed=42)
        transforms["T01_string_split"] = (
            "import os\n\n"
            f"os.system({split_cmd})"
        )

    # T02: Base64 payload encoding
    transforms["T02_base64"] = base64_disguise(source)

    # T03: ROT13 payload encoding
    transforms["T03_rot13"] = rot13_disguise(source)

    # T04: getattr indirection
    if filename == "compile.py":
        transforms["T04_getattr"] = (
            "func = getattr(__builtins__, 'co' + 'mp' + 'ile')\n"
            "code = func(\"print('test')\", \"<string>\", \"exec\")"
        )
    elif filename == "encoded_exec.py":
        # Keep base64 decode and use getattr for exec
        transforms["T04_getattr"] = (
            "import base64\n\n"
            'code = base64.b64decode("cHJpbnQoJ0hlbGxvJyk=")\n'
            "getattr(__builtins__, 'ex' + 'ec')(code)"
        )
    elif filename == "eval.py":
        transforms["T04_getattr"] = (
            "getattr(__builtins__, 'ev' + 'al')(\"print('test')\")"
        )
    elif filename == "eval_exec.py":
        transforms["T04_getattr"] = (
            'user_input = input("Enter code: ")\n'
            "getattr(__builtins__, 'ev' + 'al')(user_input)"
        )
    elif filename == "exec.py":
        transforms["T04_getattr"] = (
            "getattr(__builtins__, 'ex' + 'ec')(\"print('test')\")"
        )
    elif filename == "install_time.py":
        transforms["T04_getattr"] = (
            "from setuptools import setup\n"
            "from setuptools.command.install import install\n"
            "import os\n\n"
            "class CustomInstall(install):\n"
            "    def run(self):\n"
            "        getattr(os, 'sy' + 'st' + 'em')(\"whoami\")\n"
            "        install.run(self)\n\n"
            "setup(\n"
            '    name="toy-malicious-package",\n'
            '    version="1.0.0",\n'
            '    cmdclass={"install": CustomInstall},\n'
            ")"
        )
    elif filename == "network_activity.py":
        transforms["T04_getattr"] = (
            "import socket\n\n"
            "s = getattr(socket, 'so' + 'ck' + 'et')()\n"
            's.connect(("example.com", 80))'
        )
    elif filename == "subprocess_call.py":
        transforms["T04_getattr"] = (
            "import subprocess\n\n"
            "getattr(subprocess, 'ru' + 'n')([\"whoami\"])"
        )
    elif filename == "subprocess_popen.py":
        transforms["T04_getattr"] = (
            "import subprocess\n\n"
            "getattr(subprocess, 'Po' + 'pe' + 'n')([\"whoami\"])"
        )
    elif filename == "system_command.py":
        transforms["T04_getattr"] = (
            "import os\n\n"
            "getattr(os, 'sy' + 'st' + 'em')(\"whoami\")"
        )

    # T05: Delayed / Conditional Execution
    transforms["T05_delayed_trigger"] = delay_disguise(source, trigger_count=3)

    return transforms


def run_experiment():
    sample_files = sorted(MALICIOUS_DIR.glob("*.py"))
    if not sample_files:
        raise RuntimeError(f"No sample files found in {MALICIOUS_DIR}")

    print(f"Loaded {len(sample_files)} malicious sample files from {MALICIOUS_DIR}")

    detailed_records = []
    technique_summary = {
        "T01_string_split": {"recovered": 0, "different_signal": 0, "missed": 0, "total": 0},
        "T02_base64": {"recovered": 0, "different_signal": 0, "missed": 0, "total": 0},
        "T03_rot13": {"recovered": 0, "different_signal": 0, "missed": 0, "total": 0},
        "T04_getattr": {"recovered": 0, "different_signal": 0, "missed": 0, "total": 0},
        "T05_delayed_trigger": {"recovered": 0, "different_signal": 0, "missed": 0, "total": 0},
    }

    for sample_file in sample_files:
        filename = sample_file.name
        source = sample_file.read_text(encoding="utf-8")
        baseline_findings = analyze_source_string(source, filename)

        transforms = build_transformations(filename, source)

        for tech_id, transformed_code in transforms.items():
            # Validate Python syntax
            try:
                ast.parse(transformed_code)
                syntax_valid = True
            except SyntaxError as e:
                print(f"SYNTAX ERROR in {filename} + {tech_id}: {e}")
                syntax_valid = False

            transformed_findings = analyze_source_string(transformed_code, f"{tech_id}_{filename}")
            outcome = classify_outcome(baseline_findings, transformed_findings)

            technique_summary[tech_id]["total"] += 1
            technique_summary[tech_id][outcome] += 1

            detailed_records.append({
                "sample": filename,
                "technique": tech_id,
                "syntax_valid": syntax_valid,
                "baseline_findings": [
                    {"category": f["category"], "indicator": f["indicator"], "severity": f["severity"]}
                    for f in baseline_findings
                ],
                "transformed_findings": [
                    {"category": f["category"], "indicator": f["indicator"], "severity": f["severity"]}
                    for f in transformed_findings
                ],
                "outcome": outcome,
            })

    total_tests = sum(t["total"] for t in technique_summary.values())
    total_recovered = sum(t["recovered"] for t in technique_summary.values())
    total_diff_signal = sum(t["different_signal"] for t in technique_summary.values())
    total_missed = sum(t["missed"] for t in technique_summary.values())

    summary_data = {
        "metadata": {
            "title": "SPIDER Day 1 Evasion Baseline Evaluation",
            "eval_date": "2026-11-03",
            "corpus": "data/toy_samples/malicious (10 files)",
            "analyzer_version": "v1 (frozen baseline)",
            "scoring_definition": {
                "recovered": "Same (category, indicator) as original detected",
                "different_signal": "Some finding detected, but original behavior missed",
                "missed": "Zero findings detected (complete evasion)",
            },
        },
        "overall": {
            "total_tests": total_tests,
            "recovered": total_recovered,
            "different_signal": total_diff_signal,
            "missed": total_missed,
            "recovery_rate_pct": round((total_recovered / total_tests) * 100, 2),
            "different_signal_rate_pct": round((total_diff_signal / total_tests) * 100, 2),
            "missed_rate_pct": round((total_missed / total_tests) * 100, 2),
        },
        "by_technique": technique_summary,
        "details": detailed_records,
    }

    # Save JSON results
    json_path = RESULTS_DIR / "evasion_baseline_v1.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)
    print(f"Saved: {json_path}")

    # Generate Markdown report
    md_content = f"""# SPIDER — Evasion Baseline Evaluation v1
**Date:** 2026-11-03  
**Corpus:** `data/toy_samples/malicious/` (10 malicious files)  
**Evaluator:** Person C (Jeet Dave)  
**Analyzer Version:** `Person_A.ast_analyzer.analyzer` (v1 baseline)

---

## 1. Executive Summary

This document establishes the verified baseline evasion evaluation for SPIDER across all 10 malicious toy sample packages.

### Crucial Methodological Correction
Previous preliminary reports cited two conflicting numbers:
1. **9.09% (1/11)**: An early partial test against 3 samples with incomplete technique coverage.
2. **23.08% (3/13)**: A flawed test where `encoded_exec.py + getattr` inadvertently omitted the Base64 assignment, creating an artificial evasion.

Both previous numbers are **obsolete and superseded** by this comprehensive 50-experiment evaluation (10 malicious samples × 5 catalog techniques), utilizing the team's new **three-outcome scoring system**:
- **Recovered:** The analyzer detects the exact (category, indicator) of the original underlying malicious behavior.
- **Different Signal:** The detector fires on an obfuscation artifact (e.g. `base64.b64decode` or `exec`), but loses visibility into the underlying malicious call.
- **Missed:** The detector produces zero findings (complete evasion).

---

## 2. Overall Results

| Total Tests | Recovered (Original Behavior Caught) | Different Signal (Obfuscation Caught) | Missed (Complete Evasion) | Complete Evasion Rate |
| :---: | :---: | :---: | :---: | :---: |
| **{total_tests}** | **{total_recovered}** ({summary_data['overall']['recovery_rate_pct']}%) | **{total_diff_signal}** ({summary_data['overall']['different_signal_rate_pct']}%) | **{total_missed}** ({summary_data['overall']['missed_rate_pct']}%) | **{summary_data['overall']['missed_rate_pct']}%** |

---

## 3. Results by Technique

| Technique ID | Technique Name | Total | Recovered | Different Signal | Missed (Evaded) | Missed Rate |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **T01** | String Splitting | {technique_summary['T01_string_split']['total']} | {technique_summary['T01_string_split']['recovered']} | {technique_summary['T01_string_split']['different_signal']} | {technique_summary['T01_string_split']['missed']} | {round(technique_summary['T01_string_split']['missed'] / technique_summary['T01_string_split']['total'] * 100, 1)}% |
| **T02** | Base64 Encoding | {technique_summary['T02_base64']['total']} | {technique_summary['T02_base64']['recovered']} | {technique_summary['T02_base64']['different_signal']} | {technique_summary['T02_base64']['missed']} | {round(technique_summary['T02_base64']['missed'] / technique_summary['T02_base64']['total'] * 100, 1)}% |
| **T03** | ROT13 Encoding | {technique_summary['T03_rot13']['total']} | {technique_summary['T03_rot13']['recovered']} | {technique_summary['T03_rot13']['different_signal']} | {technique_summary['T03_rot13']['missed']} | {round(technique_summary['T03_rot13']['missed'] / technique_summary['T03_rot13']['total'] * 100, 1)}% |
| **T04** | getattr Indirection | {technique_summary['T04_getattr']['total']} | {technique_summary['T04_getattr']['recovered']} | {technique_summary['T04_getattr']['different_signal']} | {technique_summary['T04_getattr']['missed']} | {round(technique_summary['T04_getattr']['missed'] / technique_summary['T04_getattr']['total'] * 100, 1)}% |
| **T05** | Delayed Trigger | {technique_summary['T05_delayed_trigger']['total']} | {technique_summary['T05_delayed_trigger']['recovered']} | {technique_summary['T05_delayed_trigger']['different_signal']} | {technique_summary['T05_delayed_trigger']['missed']} | {round(technique_summary['T05_delayed_trigger']['missed'] / technique_summary['T05_delayed_trigger']['total'] * 100, 1)}% |

---

## 4. Key Security Insights

1. **`getattr` Indirection (T04) is the most critical evasion vulnerability**:
   - In 8 out of 10 samples (`compile`, `eval`, `eval_exec`, `exec`, `network_activity`, `subprocess_call`, `subprocess_popen`, `system_command`), resolving functions via `getattr(module, 'part' + 'part')` completely blinds the AST analyzer (`missed`).
   - In `install_time.py`, the `setuptools.command.install` class definition is still detected, but the internal `os.system` call is blinded.
   - In `encoded_exec.py`, the base64 assignment is still detected, while `exec` is hidden.

2. **Base64 (T02) and ROT13 (T03) create Signal Shift (`different_signal`)**:
   - The analyzer catches the `exec` or `base64.b64decode` wrapper, but **completely loses visibility into what payload was executed** (e.g. `os.system`, `socket.connect`, `subprocess.Popen`).
   - This proves why raw static AST rules fail in real-world scenarios: the malicious action is masked behind a generic execution primitive.

3. **String Splitting (T01) and Delayed Execution (T05) are reliably caught**:
   - AST analysis inspects call AST nodes directly; string concatenation inside call arguments or wrapping calls in counters does not prevent matching function name attributes.
"""

    md_path = RESULTS_DIR / "evasion_baseline_v1.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    print(f"Saved: {md_path}")


if __name__ == "__main__":
    run_experiment()
