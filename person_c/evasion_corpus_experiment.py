import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PERSON_C_DIR = Path(__file__).resolve().parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

if str(PERSON_C_DIR) not in sys.path:
    sys.path.insert(0, str(PERSON_C_DIR))

from Person_A.ast_analyzer.analyzer import analyze_file
from disguises import (
    base64_disguise,
    rot13_disguise,
    getattr_disguise,
    delay_disguise,
    string_split_disguise,
)


SAMPLES = {
    "system_command.py": {
        "source": 'import os\n\nos.system("whoami")',
        "transformations": {
            "Base64": lambda source: base64_disguise(source),
            "ROT13": lambda source: rot13_disguise(source),
            "getattr": lambda source: getattr_disguise("os", "system", '"whoami"'),
            "Delayed Trigger": lambda source: delay_disguise(source, 3),
            "String Split": lambda source: (
                "import os\n\nos.system("
                + string_split_disguise('"whoami"')
                + ")"
            ),
        },
    },
    "subprocess_call.py": {
        "source": 'import subprocess\n\nsubprocess.run(["whoami"])',
        "transformations": {
            "Base64": lambda source: base64_disguise(source),
            "ROT13": lambda source: rot13_disguise(source),
            "Delayed Trigger": lambda source: delay_disguise(source, 3),
        },
    },
    "encoded_exec.py": {
        "source": (
            'import base64\n\n'
            'code = base64.b64decode("cHJpbnQoJ0hlbGxvJyk=")\n'
            'exec(code)'
        ),
        "transformations": {
            "Base64": lambda source: base64_disguise(source),
            "ROT13": lambda source: rot13_disguise(source),
            "Delayed Trigger": lambda source: delay_disguise(source, 3),
        },
    },
}


def analyze_source(source_code, filename):
    with tempfile.TemporaryDirectory() as temp_dir:
        sample_path = Path(temp_dir) / filename
        sample_path.write_text(source_code, encoding="utf-8")
        return analyze_file(str(sample_path))


def detected(findings):
    return len(findings) > 0


def print_findings(findings):
    if not findings:
        print("No findings")
        return

    for finding in findings:
        print(
            f"{finding['category']} | "
            f"{finding['indicator']} | "
            f"{finding['severity']}"
        )


def main():
    total_applicable = 0
    total_evasions = 0

    print("=" * 80)
    print("SPIDER - STATIC EVASION CORPUS EXPERIMENT")
    print("=" * 80)

    for sample_name, sample_data in SAMPLES.items():
        source = sample_data["source"]

        baseline = analyze_source(source, sample_name)

        print("\n" + "#" * 80)
        print(f"SAMPLE: {sample_name}")
        print("#" * 80)

        print("\nBASELINE")
        print_findings(baseline)

        baseline_detected = detected(baseline)

        for technique, transform in sample_data["transformations"].items():
            transformed_source = transform(source)
            findings = analyze_source(transformed_source, "transformed.py")

            total_applicable += 1

            if baseline_detected and not detected(findings):
                result = "EVASION SUCCESS"
                total_evasions += 1
            elif baseline_detected and detected(findings):
                result = "DETECTED"
            elif not baseline_detected and not detected(findings):
                result = "BASELINE NOT DETECTED"
            else:
                result = "TRANSFORMED DETECTED"

            print("\n" + "-" * 60)
            print(f"TECHNIQUE: {technique}")
            print(f"RESULT: {result}")
            print("FINDINGS:")
            print_findings(findings)

    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Applicable experiments: {total_applicable}")
    print(f"Evasion successes:       {total_evasions}")

    if total_applicable:
        evasion_rate = (total_evasions / total_applicable) * 100
        print(f"Evasion rate:            {evasion_rate:.2f}%")
    else:
        print("Evasion rate:            0.00%")


if __name__ == "__main__":
    main()
