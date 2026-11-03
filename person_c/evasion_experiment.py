import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

PERSON_C_DIR = Path(__file__).resolve().parent
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


def analyze_source(source_code, filename):
    with tempfile.TemporaryDirectory() as temp_dir:
        sample_path = Path(temp_dir) / filename
        sample_path.write_text(source_code, encoding="utf-8")
        return analyze_file(str(sample_path))


def print_result(name, findings):
    print("\n" + "=" * 70)
    print(name)
    print("=" * 70)

    if findings:
        for finding in findings:
            print(
                f"{finding['category']} | "
                f"{finding['indicator']} | "
                f"{finding['severity']}"
            )
    else:
        print("No findings")


def main():
    original = 'import os\nos.system("whoami")'

    print("ORIGINAL SAMPLE")
    original_findings = analyze_source(original, "original.py")
    print_result("Original", original_findings)

    experiments = [
        (
            "Base64 disguise",
            base64_disguise(original),
        ),
        (
            "ROT13 disguise",
            rot13_disguise(original),
        ),
        (
            "getattr disguise",
            getattr_disguise("os", "system", '"whoami"'),
        ),
        (
            "Delayed trigger disguise",
            delay_disguise(original, 3),
        ),
        (
            "String split",
            "import os\nos.system(" + string_split_disguise('"whoami"') + ")",
        ),
    ]

    for name, transformed_source in experiments:
        findings = analyze_source(transformed_source, "transformed.py")
        print_result(name, findings)


if __name__ == "__main__":
    main()
