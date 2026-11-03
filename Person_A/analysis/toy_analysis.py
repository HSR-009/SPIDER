from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from Person_A.ast_analyzer.analyzer import analyze_file


def analyze_directory(directory):
    directory = PROJECT_ROOT / directory

    for file_path in sorted(directory.glob("*.py")):
        findings = analyze_file(str(file_path))

        print(f"\n=== {file_path.name} ===")

        if not findings:
            print("No findings")
            continue

        for finding in findings:
            print(
                f"[{finding['severity']}] "
                f"{finding['category']} | "
                f"{finding['indicator']} | "
                f"line {finding['line']}"
            )


analyze_directory("data/toy_samples/malicious")
analyze_directory("data/toy_samples/clean")