import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from Person_A.ast_analyzer.analyzer import analyze_file
from disguises import (
    base64_disguise,
    rot13_disguise,
    getattr_disguise,
    delay_disguise,
    string_split_disguise,
)

OUTPUT_DIR = PROJECT_ROOT / "person_c" / "day3_evidence"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

SAMPLES = {
    "system_command": {
        "source": 'import os\n\nos.system("whoami")',
        "transformations": {
            "base64": lambda source: base64_disguise(source),
            "rot13": lambda source: rot13_disguise(source),
            "getattr": lambda source: getattr_disguise("os", "system", '"whoami"'),
            "delayed": lambda source: delay_disguise(source, 3),
            "string_split": lambda source: (
                "import os\n\nos.system("
                + string_split_disguise('"whoami"')
                + ")"
            ),
        },
    },
    "subprocess_call": {
        "source": 'import subprocess\n\nsubprocess.run(["whoami"])',
        "transformations": {
            "base64": lambda source: base64_disguise(source),
            "rot13": lambda source: rot13_disguise(source),
            "getattr": lambda source: getattr_disguise(
                "subprocess", "run", "['whoami']"
            ),
            "delayed": lambda source: delay_disguise(source, 3),
        },
    },
    "encoded_exec": {
        "source": (
            'import base64\n\n'
            'code = base64.b64decode("cHJpbnQoJ0hlbGxvJyk=")\n'
            'exec(code)'
        ),
        "transformations": {
            "base64": lambda source: base64_disguise(source),
            "rot13": lambda source: rot13_disguise(source),
            "getattr": lambda source: getattr_disguise(
                "__builtins__", "exec", "code"
            ),
            "delayed": lambda source: delay_disguise(source, 3),
        },
    },
}


def format_findings(findings):
    if not findings:
        return "No findings"

    lines = []
    for finding in findings:
        lines.append(
            f"{finding['category']} | "
            f"{finding['indicator']} | "
            f"{finding['severity']} | "
            f"line {finding['line']}"
        )
    return "\n".join(lines)


def main():
    matrix = []
    successful = 0
    applicable = 0

    report_path = OUTPUT_DIR / "DAY3_LITERAL_RESULTS.txt"

    with report_path.open("w", encoding="utf-8") as report:
        report.write("SPIDER DAY 3 — REAL FILE EVASION EXPERIMENT\n")
        report.write("=" * 80 + "\n")
        report.write(f"Repo: {PROJECT_ROOT}\n")
        report.write("=" * 80 + "\n\n")

        for sample_name, sample_data in SAMPLES.items():

            sample_dir = OUTPUT_DIR / sample_name
            sample_dir.mkdir(parents=True, exist_ok=True)

            baseline_path = sample_dir / f"{sample_name}_baseline.py"
            baseline_path.write_text(
                sample_data["source"],
                encoding="utf-8"
            )

            baseline_findings = analyze_file(str(baseline_path))
            baseline_detected = bool(baseline_findings)

            report.write(f"SAMPLE: {sample_name}.py\n")
            report.write("-" * 80 + "\n")
            report.write("BASELINE SOURCE:\n")
            report.write(sample_data["source"] + "\n\n")
            report.write("BASELINE FINDINGS:\n")
            report.write(format_findings(baseline_findings) + "\n\n")

            for technique, transform in sample_data["transformations"].items():

                transformed_source = transform(sample_data["source"])

                transformed_path = (
                    sample_dir / f"{sample_name}_{technique}.py"
                )

                transformed_path.write_text(
                    transformed_source,
                    encoding="utf-8"
                )

                findings = analyze_file(str(transformed_path))
                applicable += 1

                if baseline_detected and not findings:
                    result = "EVASION SUCCESS"
                    successful += 1
                elif baseline_detected and findings:
                    result = "DETECTED"
                elif not baseline_detected and not findings:
                    result = "BASELINE NOT DETECTED"
                else:
                    result = "TRANSFORMED DETECTED"

                matrix.append(
                    (
                        f"{sample_name}.py",
                        technique,
                        result,
                        findings,
                        transformed_path,
                    )
                )

                report.write("=" * 80 + "\n")
                report.write(f"TECHNIQUE: {technique}\n")
                report.write(f"RESULT: {result}\n")
                report.write(f"FILE: {transformed_path}\n\n")

                report.write("TRANSFORMED SOURCE:\n")
                report.write(transformed_source + "\n\n")

                report.write("LITERAL ANALYZER FINDINGS:\n")
                report.write(format_findings(findings) + "\n\n")

        asr = (successful / applicable * 100) if applicable else 0

        report.write("=" * 80 + "\n")
        report.write("FINAL MATRIX\n")
        report.write("=" * 80 + "\n")
        report.write(
            "Sample | Technique | Result\n"
        )

        for sample, technique, result, findings, path in matrix:
            report.write(
                f"{sample} | {technique} | {result}\n"
            )

        report.write("\n")
        report.write(f"Applicable pairs: {applicable}\n")
        report.write(f"Successful evasions: {successful}\n")
        report.write(f"ASR: {asr:.2f}%\n")

    print("\nREAL FILE EXPERIMENT COMPLETE")
    print(f"Evidence directory: {OUTPUT_DIR}")
    print(f"Literal report: {report_path}")
    print(f"Applicable pairs: {applicable}")
    print(f"Successful evasions: {successful}")
    print(f"ASR: {asr:.2f}%")
    print("\nSuccessful evasions:")

    for sample, technique, result, findings, path in matrix:
        if result == "EVASION SUCCESS":
            print(f"  {sample} + {technique}")
            print(f"  File: {path}")
            print("  Findings: []")


if __name__ == "__main__":
    main()
