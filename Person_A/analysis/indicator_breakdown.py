from pathlib import Path
import sys
from collections import Counter

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from Person_A.ast_analyzer.analyzer import analyze_file


def analyze_directory(directory):
    directory = PROJECT_ROOT / directory
    category_counts = Counter()
    indicator_counts = Counter()

    for file_path in sorted(directory.glob("*.py")):
        findings = analyze_file(str(file_path))

        for finding in findings:
            # Parse errors are processing-status signals, not security indicators
            if finding["category"] == "Parse Error":
                continue

            category_counts[finding["category"]] += 1
            indicator_counts[finding["indicator"]] += 1

    return category_counts, indicator_counts


malicious_categories, malicious_indicators = analyze_directory(
    "data/toy_samples/malicious"
)

clean_categories, clean_indicators = analyze_directory(
    "data/toy_samples/clean"
)


print("\n=== MALICIOUS: CATEGORY COUNTS ===")
for category, count in malicious_categories.items():
    print(f"{category}: {count}")


print("\n=== MALICIOUS: INDICATOR COUNTS ===")
for indicator, count in malicious_indicators.items():
    print(f"{indicator}: {count}")


print("\n=== CLEAN: CATEGORY COUNTS ===")
for category, count in clean_categories.items():
    print(f"{category}: {count}")


print("\n=== CLEAN: INDICATOR COUNTS ===")
for indicator, count in clean_indicators.items():
    print(f"{indicator}: {count}")