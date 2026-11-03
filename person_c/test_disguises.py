import ast
import sys
from pathlib import Path

PERSON_C_DIR = Path(__file__).resolve().parent

if str(PERSON_C_DIR) not in sys.path:
    sys.path.insert(0, str(PERSON_C_DIR))

from disguises import (
    base64_disguise,
    rot13_disguise,
    getattr_disguise,
    delay_disguise,
    string_split_disguise,
)


def check_syntax(code, technique):
    try:
        ast.parse(code)
        print(f"[PASS] {technique}: valid Python syntax")
    except SyntaxError as error:
        print(f"[FAIL] {technique}: invalid Python syntax")
        print(error)


def show_result(technique, code):
    print("\n" + "=" * 60)
    print(technique)
    print("=" * 60)
    print(code)
    check_syntax(code, technique)


def main():
    payload = 'print("SPIDER test")'

    result = base64_disguise(payload)
    show_result("1. Base64 Disguise", result)

    result = rot13_disguise(payload)
    show_result("2. ROT13 Disguise", result)

    result = getattr_disguise("os", "getcwd", "")
    show_result("3. getattr() Disguise", result)

    result = delay_disguise(payload, 3)
    show_result("4. Delayed Trigger Disguise", result)

    result = string_split_disguise("sensitive_word")
    show_result("5. String Split Disguise", result)

    print("\n" + "=" * 60)
    print("All tests completed.")
    print("=" * 60)


if __name__ == "__main__":
    main()