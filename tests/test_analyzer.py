import sys
sys.path.insert(0, ".")

from Person_A.ast_analyzer.analyzer import analyze_file

result = analyze_file(
    "data/toy_samples/malicious/compile.py"
)

print(result)
