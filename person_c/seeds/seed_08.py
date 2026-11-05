"""
seed_08 — Dynamic Code Execution
Indicator under test: __import__

SAFETY: the call below is defined inside a function that is never invoked
(gated by `if False:`). It exists only so static AST analysis can find the
pattern. At runtime, only the marker print below ever executes.
"""




def _never_called():
    __import__("os")


if False:
    _never_called()

print("MARKER_008")
