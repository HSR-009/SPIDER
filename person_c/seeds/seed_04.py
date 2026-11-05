"""
seed_04 — Command Execution
Indicator under test: os.popen

SAFETY: the call below is defined inside a function that is never invoked
(gated by `if False:`). It exists only so static AST analysis can find the
pattern. At runtime, only the marker print below ever executes.
"""

import os


def _never_called():
    os.popen("echo hello")


if False:
    _never_called()

print("MARKER_004")
