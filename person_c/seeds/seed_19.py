"""
seed_19 — Install-Time / Package Execution
Indicator under test: setup.py top-level side effect

SAFETY: the call below is defined inside a function that is never invoked
(gated by `if False:`). It exists only so static AST analysis can find the
pattern. At runtime, only the marker print below ever executes.
"""

import os


def _never_called():
    os.system("echo setup-time side effect")


if False:
    _never_called()

print("MARKER_019")
