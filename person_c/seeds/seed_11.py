"""
seed_11 — Credential / Data Access
Indicator under test: os.environ secret read

SAFETY: the call below is defined inside a function that is never invoked
(gated by `if False:`). It exists only so static AST analysis can find the
pattern. At runtime, only the marker print below ever executes.
"""

import os


def _never_called():
    os.environ.get("AWS_SECRET_ACCESS_KEY")


if False:
    _never_called()

print("MARKER_011")
