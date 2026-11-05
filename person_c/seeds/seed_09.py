"""
seed_09 — Credential / Data Access
Indicator under test: .ssh/ path access

SAFETY: the call below is defined inside a function that is never invoked
(gated by `if False:`). It exists only so static AST analysis can find the
pattern. At runtime, only the marker print below ever executes.
"""

import os


def _never_called():
    open(os.path.expanduser("~/.ssh/id_rsa"))


if False:
    _never_called()

print("MARKER_009")
