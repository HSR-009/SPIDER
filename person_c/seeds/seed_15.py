"""
seed_15 — Obfuscation
Indicator under test: base64.b64decode+exec

SAFETY: the call below is defined inside a function that is never invoked
(gated by `if False:`). It exists only so static AST analysis can find the
pattern. At runtime, only the marker print below ever executes.
"""

import base64


def _never_called():
    exec(base64.b64decode("eD0x"))


if False:
    _never_called()

print("MARKER_015")
