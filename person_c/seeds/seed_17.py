"""
seed_17 — Obfuscation
Indicator under test: ROT13 decode

SAFETY: the call below is defined inside a function that is never invoked
(gated by `if False:`). It exists only so static AST analysis can find the
pattern. At runtime, only the marker print below ever executes.
"""

import codecs


def _never_called():
    codecs.decode("rknp(\"k=1\")", "rot_13")


if False:
    _never_called()

print("MARKER_017")
