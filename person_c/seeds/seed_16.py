"""
seed_16 — Obfuscation
Indicator under test: bytes.fromhex+decode

SAFETY: the call below is defined inside a function that is never invoked
(gated by `if False:`). It exists only so static AST analysis can find the
pattern. At runtime, only the marker print below ever executes.
"""




def _never_called():
    bytes.fromhex("78203d2031").decode()


if False:
    _never_called()

print("MARKER_016")
