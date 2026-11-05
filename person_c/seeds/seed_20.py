"""
seed_20 — Install-Time / Package Execution
Indicator under test: custom build-backend reference

SAFETY: the call below is defined inside a function that is never invoked
(gated by `if False:`). It exists only so static AST analysis can find the
pattern. At runtime, only the marker print below ever executes.
"""

import subprocess


def _never_called():
    subprocess.run(["pip", "install", "extra-package"])


if False:
    _never_called()

print("MARKER_020")
