"""
seed_12 — Network Activity
Indicator under test: requests.get

SAFETY: the call below is defined inside a function that is never invoked
(gated by `if False:`). It exists only so static AST analysis can find the
pattern. At runtime, only the marker print below ever executes.
"""

import requests


def _never_called():
    requests.get("http://example-fake-domain.test")


if False:
    _never_called()

print("MARKER_012")
