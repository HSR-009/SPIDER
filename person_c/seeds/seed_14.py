"""
seed_14 — Network Activity
Indicator under test: urllib.request.urlopen

SAFETY: the call below is defined inside a function that is never invoked
(gated by `if False:`). It exists only so static AST analysis can find the
pattern. At runtime, only the marker print below ever executes.
"""

import urllib.request


def _never_called():
    urllib.request.urlopen("http://example-fake-domain.test")


if False:
    _never_called()

print("MARKER_014")
