"""
seed_07 — Dynamic Code Execution
Indicator under test: compile+exec

SAFETY: the call below is defined inside a function that is never invoked
(gated by `if False:`). It exists only so static AST analysis can find the
pattern. At runtime, only the marker print below ever executes.
"""




def _never_called():
    exec(compile("x = 1", "<string>", "exec"))


if False:
    _never_called()

print("MARKER_007")
