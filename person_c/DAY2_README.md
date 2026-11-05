# Day 2 — Person C Deliverables

## What's in this delivery

1. **`seeds/`** — 20 harmless synthetic seed files covering all 6 confirmed-implemented
   analyzer categories (Command Execution, Dynamic Code Execution, Credential/Data
   Access, Network Activity, Obfuscation, Install-Time/Package Execution). Note:
   Supply-Chain Abuse is a declared taxonomy category but has no implemented
   detection rule yet, so no seeds target it — see `seeds/generate_seeds.py` for
   the full spec table, and `seeds/manifest.json` for the generated mapping.

2. **`transformations_ext.py`** — T06-T09, extending the existing T01-T05 set in
   `disguises.py`:
   - T06 `import_alias_disguise()` — import under an alias
   - T07 `dunder_import_disguise()` — resolve via `__import__()` or `importlib`
   - T08 `chr_build_disguise()` — build a word from `chr()` codes
   - T09 `hex_escape_disguise()` — build a word via `bytes.fromhex(...).decode()`

   These specifically target the new v1.1 analyzer rules (non-constant
   `__import__`/`importlib` args, `bytes.fromhex().decode()`, `chr()` joins).

3. **`equivalence_harness.py`** — AST pre-flight reachability check (rejects any
   seed where a dangerous call is reachable at module scope, not just present
   anywhere in the file) + isolated subprocess execution + marker comparison.
   Run it: `python equivalence_harness.py`. Writes results to
   `results/equivalence_harness_day2.json`.

4. **`test_harness_safety.py`** — the explicit safety test required by the Day 2
   spec: proves no seed ever actually invokes `exec`, `eval`, `os.system`, or
   `subprocess` at runtime, via monkeypatched guards. Run it:
   `python -m unittest test_harness_safety -v`

## Design note: why every seed is safe

Every seed's risky call lives inside a function (or class method) that is
**never invoked** — the call site itself is gated behind `if False:`. This
means:
- Static AST analysis still finds the pattern (exactly how a real malware
  scanner works — it flags code regardless of runtime reachability)
- At actual runtime, only `print(MARKER)` ever executes
- The equivalence harness and safety test both verify this is true, not just
  assume it

## Two real bugs found and fixed during testing (worth knowing about)

**1. Importing real `setuptools` has side effects.** The original `seed_18`
imported `from setuptools.command.install import install` at module level.
Even though the risky call itself was properly guarded, importing real
setuptools triggers its own internal machinery. Fix: the import itself is
now also inside the `if False:` guard, so setuptools is never actually
imported at runtime by this seed.

**2. Importing certain stdlib modules for the first time in a process calls
`eval()` internally**, unrelated to anything in our code. Specifically,
`urllib.request`'s import chain reaches `collections.namedtuple`, whose
`__new__` method is built using `eval()` as normal CPython stdlib behavior.
This tripped the safety test's `eval` guard on `seed_12`, `seed_13`, and
`seed_14` (all network-related) the first time they ran in a fresh process.
Fix: `test_harness_safety.py` now "warms up" these modules once before
installing any guards, so their one-time import side effects happen safely
beforehand.

**Why this matters for the team:** both of these are genuine discoveries
about how Python's import system behaves, not flaws in the seed design
itself. Worth mentioning in the report's methodology section as an example
of why "run the code and see what happens" isn't a naive check — even
getting a synthetic, deliberately harmless test seed to run cleanly surfaced
real nuances in how CPython and setuptools behave on import.

## Test results summary

- **20/20 seeds**: syntax valid, pass AST pre-flight, marker output matches expected
- **20/20 seeds**: pass the explicit safety test (no guard ever tripped)
- **4/4 new transformations (T06-T09)**: syntax-valid and behaviorally correct
  (reconstruction matches original word/call for T06-T09)
- Pre-flight and safety-test logic both independently verified to **actually
  reject** deliberately unsafe test code (not rubber-stamping everything)

## What's NOT done yet (explicitly deferred per sprint scope)

- Wiring T01-T09 transformations directly onto each seed to produce actual
  transformed variant files (the harness currently demonstrates the pipeline
  on original seeds; per-technique wiring is part of Day 3's UI MVP /
  ongoing evasion table work, to avoid redundant complexity today)
- The Cytoscape.js graph spike (separate Day 1/7 task per the latest sprint plan)
- Full evasion scoring against the real analyzer — that depends on Person A's
  `analyzer_v1_1` module and `scan_directory()`, not yet landed as of this delivery
