# Analyzer v1 Final Specification and Freeze Record

analyzer.py is frozen; never edited after this tag.

## Frozen Artifact Identification
- **Module Path:** `Person_A/ast_analyzer/analyzer_v1_frozen.py` (baseline for v1) / `Person_A/ast_analyzer/analyzer.py`
- **Frozen Baseline Commit:** `8228f43`
- **SHA-256 (LF normalized):** `d35fb8a9e43cc76bd6fecf53b9288a36a1c8637dd007c37a5eeb120aa028b1f5`

## Emitted Security Categories
The AST analyzer emits findings across six active behavioral categories (plus analysis status):
1. **Command Execution** (`HIGH`)
2. **Dynamic Code Execution** (`HIGH`)
3. **Credential / Data Access** (`HIGH`)
4. **Network Activity** (`MEDIUM`)
5. **Obfuscation** (`MEDIUM`)
6. **Install-Time / Package Execution** (`HIGH` / `LOW`)
*(Note: "Parse Error" is handled as an operational parse failure status).*

## Finding Schema (Six Fields)
Every finding emitted by v1 contains exactly six fields:
1. `category` (string): The security category name.
2. `indicator` (string): The rule identifier / target API indicator (e.g. `os.system`, `eval`).
3. `severity` (string): `HIGH`, `MEDIUM`, or `LOW`.
4. `file` (string): Path to the source file analyzed.
5. `line` (integer): Line number where the indicator was detected.
6. `evidence` (string): Textual description or excerpt explaining the detection.

## Known Blind Spots (P2 List)
The initial v1 analyzer has known syntactic blind spots:
1. `from os import system` (import alias / direct function imports).
2. `subprocess.check_output`, `subprocess.call`, etc. (untracked subprocess variants).
3. `os.popen` (untracked process invocation APIs).
4. `from urllib.request import urlopen` (alternative network APIs).
5. `getattr` indirection (e.g. `getattr(os, "system")`).

These blind spots are addressed and hardened in `analyzer_v1_1.py` under the v1.1 ruleset.

## Parity Numbers
Measured from 300 benign and 300 malicious archives on Kali (seed 42):
- **v1 equals scan_benign**: 296 of 300 benign (98.7%).
- **v1 equals v1.1**: 140 of 300 benign (46.7%) and 188 of 300 malicious (62.7%).
- **Lost indicators (with manually confirmed reasons)**:
  - `.env` (93 benign, 9 malicious): v1 matched docstring text; v1.1 requires a real path component.
  - `.netrc` (2): docstring text.
  - `compile` (7): `re.compile` imported by name.
  - `setuptools.setup` (15): non-setuptools setup.
- **v1 analyzer exceptions**: 7 exceptions (UnicodeDecodeError on `._*` macOS metadata files and one binary-looking file).
- **Note on manual checking**: Examples were manually checked for 1 to 3 cases per indicator, not all.
