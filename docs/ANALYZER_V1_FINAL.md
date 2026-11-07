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
TO FILL
