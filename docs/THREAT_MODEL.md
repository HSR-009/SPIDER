# SPIDER Threat Model (v1 demo)

Status tags: **Verified** / **Reported** / **Planned**. This document complements the earlier draft in `Person_A/threat_model/threat_model.md`.

## 1. Scope and non-goals
SPIDER inspects Python package source and installed files without running them. It does not run packages, sandbox them, watch network traffic or detect kernel-level compromise. **Residual risk statement:** "none detected in this scan" means the static rules found nothing; it never means the package is safe.

## 2. Assets
The developer machine, CI runners, and the credentials and tokens reachable from them.

## 3. Attackers
Typosquatters, dependency-confusion probers, account-takeover attackers, malicious maintainers.

## 4. Attack stages and what SPIDER sees
| Stage | Typical artifact | SPIDER sees it? | Misses |
|---|---|---|---|
| Name squat / probe | empty or dummy package | No code to see (6 of 30 zero-finding sample) | Needs metadata signals |
| Install-time hook | `setup.py` install command override | **Yes**: S1 (19.4% of malicious vs 0.9% of benign, Verified `results/rescan_v11_summary.md`) | Oversized `setup.py` (>2 MiB) is skipped without a warning (11 of 4,330 malicious archives, 0 of 2,909 benign) |
| Import-time payload | module-level exec/network/environ | Partly: S2 to S5 combinations | Package-wide S2 and S5 are noisy (see §5) |
| Runtime payload | function bodies | Partly | Same |
| Compiled payload | `.pyd` / `.so` | No (reported as uninspected; 4 of 6 compiled-payload samples ended `unable_to_assess`) | Binary analysis is out of scope |
| Dependency payload | malicious dependency in `requires.txt` | No | Dependency resolution is future work |
| Agent-targeted text | instructions hidden in MCP tool descriptions | No | Needs a text-level check |
| Installed-machine persistence | `.pth` executable lines, `sitecustomize`, entry points, modified files | **Hunter-lite** (read-only) | See §6 |

## 5. Detection signals and measured behaviour
Verdict v2 combines five signals (S1 install command, S2 dynamic exec plus network or obfuscation, S3 credential path plus network, S4 `os.environ` plus `requests.post`, S5 base64 decode plus exec). Verified rates are in `docs/METHODOLOGY.md` §5. Precision check on 100 small obscure packages: 6 flagged, 5 false positives, 1 unclear (sample, not a general rate; `results/fp_check_summary.md`).

## 6. Hunter-lite
Reads files only; never imports or executes scanned packages; caps file size and time. First real run on a Kali VM: 773 installed distributions, 243 items after fixes, none malicious on manual review (`results/hunter_kali_notes.md`). A clean hunt does not mean the machine is clean. Detection of planted `.pth`, startup-hook, entry-point and tamper cases is covered by planted test cases only; no real malicious installed package was available.

## 7. Evasions measured
Source: Person C's adversarial batch `adv-batch-v1`, 12 synthetic samples around one payload type, reproduced by A (24 of 24 per-sample outcomes agree; `results/adv_batch_verification_by_A.md`).
- Finding level: v1 missed 8 of 12 (66.67%), v1.1 missed 0 of 12. This is a feature-level metric, not a detection rate.
- Verdict level (real v1.1 engine): 1 of 12 `suspicious` (base64), 5 with `review_recommended`, 6 silent (string split, getattr, dunder import, chr build, hex escape, three-technique combination).
- Gap: ROT13 does not reach `suspicious`; base64 does.
- Not yet covered: pickle/marshal payloads, `ctypes`, payloads in data files, non-constant `getattr`.
- C's `normalize.py` columns were not verified by A.

## 8. Operational risks of the scanner itself
Archives are treated as hostile data: only regular files are extracted; symlinks, hardlinks, devices, absolute and `..` paths and Windows reserved names are rejected; limits on file count, bytes, member size, depth and expansion ratio; extraction directory removed afterwards (`spider/engine/extract.py`; tests `tests/test_extract.py`, `tests/test_hostile_archives.py`, including a test that scanned code is never executed). The limits themselves create the blind spot in backlog B2.

## 9. Future work
Same-file S2/S5, hard-coded secret rule, dependency resolution, compiled-extension coverage rule, text-level check for agent-targeted payloads, a dynamic sandbox (out of scope for v1). See `docs/ANALYZER_BACKLOG.md`.
