# Analyzer Backlog (future work — nothing here is implemented)

Status tags: **Verified** = measured in this repo (file named); **Reported** = stated by someone, not re-run; **Proposed** = idea only.
Rules are frozen for the v1 demo (tag `analyzer-v1.1`). Changing a rule means re-running both corpus rescans and recording before/after.

## A. What the zero-finding review says (n = 30, Verified: `results/zero_finding_review.csv`)
Sample: 30 malicious-labelled packages with `n_findings == 0` in `data/processed/malicious_v11.jsonl` (140 such rows of 2,039), stratified by archive-size tercile, 10 each, seed 42.
This is a small stratified sample, so the counts below describe this sample, not the population.

| Rank | Reason | n/30 | What it means | Idea (Proposed) |
|---|---|---:|---|---|
| 1 (tie) | `non_python_payload` | 6 | Compiled `.pyd`/`.so` core behind a thin Python loader. 4 of 6 were already `unable_to_assess`; 2 were `none_detected`. | Treat "package whose only real code is a compiled extension" as a coverage problem; flag import-time calls into compiled modules. |
| 1 (tie) | `empty_or_stub` | 6 | Name-squat / dependency-confusion probes with no behaviour (hello-world, "dummy package" template with a decoy module). | Not detectable from code. Needs package-name/metadata signals (out of scope for a static code analyzer). |
| 1 (tie) | `actually_benign_label` | 5 | Placeholders and harmless PoCs carrying a malicious label (3 of the 5 are provisional: keyword scan only). | Label-noise audit of the dataset; report metrics with this noise in mind. |
| 4 | `install_via_other_mechanism` | 4 | Payload is a dependency (e.g. a `-telemetry` package) or the sdist ships no source. 1 of 4 provisional (dependency not examined). | Resolve declared dependencies; flag dependencies that are new/unknown relative to a reference index. |
| 5 | `other` | 6 | 3x MCP tool descriptions with hidden instructions aimed at an AI agent; 1x oversized `setup.py` skipped by the size cap; 2x Python 2 syntax (parse failure). | See B2, B3, B4 below. |
| 6 | `api_not_in_ruleset` | 3 | LLM API client modules with hard-coded API keys; no rule covers the client or embedded secrets. | Secret-pattern rule (hard-coded API keys); add common LLM/HTTP client libraries to the network category. |

Verdicts of the 30: 24 `none_detected_in_this_scan`, 6 `unable_to_assess` (Verified, same CSV). Only the 3 `mathepy` packages are plain Python source that a rule could plausibly match.

## B. Measured limitations worth fixing first
- **B1. Package-wide S2/S5 combine unrelated files.** In the FP check (Verified: `results/fp_check_v11.csv`), 5 of 6 flagged packages were false positives; 4 of the 5 came from the common `exec(open(...).read(), about)` version-loading idiom in `setup.py` plus a network or base64 call elsewhere. Corpus rates (Verified: `results/rescan_v11_summary.md`): S2 8.1% malicious vs 9.6% benign, but same-file S2 7.1% vs 1.7%. Proposed: require the same file (or same function) for S2/S5, and ignore `exec` of a file read in `setup.py` for version loading. Needs a full rescan and a before/after table.
- **B2. Oversized install file is skipped silently.** A root `setup.py` over the 2 MiB member cap is skipped as `too_large`; coverage only warns when more than half of non-doc files are uninspected. Measured: 11 of 4,330 malicious archives and 0 of 2,909 benign archives have a root `setup.py`/`pyproject.toml` over 2 MiB, and all 11 matching rows in `malicious_v11.jsonl` are `none_detected_in_this_scan` (Verified, run on Kali). Proposed fix: any uninspected install-role file (`setup.py`, `pyproject.toml`, `setup.cfg`) forces `unable_to_assess` (one line in `spider_contract/verdict.py: coverage_problems`). It would change 11 rows (0.54% of 2,039), so it needs a rescan and a version bump, not a quiet edit.
- **B3. Python 2 sources do not parse.** Two zero-finding packages had a Python 2 `setup.py` (`print` statement, octal literal). They were correctly `unable_to_assess`, not silent. Proposed: a lenient fallback (e.g. token/regex scan) for files that fail to parse.
- **B4. Payloads aimed at AI agents.** MCP tool descriptions and docstrings can carry instructions for an LLM agent. The rules read code, not prose for models. Proposed: a separate text-level check on tool descriptions (new category).
- **B5. ROT13 is not treated as obfuscation.** `codecs.decode(x, 'rot_13')` does not set an Obfuscation finding, so the ROT13 sample in the adversarial batch does not reach `suspicious` while the base64 one does (Verified: `results/adv_batch_verification_by_A.md`).
- **B6. Non-constant `getattr` / dynamic names** are only partly resolved; 6 of 12 adversarial samples stayed silent at verdict level (same file).
- **B7. macOS `._*` AppleDouble files** break the v1 reader (7 exceptions in the 600-archive parity sample, Verified: `results/parity_v1_vs_v11.md`). v1.1 handles them differently; skipping them is a data-affecting change, so deferred.

## C. Smaller items
- `target.hash_verified` is `null` for collection archives; only real PyPI downloads can set it.
- Replay fixtures 08 and 09 share an author; use distinct authors.
- The five `fixture_0N_*` files in `fixtures/records` are Person C's old-schema files and fail validation; move them to `person_c/` and fix the generator.
