# SPIDER Methodology

Status tags: **Verified** (measured here, file named), **Reported** (taken from a teammate's file, not re-run by A), **Planned**. Static analysis only: "none detected in this scan" never means "safe".

## 1. Data
- **Malicious:** Backstabber's Knife Collection archives. 2,039 rows in `data/processed/malicious_v11.jsonl` after the v1.1 rescan (the v1 table had 2,045; 6 malformed archives did not extract under the safety limits). Verified: `results/rescan_v11_summary.md`.
- **Benign:** top-PyPI sdists, up to 2 versions per package. 2,909 rows in `data/processed/benign_v11.jsonl.gz` (v1: 2,908). Verified: same file.
- **What "benign" means here:** popular, long-lived packages. It says nothing about obscure packages (see §7).
- **Label noise:** malicious labels come from the collection and include placeholders and harmless PoCs. In a stratified sample of 30 zero-finding malicious packages, 5 were judged `actually_benign_label` (3 provisional). Verified: `results/zero_finding_review.csv`.

## 2. Provenance and grouping
Every row carries `group_id` (PEP 503 normalised name), `analyzer_version` (`analyzer-v1.1`), `ruleset_version` (`rules-v1.1`) and, for benign rows, `artifact_sha256`. Splits are made on `group_id`; no group appears in both classes (`spider_contract.dataset_check`). Columns that must not be used as ML features: label, source, malicious_evidence, collection_date, package_id, package_name, version, group_id, split, artifact_sha256, analyzer_version, ruleset_version, in_index, index_annotated, and also `strong_signals`, `verdict_outcome`, `review_recommended`, `s2_same_file` (derived from the same findings).

## 3. Analyzer v1 to v1.1
- v1 is frozen (`analyzer_v1_frozen.py`, sha256 `d35fb8a9…`, tag `analyzer-v1`). v1.1 is a separate module with import-alias resolution, constant `getattr` resolution and extra indicators, plus a directory engine with safe extraction.
- Parity on 300 benign + 300 malicious archives (seed 42, Kali). Verified: `results/parity_v1_vs_v11.md`. v1 equals the independent `scan_benign` re-implementation on 98.7% of benign packages; v1 equals v1.1 on 46.7% (benign) and 62.7% (malicious).
- Indicators v1.1 no longer emits (`.env`, `.netrc`, `compile`, `setuptools.setup`) were checked by hand on 1 to 3 examples each and were v1 false matches (docstring text, `re.compile`, non-setuptools `setup`). Not every example was checked.

## 4. Why not "any HIGH severity"
Reported in the brief (measured on the v1 tables on Day 1): raw HIGH fired on 67.2% of malicious and 61.0% of benign packages, mostly from plain `setup()`. The v1.1 verdict therefore uses combinations of signals.

## 5. Verdict v2
Three outcomes: `suspicious` (any strong signal S1 to S5), `unable_to_assess` (coverage problem), `none_detected_in_this_scan` (with an optional `review_recommended`). Verified rates on the rescan (`results/rescan_v11_summary.md`):

| | Malicious | Benign |
|---|---:|---:|
| suspicious | 32.6% | 12.0% |
| unable_to_assess | 2.1% | 6.3% |
| S1 install command | 19.4% | 0.9% |
| S2 dynamic exec + net/obf | 8.1% | 9.6% |
| S5 decode + exec | 4.6% | 6.1% |
| same-file S2 | 7.1% | 1.7% |

These are co-occurrence rates, not accuracy or detection rates. S2 and S5 fire as often on benign as on malicious; S1 separates the classes best.

## 6. Size confound
Median analysed `.py` files: 2 (malicious) vs 12 (benign). Package size alone gives AUC 0.2094 (about 0.79 read the other way); finding count alone gives 0.5635. Excluding `tests/`, `docs/` and `examples/` did not remove it. Suspicious rate, packages with at most 5 `.py` files: 30.6% vs 1.2%; larger: 41.5% vs 17.1%. ML metrics must be reported with and without `n_py_files` (Planned for B; see `results/v1_vs_v11_comparison.md`, Reported).

## 7. False-positive check
Selection frozen before scanning: 100 sdists from PyPI popularity ranks 5,000 to 15,000, at most 200 KB, at least one `.py` file, seed 42 (`results/fp_check_selection.csv`, `results/fp_check_archives.sha256`). Scanned offline with the same pipeline as the corpora (`Person_A/pipeline/fp_scan.py`). Verified: `results/fp_check_v11.csv`, `results/fp_check_summary.md`.
- 6 of 100 flagged suspicious, 2 unable_to_assess, 92 none detected (27 of them with `review_recommended`).
- Manual triage of the 6: 5 false positives, 1 unclear (a bootstrap script that downloads and executes code, in a legitimate project).
- Sentence to use: "On a sample of 100 small, obscure PyPI packages, 6 were flagged suspicious; after manual review 5 were false positives (5.0% of the sample, 95% Wilson CI 2.2% to 11.2%)." With the unclear one counted as a false positive: 2.8% to 12.5%. Counting each package family once: 2.5% to 13.0%.
- This is not "the false-positive rate of SPIDER". The sample is small, clustered (7 `mypy-*`, 5 `pyobjc-*`) and one reviewer labelled it.
- 4 of the 5 false positives share one cause: package-wide S2 combining a `setup.py` version-loading `exec` with unrelated network code (backlog B1).

## 8. Zero-finding review
See `docs/ANALYZER_BACKLOG.md` §A. 140 of 2,039 malicious rows have no findings; in a stratified sample of 30, 24 were `none_detected` and 6 `unable_to_assess`. Most were not hidden Python source: compiled payloads, empty stubs, label noise, dependency payloads and tooling limits.

## 9. Limitations
Static analysis only; no execution or sandbox. Labels are noisy. The benign set is popular packages. The FP sample is 100 packages and singly labelled. The adversarial batch is 12 synthetic samples around one payload type; v1.1 produced a finding for all 12 but only 1 reaches `suspicious` (Verified: `results/adv_batch_verification_by_A.md`). An install-time file over 2 MiB is skipped without a coverage warning (11 malicious archives, backlog B2). Rules are frozen for the demo.

## 10. Reproduction
Run from the repository root, with `SPIDER_RAW_MAL` and `SPIDER_RAW_BEN` set (data stays on the machine that holds it):
`python Person_A/pipeline/rescan_corpora.py --kind malicious|benign ...`, `python Person_A/analysis/rescan_summary.py`, `python Person_A/pipeline/parity_report.py`, `python Person_A/pipeline/fp_scan.py` then `python Person_A/analysis/fp_wilson.py`, `python Person_A/pipeline/zero_finding_sample.py`, `python -m unittest discover -s tests`.
