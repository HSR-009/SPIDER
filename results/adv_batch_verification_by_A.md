# Adversarial Batch Verification Report (Person A)

## 1. Manifest & File Integrity Verification
- **Published Manifest Hash**: `bb7f4fe8676000ef1e2f06e08d8387738e8ee4a3c33ac68ade289ffd8875aaa3`
- **Computed Raw Bytes Hash**: `45d796aedd312aade931ddd1a8ffcfd489a1eae7511f224ab35d37100c1bed01`
- **Computed Canonical JSON Hash**: `dba86fa4a50641ee0e6200ba1186e60a57e42e5ff6053044871b1f7c46d0032d`
- **Computed Hash via `freeze_batch.py` Method**: `bb7f4fe8676000ef1e2f06e08d8387738e8ee4a3c33ac68ade289ffd8875aaa3`
- **Hash Match Status**: **MATCH** (matches via `freeze_batch_method`).
- **Sample Files Integrity Check** (matching `samples/adv_*.py` to manifest `generated_code`):
  - All 12 sample files in `samples/` exactly match manifest `generated_code`.

## 2. Per-Sample Verification Table (Finding-Level and Engine Verdict-Level)

| Sample ID | Technique | A v1 | C v1 | Agree v1 | A v1.1 | C v1.1 | Agree v1.1 | Baseline Verdict | Adv Verdict | Adv Reasons | Review Rec |
|---|---|---|---|:---:|---|---|:---:|---|---|---|:---:|
| `adv_000` | `T01_string_split` | `missed` | `missed` | YES | `different_signal` | `different_signal` | YES | `none_detected_in_this_scan` | `none_detected_in_this_scan` | `none` | False |
| `adv_001` | `T02_base64` | `different_signal` | `different_signal` | YES | `different_signal` | `different_signal` | YES | `none_detected_in_this_scan` | `suspicious` | `S2_dynamic_exec_plus, S5_decode_exec` | False |
| `adv_002` | `T03_rot13` | `different_signal` | `different_signal` | YES | `different_signal` | `different_signal` | YES | `none_detected_in_this_scan` | `none_detected_in_this_scan` | `none` | True |
| `adv_003` | `T04_getattr` | `missed` | `missed` | YES | `different_signal` | `different_signal` | YES | `none_detected_in_this_scan` | `none_detected_in_this_scan` | `none` | False |
| `adv_004` | `T05_delay` | `recovered` | `recovered` | YES | `recovered` | `recovered` | YES | `none_detected_in_this_scan` | `none_detected_in_this_scan` | `none` | True |
| `adv_005` | `T05_delay` | `recovered` | `recovered` | YES | `recovered` | `recovered` | YES | `none_detected_in_this_scan` | `none_detected_in_this_scan` | `none` | True |
| `adv_006` | `T06_import_alias` | `missed` | `missed` | YES | `recovered` | `recovered` | YES | `none_detected_in_this_scan` | `none_detected_in_this_scan` | `none` | True |
| `adv_007` | `T07_dunder_import` | `missed` | `missed` | YES | `different_signal` | `different_signal` | YES | `none_detected_in_this_scan` | `none_detected_in_this_scan` | `none` | False |
| `adv_008` | `T08_chr_build` | `missed` | `missed` | YES | `different_signal` | `different_signal` | YES | `none_detected_in_this_scan` | `none_detected_in_this_scan` | `none` | False |
| `adv_009` | `T09_hex_escape` | `missed` | `missed` | YES | `different_signal` | `different_signal` | YES | `none_detected_in_this_scan` | `none_detected_in_this_scan` | `none` | False |
| `adv_010` | `T06_import_alias+T04_getattr` | `missed` | `missed` | YES | `recovered` | `recovered` | YES | `none_detected_in_this_scan` | `none_detected_in_this_scan` | `none` | True |
| `adv_011` | `T06_import_alias+T01_string_split+T04_getattr` | `missed` | `missed` | YES | `different_signal` | `different_signal` | YES | `none_detected_in_this_scan` | `none_detected_in_this_scan` | `none` | False |

## 3. Finding-Level Summary

> [!NOTE]
> Note: Finding-level evasion rate measures whether the specific baseline indicator or an auxiliary finding fired; it is a feature-level metric, not a package detection rate.

| Analyzer | Recovered | Different Signal | Missed (Evaded) | Finding-Level Evasion Rate |
|---|---:|---:|---:|---:|
| **Frozen v1 (`analyzer_v1_frozen.py`)** | 2 | 2 | 8 | **66.67%** |
| **Hardened v1.1 (`spider.engine.scan`)** | 4 | 8 | 0 | **0.00%** |

## 4. Real v1.1 Engine Verdict-Level Summary

| Verdict Classification | Sample Count | Percentage of Batch |
|---|---:|---:|
| **Suspicious** (strong signal triggered) | 1 | 8.3% |
| **Review-Kept** (`none_detected_in_this_scan` with `review_recommended: true`) | 5 | 41.7% |
| **Silent** (`none_detected_in_this_scan` without review) | 6 | 50.0% |

## 5. Comparison with Person C Published Data
- **Measured v1 Misses**: 8 of 12 samples (66.67% finding-level evasion rate).
- **Measured v1.1 Misses**: 0 of 12 samples (0.00% finding-level evasion rate).
- **Person C Published v1 Counts**: recovered=2, different_signal=2, missed=8 (finding-level evasion rate: 66.67%).
- **v1 Count Match**: Measured v1 counts exactly match C table summary.
- **Sample-Level Agreement**: 100% agreement between A's evaluation and C's published per-sample outcomes.

## Interpretation (to be written by a human)

**Reviewed by Harsh (Person A), 2026-11-07.**

- **Integrity:** the manifest content hash matches the published value (via the `freeze_batch` method, not raw file bytes), and all 12 sample files equal the manifest's `generated_code`.
- **Reproduction:** A's outcomes equal C's on all 12 samples for both v1 and v1.1 (24/24).
- **Finding-level:** v1 misses 8 of 12 (66.67%) and v1.1 misses 0 of 12. This only says v1.1 emitted some finding. It is not a detection rate.
- **Verdict-level:** only 1 of 12 adversarial samples is `suspicious` (base64: S2 + S5). 5 keep `review_recommended` and 6 are silent (no verdict signal and no review flag): string split, getattr, dunder import, chr build, hex escape and the three-technique combination.
- **Baseline caveat:** the plain `os.system("echo ...")` baseline is itself only `none_detected` with `review_recommended` under verdict v2, so this batch cannot show evasion of a `suspicious` verdict. It does show evasion of the review flag in 6 of 12 samples.
- **Gap noted:** base64 wrappers reach `suspicious` but the ROT13 equivalent does not, because `codecs.decode(..., 'rot_13')` is not treated as obfuscation. Recorded for the threat model; not fixed this sprint.
- **Limits:** 12 synthetic samples built around one payload type. C's `normalize.py` and the v1 + normalize and v1.1 + normalize columns were not verified here.
