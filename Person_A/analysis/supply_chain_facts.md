# SPIDER Supply-Chain Facts

## Dataset scope

The Backstabber's Knife Collection index contains 38,969 records across ecosystems.
The PyPI subset contains 6,428 records. The figures below use only records whose
individual metadata field has a known, non-null value.

| Field | Annotated records | Observed values |
|---|---:|---|
| trigger | 336 | install: 219; runtime: 117 |
| injectionComponent | 1,221 | name confusion: 1,086; trojan horse: 120; subvert legitimate package: 13; compromised repository system: 2 |
| objective | 366 | data exfiltration: 171; dropper: 61; backdoor: 52; botnet: 41; financial gain: 18; dropper/loader: 10; research: 9; denial of service: 2; backdoor + data exfiltration: 2 |
| obfuscated | 1,024 | true: 1,010; false: 14 |
| obfuscation | 1,022 | base64: 905; encoding: 43; pyarmor: 21; none: 14; hyperion: 14; dependency confusion + encoding: 11; pyobfusinator: 10 |
| typoTarget | 1,021 | Common targets include requests (61), requests-toolbelt (40), cryptography (34), websocket-client (34), beautifulsoup4 (32) |
| campaign | 2,627 | Includes numeric identifiers and named values; do not assume every value is a descriptive campaign name. |

## Interpretation

- Name confusion dominates the annotated injection-component values.
- Install-time and runtime triggers are both represented; install is more common among annotated trigger records.
- Base64 is the dominant recorded obfuscation method.
- Data exfiltration is the most common recorded objective in the displayed objective counts.
- These counts describe annotations, not independently verified ground truth.
- Each field has a different annotation denominator. Do not divide these counts by 6,428 and call the result the annotation rate for all fields.
- The index includes multiple ecosystems; the figures above specifically filter to PyPI using the purl prefix.

## Relevance to SPIDER

AST indicators can identify suspicious code behavior, but they cannot reliably detect name-confusion attacks from source code alone. Package-name similarity, metadata, install behavior, and code indicators should be evaluated as separate feature groups.

### Analyzer v1: Observed Gaps in Real-World Samples

The Day 7 analysis identified limitations in the frozen AST analyzer v1. Obfuscation annotation agreement was only 21 of 59 reviewed cases (35.6%), and approximately 529 packages had no `setup.py`. Roughly 86 packages were empty placeholders or similar low-content samples. Examples of observed gaps included `amazon-boto`, which contained credential-exfiltration behavior, and `maratlib`, which used dynamic import and obfuscated execution patterns. Compiled `.so` payloads and `.pth` files also represent analysis challenges that a Python AST-only approach cannot fully cover.

### Dataset Coverage and Campaign Concentration

The local malicious scan covered 2,040 of the 6,428 PyPI records in the dataset index, or approximately 31.7%. Among 2,627 records with campaign annotations, campaign IDs 30 and 47 account for 1,524 records combined. This concentration means that evaluation results may reflect campaign-specific patterns and should not automatically be generalized to unseen campaigns or malicious packages.

### Obfuscation Annotation Versus Detection

Of 1,024 PyPI records with obfuscation annotations, 1,010 were annotated as obfuscated. However, analyzer v1 flagged Obfuscation in approximately 22% of the locally scanned malicious package-version rows. These figures measure different things: the index contains annotations about known obfuscation, while v1 flags detectable patterns in available local source files. The difference highlights a coverage limitation; it does not, by itself, establish the exact false-negative rate.
