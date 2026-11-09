# False-Positive Evaluation Summary

> [!IMPORTANT]
> On a sample of 100 small, obscure PyPI packages, 6 were flagged suspicious; after manual review 5 were false positives (plus 1 unclear) (5.0%, 95% CI [0.0215, 0.1118]). This evaluates precision on small, obscure PyPI packages and is not the false-positive rate of SPIDER in general.

## 1. Package-Level Results

- **Packages Scanned (n):** 100
- **Flagged Suspicious:** 6
- **Unable to Assess:** 2
- **Review Recommended:** 27

### Triage Breakdown
- **False Positives (FP):** 5 (5.0%)
- **True Positives (TP):** 0
- **Unclear:** 1

### Wilson 95% Confidence Intervals
- **FP only (unclear counted as true positives):** [0.0215, 0.1118] (2.2% – 11.2%)
- **FP + unclear (unclear counted as false positives):** [0.0278, 0.1248] (2.8% – 12.5%)

## 2. Family-Level Results

- **Distinct Package Families (n):** 85
- **Families Flagged Suspicious:** 6
- **Family False Positives:** 5 (5.9%)
- **Family True Positives:** 0
- **Family Unclear:** 1

### Family Wilson 95% Confidence Intervals
- **FP only (unclear counted as true positives):** [0.0254, 0.1304] (2.5% – 13.0%)
- **FP + unclear (unclear counted as false positives):** [0.0328, 0.1456] (3.3% – 14.6%)

