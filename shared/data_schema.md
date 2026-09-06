# SPIDER Dataset Schema

## Purpose

This document defines the structure and fields used to identify and label
Python packages in the SPIDER dataset.

Each dataset record represents one specific package version.

---

## Dataset Record

| Field | Description |
|---|---|
| package_id | Unique identifier for the package/version |
| package_name | Name of the Python package |
| version | Specific package version |
| label | 0 = benign, 1 = malicious |
| source | Where the package/sample came from |
| malicious_evidence | Evidence supporting the malicious label |
| collection_date | Date the sample was collected |

---

## Labels

- `0` = Benign
- `1` = Malicious

---

## Sources

### Malicious

Primary source:

- Backstabber's Knife Collection

Supporting validation:

- OSV.dev
- GitHub Advisory Database

### Benign

- Popular PyPI packages
- Target corpus: approximately 3,000–5,000 packages

---

## Important Rule

A record represents a specific package version, not just a package name.

Example:

package_name = requests
version = 2.31.0

and

package_name = requests
version = 2.32.0

are treated as separate package/version records.

Package/version identifiers will later be used by the ML pipeline for
leakage-safe dataset splitting.
