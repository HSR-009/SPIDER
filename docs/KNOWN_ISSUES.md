# SPIDER Known Issues & Limitations

This document catalogs known engineering limitations, behavioral boundaries, and edge cases in SPIDER v1.0.

---

## 1. Engine & Static Analysis Limitations

### 1.1 Package-Wide Combinations (`S2` & `S5`)
- **Issue**: Strong signals `S2_dynamic_exec_plus` (dynamic execution + network/obfuscation) and `S5_decode_exec` (base64 decode + execution) combine signals across the entire package.
- **Impact**: In large packages, an innocuous dynamic call in one module and a legitimate network request in another can trigger a false positive. In our false-positive benchmark of 100 small packages (`results/fp_check_summary.md`), 5 out of 6 flags were false positives caused primarily by `exec(open(...).read())` in `setup.py`.

### 1.2 Setup Script File Size Cap
- **Issue**: Root setup scripts (`setup.py`, `pyproject.toml`) exceeding 2 MiB are skipped during AST extraction to prevent denial-of-service.
- **Impact**: Oversized files are recorded in coverage under `limits_hit` (or as uninspected files). In the v1.1 corpus rescan (`results/rescan_v11_summary.md`), `limits_hit` was recorded for 1 benign package (and 0 malicious packages) as an unable-to-assess reason.

### 1.3 Uninspected & Binary Artifacts
- **Issue**: Compiled extensions (`.so`, `.pyd`, `.dll`), native binaries (`.exe`), and bytecode-only wheels (`.pyc`) are not disassembled.
- **Impact**: Payloads implemented purely in C extensions will not trigger AST signals. When uninspected files constitute >50% of the target, `uninspected_ratio` is recorded, potentially triggering `unable_to_assess`.

### 1.4 Syntax and Parse Failures
- **Issue**: Legacy Python 2 syntax (e.g. `print "text"`) and syntax errors fail parsing in Python 3.
- **Impact**: If parse failures exceed 20% of Python files, SPIDER assigns `unable_to_assess` with the `parse_failure_ratio` flag.

---

## 2. Environment Hunter Boundaries

### 2.1 Missing RECORD & top_level.txt on Debian Packages
- **Issue**: Debian system packages (`/usr/lib/python3/dist-packages`) frequently strip `.dist-info/RECORD` and `top_level.txt`.
- **Mitigation**: SPIDER applies filesystem directory probing around `<metadata_dir>/../<top_mod>/`. When ownership cannot be proven and both metadata files are absent, findings are reported as `LOW` ("ownership unknown") rather than `MEDIUM`.

### 2.2 Symlink Traversals Outside Site-Packages
- **Issue**: Some environments utilize complex symlinks pointing outside the site-packages root (e.g. editable installs, virtualenv shims).
- **Behavior**: For safety against filesystem loops and out-of-boundary scans, the Hunter does not follow symlinks outside the specified environment root.

### 2.3 Setuptools `distutils-precedence.pth` Flagged as HIGH
- **Issue**: Standard setuptools installations drop `distutils-precedence.pth` (and namespace stubs like `*-nspkg.pth`) containing one-line executable Python code (e.g. `enabled and __import__('_distutils_hack').add_shim();`).
- **Behavior**: Because the Hunter inspects `.pth` files for arbitrary executable code, any line containing executable statements (like `import` or `__import__`) triggers a `HIGH` finding as designed. Users can allowlist known standard stubs by SHA-256 via the Hunter allowlist.

