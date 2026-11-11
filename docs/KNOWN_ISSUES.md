# SPIDER Known Issues & Limitations

This document catalogs known engineering limitations, behavioral boundaries, and edge cases in SPIDER v1.0.

---

## 1. Engine & Static Analysis Limitations

### 1.1 Package-Wide Combinations (`S2` & `S5`)
- **Issue**: Strong signals `S2_dynamic_exec_plus` (dynamic execution + network/obfuscation) and `S5_decode_exec` (base64 decode + execution) combine signals across the entire package.
- **Impact**: In large packages, an innocuous dynamic call in one module and a legitimate network request in another can trigger a false positive. In our false-positive benchmark of 100 small packages (`results/fp_check_summary.md`), 5 out of 6 flags were false positives caused primarily by `exec(open(...).read())` in `setup.py`.

### 1.2 Setup Script File Size Cap
- **Issue**: Root setup scripts (`setup.py`, `pyproject.toml`) exceeding 2 MiB are skipped during AST extraction to prevent denial-of-service.
- **Impact**: Oversized files are marked as uninspected. If a package contains no other inspectable Python files, the verdict becomes `unable_to_assess`. In corpus testing, 11 malicious packages triggered this limit and resolved to `none_detected_in_this_scan` (`results/rescan_v11_summary.md`).

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

---

## 3. UI & Platform Considerations

### 3.1 Loopback Socket Constraints in Sandboxed Environments
- **Issue**: Running the API server (`spider serve`) or socket-based tests inside certain restricted sandboxes (e.g. Windows AppContainer or strict loopback policies) can fail with `[WinError 10013] An attempt was made to access a socket in a way forbidden by its access permissions`.
- **Mitigation**: `spider serve` handles port conflicts cleanly (exit code 2) and specifies `--port` instructions. Standard development should run outside isolation when binding loopback ports.

### 3.2 Offline Browser Generation
- **Issue**: The single-page React UI uses HTML5 Canvas and CSS animations. Generating headless screenshots on systems without Chrome or Edge requires pre-installed browser binaries.

