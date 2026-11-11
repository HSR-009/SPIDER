# SPIDER

Static analysis for Python packages: a local tool that scans a package for suspicious code, checks an installed environment for persistence artifacts, and measures how well its own rules hold up against evasion. It never executes package code.

> **Status: v1 demo.** Rules are frozen (`analyzer-v1.1`). Numbers below come from files in `results/`. Anything not measured is marked *planned*.

## What it tells you

Every scan ends in one of three verdicts. SPIDER never says "safe".

| Verdict | Meaning | CLI exit code |
|---|---|---|
| `suspicious` | Strong combination of signals found; evidence lines are shown | 10 |
| `none_detected_in_this_scan` | No strong signal in the code that was inspected. Not a safety claim. `review_recommended` may be set | 0 |
| `unable_to_assess` | Too much of the package could not be inspected (native binaries, parse failures, limits hit) | 20 |

Exit code 2 means an error (bad target, network disabled, schema failure).

## Quick start

Python 3.10+.

```bash
git clone https://github.com/HSR-009/SPIDER.git
cd SPIDER
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m unittest discover -s tests

# Scan a directory, an archive (.tar.gz/.zip/.whl) or a PyPI release (needs network)
python -m spider scan fixtures/src/demo-installhook     # expect: suspicious (exit 10)
python -m spider scan fixtures/src/demo-httpclient      # expect: none detected (exit 0)
python -m spider scan some_package==1.0.0 --json

# Look through installed environments for persistence artifacts
python -m spider hunt
python -m spider hunt --site-packages /path/to/site-packages --json
```

### Run the UI (local, loopback only)

No Node.js needed. The built UI ships in the repo (`spider/static_ui/`).

```bash
python -m spider serve               # opens http://127.0.0.1:8000/ in your browser
```

`serve` binds to 127.0.0.1 only, rejects other hosts and origins, and runs the engine without executing package code. Add `--no-browser` to skip opening the browser, or `--port 8010` to change the port.

To change the UI itself (Node 20+): `cd spider-ui`, `npm install`, `npm run dev` for live development with sample data, or `npm run build:serve` to rebuild `spider/static_ui/`. Details: `spider-ui/INTEGRATION.md`.

Scan records are written to `scans/<scan_id>.json` and validate against the `scan_record` v0.1 schema in `spider_contract/`.

## What is in the repo

| Area | Where | State |
|---|---|---|
| Scan engine: safe archive extraction, AST rules, verdict policy | `spider/engine/`, `spider_contract/` | Built, tested |
| CLI (`scan`, `hunt`) | `spider/cli.py` | Built, tested |
| Hunter: `.pth` files, `sitecustomize`, entry points, `RECORD` tamper checks | `spider/hunter/` | Built, tested on planted cases; one real-environment run, see `results/hunter_kali_notes.md` |
| Resilience Lab: disguise generators and an adversarial batch of 12 samples | `person_c/`, `spider/normalize.py` | Built; normalization is opt-in with `scan --normalize` |
| ML baseline and resilience evaluation | `Person_B/`, `docs/ML_METHODOLOGY.md`, `results/resilience_table.md` | Built; read the methodology caveats before quoting any number |
| Investigation UI | `spider-ui/` (React source), built into `spider/static_ui/` and served by `python -m spider serve` (`spider/api.py`) | Built; tested end to end on fixtures. The older Streamlit prototype is in `spider/ui/` |
| Live PyPI monitoring, dependency resolution, secret scanning, LLM-agent payloads | | *Planned*, see `docs/ANALYZER_BACKLOG.md` |

## Measured results

Corpora: 2,039 malicious-labelled and 2,909 benign packages, scanned with analyzer v1.1 (`results/rescan_v11_summary.md`).

| | Malicious | Benign |
|---|---|---|
| Flagged `suspicious` | 32.6% | 12.0% |
| `unable_to_assess` | 2.1% | 6.3% |
| Median `.py` files per package | 2 | 12 |

These are signal rates, not accuracy. Two things limit how far to trust them:

- **Size confound.** Package size alone separates the classes (size-only AUC about 0.79). Malicious packages are much smaller.
- **Label noise.** In a 30-package review of malicious-labelled packages with zero findings, 5 were placeholders or harmless PoCs, and 6 were empty name-squat stubs (`results/zero_finding_review_by_A.csv`). Small sample; it describes that sample, not the corpus.

**False positives.** On 100 small, obscure PyPI packages, 6 were flagged; manual review found 5 false positives and 1 unclear (5.0%, Wilson 95% CI 2.2% to 11.2%). That is precision on small obscure packages, not a general false-positive rate (`results/fp_check_summary.md`).

**Evasion.** Of 12 adversarial samples, 1 reached `suspicious` (base64), 5 kept only the review flag and 6 were silent. The plain baseline is itself only `none_detected` with review under verdict v2, so this batch shows evasion of the review flag, not of a `suspicious` verdict. ROT13 is not treated as obfuscation. Source: `results/adv_batch_verification_by_A.md`.

## Known limitations

- Package-wide combination rules S2 and S5 join unrelated files. They fire on 9.6% and 6.1% of benign packages versus 8.1% and 4.6% of malicious, so they carry little signal. Four of the five false positives above came from the common `exec(open(...).read())` version-loading idiom in `setup.py`.
- A root `setup.py` or `pyproject.toml` over 2 MiB is skipped. 11 malicious-labelled packages hit this and all got `none_detected_in_this_scan`.
- One unparseable Python file does not change the verdict unless unparseable files exceed 20% of the Python files. Python 2 sources and non-Python text in `.py` files fail to parse.
- Compiled extensions (`.so`, `.pyd`) are not inspected.
- Prose aimed at AI agents (for example MCP tool descriptions) is not analysed.
- Static analysis only. Nothing is executed, so behaviour that depends on runtime state is out of reach.

Full list with status tags: `docs/ANALYZER_BACKLOG.md`. Threat model: `docs/THREAT_MODEL.md`. Method: `docs/METHODOLOGY.md`.

## Reproducing the numbers

The datasets live under `data/processed/` and the rescan scripts under `Person_A/pipeline/`. See `docs/METHODOLOGY.md` for the order to run them and the seeds used. Frozen versions are tagged `analyzer-v1`, `analyzer-v1.1` and `adv-batch-v1`.

## Team

Three students: A (engine, contract, Hunter, rescans), B (ML and resilience evaluation), C (evasion lab and UI).
