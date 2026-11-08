# Hunter-lite: first real run on Kali (2026-11-08)

Run: `python -m spider hunt` on a Kali VM (Debian system Python, 773 installed distributions, fresh database, about 53 s, read-only, nothing imported or executed). It exited 10 because HIGH items were present.

## Result after fixes
243 items: 234 LOW, 6 HIGH `.pth`, 2 HIGH `bottle.py`, 1 MEDIUM tamper. Nothing in this list was malicious. Reviewed by hand:

- 6 HIGH `.pth` files are the standard setuptools namespace-package stubs (`*-nspkg.pth` for zope.deprecation, zope.event, zc.lockfile, PasteScript, repoze.lru) and `distutils-precedence.pth`. They contain `__import__`, which the rule treats as executable, so HIGH is the rule working as designed. I read each file and allowlisted them by sha256.
- 2 HIGH `bottle.py` items (S2 and S5) are a framework that uses `exec` and base64 internally. These are known false positives of the file-level scan, left visible on purpose.
- 1 MEDIUM tamper item (`ujson-stubs/__init__.pyi`) is a Debian overlap: `python3-ujson` 5.13.0 ships the same stub path as `types-ujson` 5.10 and overwrote it. `dpkg -V python3-ujson` reports the file intact.

## What the first run got wrong, and what was fixed
The first run produced 320 items. Reading them found three false-positive sources: 41 MEDIUM tamper items from Debian-style hex `RECORD` digests and `bin/` scripts, 23 HIGH items from per-file scanning, and 14 MEDIUM entry-point items on real tools (netexec, gvm-tools, greenbone-feed-sync, notus-scanner, markdown-it-py) because Debian packages often have no `RECORD` or `top_level.txt`. Each was fixed in code with a planted test. Entry-point ownership now falls back to the filesystem, and to LOW when ownership is unknowable.

## Limits
- These fixes were tuned on this one machine. The low item count is not a measured false-positive rate, and it says nothing about detection.
- No real malicious package was present on this machine. Detection of `.pth`, startup-hook and entry-point attacks is covered by planted test cases only.
- Coverage: 6 files skipped as too large, 199 distributions had files missing from `RECORD`, and 53 had no file list at all.
- Machine-specific paths in `fixtures/hunt_sample.json` are replaced with `/home/user`; the sample keeps all HIGH and MEDIUM items and a seeded 40-item LOW sample.
