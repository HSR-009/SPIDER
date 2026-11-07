"""Hash helpers. The tree hash is what 'artifact.sha256' means for a directory."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_sha256(root) -> str:
    """Deterministic hash of a directory.

    One line per entry, sorted by POSIX relative path:
        "<relpath>\\0<file sha256>\\n"
    Symlinks are never followed; they are recorded as "symlink:<target>".
    """
    root = Path(root)
    lines = []
    entries = sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix())
    for p in entries:
        rel = p.relative_to(root).as_posix()
        if p.is_symlink():
            lines.append("%s\0symlink:%s\n" % (rel, os.readlink(p)))
        elif p.is_file():
            lines.append("%s\0%s\n" % (rel, sha256_file(p)))
    return sha256_bytes("".join(lines).encode("utf-8"))
