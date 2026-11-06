"""Fetch package archives safely from PyPI JSON API (section 3.6)."""
from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

USER_AGENT = "SPIDER-static-research/1.0 (+https://github.com/HSR-009/SPIDER)"
MAX_RESPONSE_BYTES = 5 * 1024 * 1024   # 5 MB
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024   # 50 MB
TIMEOUT_SECONDS = 20

NAME_REGEX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
VERSION_REGEX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!-]*$")


class FetchError(RuntimeError):
    pass


def get_cache_dir() -> Path:
    cache = Path(os.path.expanduser("~/.cache/spider"))
    cache.mkdir(parents=True, exist_ok=True)
    return cache


def fetch_package_archive(
    name: str,
    version: str,
    *,
    cache_dir: Optional[Path] = None,
    opener: Optional[urllib.request.OpenerDirector] = None,
) -> Tuple[Path, str, bool]:
    """Fetch package archive for name==version.
    
    Returns:
        (archive_path, expected_sha256, hash_verified)
    Raises:
        FetchError on validation or network/digest errors.
    """
    if not NAME_REGEX.match(name):
        raise FetchError(f"Invalid package name: {name!r}")
    if not VERSION_REGEX.match(version):
        raise FetchError(f"Invalid package version: {version!r}")

    cache = cache_dir or get_cache_dir()
    url = f"https://pypi.org/pypi/{name}/{version}/json"

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    open_fn = opener.open if opener else urllib.request.urlopen

    try:
        with open_fn(req, timeout=TIMEOUT_SECONDS) as resp:
            data = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                raise FetchError(f"JSON response exceeds limit of {MAX_RESPONSE_BYTES} bytes")
            pypi_meta = json.loads(data.decode("utf-8"))
    except urllib.error.URLError as e:
        raise FetchError(f"Network error fetching PyPI metadata: {e}")
    except json.JSONDecodeError as e:
        raise FetchError(f"Invalid JSON from PyPI: {e}")

    urls = pypi_meta.get("urls", [])
    if not urls:
        raise FetchError(f"No release files found for {name}=={version}")

    # Prefer sdist, else bdist_wheel
    sdist = None
    wheel = None
    for u in urls:
        pt = u.get("packagetype")
        if pt == "sdist" and not sdist:
            sdist = u
        elif pt == "bdist_wheel" and not wheel:
            wheel = u

    chosen = sdist or wheel
    if not chosen:
        raise FetchError(f"No sdist or wheel found for {name}=={version}")

    archive_url = chosen.get("url")
    expected_sha256 = (chosen.get("digests") or {}).get("sha256", "").lower()
    if not archive_url:
        raise FetchError(f"Missing URL in PyPI release entry for {name}=={version}")

    filename = chosen.get("filename") or f"{name}-{version}.archive"

    # Check cache by expected_sha256 if present
    if expected_sha256:
        cached_file = cache / expected_sha256 / filename
        if cached_file.exists():
            # Verify file content
            h = hashlib.sha256()
            with cached_file.open("rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            if h.hexdigest().lower() == expected_sha256:
                return cached_file, expected_sha256, True

    # Download archive
    dl_req = urllib.request.Request(archive_url, headers={"User-Agent": USER_AGENT})
    try:
        with open_fn(dl_req, timeout=TIMEOUT_SECONDS) as resp:
            content = bytearray()
            while chunk := resp.read(65536):
                content.extend(chunk)
                if len(content) > MAX_ARCHIVE_BYTES:
                    raise FetchError(f"Archive exceeds size limit of {MAX_ARCHIVE_BYTES} bytes")
    except urllib.error.URLError as e:
        raise FetchError(f"Network error downloading archive: {e}")

    actual_sha256 = hashlib.sha256(content).hexdigest().lower()
    hash_verified = (actual_sha256 == expected_sha256) if expected_sha256 else False

    dest_dir = cache / (expected_sha256 or actual_sha256)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_file = dest_dir / filename
    dest_file.write_bytes(content)

    return dest_file, expected_sha256 or actual_sha256, hash_verified

