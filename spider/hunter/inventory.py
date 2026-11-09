"""Environment and distribution inventory inspection (section 4.7 & 7.9)."""
from __future__ import annotations

import glob
import importlib.metadata
import os
import site
import sys
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


def list_environments(
    extra_site_packages: Optional[List[str | Path]] = None,
    include_system_defaults: bool = True,
) -> List[Path]:
    """Return search roots for python environments.
    
    If include_system_defaults is True:
      Linux defaults:
        /usr/lib/python3/dist-packages
        /usr/local/lib/python3*/dist-packages
        ~/.local/lib/python3*/site-packages
        active venv site-packages
      Windows defaults:
        site-packages of sys.prefix
        user site
    Plus any extra --site-packages paths provided.
    If include_system_defaults is False, only extra_site_packages are returned.
    """
    roots: List[Path] = []

    if include_system_defaults:
        if sys.platform == "win32":
            # Windows: sys.prefix site-packages
            prefix_sp = Path(sys.prefix) / "Lib" / "site-packages"
            if prefix_sp.exists():
                roots.append(prefix_sp)

            # User site
            try:
                user_sp = Path(site.getusersitepackages())
                if user_sp.exists() and user_sp not in roots:
                    roots.append(user_sp)
            except Exception:
                pass

            # Also check all getsitepackages()
            try:
                for sp in site.getsitepackages():
                    p = Path(sp)
                    if p.exists() and p not in roots:
                        roots.append(p)
            except Exception:
                pass
        else:
            # Linux / Unix
            fixed_candidates = [
                "/usr/lib/python3/dist-packages",
            ]
            for c in fixed_candidates:
                p = Path(c)
                if p.exists() and p not in roots:
                    roots.append(p)

            # Glob patterns: /usr/local/lib/python3*/dist-packages
            for match in glob.glob("/usr/local/lib/python3*/dist-packages"):
                p = Path(match)
                if p.exists() and p not in roots:
                    roots.append(p)

            # Glob patterns: ~/.local/lib/python3*/site-packages
            home = os.path.expanduser("~")
            for match in glob.glob(os.path.join(home, ".local/lib/python3*/site-packages")):
                p = Path(match)
                if p.exists() and p not in roots:
                    roots.append(p)

            # Active virtual environment
            venv = os.environ.get("VIRTUAL_ENV")
            if venv:
                for match in glob.glob(os.path.join(venv, "lib/python3*/site-packages")):
                    p = Path(match)
                    if p.exists() and p not in roots:
                        roots.append(p)

    # Any extra requested directories
    if extra_site_packages:
        for ep in extra_site_packages:
            p = Path(ep).resolve()
            if p.exists() and p not in roots:
                roots.append(p)

    return roots


def iter_distributions(root: str | Path) -> Iterator[Dict[str, Any]]:
    """Iterate installed distributions found in the specified root path.
    
    Uses importlib.metadata.distributions(path=[str(root)]).
    Returns dicts with: name, version, metadata_path, files.
    """
    root_path = Path(root).resolve()
    if not root_path.exists():
        return

    for dist in importlib.metadata.distributions(path=[str(root_path)]):
        name = dist.metadata.get("Name") or dist.name
        version = dist.metadata.get("Version") or dist.version

        # Metadata path (.dist-info or .egg-info)
        meta_path = None
        if hasattr(dist, "_path") and dist._path:
            meta_path = Path(dist._path)
        elif dist.locate_file("") is not None:
            try:
                meta_path = Path(dist.locate_file("")).resolve()
            except Exception:
                meta_path = None

        file_list: List[str] = []
        if dist.files:
            for f in dist.files:
                file_list.append(str(f))

        yield {
            "name": name,
            "version": version,
            "metadata_path": str(meta_path) if meta_path else None,
            "files": file_list,
        }

