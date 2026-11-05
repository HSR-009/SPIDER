"""File classification rules for SPIDER engine (section 7.3)."""
from pathlib import PurePosixPath, Path

PYTHON_EXTS = {".py", ".pyw"}
BUILD_CONFIG_NAMES = {"pyproject.toml", "setup.cfg", "setup.py", "manifest.in", "tox.ini"}
METADATA_NAMES = {"pkg-info", "metadata", "requires.txt", "top_level.txt", "entry_points.txt"}
BINARY_EXTS = {
    ".so", ".pyd", ".dll", ".dylib", ".exe", ".bin", ".o", ".a",
    ".pyc", ".pyo", ".class", ".jar", ".node"
}
DOC_EXTS = {
    ".md", ".rst", ".txt", ".html", ".htm", ".css", ".js", ".json",
    ".yaml", ".yml", ".csv", ".tsv", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".ico", ".pdf", ".ipynb", ".po", ".mo", ".ttf", ".woff",
    ".woff2", ".xml", ".lock"
}
EXCLUDE_DIRS = {"tests", "test", "docs", "doc", "examples", "example"}
VENDORED_DIRS = {"_vendor", "vendor", "vendored", "third_party", "extern", "site-packages"}


def classify(relpath: str) -> tuple[str, list[str]]:
    """Classify a relative file path -> (kind, roles).
    
    kind: python | build_config | metadata | binary | doc | other
    roles: install_hook | build_config | package_init | vendored | startup_hook
    """
    posix_path = PurePosixPath(relpath.replace("\\", "/"))
    parts_lower = [p.lower() for p in posix_path.parts]
    name_lower = posix_path.name.lower()
    suffix_lower = posix_path.suffix.lower()

    # Determine roles
    roles = []
    # Root-level setup.py -> install_hook
    if len(posix_path.parts) == 1 and name_lower == "setup.py":
        roles.append("install_hook")
    elif len(posix_path.parts) == 1 and name_lower in ("pyproject.toml", "setup.cfg"):
        roles.append("build_config")

    if name_lower == "__init__.py":
        roles.append("package_init")
    elif name_lower in ("sitecustomize.py", "usercustomize.py"):
        roles.append("startup_hook")

    if any(p in VENDORED_DIRS for p in parts_lower[:-1]):
        roles.append("vendored")

    # Determine kind
    # If under excluded dirs (and not root-level setup.py/pyproject.toml): kind = doc
    if any(p in EXCLUDE_DIRS for p in parts_lower[:-1]):
        if not (len(posix_path.parts) == 1 and name_lower in ("setup.py", "pyproject.toml")):
            return "doc", roles

    if suffix_lower in PYTHON_EXTS:
        return "python", roles

    if name_lower in BUILD_CONFIG_NAMES:
        return "build_config", roles

    if name_lower in METADATA_NAMES or any(p.endswith(".egg-info") for p in parts_lower):
        return "metadata", roles

    if suffix_lower in BINARY_EXTS:
        return "binary", roles

    if suffix_lower in DOC_EXTS:
        return "doc", roles

    return "other", roles
