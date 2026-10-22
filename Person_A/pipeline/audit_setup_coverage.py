import json
import tarfile
import zipfile
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "data/processed/malicious_scan.jsonl"
PYPI = ROOT / "data/raw/malicious/pypi"

SUFFIXES = (
    ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz",
    ".tar", ".zip", ".whl",
)

def setup_paths(archive):
    try:
        if zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as z:
                return [
                    n.replace("\\", "/").lstrip("./")
                    for n in z.namelist()
                    if Path(n.replace("\\", "/")).name.lower() == "setup.py"
                ]
        if tarfile.is_tarfile(archive):
            with tarfile.open(archive, "r:*") as t:
                return [
                    m.name.replace("\\", "/").lstrip("./")
                    for m in t.getmembers()
                    if m.isfile()
                    and Path(m.name.replace("\\", "/")).name.lower() == "setup.py"
                ]
    except Exception as exc:
        print(f"WARNING: cannot inspect {archive.name}: {exc}")
    return []

def result_setup_files(row):
    found = []
    for result in row.get("results", []):
        filename = str(result.get("file", "")).replace("\\", "/")
        archive = None
        if "::" in filename:
            archive, filename = filename.split("::", 1)
        if Path(filename).name.lower() == "setup.py":
            found.append((archive, filename))
    return found

rows = [
    json.loads(line)
    for line in SRC.open(encoding="utf-8")
    if line.strip()
]

stats = Counter()
examples = {
    "missing": [],
    "ambiguous": [],
    "confirmed": [],
    "inferred": [],
}

for row in rows:
    package = row.get("package", row.get("package_name", ""))
    version = str(row.get("version", ""))
    directory = PYPI / package / version

    if not directory.is_dir():
        stats["version_directory_missing"] += 1
        continue

    archives = sorted(
        p for p in directory.iterdir()
        if p.is_file() and p.name.lower().endswith(SUFFIXES)
    )

    archive_setups = {
        archive.name: setup_paths(archive)
        for archive in archives
    }
    archive_setups = {
        name: paths for name, paths in archive_setups.items() if paths
    }

    if not archive_setups:
        stats["no_setup_py_in_archives"] += 1
        continue

    stats["versions_with_setup_py_in_archive"] += 1
    stats["archives_containing_setup_py"] += len(archive_setups)

    recorded = result_setup_files(row)
    if not recorded:
        stats["setup_py_not_recorded"] += 1
        if len(examples["missing"]) < 20:
            examples["missing"].append(f"{package}@{version}")
        continue

    qualified_archives = {
        archive for archive, _ in recorded if archive is not None
    }
    matched = set(archive_setups) & qualified_archives

    if matched:
        stats["archives_confirmed_by_filename"] += len(matched)
        if len(examples["confirmed"]) < 10:
            examples["confirmed"].append(
                f"{package}@{version}: {', '.join(sorted(matched))}"
            )

    unqualified = any(archive is None for archive, _ in recorded)

    if unqualified and len(archive_setups) == 1:
        stats["versions_covered_by_unique_setup_source"] += 1
        if len(examples["inferred"]) < 10:
            examples["inferred"].append(f"{package}@{version}")
    elif unqualified and len(archive_setups) > 1:
        stats["versions_with_ambiguous_archive_provenance"] += 1
        if len(examples["ambiguous"]) < 20:
            examples["ambiguous"].append(f"{package}@{version}")

print(f"Scan rows: {len(rows)}")
print(f"Version directories missing: {stats['version_directory_missing']}")
print(f"Versions with setup.py in an archive: {stats['versions_with_setup_py_in_archive']}")
print(f"Archives containing setup.py: {stats['archives_containing_setup_py']}")
print(f"Versions with no setup.py result recorded: {stats['setup_py_not_recorded']}")
print(f"Archives identifiable from recorded archive prefixes: {stats['archives_confirmed_by_filename']}")
print(f"Versions with one identifiable setup.py source: {stats['versions_covered_by_unique_setup_source']}")
print(f"Versions with ambiguous archive provenance: {stats['versions_with_ambiguous_archive_provenance']}")
print(f"Versions with no setup.py in any archive: {stats['no_setup_py_in_archives']}")

for key, title in [
    ("missing", "Setup.py present in archive, but no result recorded"),
    ("ambiguous", "Setup.py result exists, but archive source is ambiguous"),
    ("confirmed", "Examples with archive-qualified results"),
    ("inferred", "Examples with a unique setup.py source"),
]:
    print(f"\n{title}:")
    for item in examples[key]:
        print(f"  {item}")
