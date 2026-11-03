import hashlib
import argparse
import json
import re
import shutil
import sys
import tarfile
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]
PYPI = ROOT / "data/raw/malicious/pypi"
INDEX = ROOT / "data/raw/malicious/package_index.jsonl"
OUT_DIR = ROOT / "data/processed"
OUT = OUT_DIR / "malicious_scan.jsonl"
FAIL = OUT_DIR / "malicious_scan_failures.jsonl"

ARCHIVE_SUFFIXES = (
    ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz",
    ".tar", ".zip", ".whl",
)
ANNOTATION_FIELDS = {
    "details", "objective", "trigger", "injectioncomponent",
    "typotarget", "targetedos", "obfuscated", "obfuscation",
    "condition", "conditional",
}

sys.path.insert(0, str(ROOT))
from Person_A.ast_analyzer.analyzer import analyze_file


def normalize(value):
    return re.sub(r"[-_.]+", "-", str(value).strip()).lower()


def make_id(name, version):
    return f"{normalize(name)}@{version}"


def annotation_present(item):
    """True only when a behavioral field has an actual annotated value."""
    for key in ANNOTATION_FIELDS:
        field = item.get(key)
        if not isinstance(field, dict):
            continue
        status = str(field.get("status", "")).lower()
        value = field.get("value")
        if status == "manually set" and value is not None:
            if value != "" and value != [] and value != {}:
                return True
    return False


def load_index():
    index = {}
    entry_count = 0

    if not INDEX.exists():
        raise FileNotFoundError(f"Index not found: {INDEX}")

    with INDEX.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                item = json.loads(line)
                purl = (item.get("purl") or {}).get("value", "")
                if not purl.startswith("pkg:pypi/"):
                    continue

                identity = unquote(purl[len("pkg:pypi/"):])
                name, sep, version = identity.partition("@")
                if not name or not sep or not version:
                    continue

                pid = make_id(name, version)
                index.setdefault(pid, []).append(item)
                entry_count += 1
            except (json.JSONDecodeError, AttributeError, TypeError):
                continue

    print(
        f"index entries: {entry_count} | "
        f"unique package IDs: {len(index)}"
    )
    return index


def safe_python_name(name):
    # Normalize archive paths before validating them.
    name = name.replace("\\", "/")
    path = Path(name)
    return (
        name.lower().endswith(".py")
        and not path.is_absolute()
        and ".." not in path.parts
    )


def python_files(archive):
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zf:
            for name in zf.namelist():
                if safe_python_name(name) and not name.endswith("/"):
                    info = zf.getinfo(name)
                    if info.file_size <= 5 * 1024 * 1024:
                        yield name, zf.read(name)
        return

    with tarfile.open(archive, "r:*") as tf:
        for member in tf.getmembers():
            if (
                member.isfile()
                and safe_python_name(member.name)
                and member.size <= 5 * 1024 * 1024
            ):
                source = tf.extractfile(member)
                if source:
                    yield member.name, source.read()


def scan_file(package, version, filename, source):
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".py", delete=False
        ) as temp:
            temp.write(source.decode("utf-8", errors="replace"))
            temp_path = Path(temp.name)

        findings = analyze_file(str(temp_path))
        if not isinstance(findings, list):
            raise TypeError("Analyzer did not return a list")

        for finding in findings:
            if isinstance(finding, dict):
                finding["file"] = filename

        parse_errors = [
            f for f in findings
            if isinstance(f, dict) and f.get("category") == "Parse Error"
        ]
        findings = [
            f for f in findings
            if not (isinstance(f, dict) and f.get("category") == "Parse Error")
        ]

        return {
            "package": package,
            "version": version,
            "file": filename,
            "findings": findings,
            "parse_errors": parse_errors,
        }
    except Exception as exc:
        return {
            "package": package,
            "version": version,
            "file": filename,
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        if temp_path:
            temp_path.unlink(missing_ok=True)


def artifact_priority(path):
    name = path.name.lower()
    if name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
        return 0
    if name.endswith(".zip") and not name.endswith(".whl"):
        return 1
    return 2


def make_row(package, version, results, failures, index):
    pid = make_id(package, version)
    metadata = index.get(pid, [])
    attempted = len(results)
    successful = sum(
        "error" not in result and not result.get("parse_errors")
        for result in results
    )
    all_findings = [
        finding
        for result in results
        for finding in result.get("findings", [])
        if isinstance(finding, dict)
    ]
    parse_error_count = sum(
        len(result.get("parse_errors", [])) for result in results
    )
    category_counts = {}
    for finding in all_findings:
        category = finding.get("category", "Uncategorized")
        category_counts[category] = category_counts.get(category, 0) + 1

    return {
        "package_id": pid,
        "package": package,
        "package_name": package,
        "version": version,
        "label": 1,
        "source": "Backstabber's Knife Collection",
        "in_index": bool(metadata),
        "index_annotated": any(annotation_present(item) for item in metadata),
        "files_scanned": successful,
        "files_attempted": attempted,
        "findings_count": len(all_findings),
        "findings": all_findings,
        "category_counts": category_counts,
        "parse_error_count": parse_error_count,
        "failed_static_analysis": bool(failures) or parse_error_count > 0,
        "failure_count": len(failures) + parse_error_count,
        "results": results,
    }


def scan_version(package, version, directory, index):
    results = []
    failures = []

    archives = sorted(
        (
            p for p in directory.iterdir()
            if p.is_file() and p.name.lower().endswith(ARCHIVE_SUFFIXES)
        ),
        key=lambda p: (artifact_priority(p), p.name.lower()),
    )

    # Scan every readable archive; deduplicate identical path + content.
    # If a path has different contents across archives, retain both versions.
    selected_archive = None
    seen_sources = set()
    seen_paths = set()

    for archive in archives:
        try:
            source_files = list(python_files(archive))
            if not source_files:
                continue

            if selected_archive is None:
                selected_archive = archive

            for filename, source in source_files:
                normalized = str(filename).replace("\\\\", "/")
                while normalized.startswith("./"):
                    normalized = normalized[2:]
                normalized = "/".join(
                    part for part in normalized.split("/") if part not in ("", ".")
                )

                payload = source if isinstance(source, bytes) else str(source).encode("utf-8")
                digest = hashlib.sha256(payload).hexdigest()
                key = (normalized, digest)

                if key in seen_sources:
                    continue

                display_filename = (
                    f"{archive.name}::{normalized}"
                    if normalized in seen_paths else normalized
                )
                seen_sources.add(key)
                seen_paths.add(normalized)

                result = scan_file(package, version, display_filename, source)
                results.append(result)
                if "error" in result:
                    failures.append({
                        "package_id": make_id(package, version),
                        "reason": result["error"],
                        "file": display_filename,
                        "archive": archive.name,
                    })
        except Exception as exc:
            failures.append({
                "package_id": make_id(package, version),
                "reason": f"{type(exc).__name__}: {exc}",
                "file": archive.name,
                "archive": archive.name,
            })

    # If no readable archive supplied Python source, use extracted files.
    if selected_archive is None:
        for path in sorted(directory.rglob("*.py")):
            if not path.is_file():
                continue
            try:
                filename = path.relative_to(directory).as_posix()
                result = scan_file(
                    package, version, filename, path.read_bytes()
                )
                results.append(result)
                if "error" in result:
                    failures.append({
                        "package_id": make_id(package, version),
                        "reason": result["error"],
                        "file": filename,
                    })
            except OSError as exc:
                failures.append({
                    "package_id": make_id(package, version),
                    "reason": f"{type(exc).__name__}: {exc}",
                    "file": str(path),
                })

    row = make_row(package, version, results, failures, index)
    return row, failures


def read_existing():
    rows = []
    if not OUT.exists():
        return rows

    with OUT.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON in {OUT}, line {number}: {exc}"
                ) from exc
    return rows


def print_findings(row):
    for result in row["results"]:
        for finding in result.get("findings", []):
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity", "UNKNOWN")).upper()
            category = finding.get("category", "Uncategorized")
            indicator = finding.get(
                "indicator", finding.get("name", "unknown")
            )
            line = finding.get("line", finding.get("lineno", "?"))
            print(
                f"[{severity}] {category} | {indicator} | "
                f"{result['file']}:{line}"
            )


def write_failures(failures):
    if not failures:
        return
    with FAIL.open("a", encoding="utf-8") as stream:
        for failure in failures:
            stream.write(json.dumps(failure) + "\n")


def summary():
    rows = read_existing()
    ids = [r.get("package_id") for r in rows if r.get("package_id")]

    print(f"Rows in output: {len(rows)}")
    print(f"Unique package IDs: {len(set(ids))}")
    print(f"Duplicate IDs: {len(ids) - len(set(ids))}")
    print(f"Python files analyzed: {sum(r.get('files_scanned', 0) for r in rows)}")
    print(f"Packages in index: {sum(bool(r.get('in_index')) for r in rows)}")
    print(f"Annotated package IDs: {sum(bool(r.get('index_annotated')) for r in rows)}")
    print(f"Rows with analysis failures: {sum(bool(r.get('failed_static_analysis')) for r in rows)}")
    print(f"Total findings: {sum(r.get('findings_count', 0) for r in rows)}")

    if FAIL.exists():
        failure_rows = [
            json.loads(line)
            for line in FAIL.open(encoding="utf-8")
            if line.strip()
        ]
        print(f"Failure records: {len(failure_rows)}")
    else:
        print("Failure records: 0")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--summary", action="store_true")
    parser.add_argument(
        "--reset", action="store_true",
        help="Back up existing outputs and start a fresh full scan",
    )
    args = parser.parse_args()

    if args.summary:
        summary()
        return

    if args.package and args.limit is not None:
        parser.error("--package and --limit cannot be combined")
    if args.limit is not None and args.limit < 0:
        parser.error("--limit must be non-negative")
    if args.reset and (args.package or args.limit is not None):
        parser.error("--reset is only for a full scan")

    index = load_index()
    if not PYPI.is_dir():
        raise FileNotFoundError(f"Dataset directory not found: {PYPI}")

    package_dirs = sorted(p for p in PYPI.iterdir() if p.is_dir())
    if args.package:
        package_dirs = [
            p for p in package_dirs
            if normalize(p.name) == normalize(args.package)
        ]
        if not package_dirs:
            print(f"No matching package found under {PYPI}")
            return

    candidates = []
    for package_dir in package_dirs:
        root_py = sorted(package_dir.glob("*.py"))
        version_dirs = sorted(
            p for p in package_dir.iterdir() if p.is_dir()
        )

        if root_py:
            candidates.append(
                (package_dir.name, "root", package_dir, True)
            )

        for version_dir in version_dirs:
            has_archive = any(
                p.is_file()
                and p.name.lower().endswith(ARCHIVE_SUFFIXES)
                for p in version_dir.iterdir()
            )
            has_source = any(version_dir.rglob("*.py"))
            if has_archive or has_source:
                candidates.append(
                    (package_dir.name, version_dir.name, version_dir, False)
                )

    unique = {}
    for candidate in candidates:
        package, version, _, _ = candidate
        unique.setdefault(make_id(package, version), candidate)
    candidates = list(unique.values())

    # Tests never write. --limit is also treated as a dry run.
    dry_run = bool(args.package or args.limit is not None)

    if args.reset:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        for path in (OUT, FAIL):
            if path.exists():
                backup = path.with_name(path.name + "." + timestamp + ".bak")
                shutil.move(str(path), str(backup))
                print(f"Backed up {path.name} -> {backup.name}")

    existing_rows = read_existing()
    legacy = [r for r in existing_rows if not r.get("package_id")]

    if legacy and not dry_run:
        raise SystemExit(
            "Existing output contains legacy rows without package_id. "
            "Review them, then run a fresh full scan with --reset."
        )

    scanned = {
        r["package_id"]
        for r in existing_rows
        if r.get("package_id")
    }
    print(f"already scanned: {len(scanned)}")

    if dry_run:
        print("TEST MODE: output files will not be modified.")

    pending = [
        candidate for candidate in candidates
        if make_id(candidate[0], candidate[1]) not in scanned
        or bool(args.package)
    ]
    if args.limit is not None:
        pending = pending[:args.limit]

    print(f"new candidates: {len(pending)}")
    if not dry_run:
        OUT_DIR.mkdir(parents=True, exist_ok=True)

    newly_scanned = 0
    for package, version, directory, is_root in pending:
        pid = make_id(package, version)
        print(f"\nScanning {pid}")

        if is_root:
            results = []
            failures = []
            for path in sorted(directory.glob("*.py")):
                try:
                    result = scan_file(
                        package, version, path.name, path.read_bytes()
                    )
                except OSError as exc:
                    result = {
                        "package": package,
                        "version": version,
                        "file": path.name,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                results.append(result)
                if "error" in result:
                    failures.append({
                        "package_id": pid,
                        "reason": result["error"],
                        "file": path.name,
                    })
            row = make_row(package, version, results, failures, index)
        else:
            row, failures = scan_version(
                package, version, directory, index
            )

        print_findings(row)
        print(
            f"  files: {row['files_scanned']}/{row['files_attempted']} | "
            f"findings: {row['findings_count']} | "
            f"in_index: {row['in_index']} | "
            f"index_annotated: {row['index_annotated']} | "
            f"failed_static_analysis: {row['failed_static_analysis']}"
        )

        if not dry_run:
            with OUT.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(row) + "\n")
            write_failures(failures)

        newly_scanned += 1

    print(f"\ndone. newly scanned: {newly_scanned}")


if __name__ == "__main__":
    main()
