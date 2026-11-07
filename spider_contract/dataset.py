"""Dataset guards for Level 0: group ids, leakage-safe splits, banned feature columns."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

SCHEMA_DIR = Path(__file__).parent / "schemas"

# Columns that identify the sample, reveal its origin, or ARE the label.
# None of these may ever be an ML input feature (B: call assert_no_leaky_columns
# on your feature matrix right before every fit()).
LEAKY_COLUMNS = frozenset(
    {
        "label", "source", "malicious_evidence", "collection_date", "package_id",
        "package_name", "version", "group_id", "split", "artifact_sha256",
        "analyzer_version", "ruleset_version",
        # present in data/processed/*.jsonl; both come from the malicious index,
        # so they reveal the label:
        "in_index", "index_annotated",
    }
)


# B's earlier, wider list (kept so nothing B already blocks becomes allowed).
_EXTRA_BANNED = frozenset(
    {
        "sha256", "url", "upload_time", "archive_path", "filename", "packagetype",
        "size_bytes", "campaign", "comment", "details", "purl", "reportsource",
        "reported", "targetedos",
    }
)
BANNED_FEATURE_COLUMNS = frozenset(LEAKY_COLUMNS | _EXTRA_BANNED)


class LeakageError(AssertionError):
    pass


def normalize_name(name: str) -> str:
    """PEP 503 normalisation: Foo_Bar.baz -> foo-bar-baz."""
    return re.sub(r"[-_.]+", "-", name).lower()


def make_group_id(package_name: str) -> str:
    """Default split unit: the normalised package NAME (all versions together)."""
    if not package_name:
        return ""
    return normalize_name(str(package_name).strip())


def make_package_id(name: str, version: str) -> str:
    return "%s==%s" % (name, version)


def parse_package_id(package_id: str) -> Tuple[str, str]:
    if "==" not in package_id:
        raise ValueError("package_id must look like name==version: %r" % package_id)
    name, version = package_id.split("==", 1)
    return name, version


def assert_no_leaky_columns(columns: Iterable[str], extra_blocked: Iterable[str] = ()) -> None:
    blocked = {str(c).lower() for c in BANNED_FEATURE_COLUMNS} | {str(c).lower() for c in extra_blocked}
    bad = sorted(c for c in columns if str(c).strip().lower() in blocked)
    if bad:
        raise LeakageError("Leaky columns in the feature matrix: %s" % ", ".join(bad))


def assert_group_disjoint(a, b=None, group_col: str = "group_id", group_key: str = None, split_key: str = "split") -> None:
    """Every group must live in exactly one split. Two call styles (both used in the repo):

    assert_group_disjoint(train_df, test_df, group_col="group_id")   # B's DataFrame style
    assert_group_disjoint(rows, group_key="group_id", split_key="split")  # rows with a split column
    """
    if b is not None:  # DataFrame style
        for name, df in (("train", a), ("test", b)):
            if group_col not in df.columns:
                raise ValueError("Column %r missing from %s dataset." % (group_col, name))
        overlap = set(a[group_col].dropna()) & set(b[group_col].dropna())
        if overlap:
            raise LeakageError(
                "Group leakage: %d group(s) in both train and test, e.g. %s"
                % (len(overlap), sorted(overlap)[:5])
            )
        return
    key = group_key or group_col
    seen = {}  # type: Dict[str, set]
    for row in a:
        seen.setdefault(str(row[key]), set()).add(str(row[split_key]))
    offenders = sorted(g for g, s in seen.items() if len(s) > 1)
    if offenders:
        raise LeakageError(
            "%d group(s) appear in more than one split, e.g. %s" % (len(offenders), ", ".join(offenders[:10]))
        )


def row_errors(row: Dict[str, Any]) -> List[str]:
    """Check the provenance columns of one dataset row against the schema."""
    from jsonschema import Draft7Validator

    schema = json.loads((SCHEMA_DIR / "dataset_record.schema.json").read_text(encoding="utf-8"))
    errors = []
    for err in sorted(Draft7Validator(schema).iter_errors(row), key=lambda e: list(e.path)):
        where = ".".join(str(p) for p in err.path) or "<row>"
        errors.append("%s: %s" % (where, err.message))
    return errors
