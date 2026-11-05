
import gzip
import json
from pathlib import Path

MAL = Path("data/processed/malicious_for_b.jsonl")
BEN = Path("data/processed/benign_for_b.jsonl.gz")
OUT = Path("Person_A/analysis/indicator_discrimination.md")
PIPE = Path("Person_A/pipeline")

PIPE.mkdir(parents=True, exist_ok=True)
OUT.parent.mkdir(parents=True, exist_ok=True)


def load(path, expected_label):
    opener = gzip.open if str(path).endswith(".gz") else open
    rows = [
        json.loads(line)
        for line in opener(path, "rt", encoding="utf-8")
        if line.strip()
    ]

    for r in rows:
        if r.get("label") != expected_label:
            raise ValueError(
                f"Unexpected label in {path}: {r.get('label')}"
            )

    return rows


mal = load(MAL, 1)
ben = load(BEN, 0)
datasets = {"Malicious": mal, "Benign": ben}


def row_features(r):
    categories = set()
    indicators = set()
    plain_setup = False
    custom_install = False

    for f in r.get("findings") or []:
        category = str(f.get("category", "")).strip()
        indicator = str(f.get("indicator", "")).strip()
        evidence = str(f.get("evidence", ""))
        combined = (indicator + " " + evidence).lower()

        # Parse errors describe analysis status, not package behavior.
        if category.lower() == "parse error":
            continue

        if category:
            categories.add(category)

        if indicator:
            indicators.add(f"{category} :: {indicator}")

        if indicator.lower() == "setuptools.setup":
            plain_setup = True
        elif "setuptools.setup" in combined or "setup() detected" in combined:
            plain_setup = True

        if "setuptools.command.install" in indicator.lower():
            custom_install = True
        elif any(s in combined for s in (
            "setuptools.command.install",
            "cmdclass",
            "custom install",
            "install.run",
        )):
            custom_install = True

    return categories, indicators, plain_setup, custom_install


features = {
    name: [row_features(r) for r in rows]
    for name, rows in datasets.items()
}


def prevalence(feature_set, name):
    rows = datasets[name]
    count = sum(bool(feature_set(x)) for x in features[name])
    percentage = 100 * count / len(rows) if rows else 0
    return count, percentage


lines = [
    "# Indicator Discrimination — SPIDER",
    "",
    "## Dataset scope",
    "",
    f"- Malicious package-version rows: {len(mal)}",
    f"- Benign package-version rows: {len(ben)}",
    f"- Unique malicious package names: "
    f"{len({r['package_name'].lower() for r in mal})}",
    f"- Unique benign package names: "
    f"{len({r['package_name'].lower() for r in ben})}",
    "- Unit of analysis: package-version row; an indicator counts once per row.",
    "- These are baseline prevalence comparisons, not accuracy or causal evidence.",
    "",
    "## Category prevalence",
    "",
    "| Category | Malicious rows | Malicious % | Benign rows | Benign % | Prevalence ratio |",
    "|---|---:|---:|---:|---:|---:|",
]

categories = set()
for name in datasets:
    for row_categories, _, _, _ in features[name]:
        categories.update(row_categories)

for cat in sorted(categories):
    mc, mp = prevalence(lambda x: cat in x[0], "Malicious")
    bc, bp = prevalence(lambda x: cat in x[0], "Benign")
    ratio = (
        f"{mp / bp:.2f}x"
        if bp
        else ("infinite (zero benign rows)" if mp else "undefined")
    )
    lines.append(
        f"| {cat} | {mc} | {mp:.2f}% | {bc} | {bp:.2f}% | {ratio} |"
    )


# Separate analysis status from behavioral indicators.
lines += [
    "",
    "## Static-analysis status",
    "",
    "| Dataset | Package-version rows | Rows marked failed_static_analysis | Rows with parse errors |",
    "|---|---:|---:|---:|",
]

for name, rows in datasets.items():
    failed = sum(bool(r.get("failed_static_analysis")) for r in rows)
    parse_errors = sum(
        int(r.get("parse_error_count") or 0) > 0
        for r in rows
    )
    lines.append(
        f"| {name} | {len(rows)} | {failed} | {parse_errors} |"
    )

lines += [
    "",
    "Parse errors are analysis-status information, not behavioral indicators.",
    "Rows with parse errors may still contain findings from other files.",
    "",
    "## Indicator prevalence",
    "",
    "| Category :: Indicator | Malicious rows | Malicious % | Benign rows | Benign % | Prevalence ratio |",
    "|---|---:|---:|---:|---:|---:|",
]

indicators = set()
for name in datasets:
    for _, row_indicators, _, _ in features[name]:
        indicators.update(row_indicators)

for ind in sorted(indicators):
    mc, mp = prevalence(lambda x: ind in x[1], "Malicious")
    bc, bp = prevalence(lambda x: ind in x[1], "Benign")
    ratio = (
        f"{mp / bp:.2f}x"
        if bp
        else ("infinite (zero benign rows)" if mp else "undefined")
    )
    escaped_ind = ind.replace("|", r"\|")
    lines.append(
        f"| {escaped_ind} | {mc} | {mp:.2f}% | "
        f"{bc} | {bp:.2f}% | {ratio} |"
    )


lines += [
    "",
    "## Install indicators",
    "",
    "| Indicator | Malicious rows | Benign rows |",
    "|---|---:|---:|",
]

for title, idx in [
    ("Plain setuptools.setup()", 2),
    ("Custom install indicator", 3),
]:
    mc = sum(x[idx] for x in features["Malicious"])
    bc = sum(x[idx] for x in features["Benign"])
    lines.append(f"| {title} | {mc} | {bc} |")


lines += [
    "",
    "## Benign HIGH-severity review queue",
    "",
    "These are candidates for manual false-positive review, not confirmed false positives.",
    "",
    "| Package | Version | Findings | Categories |",
    "|---|---|---:|---|",
]

high = sorted(
    (
        r for r in ben
        if str(r.get("max_severity", "")).upper() == "HIGH"
    ),
    key=lambda r: r.get("n_findings", 0),
    reverse=True,
)

for r in high[:30]:
    cats = ", ".join(sorted((r.get("category_counts") or {}).keys()))
    package = str(r.get("package_name", "")).replace("|", r"\|")
    version = str(r.get("version", "")).replace("|", r"\|")
    lines.append(
        f"| {package} | {version} | "
        f"{r.get('n_findings', 0)} | {cats} |"
    )


lines += [
    "",
    "## Interpretation and limitations",
    "",
    "- Plain `setuptools.setup()` is informational and should not independently drive risk.",
    "- A broad indicator such as `os.environ` access or network activity is not proof of malicious intent.",
    "- Finding totals are not independent events; prevalence counts each indicator once per package-version row.",
    "- Benign packages were assumed benign based on corpus selection, not independently audited.",
    "- Collection limits and differences between the datasets may bias the comparison.",
    "- Do not treat prevalence ratios as model accuracy or use them alone to choose thresholds.",
    "- Verify scanner-rule parity against frozen analyzer v1 before interpreting results.",
    "- Split ML evaluation by normalized `package_name` to prevent version leakage.",
    "",
]

OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")

print(f"Report written: {OUT}")
print(f"Rows analyzed: malicious={len(mal)}, benign={len(ben)}")
print(f"Indicator types compared: {len(indicators)}")
print(f"Benign HIGH rows queued for review: {len(high)}")
