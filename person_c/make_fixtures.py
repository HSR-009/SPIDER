"""Write the five Person C fixture packages as scan records.

Old hand-written records used a pre-contract shape (`fixture_0N_*.json`) and
do not validate. If any of those files are still in `fixtures/records`, this
script moves them to `person_c/legacy_records/` and does not rewrite them.

New records are produced by `spider.engine.scan.scan_directory` and checked
with `spider_contract.validate.validate_record` before they are saved under
`person_c/records/`. They are not written into `fixtures/records`, which holds
the shared contract examples.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from spider.engine.scan import scan_directory
from spider_contract.validate import validate_record

FIXTURES_DIR = PROJECT_ROOT / "fixtures" / "records"
SRC_ROOT = Path(__file__).resolve().parent / "fixture_src"
RECORDS_DIR = Path(__file__).resolve().parent / "records"
LEGACY_DIR = Path(__file__).resolve().parent / "legacy_records"

FIXTURE_DEFS = [
    {
        "id": "fixture_01_system_command",
        "version": "0.1.0",
        "source_file": "system_command.py",
        "source_code": 'import os\n\nos.system("whoami")\n',
    },
    {
        "id": "fixture_02_subprocess_run",
        "version": "1.0.0",
        "source_file": "subprocess_call.py",
        "source_code": 'import subprocess\n\nsubprocess.run(["whoami"])\n',
    },
    {
        "id": "fixture_03_encoded_exec",
        "version": "0.2.1",
        "source_file": "encoded_exec.py",
        "source_code": (
            "import base64\n\n"
            'code = base64.b64decode("cHJpbnQoJ0hlbGxvJyk=")\n'
            "exec(code)\n"
        ),
    },
    {
        "id": "fixture_04_custom_install",
        "version": "1.0.0",
        "source_file": "setup.py",
        "source_code": (
            "from setuptools import setup\n"
            "from setuptools.command.install import install\n"
            "import os\n\n"
            "class CustomInstall(install):\n"
            "    def run(self):\n"
            '        os.system("whoami")\n'
            "        install.run(self)\n\n"
            "setup(\n"
            '    name="toy-install-hook",\n'
            '    version="1.0.0",\n'
            '    cmdclass={"install": CustomInstall},\n'
            ")\n"
        ),
    },
    {
        "id": "fixture_05_clean_math",
        "version": "1.1.0",
        "source_file": "calculator.py",
        "source_code": (
            "# Clean arithmetic calculation\n"
            "a = 10\n"
            "b = 20\n"
            "result = a + b\n"
            'print("Result:", result)\n'
        ),
    },
]


def move_legacy_records() -> None:
    """Move old-schema fixture_0N_* files out of fixtures/records."""
    LEGACY_DIR.mkdir(parents=True, exist_ok=True)
    if not FIXTURES_DIR.is_dir():
        return
    for path in sorted(FIXTURES_DIR.glob("fixture_0*.json")):
        dest = LEGACY_DIR / path.name
        if dest.exists():
            dest.unlink()
        path.replace(dest)
        print(f"Moved old-schema record: {path.name} -> {dest}")


def make_fixtures() -> None:
    move_legacy_records()
    SRC_ROOT.mkdir(parents=True, exist_ok=True)
    RECORDS_DIR.mkdir(parents=True, exist_ok=True)

    for fdef in FIXTURE_DEFS:
        pkg_dir = SRC_ROOT / fdef["id"]
        pkg_dir.mkdir(parents=True, exist_ok=True)
        file_path = pkg_dir / fdef["source_file"]
        file_path.write_text(fdef["source_code"], encoding="utf-8")

        scan_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "spider-person-c:" + fdef["id"]))
        record = scan_directory(
            pkg_dir,
            name=fdef["id"],
            version=fdef["version"],
            scan_id=scan_id,
        )
        record["created_at"] = "2026-11-09T00:00:00Z"
        errors = validate_record(record, src_root=SRC_ROOT)
        if errors:
            raise SystemExit(
                "fixture %s failed spider_contract validation:\n%s"
                % (fdef["id"], "\n".join(errors))
            )

        record_path = RECORDS_DIR / f"{fdef['id']}.json"
        record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        print(f"Generated fixture record: {record_path}")


if __name__ == "__main__":
    make_fixtures()
