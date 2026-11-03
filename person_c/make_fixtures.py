import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from Person_A.ast_analyzer.analyzer import analyze_file

FIXTURES_DIR = PROJECT_ROOT / "fixtures"
SRC_DIR = FIXTURES_DIR / "src"
RECORDS_DIR = FIXTURES_DIR / "records"

SRC_DIR.mkdir(parents=True, exist_ok=True)
RECORDS_DIR.mkdir(parents=True, exist_ok=True)

FIXTURE_DEFS = [
    {
        "id": "fixture_01_system_command",
        "package_name": "toy-syscommand",
        "version": "0.1.0",
        "source_file": "system_command.py",
        "source_code": 'import os\n\nos.system("whoami")\n',
        "verdict": "Malicious",
        "illustrative_model_score": 0.94,
    },
    {
        "id": "fixture_02_subprocess_run",
        "package_name": "toy-subproc",
        "version": "1.0.0",
        "source_file": "subprocess_call.py",
        "source_code": 'import subprocess\n\nsubprocess.run(["whoami"])\n',
        "verdict": "Malicious",
        "illustrative_model_score": 0.88,
    },
    {
        "id": "fixture_03_encoded_exec",
        "package_name": "toy-encoded-exec",
        "version": "0.2.1",
        "source_file": "encoded_exec.py",
        "source_code": (
            'import base64\n\n'
            'code = base64.b64decode("cHJpbnQoJ0hlbGxvJyk=")\n'
            'exec(code)\n'
        ),
        "verdict": "Suspicious",
        "illustrative_model_score": 0.72,
    },
    {
        "id": "fixture_04_custom_install",
        "package_name": "toy-install-hook",
        "version": "1.0.0",
        "source_file": "setup.py",
        "source_code": (
            'from setuptools import setup\n'
            'from setuptools.command.install import install\n'
            'import os\n\n'
            'class CustomInstall(install):\n'
            '    def run(self):\n'
            '        os.system("whoami")\n'
            '        install.run(self)\n\n'
            'setup(\n'
            '    name="toy-install-hook",\n'
            '    version="1.0.0",\n'
            '    cmdclass={"install": CustomInstall},\n'
            ')\n'
        ),
        "verdict": "Malicious",
        "illustrative_model_score": 0.98,
    },
    {
        "id": "fixture_05_clean_math",
        "package_name": "toy-clean-calculator",
        "version": "1.1.0",
        "source_file": "calculator.py",
        "source_code": (
            '# Clean arithmetic calculation\n'
            'a = 10\n'
            'b = 20\n'
            'result = a + b\n'
            'print("Result:", result)\n'
        ),
        "verdict": "Needs Review",
        "illustrative_model_score": 0.12,
    },
]

def make_fixtures():
    for fdef in FIXTURE_DEFS:
        pkg_dir = SRC_DIR / fdef["id"]
        pkg_dir.mkdir(parents=True, exist_ok=True)
        
        file_path = pkg_dir / fdef["source_file"]
        file_path.write_text(fdef["source_code"], encoding="utf-8")
        
        # Analyze using Person A's real analyzer
        raw_findings = analyze_file(str(file_path))
        
        # Format findings with relative paths
        formatted_findings = []
        for finding in raw_findings:
            formatted_findings.append({
                "category": finding["category"],
                "indicator": finding["indicator"],
                "severity": finding["severity"],
                "file": fdef["source_file"],
                "line": finding["line"],
                "evidence": finding["evidence"],
            })
            
        record = {
            "fixture_id": fdef["id"],
            "package_name": fdef["package_name"],
            "version": fdef["version"],
            "record_origin": "fixture",
            "verdict": fdef["verdict"],
            "findings": formatted_findings,
            "files": [
                {
                    "filename": fdef["source_file"],
                    "path": str(Path(fdef["id"]) / fdef["source_file"]),
                    "content": fdef["source_code"],
                }
            ],
            "model_assessment": {
                "risk_score": fdef["illustrative_model_score"],
                "model_status": "illustrative",
                "label": "Illustrative (pre-training placeholder)",
            },
        }
        
        record_path = RECORDS_DIR / f"{fdef['id']}.json"
        with open(record_path, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)
        print(f"Generated fixture record: {record_path}")

if __name__ == "__main__":
    make_fixtures()
