"""
generate_seeds.py
------------------
Generates the 20 harmless synthetic seed files for Day 2.

SAFETY DESIGN (read this before touching the SEED_SPECS table):
Every seed's risky call lives inside a function that is NEVER invoked at
module scope. The call site is additionally gated behind `if False:` so
static analysis (AST-based) still finds the pattern, but at actual runtime
only `print(MARKER)` ever executes. This is what makes every seed safe to
run in the equivalence harness and in the safety test.

Do NOT "fix" a seed by actually calling the guarded function - that would
make it unsafe and violates the Day 2 safety requirement.

Run with: python generate_seeds.py
Writes 20 .py files into this directory + manifest.json
"""

import json
import os

SEED_SPECS = [
    # --- Command Execution (HIGH) ---
    {
        "id": "seed_01", "category": "Command Execution", "indicator": "os.system",
        "marker": "MARKER_001",
        "setup_code": "import os",
        "payload_code": 'os.system("echo hello")',
    },
    {
        "id": "seed_02", "category": "Command Execution", "indicator": "subprocess.run",
        "marker": "MARKER_002",
        "setup_code": "import subprocess",
        "payload_code": 'subprocess.run(["echo", "hello"])',
    },
    {
        "id": "seed_03", "category": "Command Execution", "indicator": "subprocess.Popen",
        "marker": "MARKER_003",
        "setup_code": "import subprocess",
        "payload_code": 'subprocess.Popen(["echo", "hello"])',
    },
    {
        "id": "seed_04", "category": "Command Execution", "indicator": "os.popen",
        "marker": "MARKER_004",
        "setup_code": "import os",
        "payload_code": 'os.popen("echo hello")',
    },

    # --- Dynamic Code Execution (HIGH) ---
    {
        "id": "seed_05", "category": "Dynamic Code Execution", "indicator": "eval",
        "marker": "MARKER_005",
        "setup_code": "",
        "payload_code": 'eval("1 + 1")',
    },
    {
        "id": "seed_06", "category": "Dynamic Code Execution", "indicator": "exec",
        "marker": "MARKER_006",
        "setup_code": "",
        "payload_code": 'exec("x = 1")',
    },
    {
        "id": "seed_07", "category": "Dynamic Code Execution", "indicator": "compile+exec",
        "marker": "MARKER_007",
        "setup_code": "",
        "payload_code": 'exec(compile("x = 1", "<string>", "exec"))',
    },
    {
        "id": "seed_08", "category": "Dynamic Code Execution", "indicator": "__import__",
        "marker": "MARKER_008",
        "setup_code": "",
        "payload_code": '__import__("os")',
    },

    # --- Credential / Data Access (HIGH) ---
    {
        "id": "seed_09", "category": "Credential / Data Access", "indicator": ".ssh/ path access",
        "marker": "MARKER_009",
        "setup_code": "import os",
        "payload_code": 'open(os.path.expanduser("~/.ssh/id_rsa"))',
    },
    {
        "id": "seed_10", "category": "Credential / Data Access", "indicator": ".aws/credentials path access",
        "marker": "MARKER_010",
        "setup_code": "import os",
        "payload_code": 'open(os.path.expanduser("~/.aws/credentials"))',
    },
    {
        "id": "seed_11", "category": "Credential / Data Access", "indicator": "os.environ secret read",
        "marker": "MARKER_011",
        "setup_code": "import os",
        "payload_code": 'os.environ.get("AWS_SECRET_ACCESS_KEY")',
    },

    # --- Network Activity (MEDIUM) ---
    {
        "id": "seed_12", "category": "Network Activity", "indicator": "requests.get",
        "marker": "MARKER_012",
        "setup_code": "import requests",
        "payload_code": 'requests.get("http://example-fake-domain.test")',
    },
    {
        "id": "seed_13", "category": "Network Activity", "indicator": "requests.post",
        "marker": "MARKER_013",
        "setup_code": "import requests",
        "payload_code": 'requests.post("http://example-fake-domain.test", data={})',
    },
    {
        "id": "seed_14", "category": "Network Activity", "indicator": "urllib.request.urlopen",
        "marker": "MARKER_014",
        "setup_code": "import urllib.request",
        "payload_code": 'urllib.request.urlopen("http://example-fake-domain.test")',
    },

    # --- Obfuscation (MEDIUM) ---
    {
        "id": "seed_15", "category": "Obfuscation", "indicator": "base64.b64decode+exec",
        "marker": "MARKER_015",
        "setup_code": "import base64",
        "payload_code": 'exec(base64.b64decode("eD0x"))',
    },
    {
        "id": "seed_16", "category": "Obfuscation", "indicator": "bytes.fromhex+decode",
        "marker": "MARKER_016",
        "setup_code": "",
        "payload_code": 'bytes.fromhex("78203d2031").decode()',
    },
    {
        "id": "seed_17", "category": "Obfuscation", "indicator": "ROT13 decode",
        "marker": "MARKER_017",
        "setup_code": "import codecs",
        "payload_code": 'codecs.decode("rknp(\\"k=1\\")", "rot_13")',
    },

    # --- Install-Time / Package Execution (HIGH) ---
    {
        "id": "seed_18", "category": "Install-Time / Package Execution",
        "indicator": "custom install cmdclass",
        "marker": "MARKER_018",
        # NOTE: the setuptools import itself is kept inside the guarded
        # block below, not at module level. Importing real setuptools
        # triggers its own internal eval() calls as a side effect of
        # package/plugin discovery - unrelated to our seed's own code, but
        # it would trip the safety test's eval guard regardless. Guarding
        # the import too keeps this seed genuinely inert at runtime.
        "setup_code": "",
        "payload_code": (
            'from setuptools.command.install import install\n'
            '    class _CustomInstall(install):\n'
            '        def run(self):\n'
            '            install.run(self)\n'
            '            import os\n'
            '            os.system("echo post-install hook")'
        ),
        "is_class": True,
    },
    {
        "id": "seed_19", "category": "Install-Time / Package Execution",
        "indicator": "setup.py top-level side effect",
        "marker": "MARKER_019",
        "setup_code": "import os",
        "payload_code": 'os.system("echo setup-time side effect")',
    },
    {
        "id": "seed_20", "category": "Install-Time / Package Execution",
        "indicator": "custom build-backend reference",
        "marker": "MARKER_020",
        "setup_code": "import subprocess",
        "payload_code": 'subprocess.run(["pip", "install", "extra-package"])',
    },
]


FILE_TEMPLATE_FUNC = '''"""
{seed_id} — {category}
Indicator under test: {indicator}

SAFETY: the call below is defined inside a function that is never invoked
(gated by `if False:`). It exists only so static AST analysis can find the
pattern. At runtime, only the marker print below ever executes.
"""

{setup_code}


def _never_called():
    {payload_line}


if False:
    _never_called()

print("{marker}")
'''

FILE_TEMPLATE_CLASS = '''"""
{seed_id} — {category}
Indicator under test: {indicator}

SAFETY: the class below defines a risky method body but is never
instantiated or used as a real setup.py cmdclass. It exists only so static
AST analysis can find the pattern. At runtime, only the marker print below
ever executes.
"""

{setup_code}

if False:
    {payload_line}

print("{marker}")
'''


def build_seed_source(spec):
    if spec.get("is_class"):
        return FILE_TEMPLATE_CLASS.format(
            seed_id=spec["id"],
            category=spec["category"],
            indicator=spec["indicator"],
            setup_code=spec["setup_code"],
            payload_line=spec["payload_code"],
            marker=spec["marker"],
        )
    else:
        return FILE_TEMPLATE_FUNC.format(
            seed_id=spec["id"],
            category=spec["category"],
            indicator=spec["indicator"],
            setup_code=spec["setup_code"],
            payload_line=spec["payload_code"],
            marker=spec["marker"],
        )


def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    manifest = []

    for spec in SEED_SPECS:
        filename = f"{spec['id']}.py"
        filepath = os.path.join(out_dir, filename)
        source = build_seed_source(spec)

        with open(filepath, "w") as f:
            f.write(source)

        manifest.append({
            "seed_id": spec["id"],
            "filename": filename,
            "category": spec["category"],
            "intended_indicator": spec["indicator"],
            "expected_marker": spec["marker"],
        })

    manifest_path = os.path.join(out_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"Generated {len(manifest)} seeds + manifest.json")
    print(f"Categories covered: {len(set(m['category'] for m in manifest))}")


if __name__ == "__main__":
    main()
