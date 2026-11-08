"""
freeze_batch.py
----------------
Builds and freezes a fresh adversarial batch (adv-batch-v1) with
varied parameters and technique combinations across T01-T09.

Every sample stores:
- sample_id: e.g. "adv_000"
- technique: technique ID or combination (e.g. "T02_base64", "T06_import_alias+T04_getattr")
- parameters: exact arguments passed to disguise generators
- baseline_source: clean, un-obfuscated baseline code
- generated_code: real transformed adversarial code

Produces a SHA-256 content hash of the frozen manifest so downstream consumers
(Person B for ML retraining and evaluation) can verify integrity without drift.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import sys
from pathlib import Path

# Add repo root to sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Ensure person_c aliases to Person_c for compatibility
try:
    import Person_c
    sys.modules.setdefault("person_c", Person_c)
except ImportError:
    pass

from Person_c.disguises import (
    base64_disguise,
    rot13_disguise,
    getattr_disguise,
    delay_disguise,
    string_split_disguise,
)
from Person_c.transformations_ext import (
    import_alias_disguise,
    dunder_import_disguise,
    chr_build_disguise,
    hex_escape_disguise,
)

OUTPUT_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = OUTPUT_DIR / "samples"

# 12 adversarial test cases covering T01-T09 and multi-technique combinations
# with varied parameters (trigger counts, alias names, alternative words, combos)
ADVERSARIAL_SPECIFICATIONS = [
    {
        "technique": "T01_string_split",
        "description": "String concatenation split on function attribute name",
        "parameters": {"sensitive_word": "system", "seed": 42},
        "baseline_source": 'import os\nos.system("echo adv_000")',
        "builder": lambda spec: (
            f"import os\n"
            f"getattr(os, {string_split_disguise(spec['parameters']['sensitive_word'], seed=spec['parameters']['seed'])})(\"echo adv_000\")"
        ),
    },
    {
        "technique": "T02_base64",
        "description": "Base64 encoded payload with dynamic execution",
        "parameters": {"payload": 'import os\nos.system("echo adv_001")'},
        "baseline_source": 'import os\nos.system("echo adv_001")',
        "builder": lambda spec: base64_disguise(spec["parameters"]["payload"]),
    },
    {
        "technique": "T03_rot13",
        "description": "ROT13 encoded payload with dynamic execution",
        "parameters": {"payload": 'import os\nos.system("echo adv_002")'},
        "baseline_source": 'import os\nos.system("echo adv_002")',
        "builder": lambda spec: rot13_disguise(spec["parameters"]["payload"]),
    },
    {
        "technique": "T04_getattr",
        "description": "Dynamic function resolution via getattr with split name",
        "parameters": {"module": "os", "func_name": "system", "args": '"echo adv_003"'},
        "baseline_source": 'import os\nos.system("echo adv_003")',
        "builder": lambda spec: getattr_disguise(
            spec["parameters"]["module"],
            spec["parameters"]["func_name"],
            spec["parameters"]["args"],
        ),
    },
    {
        "technique": "T05_delay",
        "description": "Delayed execution trigger with counter threshold = 7",
        "parameters": {"payload": 'import os\nos.system("echo adv_004")', "trigger_count": 7},
        "baseline_source": 'import os\nos.system("echo adv_004")',
        "builder": lambda spec: delay_disguise(
            spec["parameters"]["payload"],
            trigger_count=spec["parameters"]["trigger_count"],
        ),
    },
    {
        "technique": "T05_delay",
        "description": "Delayed execution trigger with counter threshold = 3",
        "parameters": {"payload": 'import os\nos.system("echo adv_005")', "trigger_count": 3},
        "baseline_source": 'import os\nos.system("echo adv_005")',
        "builder": lambda spec: delay_disguise(
            spec["parameters"]["payload"],
            trigger_count=spec["parameters"]["trigger_count"],
        ),
    },
    {
        "technique": "T06_import_alias",
        "description": "Module import aliasing concealing os.popen",
        "parameters": {"module": "os", "func_name": "popen", "args": '"echo adv_006"', "alias": "_sysq"},
        "baseline_source": 'import os\nos.popen("echo adv_006")',
        "builder": lambda spec: import_alias_disguise(
            spec["parameters"]["module"],
            spec["parameters"]["func_name"],
            spec["parameters"]["args"],
            alias=spec["parameters"]["alias"],
        ),
    },
    {
        "technique": "T07_dunder_import",
        "description": "Dynamic import resolution via __import__ and dynamic string arg",
        "parameters": {"module_expr": '"o" + "s"', "func_name": "system", "args": '"echo adv_007"'},
        "baseline_source": 'import os\nos.system("echo adv_007")',
        "builder": lambda spec: f'__import__({spec["parameters"]["module_expr"]}).{spec["parameters"]["func_name"]}({spec["parameters"]["args"]})',
    },
    {
        "technique": "T08_chr_build",
        "description": "Attribute name constructed via chr() joins and resolved with getattr",
        "parameters": {"word": "popen", "args": '"echo adv_008"'},
        "baseline_source": 'import os\nos.popen("echo adv_008")',
        "builder": lambda spec: (
            f"import os\n"
            f"cmd_fn = {chr_build_disguise(spec['parameters']['word'])}\n"
            f"getattr(os, cmd_fn)({spec['parameters']['args']})"
        ),
    },
    {
        "technique": "T09_hex_escape",
        "description": "Attribute name hex-decoded via bytes.fromhex and resolved with getattr",
        "parameters": {"word": "system", "args": '"echo adv_009"'},
        "baseline_source": 'import os\nos.system("echo adv_009")',
        "builder": lambda spec: (
            f"import os\n"
            f"cmd_fn = {hex_escape_disguise(spec['parameters']['word'])}\n"
            f"getattr(os, cmd_fn)({spec['parameters']['args']})"
        ),
    },
    {
        "technique": "T06_import_alias+T04_getattr",
        "description": "Combination: aliased import followed by 2-arg getattr call",
        "parameters": {"module": "os", "alias": "sec_os", "func_name": "system", "args": '"echo adv_010"'},
        "baseline_source": 'import os\nos.system("echo adv_010")',
        "builder": lambda spec: (
            f"import {spec['parameters']['module']} as {spec['parameters']['alias']}\n"
            f"getattr({spec['parameters']['alias']}, \"{spec['parameters']['func_name']}\")({spec['parameters']['args']})"
        ),
    },
    {
        "technique": "T06_import_alias+T01_string_split+T04_getattr",
        "description": "Combination: aliased import, string split function name, and getattr call",
        "parameters": {"module": "subprocess", "alias": "sp", "func_split": '"r" + "un"', "args": '["echo", "adv_011"]'},
        "baseline_source": 'import subprocess\nsubprocess.run(["echo", "adv_011"])',
        "builder": lambda spec: (
            f"import {spec['parameters']['module']} as {spec['parameters']['alias']}\n"
            f"getattr({spec['parameters']['alias']}, {spec['parameters']['func_split']})({spec['parameters']['args']})"
        ),
    },
]


def freeze_batch() -> dict:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

    manifest_entries = []

    for i, spec in enumerate(ADVERSARIAL_SPECIFICATIONS):
        sample_id = f"adv_{i:03d}"
        generated_code = spec["builder"](spec)

        # Pre-flight syntax validation: every generated sample MUST be valid Python
        try:
            ast.parse(generated_code)
        except SyntaxError as e:
            raise RuntimeError(f"Generated sample {sample_id} ({spec['technique']}) failed AST syntax validation: {e}")

        # Write sample to standalone file for inspection
        sample_file = SAMPLES_DIR / f"{sample_id}.py"
        sample_file.write_text(generated_code, encoding="utf-8")

        manifest_entries.append({
            "sample_id": sample_id,
            "technique": spec["technique"],
            "description": spec["description"],
            "parameters": spec["parameters"],
            "baseline_source": spec["baseline_source"],
            "generated_code": generated_code,
            "source_file": f"samples/{sample_id}.py",
        })

    manifest = {
        "batch_name": "adv-batch-v1",
        "version": "1.0.0",
        "total_samples": len(manifest_entries),
        "real_disguises_used": True,
        "note": "Official frozen adversarial evaluation batch v1. Used for Person A evasion evaluation and Person B ML retraining.",
        "entries": manifest_entries,
    }

    # Deterministic SHA-256 calculation over canonical JSON representation
    manifest_raw = json.dumps(manifest, indent=2, sort_keys=True)
    content_hash = hashlib.sha256(manifest_raw.encode("utf-8")).hexdigest()
    manifest["manifest_hash_sha256"] = content_hash

    # Write final manifest
    manifest_path = OUTPUT_DIR / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)

    print(f"Successfully froze {len(manifest_entries)} adversarial samples to {manifest_path}")
    print(f"Manifest SHA-256 hash: {content_hash}")
    return manifest


if __name__ == "__main__":
    freeze_batch()
