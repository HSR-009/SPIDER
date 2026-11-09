"""Verification of Person C's Frozen Adversarial Evaluation Batch (adv-batch-v1).

Enforces strict integrity requirements:
1. Manifest canonical content hash matches the published expected hash.
2. All 12 standalone sample files in samples/ exactly match manifest generated_code.
3. No frozen adversarial files have been modified or tampered with.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[2]
BATCH_DIR = ROOT / "person_c" / "adv_batch"
MANIFEST_PATH = BATCH_DIR / "manifest.json"
SAMPLES_DIR = BATCH_DIR / "samples"

TAG_NAME = "adv-batch-v1"
EXPECTED_MANIFEST_HASH = "bb7f4fe8676000ef1e2f06e08d8387738e8ee4a3c33ac68ade289ffd8875aaa3"


def compute_manifest_hash(manifest_dict: Dict[str, Any]) -> str:
    """Reproduce Person C's freeze_batch.py canonical SHA-256 calculation."""
    obj_copy = dict(manifest_dict)
    obj_copy.pop("manifest_hash_sha256", None)
    canonical_raw = json.dumps(obj_copy, indent=2, sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical_raw).hexdigest()


def verify_adversarial_batch() -> Dict[str, Any]:
    """Verify integrity of adv-batch-v1. Raises RuntimeError if any check fails."""
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(f"Adversarial batch manifest not found: {MANIFEST_PATH}")
    if not SAMPLES_DIR.exists():
        raise FileNotFoundError(f"Adversarial samples directory not found: {SAMPLES_DIR}")

    # 1. Resolve Git Tag SHA if available
    tag_sha = None
    try:
        tag_sha = subprocess.check_output(
            ["git", "rev-parse", TAG_NAME],
            cwd=str(ROOT),
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        pass

    # 2. Read and verify manifest JSON
    manifest_text = MANIFEST_PATH.read_text(encoding="utf-8")
    manifest = json.loads(manifest_text)

    published_hash = manifest.get("manifest_hash_sha256")
    computed_hash = compute_manifest_hash(manifest)

    if computed_hash != EXPECTED_MANIFEST_HASH:
        raise ValueError(
            f"Adversarial manifest hash mismatch!\n"
            f"Expected: {EXPECTED_MANIFEST_HASH}\n"
            f"Computed: {computed_hash}"
        )

    if published_hash != EXPECTED_MANIFEST_HASH:
        raise ValueError(
            f"Published manifest hash in JSON does not match expected!\n"
            f"Expected : {EXPECTED_MANIFEST_HASH}\n"
            f"Published: {published_hash}"
        )

    # 3. Verify all sample files match generated_code
    entries = manifest.get("entries", [])
    if len(entries) != 12:
        raise ValueError(f"Expected 12 adversarial samples, found {len(entries)}")

    sample_checks: List[Dict[str, Any]] = []
    differing_samples: List[str] = []

    for entry in entries:
        sid = entry["sample_id"]
        source_rel = entry["source_file"]
        sample_path = BATCH_DIR / source_rel

        if not sample_path.exists():
            differing_samples.append(f"{sid}: file missing at {sample_path}")
            continue

        disk_content = sample_path.read_text(encoding="utf-8")
        expected_content = entry["generated_code"]

        if disk_content != expected_content:
            differing_samples.append(f"{sid}: content mismatch")

        disk_sha = hashlib.sha256(disk_content.encode("utf-8")).hexdigest()
        sample_checks.append({
            "sample_id": sid,
            "technique": entry["technique"],
            "source_file": source_rel,
            "sha256": disk_sha,
            "matches_manifest": disk_content == expected_content,
        })

    if differing_samples:
        raise ValueError(f"Sample file verification failed for: {differing_samples}")

    return {
        "status": "VERIFIED",
        "tag_name": TAG_NAME,
        "tag_sha": tag_sha,
        "expected_manifest_hash": EXPECTED_MANIFEST_HASH,
        "computed_manifest_hash": computed_hash,
        "hash_matched": True,
        "total_samples": len(entries),
        "differing_samples_count": len(differing_samples),
        "samples": sample_checks,
    }


if __name__ == "__main__":
    report = verify_adversarial_batch()
    print("Adversarial Batch Verification: SUCCESS")
    print(f"Tag SHA       : {report['tag_sha']}")
    print(f"Manifest Hash : {report['computed_manifest_hash']}")
    print(f"Total Samples : {report['total_samples']} (all byte-for-byte verified)")
