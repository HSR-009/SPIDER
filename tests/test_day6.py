"""Unit tests for Day 6 tasks 1, 2, and 3."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path

from Person_A.analysis.fp_wilson import generate_wilson_summary, wilson_95_ci
from Person_A.pipeline.fp_scan import run_fp_scan, sha256_of_file
from Person_A.pipeline.zero_finding_sample import (
    load_zero_finding_candidates,
    run_zero_finding_sampling,
    sample_zero_findings,
    stratify_into_terciles,
)


def make_tar_gz(dest: Path, files: dict[str, str | bytes]) -> str:
    """Create a .tar.gz archive and return its sha256."""
    with tarfile.open(dest, "w:gz") as tf:
        for name, content in files.items():
            if isinstance(content, str):
                data = content.encode("utf-8")
            else:
                data = content
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return sha256_of_file(dest)


class TestDay6(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="spider_day6_tests_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # --- TASK 2 TESTS: Wilson 95% Interval ---
    def test_wilson_formula_against_reference_values(self):
        """Verify Wilson 95% CI formula on hand-computed references with tolerance 1e-3.
        
        Reference:
          k=0, n=100 -> [0.0, 0.0370]
          k=5, n=100 -> [0.0215, 0.1118]
        """
        low0, up0 = wilson_95_ci(0, 100)
        self.assertAlmostEqual(low0, 0.0, delta=1e-3)
        self.assertAlmostEqual(up0, 0.0370, delta=1e-3)

        low5, up5 = wilson_95_ci(5, 100)
        self.assertAlmostEqual(low5, 0.0215, delta=1e-3)
        self.assertAlmostEqual(up5, 0.1118, delta=1e-3)

    def test_wilson_summary_validation_and_output(self):
        """Verify fp_wilson refuses unreviewed rows and produces expected markdown."""
        csv_path = self.temp_dir / "fp_v11.csv"
        out_md = self.temp_dir / "summary.md"

        # 1. Unreviewed row -> must refuse (exit code 1)
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["name", "version", "family", "verdict", "triage_label"])
            writer.writeheader()
            writer.writerow({"name": "pkg-a", "version": "1.0", "family": "pkg", "verdict": "suspicious", "triage_label": ""})
            writer.writerow({"name": "pkg-b", "version": "1.0", "family": "pkg", "verdict": "none_detected_in_this_scan", "triage_label": ""})

        ret_unreviewed = generate_wilson_summary(csv_path, out_md)
        self.assertEqual(ret_unreviewed, 1)

        # 2. Reviewed rows -> exit 0 and check contents
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["name", "version", "family", "verdict", "review_recommended", "triage_label"])
            writer.writeheader()
            writer.writerow({"name": "pkg-a", "version": "1.0", "family": "pkg", "verdict": "suspicious", "review_recommended": "False", "triage_label": "false_positive"})
            writer.writerow({"name": "pkg-b", "version": "1.0", "family": "pkg", "verdict": "none_detected_in_this_scan", "review_recommended": "True", "triage_label": ""})

        ret_ok = generate_wilson_summary(csv_path, out_md)
        self.assertEqual(ret_ok, 0)
        self.assertTrue(out_md.exists())
        content = out_md.read_text(encoding="utf-8")
        self.assertNotIn("X were", content)
        self.assertNotIn(" Y were ", content)
        self.assertNotIn("Z%", content)
        self.assertNotIn("[a, b]", content)
        self.assertIn("On a sample of 2 small, obscure PyPI packages, 1 were flagged suspicious", content)
        self.assertIn("after manual review 1 were false positives", content)
        self.assertIn("**Packages Scanned (n):** 2", content)
        self.assertIn("**False Positives (FP):** 1", content)
        self.assertIn("FP only (unclear counted as true positives)", content)
        self.assertIn("FP + unclear (unclear counted as false positives)", content)

    # --- TASK 1 TESTS: FP Scan with Synthetic Archives ---
    def test_fp_scan_synthetic_corpora(self):
        """Build clean and suspicious synthetic archives, test sha256 verification and scanning."""
        arc_dir = self.temp_dir / "fp_check"
        arc_dir.mkdir()

        # 1. Suspicious archive (install-command override in setup.py)
        susp_tar = arc_dir / "demo-susp-1.0.tar.gz"
        susp_setup = (
            "from setuptools import setup\n"
            "from setuptools.command.install import install\n"
            "class CustomInstall(install):\n"
            "    def run(self):\n"
            "        install.run(self)\n"
            "setup(name='demo-susp', version='1.0', cmdclass={'install': CustomInstall})\n"
        )
        susp_sha = make_tar_gz(susp_tar, {"setup.py": susp_setup, "pkg/__init__.py": "# clean\n"})

        # 2. Clean archive
        clean_tar = arc_dir / "demo-clean-1.0.tar.gz"
        clean_setup = "from setuptools import setup\nsetup(name='demo-clean', version='1.0')\n"
        clean_sha = make_tar_gz(clean_tar, {"setup.py": clean_setup, "clean_pkg/__init__.py": "# hello\n"})

        # Write selection CSV
        sel_csv = self.temp_dir / "selection.csv"
        with sel_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["name", "version", "rank", "size", "sha256"])
            writer.writeheader()
            writer.writerow({"name": "demo-susp", "version": "1.0", "rank": "5001", "size": str(susp_tar.stat().st_size), "sha256": susp_sha})
            writer.writerow({"name": "demo-clean", "version": "1.0", "rank": "5002", "size": str(clean_tar.stat().st_size), "sha256": clean_sha})

        # Write valid hashes file
        hashes_file = self.temp_dir / "archives.sha256"
        hashes_file.write_text(f"{susp_sha}  fp_check/{susp_tar.name}\n{clean_sha}  fp_check/{clean_tar.name}\n", encoding="utf-8")

        out_csv = self.temp_dir / "out.csv"
        excerpts_md = arc_dir / "triage_excerpts.md"

        # Scan
        ret = run_fp_scan(
            sel_path=sel_csv,
            archives_dir=arc_dir,
            hashes_path=hashes_file,
            out_csv_path=out_csv,
            excerpts_path=excerpts_md,
        )
        self.assertEqual(ret, 0)
        self.assertTrue(out_csv.exists())
        self.assertTrue(excerpts_md.exists())

        # Read results
        with out_csv.open("r", encoding="utf-8") as f:
            reader = list(csv.DictReader(f))
            self.assertEqual(len(reader), 2)
            row_map = {r["name"]: r for r in reader}
            self.assertEqual(row_map["demo-susp"]["verdict"], "suspicious")
            self.assertIn("S1_install_command", row_map["demo-susp"]["strong_signals"])
            self.assertEqual(row_map["demo-clean"]["verdict"], "none_detected_in_this_scan")

        # Excerpts must contain demo-susp
        ex_content = excerpts_md.read_text(encoding="utf-8")
        self.assertIn("demo-susp==1.0", ex_content)
        self.assertIn("CustomInstall", ex_content)

    def test_fp_scan_archive_with_symlink_and_comparison_with_rescan(self):
        """Test archive with symlink records rejection/coverage problem and matches rescan_corpora logic."""
        arc_dir = self.temp_dir / "fp_check_symlink"
        arc_dir.mkdir()
        tar_path = arc_dir / "pkg-symlink-1.0.tar.gz"

        with tarfile.open(tar_path, "w:gz") as tf:
            # Symlink member
            ti_link = tarfile.TarInfo("symlink_member")
            ti_link.type = tarfile.SYMTYPE
            ti_link.linkname = "some_target"
            tf.addfile(ti_link)

            # Normal .py member
            ti_py = tarfile.TarInfo("clean_module.py")
            py_data = b"def foo():\n    return 42\n"
            ti_py.size = len(py_data)
            tf.addfile(ti_py, io.BytesIO(py_data))

        tar_sha = sha256_of_file(tar_path)

        sel_csv = self.temp_dir / "sel_symlink.csv"
        with sel_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["name", "version", "rank", "size", "sha256"])
            writer.writeheader()
            writer.writerow({"name": "pkg-symlink", "version": "1.0", "rank": "5001", "size": str(tar_path.stat().st_size), "sha256": tar_sha})

        hashes_file = self.temp_dir / "symlink.sha256"
        hashes_file.write_text(f"{tar_sha}  fp_check/{tar_path.name}\n", encoding="utf-8")

        out_csv = self.temp_dir / "out_symlink.csv"
        ret = run_fp_scan(
            sel_path=sel_csv,
            archives_dir=arc_dir,
            hashes_path=hashes_file,
            out_csv_path=out_csv,
        )
        self.assertEqual(ret, 0)
        self.assertTrue(out_csv.exists())

        with out_csv.open("r", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 1)
            row = rows[0]
            # Symlink rejection in uninspected causes uninspected_ratio coverage problem
            self.assertIn("uninspected_ratio", row["coverage_problems"])
            self.assertEqual(row["verdict"], "unable_to_assess")

        # Compare with rescan_corpora's scan logic for the exact same archive
        from Person_A.pipeline.rescan_corpora import scan_single_archive_task
        task_args = {
            "archive_path": str(tar_path),
            "package_name": "pkg-symlink",
            "version": "1.0",
            "label": 0,
            "source": "benign_pypi",
            "group_id": "pkg-symlink",
            "package_id": "pkg-symlink==1.0",
            "artifact_sha256": tar_sha,
        }
        rescan_row = scan_single_archive_task(task_args)
        # Verdict outcome must equal what rescan_corpora produced
        self.assertEqual(row["verdict"], rescan_row["verdict_outcome"])
        self.assertEqual(row["verdict"], "unable_to_assess")

    def test_fp_scan_corrupted_hash_refuses(self):
        """Corrupted hash must cause fp_scan to refuse to run with exit code 2."""
        arc_dir = self.temp_dir / "fp_check_bad"
        arc_dir.mkdir()
        tar = arc_dir / "pkg-1.0.tar.gz"
        real_sha = make_tar_gz(tar, {"a.py": "x=1\n"})

        sel_csv = self.temp_dir / "selection.csv"
        with sel_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["name", "version", "rank", "size", "sha256"])
            writer.writeheader()
            writer.writerow({"name": "pkg", "version": "1.0", "rank": "5001", "size": "100", "sha256": real_sha})

        # Mismatched expected sha
        hashes_file = self.temp_dir / "bad.sha256"
        hashes_file.write_text(f"0000000000000000000000000000000000000000000000000000000000000000  fp_check/{tar.name}\n", encoding="utf-8")

        out_csv = self.temp_dir / "out.csv"
        ret = run_fp_scan(
            sel_path=sel_csv,
            archives_dir=arc_dir,
            hashes_path=hashes_file,
            out_csv_path=out_csv,
        )
        self.assertEqual(ret, 2)
        self.assertFalse(out_csv.exists())

    # --- TASK 3 TESTS: Zero-Finding Sampling ---
    def test_zero_finding_sample_synthetic(self):
        """Verify tercile stratification, sampling, context excerpting and deterministic sorting."""
        raw_pypi = self.temp_dir / "raw_pypi"
        raw_pypi.mkdir()

        # Create 6 zero-finding packages with different sizes
        pkgs = []
        for i in range(6):
            name = f"zeropkg{i}"
            ver = "1.0"
            ver_dir = raw_pypi / name / ver
            ver_dir.mkdir(parents=True)
            arc_file = ver_dir / f"{name}-{ver}.tar.gz"

            content = {
                "setup.py": f"# setup {i}\nprint('stub')\n",
                "pkg/__init__.py": f"# zero finding module {i}\n",
                "README.txt": "data" * (100 * (i + 1)),
            }
            make_tar_gz(arc_file, content)

            pkgs.append({
                "package_id": f"{name}=={ver}",
                "package_name": name,
                "version": ver,
                "label": "malicious",
                "n_findings": 0,
                "n_py_files": 2,
                "n_files_all": 3,
                "archive_used": str(arc_file),
            })

        table_file = self.temp_dir / "malicious_v11.jsonl"
        with table_file.open("w", encoding="utf-8") as f:
            for p in pkgs:
                f.write(json.dumps(p) + "\n")

        out_csv = self.temp_dir / "zero_finding_review.csv"
        context_md = self.temp_dir / "context.md"

        ret = run_zero_finding_sampling(
            table_path=table_file,
            raw_dir=raw_pypi,
            out_csv=out_csv,
            context_md=context_md,
            seed=42,
        )
        self.assertEqual(ret, 0)
        self.assertTrue(out_csv.exists())
        self.assertTrue(context_md.exists())

        with out_csv.open("r", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 6)
            # Check terciles assigned
            terciles = [r["tercile"] for r in rows]
            self.assertIn("low", terciles)
            self.assertIn("mid", terciles)
            self.assertIn("high", terciles)
            # Empty miss_reason / miss_note
            for r in rows:
                self.assertEqual(r["miss_reason"], "")
                self.assertEqual(r["miss_note"], "")

        # Verify context excerpts
        ctx_text = context_md.read_text(encoding="utf-8")
        self.assertIn("zeropkg0==1.0", ctx_text)
        self.assertIn("setup.py", ctx_text)


if __name__ == "__main__":
    unittest.main()
