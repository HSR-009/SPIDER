"""Tests for rescan_corpora driver (Day 3 step 3.3)."""
import gzip
import io
import json
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

from Person_A.pipeline.rescan_corpora import (
    scan_single_archive_task,
    run_rescan,
    check_s2_same_file,
)


def create_tar_gz(path: Path, files: dict) -> None:
    with tarfile.open(path, "w:gz") as tar:
        for name, content in files.items():
            data = content if isinstance(content, bytes) else content.encode("utf-8")
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            ti.mtime = int(time.time())
            tar.addfile(ti, io.BytesIO(data))


class RescanTests(unittest.TestCase):
    def test_01_columns_present(self):
        """Test: required columns present in output row."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            arc_file = tmp_p / "sample-1.0.tar.gz"
            create_tar_gz(arc_file, {
                "sample-1.0/setup.py": "from setuptools import setup\nsetup(name='sample', version='1.0')\n",
                "sample-1.0/sample/__init__.py": "import os\nos.system('id')\n",
            })

            task = {
                "package_id": "sample==1.0",
                "package_name": "sample",
                "version": "1.0",
                "group_id": "sample",
                "label": 1,
                "source": "test",
                "in_index": True,
                "index_annotated": False,
                "archive_path": str(arc_file),
                "artifact_sha256": "123456",
            }

            row = scan_single_archive_task(task)

            # Check required legacy and new columns
            expected_cols = [
                "package_id", "package_name", "version", "group_id", "label", "source",
                "analyzer_version", "ruleset_version", "in_index", "index_annotated",
                "n_py_files", "n_py_files_all", "n_findings", "category_counts",
                "parse_error_count", "failed_static_analysis", "max_severity",
                "findings", "strong_signals", "review_recommended", "verdict_outcome",
                "coverage_problems", "n_parse_failures", "limits_hit", "s2_same_file",
                "archive_used", "scan_seconds", "artifact_sha256"
            ]
            for col in expected_cols:
                self.assertIn(col, row, f"Missing column: {col}")

            self.assertEqual(row["analyzer_version"], "analyzer-v1.1")
            self.assertEqual(row["ruleset_version"], "rules-v1.1")
            self.assertIsInstance(row["strong_signals"], list)
            self.assertIsInstance(row["coverage_problems"], list)
            self.assertIsInstance(row["limits_hit"], list)

    def test_02_resume_works(self):
        """Test: resume skips package_ids already present."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            arc1 = tmp_p / "p1-1.0.tar.gz"
            create_tar_gz(arc1, {"p1-1.0/a.py": "x = 1\n"})
            arc2 = tmp_p / "p2-1.0.tar.gz"
            create_tar_gz(arc2, {"p2-1.0/b.py": "y = 2\n"})

            manifest = tmp_p / "manifest.jsonl"
            manifest.write_text(
                json.dumps({"package_name": "p1", "version": "1.0", "archive_path": str(arc1), "sha256": "sha1"}) + "\n" +
                json.dumps({"package_name": "p2", "version": "1.0", "archive_path": str(arc2), "sha256": "sha2"}) + "\n",
                encoding="utf-8"
            )

            out_file = tmp_p / "output.jsonl"
            partial_file = tmp_p / "output.jsonl.partial"

            # Pre-populate partial file with p1
            partial_file.write_text(json.dumps({"package_id": "p1==1.0", "package_name": "p1"}) + "\n", encoding="utf-8")

            # Run rescan with --resume
            run_rescan(kind="benign", out_path=out_file, manifest_path=manifest, workers=1, resume=True)

            self.assertTrue(out_file.exists())
            lines = [json.loads(l) for l in out_file.read_text(encoding="utf-8").splitlines() if l.strip()]
            pids = [l["package_id"] for l in lines]
            self.assertIn("p1==1.0", pids)
            self.assertIn("p2==1.0", pids)
            self.assertEqual(len(pids), 2)

    def test_03_worker_error_becomes_unable_to_assess(self):
        """Test: unreadable/corrupted archive produces unable_to_assess with worker_error."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            bad_arc = tmp_p / "corrupt.tar.gz"
            bad_arc.write_bytes(b"not a tar file at all!")

            task = {
                "package_id": "bad==1.0",
                "package_name": "bad",
                "version": "1.0",
                "group_id": "bad",
                "label": 1,
                "source": "test",
                "archive_path": str(bad_arc),
            }

            row = scan_single_archive_task(task)
            self.assertEqual(row["verdict_outcome"], "unable_to_assess")
            self.assertTrue(any("worker_error" in p for p in row["coverage_problems"]))

    def test_04_tests_folder_excluded_from_n_py_files_but_in_n_py_files_all(self):
        """Test: tests/ folder is excluded from n_py_files but counted in n_py_files_all."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            arc_file = tmp_p / "testpkg-1.0.tar.gz"
            create_tar_gz(arc_file, {
                "testpkg-1.0/lib/__init__.py": "x = 1\n",
                "testpkg-1.0/tests/test_x.py": "assert 1 == 1\n",
                "testpkg-1.0/tests/test_y.py": "assert 2 == 2\n",
            })

            task = {
                "package_id": "testpkg==1.0",
                "package_name": "testpkg",
                "version": "1.0",
                "group_id": "testpkg",
                "label": 0,
                "source": "test",
                "archive_path": str(arc_file),
            }

            row = scan_single_archive_task(task)
            # 1 file in lib/ is inspected python; 2 files under tests/ are classified doc
            self.assertEqual(row["n_py_files"], 1)
            self.assertEqual(row["n_py_files_all"], 3)

    def test_05_archive_with_path_traversal_handled(self):
        """Test: archive with path-traversal member is safely rejected and handled."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            arc_file = tmp_p / "traversal-1.0.tar.gz"
            create_tar_gz(arc_file, {
                "../../evil.py": "import os\nos.system('evil')\n",
                "safe.py": "a = 10\n",
            })

            task = {
                "package_id": "traversal==1.0",
                "package_name": "traversal",
                "version": "1.0",
                "group_id": "traversal",
                "label": 1,
                "source": "test",
                "archive_path": str(arc_file),
            }

            row = scan_single_archive_task(task)
            # safe.py inspected, evil.py rejected
            self.assertEqual(row["package_id"], "traversal==1.0")
            self.assertEqual(row["n_py_files"], 1)

    def test_06_malicious_task_id_format_and_sorting(self):
        """Test: malicious tasks format id as name==version (not @), category_counts has legacy names, and output is sorted."""
        from Person_A.pipeline.rescan_corpora import build_malicious_tasks

        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            pkg_root = tmp_p / "pypi"
            pkg_d = pkg_root / "my-malpkg" / "1.2.3"
            pkg_d.mkdir(parents=True)
            arc = pkg_d / "my-malpkg-1.2.3.tar.gz"
            create_tar_gz(arc, {
                "my-malpkg-1.2.3/setup.py": "import os\nos.system('id')\n",
            })

            index = {"my-malpkg@1.2.3": [{"purl": {"value": "pkg:pypi/my-malpkg@1.2.3"}}]}
            tasks = build_malicious_tasks(pkg_root, index)

            self.assertEqual(len(tasks), 1)
            t = tasks[0]
            self.assertEqual(t["package_id"], "my-malpkg==1.2.3")
            self.assertIn("==", t["package_id"])
            self.assertNotIn("@", t["package_id"])
            self.assertTrue(t["in_index"])

            row = scan_single_archive_task(t)
            self.assertEqual(row["package_id"], "my-malpkg==1.2.3")
            # Category counts must be legacy labels
            self.assertIn("Command Execution", row["category_counts"])
            self.assertNotIn("command_execution", row["category_counts"])

    def test_07_rescan_summary_coverage_with_fake_files(self):
        """Test: check_coverage in rescan_summary accurately reports missing IDs and samples."""
        from Person_A.analysis.rescan_summary import check_coverage

        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            v1_file = tmp_p / "v1.jsonl"
            v1_file.write_text(
                json.dumps({"package_id": "pkg_a==1.0"}) + "\n" +
                json.dumps({"package_id": "pkg_b==2.0"}) + "\n" +
                json.dumps({"package_id": "pkg_c==3.0"}) + "\n",
                encoding="utf-8"
            )

            holdout_file = tmp_p / "holdout.csv"
            holdout_file.write_text(
                "package_id,package_name,group_id,label\n"
                "pkg_b==2.0,pkg_b,pkg_b,1\n"
                "pkg_d==4.0,pkg_d,pkg_d,1\n",
                encoding="utf-8"
            )

            v11_ids = {"pkg_a==1.0", "pkg_b==2.0"}

            cov = check_coverage(v11_ids, v1_file, holdout_file, filter_label=1)
            self.assertEqual(cov["v1_total"], 3)
            self.assertEqual(cov["missing_v1_count"], 1)
            self.assertEqual(cov["missing_v1_sample"], ["pkg_c==3.0"])
            self.assertEqual(cov["holdout_total"], 2)
            self.assertEqual(cov["missing_holdout_count"], 1)
            self.assertEqual(cov["missing_holdout_sample"], ["pkg_d==4.0"])


if __name__ == "__main__":
    unittest.main()

