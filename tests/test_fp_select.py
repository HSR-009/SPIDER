"""Tests for Person_A/pipeline/fp_select.py."""
import csv
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from Person_A.pipeline.fp_select import (
    archive_has_py_file,
    load_corpus_groups,
    query_pypi_candidate,
    run_download,
    run_selection,
    select_candidates,
)
from spider_contract.dataset import make_group_id


class TestFPSelect(unittest.TestCase):
    def test_default_rank_bounds(self):
        # Fake 20,000 package rows
        rows = [{"project": f"pkg_{i}"} for i in range(1, 20001)]
        corpus_groups = {make_group_id("pkg_5001")}
        candidates = select_candidates(rows, corpus_groups)
        ranks = [r for r, p in candidates]
        self.assertTrue(all(5000 <= r <= 15000 for r in ranks))
        self.assertNotIn((5001, "pkg_5001"), candidates)

    def test_archive_has_py_file_zip(self):
        with tempfile.TemporaryDirectory() as td:
            p_with_py = Path(td) / "with_py.whl"
            with zipfile.ZipFile(p_with_py, "w") as zf:
                zf.writestr("module.py", "# code")
                zf.writestr("metadata.txt", "data")
            self.assertTrue(archive_has_py_file(p_with_py))

            p_without_py = Path(td) / "without_py.whl"
            with zipfile.ZipFile(p_without_py, "w") as zf:
                zf.writestr("metadata.txt", "data")
                zf.writestr("binary.so", b"\x7fELF")
            self.assertFalse(archive_has_py_file(p_without_py))

    def test_archive_has_py_file_tar(self):
        with tempfile.TemporaryDirectory() as td:
            p_with_py = Path(td) / "with_py.tar.gz"
            with tarfile.open(p_with_py, "w:gz") as tf:
                data = b"print('hello')\n"
                ti = tarfile.TarInfo("pkg/init.py")
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
            self.assertTrue(archive_has_py_file(p_with_py))

            p_without_py = Path(td) / "without_py.tar.gz"
            with tarfile.open(p_without_py, "w:gz") as tf:
                data = b"plain text data\n"
                ti = tarfile.TarInfo("pkg/README.txt")
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
            self.assertFalse(archive_has_py_file(p_without_py))

    def test_run_selection_offline(self):
        candidates = [(5001, "demo1"), (5002, "demo2")]
        fake_api_responses = {
            "demo1": {
                "name": "demo1",
                "version": "1.0.0",
                "rank": 5001,
                "size": 1024,
                "sha256": "abc1",
                "url": "https://example.com/demo1.tar.gz",
                "filename": "demo1.tar.gz",
            },
            "demo2": {
                "name": "demo2",
                "version": "2.0.0",
                "rank": 5002,
                "size": 2048,
                "sha256": "abc2",
                "url": "https://example.com/demo2.tar.gz",
                "filename": "demo2.tar.gz",
            },
        }

        with tempfile.TemporaryDirectory() as td:
            csv_path = Path(td) / "results" / "fp_check_selection.csv"
            with patch("Person_A.pipeline.fp_select.query_pypi_candidate", side_effect=lambda r, p: fake_api_responses.get(p)):
                selected = run_selection(
                    count=2,
                    csv_out=csv_path,
                    custom_candidates=candidates,
                    delay_sec=0.0,
                )

            self.assertEqual(len(selected), 2)
            self.assertTrue(csv_path.exists())
            with csv_path.open("r", encoding="utf-8") as f:
                reader = list(csv.DictReader(f))
                self.assertEqual(len(reader), 2)
                self.assertEqual(reader[0]["name"], "demo1")
                self.assertEqual(reader[1]["name"], "demo2")

    def test_run_download_skips_no_py(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            csv_path = root / "selection.csv"
            out_dir = root / "fp_check"
            out_dir.mkdir()

            # Create archive without py (pkg_no_py)
            p_no = out_dir / "pkg_no_py-1.0.tar.gz"
            with tarfile.open(p_no, "w:gz") as tf:
                data = b"hello\n"
                ti = tarfile.TarInfo("pkg_no_py/data.txt")
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))

            # Create archive with py (pkg_with_py)
            p_yes = out_dir / "pkg_with_py-1.0.tar.gz"
            with tarfile.open(p_yes, "w:gz") as tf:
                data = b"print(1)\n"
                ti = tarfile.TarInfo("pkg_with_py/a.py")
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))

            with csv_path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["name", "version", "rank", "size", "sha256"])
                writer.writeheader()
                writer.writerow({"name": "pkg_no_py", "version": "1.0", "rank": "5001", "size": "100", "sha256": "h1"})
                writer.writerow({"name": "pkg_with_py", "version": "1.0", "rank": "5002", "size": "100", "sha256": "h2"})

            def fake_fetch(name, version, cache_dir=None):
                if name == "pkg_no_py":
                    return p_no, "h1", True
                return p_yes, "h2", True

            with patch("Person_A.pipeline.fp_select.fetch_package_archive", side_effect=fake_fetch):
                accepted = run_download(csv_file=csv_path, out_dir=out_dir, target_count=1)

            self.assertEqual(len(accepted), 1)
            self.assertEqual(accepted[0]["name"], "pkg_with_py")
            # Verify p_no was removed when skipped
            self.assertFalse(p_no.exists())
            self.assertTrue(p_yes.exists())


if __name__ == "__main__":
    unittest.main()
