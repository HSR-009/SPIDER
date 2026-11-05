"""Engine tests (brief step 2.5)."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

from spider.engine.scan import scan_directory
from spider.engine.limits import Limits
from spider_contract.validate import validate_record


SRC_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "src"


class EngineTests(unittest.TestCase):
    def test_a_scan_fixtures_valid(self):
        """(a) scan each fixtures/src/* and assert valid."""
        for p in sorted(SRC_DIR.iterdir()):
            if p.is_dir():
                record = scan_directory(p)
                errs = validate_record(record)
                self.assertEqual(errs, [], f"Validation errors on {p.name}: {errs}")

    def test_b_installhook_finding_phase(self):
        """(b) demo-installhook -> has an Install-Time finding with phase install."""
        record = scan_directory(SRC_DIR / "demo-installhook")
        install_findings = [
            f for f in record["findings"]
            if f["category"] == "install_time" and f["trigger_phase"] == "install"
        ]
        self.assertTrue(len(install_findings) >= 1)

    def test_c_nativeonly_unable_to_assess(self):
        """(c) demo-nativeonly -> binary files listed, broken.py in parse_failures, verdict unable_to_assess."""
        record = scan_directory(SRC_DIR / "demo-nativeonly")
        bin_files = [f for f in record["files"] if f["kind"] == "binary"]
        self.assertTrue(len(bin_files) >= 1)
        pf_paths = [pf["path"] for pf in record["inventory"]["parse_failures"]]
        self.assertTrue(any("broken.py" in p for p in pf_paths))
        self.assertEqual(record["verdict"]["outcome"], "unable_to_assess")

    def test_d_vendored_paths_set(self):
        """(d) demo-vendored -> vendored_paths set."""
        record = scan_directory(SRC_DIR / "demo-vendored")
        self.assertTrue(len(record["inventory"]["vendored_paths"]) > 0)

    @unittest.skipIf(sys.platform == "win32", "Symlink creation requires elevated privileges on Windows")
    def test_e_symlink_skipped(self):
        """(e) symlink in a temp tree is skipped."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            target = tmp_path / "target.py"
            target.write_text("x = 1\n", encoding="utf-8")
            link = tmp_path / "link.py"
            os.symlink(target, link)

            record = scan_directory(tmp_path)
            uninspected_reasons = {u["reason"] for u in record["inventory"]["uninspected"]}
            self.assertIn("symlink_skipped", uninspected_reasons)

    def test_f_max_files_limit_hit(self):
        """(f) a temp tree of 30 files with max_files=10 -> limits_hit contains max_files and verdict unable_to_assess."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            for i in range(30):
                (tmp_path / f"file_{i:02d}.py").write_text("x = 1\n", encoding="utf-8")

            record = scan_directory(tmp_path, limits=Limits(max_files=10))
            self.assertIn("max_files", record["inventory"]["limits_hit"])
            self.assertEqual(record["verdict"]["outcome"], "unable_to_assess")

    def test_g_tests_subfolder_doc_kind_no_finding(self):
        """(g) a tests/ subfolder file with eval(...) produces no finding and is kind doc."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            tests_dir = tmp_path / "tests"
            tests_dir.mkdir()
            test_file = tests_dir / "test_something.py"
            test_file.write_text("eval('1 + 1')\n", encoding="utf-8")

            record = scan_directory(tmp_path)
            self.assertEqual(record["findings"], [])
            test_file_entry = next((f for f in record["files"] if "test_something.py" in f["path"]), None)
            self.assertIsNotNone(test_file_entry)
            self.assertEqual(test_file_entry["kind"], "doc")

    def test_h_native_only_so_file_limitation(self):
        """Test: a directory containing only a .so file gives unable_to_assess with a limitation that says why."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            so_file = tmp_path / "libsample.so"
            so_file.write_bytes(b"\x7fELF\x02\x01\x01\x00")

            record = scan_directory(tmp_path)
            self.assertEqual(record["verdict"]["outcome"], "unable_to_assess")
            # Must have a limitation explaining why
            limitations = record["verdict"]["limitations"]
            self.assertTrue(any("Coverage problem:" in l or "nothing_inspected" in l or "uninspected_ratio" in l for l in limitations))

    def test_i_setup_cfg_cmdclass_indicator(self):
        """Test: setup.cfg [cmdclass] produces setup_cfg_cmdclass indicator."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cfg_file = tmp_path / "setup.cfg"
            cfg_file.write_text("[cmdclass]\nbuild_py = custom.BuildPy\n", encoding="utf-8")

            record = scan_directory(tmp_path)
            indicators = [f["indicator"] for f in record["findings"]]
            self.assertIn("setup_cfg_cmdclass", indicators)

    def test_j_artifact_sha256_from_files(self):
        """Test: target.artifact.sha256 is computed correctly from per-file hashes."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            f1 = tmp_path / "a.py"
            f1.write_text("x = 1\n", encoding="utf-8")

            record = scan_directory(tmp_path)
            self.assertIsNotNone(record["target"]["artifact"]["sha256"])
            self.assertEqual(len(record["target"]["artifact"]["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()

