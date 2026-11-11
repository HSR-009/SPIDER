import unittest
import warnings
from pathlib import Path
import tempfile
import shutil
from unittest.mock import patch

from spider.engine.scan import scan_directory


class TestNormalizeIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="spider_test_norm_"))

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_normalization_marks_findings_and_preserves_original_file(self):
        source = "import os\nos.system('id')\n"
        target = self.tmp_dir / "sample.py"
        target.write_text(source, encoding="utf-8")
        original_bytes = target.read_bytes()

        with patch(
            "spider.engine.scan.normalize_source",
            lambda code: code + "\n# normalized in memory\n",
        ):
            record = scan_directory(self.tmp_dir, normalize=True)

        self.assertEqual(target.read_bytes(), original_bytes)
        self.assertTrue(record["findings"])
        self.assertTrue(all(
            finding["context"]["after_normalization"] is True
            for finding in record["findings"]
        ))

    def test_normalization_disabled_by_default(self):
        target = self.tmp_dir / "sample.py"
        target.write_text("import os\nos.system('id')\n", encoding="utf-8")

        record = scan_directory(self.tmp_dir)

        self.assertTrue(record["findings"])
        self.assertTrue(all(
            finding["context"]["after_normalization"] is False
            for finding in record["findings"]
        ))

    def test_normalization_failure_falls_back_to_original(self):
        target = self.tmp_dir / "sample.py"
        target.write_text("import os\nos.system('id')\n", encoding="utf-8")

        def fail_normalization(_source):
            raise ValueError("test normalization failure")

        with patch("spider.engine.scan.normalize_source", fail_normalization):
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                record = scan_directory(self.tmp_dir, normalize=True)
                self.assertTrue(any(issubclass(warn.category, RuntimeWarning) and "Normalization failed" in str(warn.message) for warn in w))

        self.assertTrue(record["findings"])
        self.assertTrue(all(
            finding["context"]["after_normalization"] is False
            for finding in record["findings"]
        ))


if __name__ == "__main__":
    unittest.main()

