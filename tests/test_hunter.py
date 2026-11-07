"""Unit tests for spider.hunter.inventory (Day 4 step 4.7)."""
import sys
import tempfile
import unittest
from pathlib import Path

from spider.hunter.inventory import iter_distributions, list_environments


class HunterInventoryTests(unittest.TestCase):
    def test_list_environments_returns_paths(self):
        roots = list_environments()
        self.assertIsInstance(roots, list)
        for r in roots:
            self.assertIsInstance(r, Path)
            self.assertTrue(r.exists())

        # Test with extra site packages
        with tempfile.TemporaryDirectory() as tmp:
            extra = Path(tmp)
            roots_with_extra = list_environments([extra])
            self.assertIn(extra.resolve(), roots_with_extra)

    def test_iter_distributions_fake_dist_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dist_info = root / "sample_pkg-1.2.3.dist-info"
            dist_info.mkdir(parents=True)

            metadata_content = (
                "Metadata-Version: 2.1\n"
                "Name: sample-pkg\n"
                "Version: 1.2.3\n"
                "Summary: Synthetic package for testing\n"
            )
            (dist_info / "METADATA").write_text(metadata_content, encoding="utf-8")

            record_content = (
                "sample_pkg/__init__.py,sha256=xxx,10\n"
                "sample_pkg/mod.py,sha256=yyy,20\n"
                "sample_pkg-1.2.3.dist-info/METADATA,sha256=zzz,100\n"
                "sample_pkg-1.2.3.dist-info/RECORD,,\n"
            )
            (dist_info / "RECORD").write_text(record_content, encoding="utf-8")

            # Also create package files
            pkg_dir = root / "sample_pkg"
            pkg_dir.mkdir(parents=True)
            (pkg_dir / "__init__.py").write_text("# init\n", encoding="utf-8")
            (pkg_dir / "mod.py").write_text("x = 1\n", encoding="utf-8")

            dists = list(iter_distributions(root))
            self.assertEqual(len(dists), 1)
            d = dists[0]

            self.assertEqual(d["name"], "sample-pkg")
            self.assertEqual(d["version"], "1.2.3")
            self.assertIsNotNone(d["metadata_path"])
            self.assertTrue("sample_pkg-1.2.3.dist-info" in d["metadata_path"])
            self.assertTrue(len(d["files"]) >= 2)
            self.assertTrue(any("sample_pkg" in f for f in d["files"]))


if __name__ == "__main__":
    unittest.main()

