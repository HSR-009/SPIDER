"""Tests for spider/hunter (brief section 5.6).

Planted-artifact tests:
(a) evil.pth containing import os; os.system("id") -> HIGH
(b) sitecustomize.py with exec(...) -> HIGH / strong signal
(c) dist whose entry_points.txt console script points to a module outside its own package -> MEDIUM
(d) normal dist -> not flagged
(e) dist whose RECORD lists a missing file -> coverage problem
(f) dist without RECORD (Kali apt style .egg-info dir with top_level.txt) -> falls back to directory listing
Assert (a)(b)(c) flagged with correct severity, (d) not, (e) records coverage problem,
(f) falls back to directory listing (or notes file_list_unavailable).
Assert second run reports 0 "new".
Adding allowlist hash removes (a) / sets priority to 0.
Assert no module from the fake tree is imported (sys.modules unchanged).
"""
import base64
import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from spider.hunter.hunt import run_hunt, sha256_of_file
from spider.hunter.store import HunterStore


def b64_hash(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


class TestHunter(unittest.TestCase):
    def setUp(self):
        # Snapshot sys.modules keys
        self._initial_modules = set(sys.modules.keys())

    def tearDown(self):
        # Verify sys.modules did not import anything from fake trees
        current_modules = set(sys.modules.keys())
        diff = current_modules - self._initial_modules
        # Ignore any standard library modules loaded by the hunter itself
        leaked = [m for m in diff if "evil" in m or "fake" in m or "otherpkg" in m]
        self.assertEqual(leaked, [], f"Modules from fake tree leaked into sys.modules: {leaked}")

    def test_planted_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            site_dir = Path(td) / "site-packages"
            site_dir.mkdir()
            db_file = Path(td) / "hunter.db"

            # (a) evil.pth with executable line
            evil_pth = site_dir / "evil.pth"
            evil_pth.write_text('import os; os.system("id")\n', encoding="utf-8")
            evil_pth_sha = sha256_of_file(evil_pth)

            # (b) sitecustomize.py with exec
            site_custom = site_dir / "sitecustomize.py"
            site_custom.write_text('exec("x = 1")\n', encoding="utf-8")

            # (c) dist whose entry_points.txt console script points outside own package
            # e.g. dist name = mypkg, top_level = mypkg, entry point points to otherpkg.x:main
            dist_c = site_dir / "pkg_c-1.0.dist-info"
            dist_c.mkdir()
            (dist_c / "METADATA").write_text("Metadata-Version: 2.1\nName: pkg-c\nVersion: 1.0\n", encoding="utf-8")
            (dist_c / "top_level.txt").write_text("pkg_c\n", encoding="utf-8")
            (dist_c / "entry_points.txt").write_text(
                "[console_scripts]\nfoo = otherpkg.x:main\n",
                encoding="utf-8",
            )
            # RECORD for dist_c
            rec_c = dist_c / "RECORD"
            rec_c.write_text("pkg_c/__init__.py,,0\n", encoding="utf-8")
            pkg_c_dir = site_dir / "pkg_c"
            pkg_c_dir.mkdir()
            (pkg_c_dir / "__init__.py").write_text("# normal code\n", encoding="utf-8")

            # (d) normal dist
            dist_d = site_dir / "normal_pkg-1.0.dist-info"
            dist_d.mkdir()
            (dist_d / "METADATA").write_text("Metadata-Version: 2.1\nName: normal-pkg\nVersion: 1.0\n", encoding="utf-8")
            (dist_d / "top_level.txt").write_text("normal_pkg\n", encoding="utf-8")
            normal_dir = site_dir / "normal_pkg"
            normal_dir.mkdir()
            norm_code = b"def add(a, b):\n    return a + b\n"
            norm_file = normal_dir / "__init__.py"
            norm_file.write_bytes(norm_code)
            rec_d = dist_d / "RECORD"
            rec_d.write_text(f"normal_pkg/__init__.py,sha256={b64_hash(norm_code)},{len(norm_code)}\n", encoding="utf-8")

            # (e) dist whose RECORD lists a missing file
            dist_e = site_dir / "pkg_e-1.0.dist-info"
            dist_e.mkdir()
            (dist_e / "METADATA").write_text("Metadata-Version: 2.1\nName: pkg-e\nVersion: 1.0\n", encoding="utf-8")
            (dist_e / "RECORD").write_text("pkg_e/missing.py,sha256=abcdef,100\n", encoding="utf-8")

            # (f) dist without RECORD (Kali apt style .egg-info dir with top_level.txt)
            dist_f = site_dir / "apt_pkg-1.0.egg-info"
            dist_f.mkdir()
            (dist_f / "PKG-INFO").write_text("Metadata-Version: 2.1\nName: apt-pkg\nVersion: 1.0\n", encoding="utf-8")
            (dist_f / "top_level.txt").write_text("apt_pkg\n", encoding="utf-8")
            apt_dir = site_dir / "apt_pkg"
            apt_dir.mkdir()
            (apt_dir / "__init__.py").write_text("# apt code\n", encoding="utf-8")

            # --- RUN 1 ---
            res1 = run_hunt(extra_site_packages=[site_dir], db_path=db_file, include_system_defaults=False)
            items1 = res1["items"]

            # (a) evil.pth should be HIGH
            pth_items = [it for it in items1 if it["artifact"] == "pth"]
            self.assertEqual(len(pth_items), 1)
            self.assertEqual(pth_items[0]["severity"], "HIGH")
            self.assertTrue(pth_items[0]["new_since_last"])

            # (b) sitecustomize.py should be flagged
            custom_items = [it for it in items1 if it["artifact"] == "startup"]
            self.assertEqual(len(custom_items), 1)
            self.assertIn(custom_items[0]["severity"], ("HIGH", "MEDIUM"))

            # (c) entry point targeting otherpkg outside package should be MEDIUM
            ep_items = [it for it in items1 if it["artifact"] == "entrypoint"]
            self.assertEqual(len(ep_items), 1)
            self.assertEqual(ep_items[0]["severity"], "MEDIUM")
            self.assertIn("otherpkg", ep_items[0]["reason"])

            # (d) normal dist should have NO findings
            normal_items = [it for it in items1 if it.get("dist") == "normal-pkg"]
            self.assertEqual(normal_items, [])

            # (e) dist e should record coverage problem (missing file listed in RECORD)
            cov_errors = res1["coverage"]["errors"]
            self.assertTrue(any("pkg-e" in err or "missing.py" in err for err in cov_errors))

            # (f) dist f without RECORD falls back to directory listing (no crash)
            # apt_pkg has top_level.txt and files on disk
            self.assertNotIn("apt-pkg", res1["coverage"]["dists_without_file_list"])

            # Assert all items in run 1 had new_since_last = True
            for it in items1:
                self.assertTrue(it["new_since_last"])

            # --- RUN 2 ---
            res2 = run_hunt(extra_site_packages=[site_dir], db_path=db_file, include_system_defaults=False)
            items2 = res2["items"]
            # Assert second run reports 0 "new"
            new_items = [it for it in items2 if it["new_since_last"]]
            self.assertEqual(len(new_items), 0, f"Expected 0 new items in second run, got: {new_items}")

            # --- ALLOWLIST TEST ---
            store = HunterStore(db_path=db_file)
            store.add_allow(evil_pth_sha, note="Allowing test evil.pth")

            # --- RUN 3 ---
            res3 = run_hunt(extra_site_packages=[site_dir], db_path=db_file, include_system_defaults=False)
            items3 = res3["items"]
            pth_item3 = next(it for it in items3 if it["artifact"] == "pth")
            self.assertTrue(pth_item3["allowlisted"])
            self.assertEqual(pth_item3["priority"], 0)


if __name__ == "__main__":
    unittest.main()
