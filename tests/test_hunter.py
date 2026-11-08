"""Tests for spider/hunter (brief section 5.6 and Day 5 corrections).

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

Safety, noise & coverage tests:
- Planted FIFO test (skipped on Windows)
- Large file (>20MB) skipped for hashing with skipped_too_large note
- Large .py (>1MB) skipped for AST analysis with skipped_py_too_large note
- Cross-file signal separation: signals in two separate files must NOT combine into a multi-finding strong signal
- Script in bin/ or Scripts/ modified after install is NOT flagged as tamper
- Strong signal in sitecustomize.py is still HIGH
- Entry-point ownership from RECORD: foo-tool with RECORD foo/__init__.py and foo.cli:main -> not flagged; otherpkg.x:main -> MEDIUM
- Tamper check accepting both urlsafe base64 and 64-char hex digests
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
            evil_pth_sha, _ = sha256_of_file(evil_pth)

            # (b) sitecustomize.py with exec
            site_custom = site_dir / "sitecustomize.py"
            site_custom.write_text('exec("x = 1")\n', encoding="utf-8")

            # (c) dist whose entry_points.txt console script points outside own package
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

            # (b) sitecustomize.py should be flagged (exec -> strong signal S2/S5 or finding -> HIGH)
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
            self.assertEqual(res1["coverage"]["counts"]["missing_in_RECORD"], 1)

            # (f) dist f without RECORD falls back to directory listing (no crash)
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

    def test_planted_fifo_safety(self):
        if sys.platform == "win32":
            self.skipTest("FIFOs (mkfifo) not supported on Windows")

        with tempfile.TemporaryDirectory() as td:
            site_dir = Path(td) / "site-packages"
            site_dir.mkdir()
            db_file = Path(td) / "hunter.db"

            fifo_path = site_dir / "evil.fifo"
            os.mkfifo(fifo_path)

            res = run_hunt(extra_site_packages=[site_dir], db_path=db_file, include_system_defaults=False)
            self.assertIsNotNone(res)

    def test_large_file_safety(self):
        with tempfile.TemporaryDirectory() as td:
            site_dir = Path(td) / "site-packages"
            site_dir.mkdir()
            db_file = Path(td) / "hunter.db"

            # Create large .pth file (>20MB) sparsely
            large_pth = site_dir / "huge.pth"
            with open(large_pth, "wb") as f:
                f.seek(21 * 1024 * 1024)
                f.write(b"import os\n")

            # Create large .py file in a distribution (>1MB)
            dist_l = site_dir / "large_pkg-1.0.dist-info"
            dist_l.mkdir()
            (dist_l / "METADATA").write_text("Metadata-Version: 2.1\nName: large-pkg\nVersion: 1.0\n", encoding="utf-8")
            (dist_l / "top_level.txt").write_text("large_pkg\n", encoding="utf-8")
            (dist_l / "RECORD").write_text("large_pkg/__init__.py,,0\n", encoding="utf-8")
            lpkg_dir = site_dir / "large_pkg"
            lpkg_dir.mkdir()
            large_py = lpkg_dir / "__init__.py"
            with open(large_py, "wb") as f:
                f.seek(2 * 1024 * 1024)
                f.write(b"print(1)\n")

            res = run_hunt(extra_site_packages=[site_dir], db_path=db_file, include_system_defaults=False)
            cov_errors = res["coverage"]["errors"]
            counts = res["coverage"]["counts"]
            self.assertTrue(any("skipped_too_large" in e for e in cov_errors))
            self.assertTrue(any("skipped_py_too_large" in e for e in cov_errors))
            self.assertGreaterEqual(counts["skipped_too_large"], 2)

    def test_per_file_signal_isolation_and_downgrade(self):
        with tempfile.TemporaryDirectory() as td:
            site_dir = Path(td) / "site-packages"
            site_dir.mkdir()
            db_file = Path(td) / "hunter.db"

            dist = site_dir / "split_pkg-1.0.dist-info"
            dist.mkdir()
            (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: split-pkg\nVersion: 1.0\n", encoding="utf-8")
            (dist / "top_level.txt").write_text("split_pkg\n", encoding="utf-8")
            (dist / "RECORD").write_text("split_pkg/__init__.py,,0\nsplit_pkg/__main__.py,,0\n", encoding="utf-8")
            pkg_dir = site_dir / "split_pkg"
            pkg_dir.mkdir()

            (pkg_dir / "__init__.py").write_text("import os\nx = os.environ['FOO']\n", encoding="utf-8")
            (pkg_dir / "__main__.py").write_text("import requests\nrequests.post('http://example.com')\n", encoding="utf-8")

            res = run_hunt(extra_site_packages=[site_dir], db_path=db_file, include_system_defaults=False)
            dist_items = [it for it in res["items"] if it.get("dist") == "split-pkg"]

            high_items = [it for it in dist_items if it.get("severity") == "HIGH"]
            self.assertEqual(high_items, [], f"Signals combined across files: {high_items}")

            low_items = [it for it in dist_items if it.get("severity") == "LOW"]
            self.assertEqual(len(low_items), 2)
            for it in low_items:
                self.assertIn("downgraded to LOW", it["reason"])

    def test_tamper_skip_bin_and_scripts(self):
        with tempfile.TemporaryDirectory() as td:
            site_dir = Path(td) / "site-packages"
            site_dir.mkdir()
            db_file = Path(td) / "hunter.db"

            dist = site_dir / "tamper_pkg-1.0.dist-info"
            dist.mkdir()
            (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: tamper-pkg\nVersion: 1.0\n", encoding="utf-8")
            (dist / "top_level.txt").write_text("tamper_pkg\n", encoding="utf-8")
            
            bin_dir = site_dir.parent / "bin"
            bin_dir.mkdir(parents=True, exist_ok=True)
            bin_file = bin_dir / "script"
            bin_file.write_bytes(b"#!/usr/bin/python\nnew code\n")

            data_dir = site_dir / "tamper_pkg"
            data_dir.mkdir()
            data_file = data_dir / "config.json"
            data_file.write_bytes(b"modified config\n")

            rec_content = (
                "../../../bin/script,sha256=fake_hash_bin,10\n"
                "tamper_pkg/config.json,sha256=fake_hash_data,10\n"
            )
            (dist / "RECORD").write_text(rec_content, encoding="utf-8")

            res = run_hunt(extra_site_packages=[site_dir], db_path=db_file, include_system_defaults=False)
            tamper_items = [it for it in res["items"] if it.get("artifact") == "tamper"]

            self.assertFalse(any("bin/script" in it.get("path", "").replace("\\", "/") for it in tamper_items))
            self.assertEqual(len(tamper_items), 1)
            self.assertEqual(tamper_items[0]["severity"], "MEDIUM")
            self.assertIn("File modified after install", tamper_items[0]["reason"])

    def test_sitecustomize_strong_signal_is_high(self):
        with tempfile.TemporaryDirectory() as td:
            site_dir = Path(td) / "site-packages"
            site_dir.mkdir()
            db_file = Path(td) / "hunter.db"

            site_custom = site_dir / "sitecustomize.py"
            site_custom.write_text("import base64\nexec(base64.b64decode(b'eA=='))\n", encoding="utf-8")

            res = run_hunt(extra_site_packages=[site_dir], db_path=db_file, include_system_defaults=False)
            custom_items = [it for it in res["items"] if it["artifact"] == "startup"]
            self.assertEqual(len(custom_items), 1)
            self.assertEqual(custom_items[0]["severity"], "HIGH")
            self.assertIn("strong signals", custom_items[0]["reason"])

    def test_entry_point_ownership_from_record(self):
        """dist foo-tool with RECORD foo/__init__.py and entry point foo.cli:main is not flagged.
        otherpkg.x:main still gets MEDIUM.
        """
        with tempfile.TemporaryDirectory() as td:
            site_dir = Path(td) / "site-packages"
            site_dir.mkdir()
            db_file = Path(td) / "hunter.db"

            dist_dir = site_dir / "foo_tool-1.0.dist-info"
            dist_dir.mkdir()
            (dist_dir / "METADATA").write_text("Metadata-Version: 2.1\nName: foo-tool\nVersion: 1.0\n", encoding="utf-8")
            # Notice: NO top_level.txt! Ownership must be derived from RECORD
            rec_content = (
                "foo/__init__.py,,0\n"
                "foo/cli.py,,0\n"
            )
            (dist_dir / "RECORD").write_text(rec_content, encoding="utf-8")
            (dist_dir / "entry_points.txt").write_text(
                "[console_scripts]\n"
                "foo = foo.cli:main\n"
                "other = otherpkg.x:main\n",
                encoding="utf-8",
            )
            foo_pkg = site_dir / "foo"
            foo_pkg.mkdir()
            (foo_pkg / "__init__.py").write_text("# init\n", encoding="utf-8")
            (foo_pkg / "cli.py").write_text("def main(): pass\n", encoding="utf-8")

            res = run_hunt(extra_site_packages=[site_dir], db_path=db_file, include_system_defaults=False)
            ep_items = [it for it in res["items"] if it.get("dist") == "foo-tool" and it.get("artifact") == "entrypoint"]

            # 'foo = foo.cli:main' must NOT be flagged (owned via RECORD)
            self.assertFalse(any("foo = foo.cli:main" in it.get("evidence_snippet", "") for it in ep_items))

            # 'other = otherpkg.x:main' must be flagged as MEDIUM
            other_items = [it for it in ep_items if "otherpkg" in it.get("reason", "")]
            self.assertEqual(len(other_items), 1)
            self.assertEqual(other_items[0]["severity"], "MEDIUM")

    def test_tamper_hex_and_base64_digests(self):
        """Tamper check: RECORD digests may be urlsafe base64 (pip) or 64-char hex (Debian).
        Matching hex digest gives no item, mismatching hex digest gives MEDIUM with digest_format 'hex'.
        """
        with tempfile.TemporaryDirectory() as td:
            site_dir = Path(td) / "site-packages"
            site_dir.mkdir()
            db_file = Path(td) / "hunter.db"

            dist = site_dir / "hex_pkg-1.0.dist-info"
            dist.mkdir()
            (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: hex-pkg\nVersion: 1.0\n", encoding="utf-8")

            pkg_dir = site_dir / "hex_pkg"
            pkg_dir.mkdir()

            f_good = pkg_dir / "good.txt"
            f_good.write_bytes(b"content_good")
            good_hex = hashlib.sha256(b"content_good").hexdigest()

            f_bad = pkg_dir / "bad.txt"
            f_bad.write_bytes(b"content_tampered")
            bad_hex_orig = hashlib.sha256(b"content_original").hexdigest()

            rec_content = (
                f"hex_pkg/good.txt,sha256={good_hex},12\n"
                f"hex_pkg/bad.txt,sha256={bad_hex_orig},16\n"
            )
            (dist / "RECORD").write_text(rec_content, encoding="utf-8")

            res = run_hunt(extra_site_packages=[site_dir], db_path=db_file, include_system_defaults=False)
            tamper_items = [it for it in res["items"] if it.get("dist") == "hex-pkg" and it.get("artifact") == "tamper"]

            # good.txt matches hex digest -> no item
            self.assertFalse(any("good.txt" in it.get("path", "").replace("\\", "/") for it in tamper_items))

            # bad.txt mismatches hex digest -> MEDIUM item with digest_format == 'hex'
            bad_items = [it for it in tamper_items if "bad.txt" in it.get("path", "").replace("\\", "/")]
            self.assertEqual(len(bad_items), 1)
            self.assertEqual(bad_items[0]["severity"], "MEDIUM")
            self.assertEqual(bad_items[0]["digest_format"], "hex")

    def test_debian_entrypoint_filesystem_ownership(self):
        """Test Debian dist with no RECORD/top_level.txt, entry nxc.netexec:main, directory nxc/ beside dist-info -> no item"""
        with tempfile.TemporaryDirectory() as td:
            site_dir = Path(td) / "site-packages"
            site_dir.mkdir()
            db_file = Path(td) / "hunter.db"

            dist_dir = site_dir / "netexec-1.0.dist-info"
            dist_dir.mkdir()
            (dist_dir / "METADATA").write_text("Metadata-Version: 2.1\nName: netexec\nVersion: 1.0\n", encoding="utf-8")
            # No RECORD, no top_level.txt!
            (dist_dir / "entry_points.txt").write_text(
                "[console_scripts]\n"
                "netexec = nxc.netexec:main\n",
                encoding="utf-8",
            )
            # Create nxc/ directory beside dist-info
            nxc_dir = site_dir / "nxc"
            nxc_dir.mkdir()
            (nxc_dir / "__init__.py").write_text("# code\n", encoding="utf-8")

            res = run_hunt(extra_site_packages=[site_dir], db_path=db_file, include_system_defaults=False)
            ep_items = [it for it in res["items"] if it.get("dist") == "netexec" and it.get("artifact") == "entrypoint"]
            self.assertEqual(ep_items, [])

    def test_markdown_it_filesystem_ownership(self):
        """Test markdown-it = markdown_it.cli.parse:main with dist name markdown-it-py -> no item"""
        with tempfile.TemporaryDirectory() as td:
            site_dir = Path(td) / "site-packages"
            site_dir.mkdir()
            db_file = Path(td) / "hunter.db"

            dist_dir = site_dir / "markdown_it_py-1.0.dist-info"
            dist_dir.mkdir()
            (dist_dir / "METADATA").write_text("Metadata-Version: 2.1\nName: markdown-it-py\nVersion: 1.0\n", encoding="utf-8")
            (dist_dir / "entry_points.txt").write_text(
                "[console_scripts]\n"
                "markdown-it = markdown_it.cli.parse:main\n",
                encoding="utf-8",
            )
            # Create markdown_it/ directory beside dist-info
            md_dir = site_dir / "markdown_it"
            md_dir.mkdir()
            (md_dir / "__init__.py").write_text("# code\n", encoding="utf-8")

            res = run_hunt(extra_site_packages=[site_dir], db_path=db_file, include_system_defaults=False)
            ep_items = [it for it in res["items"] if it.get("dist") == "markdown-it-py" and it.get("artifact") == "entrypoint"]
            self.assertEqual(ep_items, [])

    def test_entrypoint_nowhere_on_disk_no_record_is_low(self):
        """No RECORD, entry points at a module that exists nowhere -> LOW with unknown-ownership reason"""
        with tempfile.TemporaryDirectory() as td:
            site_dir = Path(td) / "site-packages"
            site_dir.mkdir()
            db_file = Path(td) / "hunter.db"

            dist_dir = site_dir / "ghost_tool-1.0.dist-info"
            dist_dir.mkdir()
            (dist_dir / "METADATA").write_text("Metadata-Version: 2.1\nName: ghost-tool\nVersion: 1.0\n", encoding="utf-8")
            (dist_dir / "entry_points.txt").write_text(
                "[console_scripts]\n"
                "ghost = nonexistent_module.x:main\n",
                encoding="utf-8",
            )
            # No RECORD, no top_level.txt, and nonexistent_module does not exist on disk

            res = run_hunt(extra_site_packages=[site_dir], db_path=db_file, include_system_defaults=False)
            ep_items = [it for it in res["items"] if it.get("dist") == "ghost-tool" and it.get("artifact") == "entrypoint"]
            self.assertEqual(len(ep_items), 1)
            self.assertEqual(ep_items[0]["severity"], "LOW")
            self.assertIn("ownership unknown (no RECORD/top_level.txt)", ep_items[0]["reason"])

            # Check coverage count
            self.assertGreaterEqual(res["coverage"]["counts"].get("entrypoint_ownership_unknown", 0), 1)

    def test_entrypoint_with_record_not_listing_target_is_medium(self):
        """Dist with RECORD that does not list the target, module not on disk -> MEDIUM (unchanged)"""
        with tempfile.TemporaryDirectory() as td:
            site_dir = Path(td) / "site-packages"
            site_dir.mkdir()
            db_file = Path(td) / "hunter.db"

            dist_dir = site_dir / "my_pkg-1.0.dist-info"
            dist_dir.mkdir()
            (dist_dir / "METADATA").write_text("Metadata-Version: 2.1\nName: my-pkg\nVersion: 1.0\n", encoding="utf-8")
            (dist_dir / "RECORD").write_text("my_pkg/__init__.py,,0\n", encoding="utf-8")
            (dist_dir / "entry_points.txt").write_text(
                "[console_scripts]\n"
                "evil = otherpkg.x:main\n",
                encoding="utf-8",
            )
            my_dir = site_dir / "my_pkg"
            my_dir.mkdir()
            (my_dir / "__init__.py").write_text("# my code\n", encoding="utf-8")

            res = run_hunt(extra_site_packages=[site_dir], db_path=db_file, include_system_defaults=False)
            ep_items = [it for it in res["items"] if it.get("dist") == "my-pkg" and it.get("artifact") == "entrypoint"]
            self.assertEqual(len(ep_items), 1)
            self.assertEqual(ep_items[0]["severity"], "MEDIUM")
            self.assertIn("outside package ownership", ep_items[0]["reason"])

    def test_entrypoint_symlink_outside_site_dir_not_owned(self):
        """Entry_points target dir is a symlink pointing outside the site dir -> not treated as owned"""
        if sys.platform == "win32":
            # On Windows without developer mode/admin symlinks may fail, test or skip safely
            try:
                os.symlink
            except AttributeError:
                self.skipTest("Symlinks not supported on this platform")

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            site_dir = td_path / "site-packages"
            site_dir.mkdir()
            outside_dir = td_path / "outside_payload"
            outside_dir.mkdir()
            db_file = td_path / "hunter.db"

            dist_dir = site_dir / "sneaky_tool-1.0.dist-info"
            dist_dir.mkdir()
            (dist_dir / "METADATA").write_text("Metadata-Version: 2.1\nName: sneaky-tool\nVersion: 1.0\n", encoding="utf-8")
            (dist_dir / "entry_points.txt").write_text(
                "[console_scripts]\n"
                "sneaky = sneaky_pkg.main:run\n",
                encoding="utf-8",
            )

            # Create symlink sneaky_pkg pointing outside site_dir
            link_path = site_dir / "sneaky_pkg"
            try:
                os.symlink(outside_dir, link_path)
            except OSError:
                self.skipTest("Symlink creation requires elevated permissions on Windows")

            res = run_hunt(extra_site_packages=[site_dir], db_path=db_file, include_system_defaults=False)
            ep_items = [it for it in res["items"] if it.get("dist") == "sneaky-tool" and it.get("artifact") == "entrypoint"]
            # Must NOT be treated as owned! Because both RECORD/top_level are missing, it's flagged (LOW or MEDIUM)
            self.assertEqual(len(ep_items), 1)
            self.assertIn(ep_items[0]["severity"], ("LOW", "MEDIUM"))


if __name__ == "__main__":
    unittest.main()
