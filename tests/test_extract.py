import io
import os
import tarfile
import tempfile
import unittest
import zipfile

from spider.engine.extract import safe_extract


def _tar(path, members):
    with tarfile.open(path, "w:gz") as tf:
        for ti, data in members:
            tf.addfile(ti, io.BytesIO(data) if data is not None else None)


def _ti(name, data=b"", type=tarfile.REGTYPE, link=""):
    ti = tarfile.TarInfo(name)
    ti.size = len(data) if type == tarfile.REGTYPE else 0
    ti.type = type
    ti.linkname = link
    return ti, (data if type == tarfile.REGTYPE else None)


class Extract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.dest = os.path.join(self.root, "out")
        self.arc = os.path.join(self.root, "a.tar.gz")

    def tearDown(self):
        self.tmp.cleanup()

    def run_tar(self, members, **kw):
        _tar(self.arc, members)
        return safe_extract(self.arc, self.dest, **kw)

    def reasons(self, rep):
        return {r["reason"] for r in rep["rejected"]}

    def test_normal(self):
        rep = self.run_tar([_ti("pkg/a.py", b"x=1\n")])
        self.assertEqual(rep["files"], 1)
        self.assertTrue(os.path.exists(os.path.join(self.dest, "pkg", "a.py")))

    def test_traversal_and_absolute(self):
        rep = self.run_tar([_ti("../../evil.py", b"1"), _ti("/tmp/spider_abs_test.py", b"1"), _ti("ok.py", b"1")])
        self.assertEqual(rep["files"], 1)
        self.assertEqual(self.reasons(rep), {"path_traversal", "absolute_path"})
        self.assertFalse(os.path.exists(os.path.join(self.root, "evil.py")))
        self.assertFalse(os.path.exists("/tmp/spider_abs_test.py"))

    def test_links_and_special(self):
        rep = self.run_tar([_ti("l", type=tarfile.SYMTYPE, link="/etc/passwd"),
                            _ti("h", type=tarfile.LNKTYPE, link="ok.py"),
                            _ti("d", type=tarfile.CHRTYPE), _ti("f", type=tarfile.FIFOTYPE)])
        self.assertEqual(rep["files"], 0)
        self.assertEqual(self.reasons(rep), {"symlink", "hardlink", "special_file"})

    def test_max_files(self):
        rep = self.run_tar([_ti("f%d.py" % i, b"1") for i in range(50)], max_files=10)
        self.assertEqual(rep["files"], 10)
        self.assertIn("max_files", rep["limits_hit"])

    def test_member_too_large(self):
        rep = self.run_tar([_ti("big.py", b"a" * 3000), _ti("s.py", b"1")], max_member_bytes=1000)
        self.assertEqual(rep["files"], 1)
        self.assertIn("too_large", self.reasons(rep))
        self.assertFalse(os.path.exists(os.path.join(self.dest, "big.py")))

    def test_total_bytes(self):
        rep = self.run_tar([_ti("f%d.py" % i, b"a" * 400) for i in range(10)], max_total_bytes=1000, max_member_bytes=500)
        self.assertIn("max_total_bytes", rep["limits_hit"])
        self.assertLessEqual(rep["bytes"], 1000)

    def test_windows_reserved_and_long(self):
        rep = self.run_tar([_ti("pkg/con.py", b"1"), _ti("a/" * 130 + "x.py", b"1")])
        self.assertEqual(rep["files"], 0)
        self.assertEqual(self.reasons(rep), {"windows_reserved_name", "path_too_long"})

    def test_zip_bomb_ratio(self):
        z = os.path.join(self.root, "b.zip")
        with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bomb.py", b"0" * (20 * 1024 * 1024))
            zf.writestr("ok.py", b"x=1")
        rep = safe_extract(z, self.dest)
        self.assertIn("expansion_ratio", self.reasons(rep))
        self.assertEqual(rep["files"], 1)

    def test_zip_symlink_and_traversal(self):
        z = os.path.join(self.root, "s.zip")
        with zipfile.ZipFile(z, "w") as zf:
            zi = zipfile.ZipInfo("link")
            zi.external_attr = (0o120777 << 16)
            zf.writestr(zi, "/etc/passwd")
            zf.writestr("../up.py", "1")
            zf.writestr("fine.py", "1")
        rep = safe_extract(z, self.dest)
        self.assertEqual(rep["files"], 1)
        self.assertEqual(self.reasons(rep), {"symlink", "path_traversal"})

    def test_garbage_archive(self):
        with open(self.arc, "wb") as f:
            f.write(b"not an archive at all")
        rep = safe_extract(self.arc, self.dest)
        self.assertEqual(rep["files"], 0)
        self.assertTrue(any(r["reason"].startswith("unreadable_archive") for r in rep["rejected"]))

    @unittest.skipIf(os.name == "nt", "POSIX permission bits are not meaningful on Windows")
    def test_no_exec_bit(self):
        ti, d = _ti("run.sh", b"#!/bin/sh\n")
        ti.mode = 0o755
        self.run_tar([(ti, d)])
        self.assertFalse(os.stat(os.path.join(self.dest, "run.sh")).st_mode & 0o111)


if __name__ == "__main__":
    unittest.main()
