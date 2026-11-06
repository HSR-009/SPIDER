import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path

from spider.fetch import (
    FetchError,
    fetch_package_archive,
    NAME_REGEX,
    VERSION_REGEX,
)


class FakeResponse:
    def __init__(self, data: bytes):
        self.bio = io.BytesIO(data)

    def read(self, amt: int = -1) -> bytes:
        return self.bio.read(amt)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class FakeOpener:
    def __init__(self, url_map):
        self.url_map = url_map

    def open(self, req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else req
        if url in self.url_map:
            val = self.url_map[url]
            if isinstance(val, Exception):
                raise val
            return FakeResponse(val)
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)


class FetchTests(unittest.TestCase):
    def test_name_and_version_regex(self):
        self.assertTrue(NAME_REGEX.match("requests"))
        self.assertTrue(NAME_REGEX.match("boto3"))
        self.assertTrue(NAME_REGEX.match("my-pkg_name.v1"))
        self.assertFalse(NAME_REGEX.match("-invalid"))
        self.assertFalse(NAME_REGEX.match("invalid/name"))
        self.assertFalse(NAME_REGEX.match("../evil"))

        self.assertTrue(VERSION_REGEX.match("1.0.0"))
        self.assertTrue(VERSION_REGEX.match("2.31.0.post1"))
        self.assertTrue(VERSION_REGEX.match("0.1.0-dev"))
        self.assertFalse(VERSION_REGEX.match("-invalid"))
        self.assertFalse(VERSION_REGEX.match("1.0.0/evil"))

    def test_fetch_success_with_fake_opener(self):
        archive_content = b"fake tar gz content"
        import hashlib
        archive_sha = hashlib.sha256(archive_content).hexdigest()

        meta = {
            "urls": [
                {
                    "packagetype": "sdist",
                    "filename": "demo-1.0.0.tar.gz",
                    "url": "https://fake.pypi/packages/demo-1.0.0.tar.gz",
                    "digests": {"sha256": archive_sha},
                }
            ]
        }

        url_map = {
            "https://pypi.org/pypi/demo/1.0.0/json": json.dumps(meta).encode("utf-8"),
            "https://fake.pypi/packages/demo-1.0.0.tar.gz": archive_content,
        }
        opener = FakeOpener(url_map)

        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp)
            path, sha, verified = fetch_package_archive("demo", "1.0.0", cache_dir=cache_dir, opener=opener)
            self.assertTrue(path.exists())
            self.assertEqual(sha, archive_sha)
            self.assertTrue(verified)
            self.assertEqual(path.read_bytes(), archive_content)

            # Test cache hit on second fetch (metadata is fetched to check expected sha, but file is not re-downloaded)
            opener_meta_only = FakeOpener({
                "https://pypi.org/pypi/demo/1.0.0/json": json.dumps(meta).encode("utf-8"),
            })
            p2, s2, v2 = fetch_package_archive("demo", "1.0.0", cache_dir=cache_dir, opener=opener_meta_only)
            self.assertEqual(p2, path)
            self.assertTrue(v2)

    def test_fetch_hash_mismatch(self):
        archive_content = b"corrupted content"
        meta = {
            "urls": [
                {
                    "packagetype": "sdist",
                    "filename": "demo-1.0.0.tar.gz",
                    "url": "https://fake.pypi/packages/demo-1.0.0.tar.gz",
                    "digests": {"sha256": "0000000000000000000000000000000000000000000000000000000000000000"},
                }
            ]
        }
        url_map = {
            "https://pypi.org/pypi/demo/1.0.0/json": json.dumps(meta).encode("utf-8"),
            "https://fake.pypi/packages/demo-1.0.0.tar.gz": archive_content,
        }
        opener = FakeOpener(url_map)
        with tempfile.TemporaryDirectory() as tmp:
            path, sha, verified = fetch_package_archive("demo", "1.0.0", cache_dir=Path(tmp), opener=opener)
            self.assertFalse(verified)

    def test_invalid_name_raises(self):
        with self.assertRaises(FetchError):
            fetch_package_archive("../bad_name", "1.0.0")


if __name__ == "__main__":
    unittest.main()
