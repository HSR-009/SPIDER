"""Tests for the local UI API (spider/api.py). No network; loopback only."""
import json
import shutil
import tarfile
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from spider.api import make_handler

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "src" / "demo-installhook"


def call(base, path, method="GET", data=None, headers=None):
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.tmp / "scans", str(cls.tmp / "h.db")))
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def post_json(self, path, obj):
        return call(self.base, path, "POST", json.dumps(obj).encode(), {"Content-Type": "application/json"})

    def test_scan_folder_returns_real_verdict(self):
        st, body = self.post_json("/api/scan", {"path": str(FIXTURE)})
        self.assertEqual(st, 200)
        sid = json.loads(body)["scan_id"]
        st, body = call(self.base, f"/api/scans/{sid}")
        rec = json.loads(body)
        self.assertEqual(rec["verdict"]["outcome"], "suspicious")
        self.assertTrue(rec["findings"])

    def test_unknown_id_is_404_and_traversal_blocked(self):
        self.assertEqual(call(self.base, "/api/scans/nope")[0], 404)
        self.assertEqual(call(self.base, "/api/scans/..%2F..%2Fetc%2Fpasswd")[0], 404)

    def test_bad_inputs_are_rejected(self):
        self.assertEqual(self.post_json("/api/scan", {"path": "/no/such/dir"})[0], 400)
        self.assertEqual(self.post_json("/api/scan", {})[0], 400)
        self.assertEqual(self.post_json("/api/hunter/allow", {"sha256": "xyz"})[0], 400)
        self.assertEqual(self.post_json("/api/hunt", {"roots": ["/no/such/dir"]})[0], 400)

    def test_non_loopback_host_and_origin_refused(self):
        self.assertEqual(call(self.base, "/api/scans", headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(call(self.base, "/api/scans", headers={"Origin": "http://evil.example"})[0], 403)

    def test_archive_upload(self):
        td = Path(tempfile.mkdtemp())
        try:
            arc = td / "demo-installhook.tar.gz"
            with tarfile.open(arc, "w:gz") as t:
                t.add(FIXTURE, arcname="demo-installhook")
            boundary = "XBOUNDARYX"
            body = (
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"archive\"; filename=\"{arc.name}\"\r\n"
                "Content-Type: application/gzip\r\n\r\n"
            ).encode() + arc.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
            st, out = call(self.base, "/api/scan", "POST", body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})
            self.assertEqual(st, 200, out)
            self.assertEqual(call(self.base, "/api/scans")[0], 200)
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_built_ui_is_served(self):
        st, body = call(self.base, "/")
        self.assertEqual(st, 200)
        self.assertIn(b"<div id=\"root\">", body)
        st, _ = call(self.base, "/scanner/result")  # single-page-app fallback
        self.assertEqual(st, 200)

    def test_results_and_empty_hunt(self):
        st, body = call(self.base, "/api/results")
        self.assertEqual(st, 200)
        self.assertIn("corpus", json.loads(body))
        d = Path(tempfile.mkdtemp())
        try:
            st, body = self.post_json("/api/hunt", {"roots": [str(d)]})
            self.assertEqual(st, 200)
            self.assertEqual(json.loads(body)["items"], [])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_unsupported_archive_extension_rejected(self):
        boundary = "XBOUNDARYX"
        body = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"archive\"; filename=\"test.exe\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\nMZ\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        st, out = call(self.base, "/api/scan", "POST", body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})
        self.assertEqual(st, 400)
        self.assertIn(b"Unsupported archive type", out)

    def test_corrupt_archive_handled_gracefully(self):
        boundary = "XBOUNDARYX"
        body = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"archive\"; filename=\"corrupt.zip\"\r\n"
            "Content-Type: application/zip\r\n\r\nPK\x03\x04corrupteddata\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        st, out = call(self.base, "/api/scan", "POST", body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})
        self.assertEqual(st, 200)
        sid = json.loads(out)["scan_id"]
        st, rec_body = call(self.base, f"/api/scans/{sid}")
        self.assertEqual(st, 200)
        rec = json.loads(rec_body)
        self.assertEqual(rec["verdict"]["outcome"], "unable_to_assess")

    def test_folder_path_with_spaces_and_backslashes(self):
        td = Path(tempfile.mkdtemp())
        try:
            space_dir = td / "folder with spaces" / "sub dir"
            space_dir.mkdir(parents=True)
            (space_dir / "clean.py").write_text("x = 1\n", encoding="utf-8")
            st, body = self.post_json("/api/scan", {"path": str(space_dir)})
            self.assertEqual(st, 200)
            sid = json.loads(body)["scan_id"]
            st, rec_body = call(self.base, f"/api/scans/{sid}")
            self.assertEqual(st, 200)
            rec = json.loads(rec_body)
            self.assertEqual(rec["verdict"]["outcome"], "none_detected_in_this_scan")
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_upload_exceeding_size_limit(self):
        import socket
        port = self.httpd.server_address[1]
        sock = socket.create_connection(("127.0.0.1", port))
        sock.sendall(b"POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 105000000\r\n\r\n")
        resp = sock.recv(1024)
        sock.close()
        self.assertTrue(resp.startswith(b"HTTP/1.0 413") or resp.startswith(b"HTTP/1.1 413"))


if __name__ == "__main__":
    unittest.main()
