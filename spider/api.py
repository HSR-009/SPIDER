"""Local HTTP API for the SPIDER UI (`python -m spider serve`).

Loopback only, standard library only. It exposes the same engine the CLI uses:
nothing is executed, uploaded archives are extracted with the safe extractor,
and scan records are the unmodified `scan_record` JSON written to `scans/`.

Endpoints (see spider-ui/INTEGRATION.md):
  POST /api/scan            multipart `archive` file, or JSON/form `path`
  GET  /api/scans           list of saved scan records (oldest first)
  GET  /api/scans/<id>      one record; 404 if it does not exist
  GET  /api/hunter/roots    candidate site-packages directories
  POST /api/hunt            {"roots": [...]}  -> hunt result
  POST /api/hunter/allow    {"sha256": "...", "note": "..."}
  GET  /api/results         verified figures shown on the Results page
Anything else is served from spider/static_ui (the built single-page app).
"""
from __future__ import annotations

import json
import mimetypes
import os
import re
import shutil
import sys
import tempfile
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from spider.engine.extract import safe_extract
from spider.engine.scan import scan_directory
from spider.hunter.hunt import run_hunt, sanitize_path
from spider.hunter.inventory import list_environments
from spider.hunter.store import HunterStore
from spider_contract.validate import validate_record

REPO_ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = Path(__file__).resolve().parent / "static_ui"  # built UI (VITE_BACKEND=http), committed
RESULTS_FILE = REPO_ROOT / "results" / "ui_results.json"
ARCHIVE_EXTENSIONS = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar", ".zip", ".whl")
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
SCAN_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# ---------------------------------------------------------------- engine glue

def scan_path(target: Path, scans_dir: Path, name: Optional[str] = None) -> Dict[str, Any]:
    """Scan a directory or archive and save the record. Returns the record."""
    tmp: Optional[Path] = None
    try:
        if target.is_dir():
            scan_dir, pkg_name = target, name or target.name
        elif target.is_file() and target.name.lower().endswith(ARCHIVE_EXTENSIONS):
            tmp = Path(tempfile.mkdtemp(prefix="spider_api_"))
            safe_extract(target, tmp)
            scan_dir, pkg_name = tmp, name or target.name.split(".")[0]
        else:
            raise ApiError(400, "Target is not an existing folder or a supported archive (.whl, .tar.gz, .zip).")
        record = scan_directory(scan_dir, name=pkg_name, version=None)
        errs = validate_record(record)
        if errs:
            raise ApiError(500, "The scan produced a record that failed schema validation.")
        scans_dir.mkdir(parents=True, exist_ok=True)
        (scans_dir / f"{record['scan_id']}.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        return record
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)


def load_scan(scans_dir: Path, scan_id: str) -> Dict[str, Any]:
    if not SCAN_ID_RE.match(scan_id):
        raise ApiError(404, "This exact record is unavailable.")
    f = scans_dir / f"{scan_id}.json"
    if not f.is_file():
        raise ApiError(404, "This exact record is unavailable.")
    return json.loads(f.read_text(encoding="utf-8"))


def list_scans(scans_dir: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if scans_dir.is_dir():
        for f in scans_dir.glob("*.json"):
            try:
                out.append(json.loads(f.read_text(encoding="utf-8")))
            except Exception:
                continue  # a damaged file must not hide the others
    out.sort(key=lambda r: r.get("created_at", ""))
    return out


def clean_hunt(result: Dict[str, Any]) -> Dict[str, Any]:
    res = json.loads(json.dumps(result))
    for it in res.get("items", []):
        if it.get("path"):
            it["path"] = sanitize_path(it["path"])
    res["roots"] = [sanitize_path(r) for r in res.get("roots", [])]
    return res


# ------------------------------------------------------------------ multipart

def parse_multipart(content_type: str, body: bytes) -> Tuple[Dict[str, str], Dict[str, Tuple[str, bytes]]]:
    raw = b"Content-Type: " + content_type.encode("latin-1") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    fields: Dict[str, str] = {}
    files: Dict[str, Tuple[str, bytes]] = {}
    if not msg.is_multipart():
        raise ApiError(400, "Expected multipart/form-data.")
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if filename is not None:
            files[name] = (filename, payload)
        else:
            fields[name] = payload.decode("utf-8", "replace")
    return fields, files


# --------------------------------------------------------------------- server

def make_handler(scans_dir: Path, db_path: Optional[str]):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SpiderLocal/0.1"

        def log_message(self, fmt, *args):  # quiet by default
            pass

        # -- helpers
        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0] if not (self.headers.get("Host") or "").startswith("[") else "[::1]"
            if host not in ALLOWED_HOSTS:
                return False
            origin = self.headers.get("Origin")
            if origin and urlparse(origin).hostname not in {"127.0.0.1", "localhost", "::1"}:
                return False
            return True

        def _send(self, status: int, payload: Any = None, raw: Optional[bytes] = None, ctype: str = "application/json") -> None:
            body = raw if raw is not None else (b"" if payload is None else json.dumps(payload).encode("utf-8"))
            self.send_response(status)
            if status != 204:
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if status != 204:
                self.wfile.write(body)

        def _body(self, limit: int) -> bytes:
            n = int(self.headers.get("Content-Length") or 0)
            if n > limit:
                raise ApiError(413, "Upload is too large.")
            return self.rfile.read(n)

        def _dispatch(self, method: str) -> None:
            try:
                if not self._host_ok():
                    raise ApiError(403, "Only loopback access is allowed.")
                path = urlparse(self.path).path
                if path.startswith("/api/"):
                    self._api(method, path)
                elif method == "GET":
                    self._static(path)
                else:
                    raise ApiError(405, "Method not allowed.")
            except ApiError as e:
                self._send(e.status, {"error": e.message})
            except Exception:
                self._send(500, {"error": "Unexpected server error."})

        def do_GET(self) -> None:
            self._dispatch("GET")

        def do_POST(self) -> None:
            self._dispatch("POST")

        # -- API
        def _api(self, method: str, path: str) -> None:
            if method == "GET" and path == "/api/scans":
                return self._send(200, list_scans(scans_dir))
            if method == "GET" and path.startswith("/api/scans/"):
                return self._send(200, load_scan(scans_dir, unquote(path[len("/api/scans/"):])))
            if method == "GET" and path == "/api/hunter/roots":
                return self._send(200, [sanitize_path(str(p)) for p in list_environments(include_system_defaults=True)])
            if method == "GET" and path == "/api/results":
                if not RESULTS_FILE.is_file():
                    raise ApiError(404, "Results file is missing.")
                return self._send(200, raw=RESULTS_FILE.read_bytes())
            if method == "POST" and path == "/api/scan":
                return self._scan()
            if method == "POST" and path == "/api/hunt":
                return self._hunt()
            if method == "POST" and path == "/api/hunter/allow":
                data = json.loads(self._body(65536) or b"{}")
                sha = str(data.get("sha256", ""))
                if not SHA256_RE.match(sha):
                    raise ApiError(400, "sha256 must be 64 hex characters.")
                HunterStore(db_path=db_path).add_allow(sha.lower(), note=str(data.get("note") or "")[:500])
                return self._send(200, {"ok": True})
            raise ApiError(404, "Unknown endpoint.")

        def _scan(self) -> None:
            ctype = self.headers.get("Content-Type", "")
            if ctype.startswith("multipart/form-data"):
                fields, files = parse_multipart(ctype, self._body(MAX_UPLOAD_BYTES))
                if "archive" in files:
                    fname, data = files["archive"]
                    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(fname).name) or "upload"
                    if not safe_name.lower().endswith(ARCHIVE_EXTENSIONS):
                        raise ApiError(400, "Unsupported archive type. Use .whl, .tar.gz or .zip.")
                    td = Path(tempfile.mkdtemp(prefix="spider_up_"))
                    try:
                        up = td / safe_name
                        up.write_bytes(data)
                        record = scan_path(up, scans_dir)
                    finally:
                        shutil.rmtree(td, ignore_errors=True)
                elif fields.get("path"):
                    record = scan_path(Path(fields["path"]).expanduser(), scans_dir)
                else:
                    raise ApiError(400, "Send an `archive` file or a `path`.")
            else:
                data = json.loads(self._body(65536) or b"{}")
                if not data.get("path"):
                    raise ApiError(400, "Send an `archive` file or a `path`.")
                record = scan_path(Path(str(data["path"])).expanduser(), scans_dir)
            self._send(200, {"scan_id": record["scan_id"]})

        def _hunt(self) -> None:
            data = json.loads(self._body(65536) or b"{}")
            roots = data.get("roots") or None
            if roots is not None:
                if not isinstance(roots, list) or not all(isinstance(r, str) for r in roots):
                    raise ApiError(400, "roots must be a list of paths.")
                expanded = [str(Path(r).expanduser()) for r in roots]
                missing = [r for r in roots if not Path(r).expanduser().exists()]
                if missing:
                    raise ApiError(400, "Directory does not exist: " + sanitize_path(missing[0]))
                result = run_hunt(extra_site_packages=expanded, db_path=db_path, include_system_defaults=False)
            else:
                result = run_hunt(db_path=db_path, include_system_defaults=True)
            self._send(200, clean_hunt(result))

        # -- static UI
        def _static(self, path: str) -> None:
            if not DIST_DIR.is_dir():
                return self._send(
                    200,
                    raw=b"SPIDER API is running, but spider/static_ui is missing. Run `npm install` and `npm run build:serve` in spider-ui/.",
                    ctype="text/plain; charset=utf-8",
                )
            rel = unquote(path).lstrip("/") or "index.html"
            f = (DIST_DIR / rel).resolve()
            if DIST_DIR.resolve() not in f.parents and f != DIST_DIR.resolve():
                raise ApiError(404, "Not found.")
            if not f.is_file():
                f = DIST_DIR / "index.html"  # single-page app fallback
            ctype = mimetypes.guess_type(str(f))[0] or "application/octet-stream"
            self._send(200, raw=f.read_bytes(), ctype=ctype)

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8000, scans_dir: str = "scans", db_path: Optional[str] = None, open_browser: bool = True) -> None:
    if host not in ("127.0.0.1", "localhost"):
        raise SystemExit("Refusing to bind to a non-loopback address.")
    if not DIST_DIR.is_dir():
        print("Note: spider/static_ui is missing. Run `npm install` and `npm run build:serve` in spider-ui/ to build the UI.")
    try:
        httpd = ThreadingHTTPServer((host, port), make_handler(Path(scans_dir), db_path))
    except (OSError, PermissionError) as e:
        # Check for address in use (WinError 10048, 10013, EADDRINUSE, or permission error binding port)
        err_str = str(e).lower()
        winerr = getattr(e, "winerror", None)
        errno = getattr(e, "errno", None)
        if winerr in (10048, 10013) or errno in (98, 48) or "address already in use" in err_str or "access permissions" in err_str:
            sys.stderr.write(f"Error: Port {port} is busy or cannot be bound. Try passing a different port with --port (e.g. --port {port + 1}).\n")
            sys.exit(2)
        raise
    url = f"http://{host}:{port}/"
    print(f"SPIDER running at {url}  (Ctrl+C to stop)")
    if open_browser:
        import threading
        import webbrowser
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
