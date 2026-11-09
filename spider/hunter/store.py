"""Hunter SQLite store (brief section 5.3).

Schema:
- scans(scan_id TEXT PRIMARY KEY, ts TEXT, root_count INTEGER)
- items(scan_id TEXT, dist TEXT, version TEXT, artifact TEXT, path TEXT, sha256 TEXT, severity TEXT, reason TEXT)
- allow(sha256 TEXT PRIMARY KEY, note TEXT, ts TEXT)

"New since last scan" = items whose (dist, artifact, sha256) were absent in the previous scan.
"""
from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

DEFAULT_DB_PATH = Path.home() / ".spider" / "hunter.db"


class HunterStore:
    def __init__(self, db_path: Optional[str | Path] = None) -> None:
        if db_path is None:
            self.db_path = DEFAULT_DB_PATH
        else:
            self.db_path = Path(db_path).resolve()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    ts TEXT,
                    root_count INTEGER
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS items (
                    scan_id TEXT,
                    dist TEXT,
                    version TEXT,
                    artifact TEXT,
                    path TEXT,
                    sha256 TEXT,
                    severity TEXT,
                    reason TEXT
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS allow (
                    sha256 TEXT PRIMARY KEY,
                    note TEXT,
                    ts TEXT
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def add_allow(self, sha256: str, note: str = "") -> None:
        """Add a sha256 hash to the allowlist."""
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO allow (sha256, note, ts) VALUES (?, ?, ?)",
                (sha256.lower(), note, now),
            )
            conn.commit()
        finally:
            conn.close()

    def get_allowlist(self) -> Dict[str, Dict[str, str]]:
        """Return dict of sha256 -> {note, ts}."""
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT sha256, note, ts FROM allow")
            rows = cur.fetchall()
            return {r[0].lower(): {"note": r[1], "ts": r[2]} for r in rows}
        finally:
            conn.close()

    def get_last_scan_id(self) -> Optional[str]:
        """Return the scan_id of the most recent scan."""
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT scan_id FROM scans ORDER BY ts DESC LIMIT 1")
            row = cur.fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    def get_previous_scan_items(self) -> Set[Tuple[str, str, str]]:
        """Return set of (dist, artifact, sha256) from the last recorded scan."""
        last_id = self.get_last_scan_id()
        if not last_id:
            return set()
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT dist, artifact, sha256 FROM items WHERE scan_id = ?",
                (last_id,),
            )
            rows = cur.fetchall()
            return {(r[0], r[1], (r[2] or "").lower()) for r in rows}
        finally:
            conn.close()

    def record_scan(
        self,
        scan_id: str,
        roots_count: int,
        items: List[Dict[str, Any]],
        ts: Optional[str] = None,
    ) -> None:
        """Record scan metadata and items into the store."""
        if ts is None:
            ts = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO scans (scan_id, ts, root_count) VALUES (?, ?, ?)",
                (scan_id, ts, roots_count),
            )
            for item in items:
                cur.execute(
                    """
                    INSERT INTO items (scan_id, dist, version, artifact, path, sha256, severity, reason)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        item.get("dist", ""),
                        item.get("version", ""),
                        item.get("artifact", ""),
                        item.get("path", ""),
                        (item.get("sha256") or "").lower(),
                        item.get("severity", ""),
                        item.get("reason", ""),
                    ),
                )
            conn.commit()
        finally:
            conn.close()

    def list_scans(self) -> List[Dict[str, Any]]:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT scan_id, ts, root_count FROM scans ORDER BY ts DESC")
            rows = cur.fetchall()
            return [{"scan_id": r[0], "ts": r[1], "root_count": r[2]} for r in rows]
        finally:
            conn.close()

    def get_scan_items(self, scan_id: str) -> List[Dict[str, Any]]:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT scan_id, dist, version, artifact, path, sha256, severity, reason
                FROM items WHERE scan_id = ?
                """,
                (scan_id,),
            )
            rows = cur.fetchall()
            return [
                {
                    "scan_id": r[0],
                    "dist": r[1],
                    "version": r[2],
                    "artifact": r[3],
                    "path": r[4],
                    "sha256": r[5],
                    "severity": r[6],
                    "reason": r[7],
                }
                for r in rows
            ]
        finally:
            conn.close()

