"""Sanitization utilities for replay fixture scan records (Day 4 step 4.4)."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# IPv4 pattern (e.g. 192.168.1.1, 10.0.0.1)
IPV4_REGEX = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

# URL pattern (http:// or https://)
URL_REGEX = re.compile(r"https?://[^\s'\"\)\]\}]+")

# Common hostnames (domains like .com, .org, .io, .net or specific hostnames)
HOST_REGEX = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|io|ru|cn|cc|xyz|info|biz|me|top|link)\b", re.IGNORECASE)

# Base64 blobs over 40 characters
BASE64_BLOB_REGEX = re.compile(r"[A-Za-z0-9+/=]{41,}")

# Token patterns: AWS AKIA, GitHub ghp_/gho_/ghu_, Slack xoxb, generic api keys
TOKEN_REGEXES = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b"),
    re.compile(r"\bxox[baprs]-[0-9a-zA-Z-]+\b"),
    re.compile(r"\b[A-Za-z0-9_-]{20,}secret[A-Za-z0-9_-]*\b", re.IGNORECASE),
]


def sanitize_snippet(snippet: Optional[str]) -> Optional[str]:
    """Sanitize finding snippet according to Day 4 replay rules:
    - At most 8 lines around the hit
    - Lines cut to 120 characters
    - URLs, IPs, hostnames replaced with <redacted-host>
    - Base64 blobs over 40 characters replaced with <redacted-blob>
    - Token patterns like AKIA and ghp_ replaced with <redacted-token>
    """
    if snippet is None:
        return None

    lines = snippet.splitlines()
    # At most 8 lines
    if len(lines) > 8:
        lines = lines[:8]

    sanitized_lines: List[str] = []
    for line in lines:
        # Cut to 120 chars
        if len(line) > 120:
            line = line[:120]

        # Replace URLs
        line = URL_REGEX.sub("<redacted-host>", line)

        # Replace IPs
        line = IPV4_REGEX.sub("<redacted-host>", line)

        # Replace hostnames
        line = HOST_REGEX.sub("<redacted-host>", line)

        # Replace base64 blobs over 40 chars
        line = BASE64_BLOB_REGEX.sub("<redacted-blob>", line)

        # Replace tokens
        for t_regex in TOKEN_REGEXES:
            line = t_regex.sub("<redacted-token>", line)

        sanitized_lines.append(line)

    return "\n".join(sanitized_lines)


def sanitize_scan_record_for_replay(record: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize an entire scan record for replay origin:
    - Set record_origin to "replay"
    - Replace finding snippets with sanitized snippets
    """
    rec = dict(record)
    rec["record_origin"] = "replay"

    if "target" in rec:
        rec["target"]["kind"] = "archive"

    sanitized_findings = []
    for f in rec.get("findings", []):
        f_copy = dict(f)
        f_copy["snippet"] = sanitize_snippet(f_copy.get("snippet"))
        sanitized_findings.append(f_copy)
    rec["findings"] = sanitized_findings

    return rec

