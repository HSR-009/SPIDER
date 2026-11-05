"""Synthetic SPIDER fixture: harmless encoded-marker pattern."""
import base64
import os

PAYLOAD = "cHJpbnQoJ1NQSURFUi1NQVJLRVInKQ=="  # decodes to a harmless print

blob = base64.b64decode(PAYLOAD).decode()
exec(blob)


def helper():
    fn = getattr(os, "sys" + "tem")
    return fn("echo SPIDER-FIXTURE")
