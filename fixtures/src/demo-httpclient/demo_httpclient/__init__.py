"""Tiny demo HTTP helper (synthetic fixture, harmless)."""
import socket

__version__ = "1.0.0"


def can_connect(host, port, timeout=1.0):
    """Return True if a TCP connection succeeds."""
    with socket.create_connection((host, port), timeout=timeout):
        return True
