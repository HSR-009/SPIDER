"""Own code of the synthetic vendored-heavy package."""
import urllib.request


def fetch_status(url):
    with urllib.request.urlopen(url, timeout=2) as resp:
        return resp.status
