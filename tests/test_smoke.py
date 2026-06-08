"""Smoke tests for DIRSIGHT. No network access."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dirsight import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    analyze,
    parse_auto,
    parse_ffuf_json,
    parse_gobuster_text,
    score_finding,
    summarize,
)
from dirsight.core import Finding  # noqa: E402
from dirsight import cli  # noqa: E402

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos", "01-basic", "ffuf.json",
)


class TestParsers(unittest.TestCase):
    def test_ffuf_json(self):
        with open(DEMO, encoding="utf-8") as fh:
            findings = parse_ffuf_json(fh.read())
        self.assertEqual(len(findings), 12)
        self.assertTrue(any(f.path == "/.env" for f in findings))
        self.assertEqual(findings[0].source, "ffuf")

    def test_gobuster_text(self):
        sample = (
            "/.git/config         (Status: 200) [Size: 412]\n"
            "/admin               (Status: 302) [Size: 0] [--> /login]\n"
            "/index.html          (Status: 200) [Size: 4242]\n"
        )
        findings = parse_gobuster_text(sample, base_url="https://app.example.com")
        self.assertEqual(len(findings), 3)
        admin = next(f for f in findings if f.path == "/admin")
        self.assertEqual(admin.status, 302)
        self.assertEqual(admin.redirect, "/login")
        self.assertTrue(admin.url.startswith("https://"))

    def test_auto_detect(self):
        with open(DEMO, encoding="utf-8") as fh:
            self.assertTrue(parse_auto(fh.read()))
        self.assertTrue(parse_auto("/x (Status: 200) [Size: 10]"))


class TestScoring(unittest.TestCase):
    def test_secret_file_outranks_static(self):
        env = score_finding(Finding(url="", path="/.env", status=200, length=300))
        about = score_finding(Finding(url="", path="/about", status=200, length=4242))
        self.assertGreater(env.score, about.score)
        self.assertTrue(env.reasons)

    def test_noise_detection_and_ranking(self):
        with open(DEMO, encoding="utf-8") as fh:
            ranked = analyze(parse_ffuf_json(fh.read()))
        # soft-404 pages (4242 bytes, repeated) flagged noise
        noisy = [f for f in ranked if f.noise]
        self.assertGreaterEqual(len(noisy), 4)
        self.assertTrue(all(f.length == 4242 for f in noisy))
        # top finding is high-interest and not noise
        self.assertFalse(ranked[0].noise)
        self.assertGreater(ranked[0].score, 40)

    def test_summary(self):
        with open(DEMO, encoding="utf-8") as fh:
            ranked = analyze(parse_ffuf_json(fh.read()))
        s = summarize(ranked)
        self.assertEqual(s["total"], 12)
        self.assertGreater(s["high_interest"], 0)
        self.assertGreaterEqual(s["noise"], 4)


class TestCLI(unittest.TestCase):
    def test_version_constants(self):
        self.assertEqual(TOOL_NAME, "dirsight")
        self.assertTrue(TOOL_VERSION)

    def test_analyze_json_exit_code(self):
        from io import StringIO
        buf = StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = cli.main(["analyze", DEMO, "--format", "json"])
        finally:
            sys.stdout = old
        self.assertEqual(rc, 2)  # high-interest findings present
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["tool"], "dirsight")
        self.assertIn("findings", payload)
        self.assertIn("summary", payload)

    def test_no_command_returns_1(self):
        self.assertEqual(cli.main([]), 1)


if __name__ == "__main__":
    unittest.main()
