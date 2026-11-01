"""CLI output, failure handling, and executable entry points."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import subprocess
import sys
import unittest
from unittest.mock import patch

import requests

from byse_resolver.cli import main
from byse_resolver.resolver import ResolvedStream


class CliTests(unittest.TestCase):
    def invoke(self, argv, *, result=None, error=None):
        stdout, stderr = StringIO(), StringIO()
        with patch("byse_resolver.resolver.ByseResolver") as factory:
            factory.return_value.resolve.return_value = result
            factory.return_value.resolve.side_effect = error
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue(), factory

    def test_success_prints_only_url_and_forwards_referer(self):
        url = "https://media.example/master.m3u8?signature=a%2Fb&token=x"
        code, out, err, factory = self.invoke(
            ["https://host.example/e/abcdef", "--referer", "https://site.example/watch"],
            result=ResolvedStream(url, "1080p"))
        self.assertEqual((code, out, err), (0, url + "\n", ""))
        factory.return_value.resolve.assert_called_once_with(
            "https://host.example/e/abcdef", referer="https://site.example/watch")

    def test_missing_stream_returns_failure_without_stdout(self):
        code, out, err, _ = self.invoke(["https://host.example/e/abcdef"])
        self.assertEqual((code, out), (1, ""))
        self.assertIn("no supported HLS stream", err)

    def test_failures_go_to_stderr_without_traceback(self):
        for error in [ValueError("bad URL"), requests.Timeout("request timed out"),
                      TimeoutError("proof deadline exceeded"), KeyError("playback"),
                      ImportError("extension unavailable")]:
            with self.subTest(error=error):
                code, out, err, _ = self.invoke(["https://host.example/e/abcdef"], error=error)
                self.assertEqual((code, out), (1, ""))
                self.assertIn(str(error), err)
                self.assertNotIn("Traceback", err)

    def test_interruption_returns_130(self):
        code, out, err, _ = self.invoke(["https://host.example/e/abcdef"], error=KeyboardInterrupt())
        self.assertEqual((code, out), (130, ""))
        self.assertIn("interrupted", err)

    def test_module_help_version_and_missing_url(self):
        for args, expected in [(["--help"], 0), (["--version"], 0), ([], 2)]:
            with self.subTest(args=args):
                result = subprocess.run([sys.executable, "-m", "byse_resolver", *args],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_invalid_embed_exits_cleanly(self):
        result = subprocess.run([sys.executable, "-m", "byse_resolver", "not-a-url"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("unsupported embed URL", result.stderr)


if __name__ == "__main__":
    unittest.main()
