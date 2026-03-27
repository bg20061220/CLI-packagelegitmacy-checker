import ast
import io
import tarfile
from pathlib import Path

import httpx

# Files that execute automatically during install or first import
TARGET_FILES = {"setup.py", "pyproject.toml", "__init__.py"}

_NETWORK_PATTERNS = [
    "requests.", "urllib.", "httpx.", "http.client",
    "ftplib", "smtplib", "socket.",
]
_SHELL_PATTERNS = ["os.system", "subprocess.", "commands.getoutput"]
_HOME_STRINGS = ["~/.ssh", "~/.aws", "~/.config", "~/.gnupg", "~/.netrc"]


class _FlagVisitor(ast.NodeVisitor):
    def __init__(self):
        self.flags: dict[str, bool] = {
            "network_call": False,
            "env_access": False,
            "home_dir_access": False,
            "shell_exec": False,
            "base64_obfuscation": False,
            "dynamic_exec": False,
        }

    def visit_Call(self, node: ast.Call):
        func_str = ast.unparse(node)

        if any(p in func_str for p in _NETWORK_PATTERNS):
            self.flags["network_call"] = True

        # curl/wget buried in string args
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                if any(s in child.value for s in ("curl ", "wget ", "http://", "https://")):
                    self.flags["network_call"] = True

        if "os.environ" in func_str or "os.getenv" in func_str:
            self.flags["env_access"] = True

        if any(p in func_str for p in _SHELL_PATTERNS):
            self.flags["shell_exec"] = True

        if func_str.startswith("eval(") or func_str.startswith("exec("):
            self.flags["dynamic_exec"] = True
            self.flags["shell_exec"] = True

        if "base64.b64decode" in func_str or "base64.decodebytes" in func_str:
            self.flags["base64_obfuscation"] = True

        # getattr-based obfuscation: getattr(os, 'sys'+'tem')(...)
        if (
            isinstance(node.func, ast.Call)
            and isinstance(node.func.func, ast.Name)
            and node.func.func.id == "getattr"
        ):
            self.flags["dynamic_exec"] = True

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        full = ast.unparse(node)
        if "expanduser" in full or ".home()" in full:
            self.flags["home_dir_access"] = True
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            if any(node.value.startswith(p) for p in _HOME_STRINGS):
                self.flags["home_dir_access"] = True
        self.generic_visit(node)


def _analyze_source(source: str) -> dict[str, bool]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}
    visitor = _FlagVisitor()
    visitor.visit(tree)
    return visitor.flags


async def analyze_tarball(tarball_url: str) -> dict[str, bool]:
    """Download source tarball and run AST analysis on install-time files."""
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        r = await client.get(tarball_url)
        r.raise_for_status()

    combined: dict[str, bool] = {
        "network_call": False,
        "env_access": False,
        "home_dir_access": False,
        "shell_exec": False,
        "base64_obfuscation": False,
        "dynamic_exec": False,
    }

    buf = io.BytesIO(r.content)
    with tarfile.open(fileobj=buf, mode="r:gz") as tar:
        for member in tar.getmembers():
            if Path(member.name).name not in TARGET_FILES:
                continue
            f = tar.extractfile(member)
            if f is None:
                continue
            source = f.read().decode("utf-8", errors="ignore")
            for key, val in _analyze_source(source).items():
                if val:
                    combined[key] = True

    return combined
