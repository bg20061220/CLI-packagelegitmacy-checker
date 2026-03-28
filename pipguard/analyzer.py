import ast
import io
import tarfile
from pathlib import Path

import httpx

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    tomllib = None

# Files that execute automatically during install or first import
TARGET_FILES = {"setup.py", "pyproject.toml", "__init__.py"}

_NETWORK_PATTERNS = [
    "requests.", "urllib.", "httpx.", "http.client",
    "ftplib", "smtplib", "socket.",
]
_SHELL_PATTERNS = ["os.system", "subprocess.", "commands.getoutput"]
_HOME_STRINGS = ["~/.ssh", "~/.aws", "~/.config", "~/.gnupg", "~/.netrc"]
_HOME_ENV_VARS = {"HOME", "USERPROFILE"}
_STRING_NETWORK_PATTERNS = ("curl ", "wget ", "http://", "https://")
_STRING_SHELL_PATTERNS = ("| bash", "bash -c", "sh -c", "powershell ")
_PYPROJECT_SUSPICIOUS_TOKENS = {
    "backend-path",
    "bootstrap",
    "build-system",
    "cmd",
    "command",
    "commands",
    "dependencies",
    "entry-points",
    "exec",
    "hook",
    "hooks",
    "optional-dependencies",
    "post-install",
    "pre-install",
    "requires",
    "run",
    "script",
    "scripts",
    "task",
    "tasks",
}
_PYPROJECT_METADATA_TOKENS = {
    "changelog",
    "documentation",
    "homepage",
    "issue",
    "issues",
    "repository",
    "source",
    "sources",
    "tracker",
    "url",
    "urls",
}


def _empty_flags() -> dict[str, bool]:
    return {
        "network_call": False,
        "env_access": False,
        "home_dir_access": False,
        "shell_exec": False,
        "base64_obfuscation": False,
        "dynamic_exec": False,
    }


def _merge_flags(target: dict[str, bool], source: dict[str, bool]) -> dict[str, bool]:
    for key, value in source.items():
        if value:
            target[key] = True
    return target


def _resolve_string(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            resolved = _resolve_string(value)
            if resolved is None:
                return None
            parts.append(resolved)
        return "".join(parts)
    if isinstance(node, ast.FormattedValue):
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve_string(node.left)
        right = _resolve_string(node.right)
        if left is None or right is None:
            return None
        return left + right
    return None


def _matches(path: str | None, patterns: list[str]) -> bool:
    if not path:
        return False
    return any(pattern in path for pattern in patterns)


def _scan_text_value(text: str, flags: dict[str, bool]) -> None:
    lowered = text.lower()

    if any(pattern in lowered for pattern in _STRING_NETWORK_PATTERNS):
        flags["network_call"] = True
    if any(pattern in lowered for pattern in _STRING_SHELL_PATTERNS):
        flags["shell_exec"] = True
    if any(path in text for path in _HOME_STRINGS):
        flags["home_dir_access"] = True
    if "os.environ" in text or "os.getenv" in text:
        flags["env_access"] = True
    if "base64.b64decode" in text or "base64.decodebytes" in text:
        flags["base64_obfuscation"] = True
    if any(pattern in text for pattern in ("eval(", "exec(", "getattr(", "__import__(")):
        flags["dynamic_exec"] = True


def _normalize_pyproject_path(path: tuple[str, ...]) -> list[str]:
    return [segment.lower().replace("_", "-").replace(" ", "-") for segment in path]


def _path_has_token(path: tuple[str, ...], tokens: set[str]) -> bool:
    normalized = _normalize_pyproject_path(path)
    return any(token in segment for segment in normalized for token in tokens)


def _scan_pyproject_string(text: str, path: tuple[str, ...], flags: dict[str, bool]) -> None:
    lowered = text.lower()
    suspicious_path = _path_has_token(path, _PYPROJECT_SUSPICIOUS_TOKENS)
    metadata_path = _path_has_token(path, _PYPROJECT_METADATA_TOKENS)

    if any(pattern in lowered for pattern in ("curl ", "wget ")):
        flags["network_call"] = True
    elif (
        any(pattern in lowered for pattern in ("http://", "https://"))
        and suspicious_path
        and not metadata_path
    ):
        flags["network_call"] = True

    if any(pattern in lowered for pattern in _STRING_SHELL_PATTERNS):
        flags["shell_exec"] = True
    if any(path_value in text for path_value in _HOME_STRINGS):
        flags["home_dir_access"] = True
    if "os.environ" in text or "os.getenv" in text:
        flags["env_access"] = True
    if "base64.b64decode" in text or "base64.decodebytes" in text:
        flags["base64_obfuscation"] = True
    if any(pattern in text for pattern in ("eval(", "exec(", "getattr(", "__import__(")):
        flags["dynamic_exec"] = True


def _walk_pyproject_value(value: object, flags: dict[str, bool], path: tuple[str, ...] = ()) -> None:
    if isinstance(value, str):
        _scan_pyproject_string(value, path, flags)
    elif isinstance(value, dict):
        for key, nested in value.items():
            _walk_pyproject_value(nested, flags, path + (str(key),))
    elif isinstance(value, list):
        for nested in value:
            _walk_pyproject_value(nested, flags, path)


class _FlagVisitor(ast.NodeVisitor):
    def __init__(self):
        self.flags = _empty_flags()
        self.module_aliases: dict[str, str] = {}
        self.symbol_aliases: dict[str, str] = {}

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.module_aliases[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if not node.module:
            self.generic_visit(node)
            return

        for alias in node.names:
            target = f"{node.module}.{alias.name}"
            self.symbol_aliases[alias.asname or alias.name] = target
        self.generic_visit(node)

    def _resolve_expr_path(self, node: ast.AST | None) -> str | None:
        if node is None:
            return None
        if isinstance(node, ast.Name):
            return self.symbol_aliases.get(node.id) or self.module_aliases.get(node.id) or node.id
        if isinstance(node, ast.Attribute):
            base = self._resolve_expr_path(node.value)
            if base:
                return f"{base}.{node.attr}"
            return node.attr
        if isinstance(node, ast.Call):
            func_path = self._resolve_expr_path(node.func)
            if func_path in {"__import__", "builtins.__import__"} and node.args:
                module_name = _resolve_string(node.args[0])
                if module_name:
                    self.flags["dynamic_exec"] = True
                    return module_name
        return None

    def visit_Call(self, node: ast.Call):
        func_str = self._resolve_expr_path(node.func) or ast.unparse(node)

        if _matches(func_str, _NETWORK_PATTERNS):
            self.flags["network_call"] = True

        # curl/wget or shell snippets buried in string args
        for child in ast.walk(node):
            text = _resolve_string(child)
            if not text:
                continue
            if any(pattern in text for pattern in _STRING_NETWORK_PATTERNS):
                self.flags["network_call"] = True
            if any(pattern in text.lower() for pattern in _STRING_SHELL_PATTERNS):
                self.flags["shell_exec"] = True
            if any(path in text for path in _HOME_STRINGS):
                self.flags["home_dir_access"] = True

        if "os.environ" in func_str or "os.getenv" in func_str or func_str.endswith(".environ.get"):
            self.flags["env_access"] = True

        if _matches(func_str, _SHELL_PATTERNS):
            self.flags["shell_exec"] = True

        if func_str in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            self.flags["dynamic_exec"] = True
            self.flags["shell_exec"] = True

        if func_str in {"base64.b64decode", "base64.decodebytes"}:
            self.flags["base64_obfuscation"] = True

        # getattr-based obfuscation: getattr(os, 'sys'+'tem')(...)
        getter = None
        if isinstance(node.func, ast.Call):
            getter = self._resolve_expr_path(node.func.func)
        if getter in {"getattr", "builtins.getattr"}:
            self.flags["dynamic_exec"] = True
            if len(node.func.args) >= 2:
                base = self._resolve_expr_path(node.func.args[0])
                attr = _resolve_string(node.func.args[1])
                full_attr = f"{base}.{attr}" if base and attr else None
                if _matches(full_attr, _NETWORK_PATTERNS):
                    self.flags["network_call"] = True
                if _matches(full_attr, _SHELL_PATTERNS):
                    self.flags["shell_exec"] = True

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        full = self._resolve_expr_path(node) or ast.unparse(node)
        if "expanduser" in full or full.endswith(".home"):
            self.flags["home_dir_access"] = True
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        full = self._resolve_expr_path(node.value) or ast.unparse(node.value)
        if full == "os.environ":
            self.flags["env_access"] = True
            key = _resolve_string(node.slice)
            if key in _HOME_ENV_VARS:
                self.flags["home_dir_access"] = True
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            if any(path in node.value for path in _HOME_STRINGS):
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


def _analyze_pyproject(source: str) -> dict[str, bool]:
    flags = _empty_flags()

    if tomllib is not None:
        try:
            data = tomllib.loads(source)
        except Exception:
            data = None
        if data is not None:
            _walk_pyproject_value(data, flags)
            return flags

    _scan_text_value(source, flags)
    return flags


async def analyze_tarball(tarball_url: str) -> dict[str, bool]:
    """Download source tarball and run AST analysis on install-time files."""
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        r = await client.get(tarball_url)
        r.raise_for_status()

    combined = _empty_flags()

    buf = io.BytesIO(r.content)
    with tarfile.open(fileobj=buf, mode="r:gz") as tar:
        for member in tar.getmembers():
            filename = Path(member.name).name
            if filename not in TARGET_FILES:
                continue
            f = tar.extractfile(member)
            if f is None:
                continue
            source = f.read().decode("utf-8", errors="ignore")
            if filename == "pyproject.toml":
                flags = _analyze_pyproject(source)
            else:
                flags = _analyze_source(source)
            _merge_flags(combined, flags)

    return combined
