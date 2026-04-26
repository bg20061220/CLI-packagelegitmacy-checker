# pipguard — Codebase Guide

## Recent Changes

### MCP Server Integration for Claude Code
**Status**: Implemented (v0.1.5+)

Created `mcp_server.py` to integrate pipguard with Claude Code via the Model Context Protocol (MCP):
- MCP server exposes `analyze_package(package_name)` tool that Claude Code can call before running `pip install`
- Claude Code automatically checks package legitimacy during code generation
- Returns JSON: `{score, verdict, signals, cves, should_install, message}`
- Registered in `.claude/settings.json` with command: `python -m pipguard.mcp_server`
- Uses existing `_analyze()` from main.py; no duplication

**How it works**: When Claude Code encounters an import statement, it calls the MCP tool before installing. If HIGH risk, it prompts user for confirmation.

**Why**: Brings security checks into the agentic workflow—users get asked "is this package safe?" at the moment Claude tries to install it.

---

### Option B: Smart Passthrough for Non-PyPI Packages
**Status**: Implemented (v0.1.4+)

The install command now gracefully falls back when packages are not on PyPI (e.g., GitHub repos, local paths, or typos):
- `_analyze()` returns `(None, False)` instead of raising exceptions when `pypi.fetch_metadata()` fails
- `install` command detects `None` result and skips analysis, showing yellow warning: `"Package not found on PyPI—skipping security analysis."`
- User is then passed through to real `pip install` without UX breakage
- `info` command shows a clear error when package isn't on PyPI (no generic "Analysis failed")
- Shell alias already routes obvious non-PyPI specs (git+, paths, archives) to real pip before reaching pipguard

**Why**: Prevents users from needing `python -m pip` workarounds and allows pipguard to be aliased to `pip` without breaking non-PyPI installs.

---

## Project Structure

### `pipguard/`

| File | Description |
|------|-------------|
| `main.py` | CLI entry point built with Typer; defines all commands (`install`, `scan`, `info`, `history`, `update`, `configure`) and orchestrates the analysis pipeline. Contains `_analyze()` (graceful fallback for non-PyPI), `_is_likely_pypi_package()` (source detection helper), and `install()`/`info()` commands with fallback handling. |
| `mcp_server.py` | MCP (Model Context Protocol) server for Claude Code integration. Exposes `analyze_package(package_name)` tool that Claude Code calls before installing. Uses `@server.list_tools()` and `@server.call_tool()` to define and execute the tool. Returns JSON with score, verdict, signals, CVEs, and recommendation. Reuses `_analyze()` from main.py. |
| `pypi.py` | Fetches package metadata from the PyPI JSON API — package age, version history, maintainer info, linked GitHub repo, and download stats from pypistats.org |
| `osv.py` | Queries the OSV.dev API for known CVEs and vulnerabilities associated with a package |
| `github.py` | Fetches GitHub README content for classifier-gated context checks; used to discount network-call flags when a package's stated purpose legitimately requires networking |
| `analyzer.py` | Downloads the source tarball (via httpx) and runs AST-based static analysis on `setup.py`, `pyproject.toml`, and `__init__.py` to detect red flags without executing code |
| `scorer.py` | Aggregates signals into a weighted risk score. Buckets monthly downloads into tiers (`massive/large/medium/small/obscure`) via `get_download_tier()`, caps raw scores per tier via `TRUST_CAP`, then applies post-cap recency bump (+20 if version <7d old) and spike bump (+25). CVE score is accumulated separately and added back after capping so a compromised high-trust package still scores HIGH. Returns `score`, `verdict`, `signals`, `tier`, and `capped`. |
| `cache.py` | SQLite-backed cache (`~/.pipguard/cache.db`) for trust scores (24hr TTL) and CVE data (6hr TTL); supports `--no-cache` bypass and `--force` wipe |
| `display.py` | Rich-powered terminal output; renders trust score panel, code analysis panel, and verdict. Verdict line shows risk label, score, download tier, trust level (`high-trust/medium-trust/low-trust`), a `(score capped by download tier)` note when applicable, and a contributing factors list of every signal that fired. |
| `__init__.py` | Package initializer; exposes the pipguard version |

## Testing

### CLI Testing

For local testing without publishing to PyPI:
1. Install in editable mode: `pip install -e .`
2. Test valid PyPI packages: `pipguard install requests --yes`
3. Test non-PyPI fallback: `pipguard install fake-package-xyz` (should show yellow warning and attempt pip install)
4. Test info command: `pipguard info fake-package-xyz` (should show "not found on PyPI")

### MCP Server Testing

To test the MCP server standalone:
1. Start the server: `python -m pipguard.mcp_server`
2. Send a tool call via MCP protocol (requires MCP client; Claude Code does this automatically)
3. Verify response includes all fields: `status`, `package`, `score`, `verdict`, `signals`, `cves`, `should_install`, `message`

To test with Claude Code:
1. Open `.claude/settings.json` and verify `mcpServers.pipguard` is configured
2. In Claude Code, ask it to generate code with an import (e.g., "create a script that uses requests")
3. Check Claude Code's terminal output—it should call pipguard's `analyze_package` tool
4. Verify the response formats correctly and Claude Code proceeds/blocks based on verdict
