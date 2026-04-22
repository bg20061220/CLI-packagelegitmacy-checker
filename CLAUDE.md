# pipguard — Codebase Guide

## Project Structure

### `pipguard/`

| File | Description |
|------|-------------|
| `main.py` | CLI entry point built with Typer; defines all commands (`install`, `scan`, `info`, `history`, `update`, `configure`) and orchestrates the analysis pipeline |
| `pypi.py` | Fetches package metadata from the PyPI JSON API — package age, version history, maintainer info, linked GitHub repo, and download stats from pypistats.org |
| `osv.py` | Queries the OSV.dev API for known CVEs and vulnerabilities associated with a package |
| `github.py` | Fetches GitHub README content for classifier-gated context checks; used to discount network-call flags when a package's stated purpose legitimately requires networking |
| `analyzer.py` | Downloads the source tarball (via httpx) and runs AST-based static analysis on `setup.py`, `pyproject.toml`, and `__init__.py` to detect red flags without executing code |
| `scorer.py` | Aggregates signals into a weighted risk score. Buckets monthly downloads into tiers (`massive/large/medium/small/obscure`) via `get_download_tier()`, caps raw scores per tier via `TRUST_CAP`, then applies post-cap recency bump (+20 if version <7d old) and spike bump (+25). CVE score is accumulated separately and added back after capping so a compromised high-trust package still scores HIGH. Returns `score`, `verdict`, `signals`, `tier`, and `capped`. |
| `cache.py` | SQLite-backed cache (`~/.pipguard/cache.db`) for trust scores (24hr TTL) and CVE data (6hr TTL); supports `--no-cache` bypass and `--force` wipe |
| `display.py` | Rich-powered terminal output; renders trust score panel, code analysis panel, and verdict. Verdict line shows risk label, score, download tier, trust level (`high-trust/medium-trust/low-trust`), a `(score capped by download tier)` note when applicable, and a contributing factors list of every signal that fired. |
| `__init__.py` | Package initializer; exposes the pipguard version |
