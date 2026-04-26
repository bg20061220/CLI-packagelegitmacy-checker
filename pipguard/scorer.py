_WEIGHTS = {
    "known_cve": 50,
    "shell_exec": 40,
    "dynamic_exec": 40,
    "base64_obfuscation": 35,
    "package_new": 30,
    "home_dir_access": 30,
    "network_call_full": 25,       # pure Python package making network calls
    "network_call_discounted": 8,  # network calls expected for this package type
    "env_access": 20,
    "maintainer_new": 20,
    "download_spike": 15,
    "no_github": 10,
    "recency_bump": 20,            # version released < 7 days ago
    "spike_bump": 25,              # download spike detected
    "repo_new": 30,                # GitHub repo < 30 days old
    "no_license": 15,              # GitHub repo has no license
    "zero_stars": 15,              # GitHub repo with zero stars (and age > 30d)
    "stale_repo": 15,              # Last push > 2 years ago
    "solo_contributor": 10,        # Only 1 contributor and repo > 90 days old
}


# Monthly download thresholds for tier bucketing
_TIER_THRESHOLDS = {
    "massive": 10_000_000,
    "large":    1_000_000,
    "medium":     100_000,
    "small":       10_000,
    # below 10k → obscure
}

# Max score (before CVE override) that each tier can reach
TRUST_CAP = {
    "massive": 30,   # well-established packages get benefit of the doubt
    "large":   45,
    "medium":  60,
    "small":   80,
    "obscure": 100,  # no cap for unknown packages
}


def get_download_tier(monthly_downloads: int) -> str:
    if monthly_downloads >= _TIER_THRESHOLDS["massive"]:
        return "massive"
    if monthly_downloads >= _TIER_THRESHOLDS["large"]:
        return "large"
    if monthly_downloads >= _TIER_THRESHOLDS["medium"]:
        return "medium"
    if monthly_downloads >= _TIER_THRESHOLDS["small"]:
        return "small"
    return "obscure"


def compute(
    metadata: dict,
    download_stats: dict,
    vulns: list[dict],
    analysis_flags: dict,
    classifier_context: str,  # 'pure_python' | 'network_expected' | 'ambiguous'
    readme_context: str,       # 'network_expected' | 'pure_python' | 'unknown'
) -> dict:
    raw_score = 0
    cve_score = 0
    signals: dict[str, int] = {}

    def add(label: str, pts: int, *, cve: bool = False):
        nonlocal raw_score, cve_score
        if cve:
            cve_score += pts
        else:
            raw_score += pts
        signals[label] = pts

    if vulns:
        add(f"Known CVE ({vulns[0]['id']})", _WEIGHTS["known_cve"], cve=True)

    age_days = metadata.get("age_days")
    if age_days is not None and age_days < 30:
        add(f"Package < 30 days old ({age_days}d)", _WEIGHTS["package_new"])

    if not metadata.get("github_url"):
        add("No GitHub repo linked", _WEIGHTS["no_github"])

    if analysis_flags.get("shell_exec"):
        add("Shell execution in setup.py", _WEIGHTS["shell_exec"])

    if analysis_flags.get("dynamic_exec"):
        add("Dynamic execution / obfuscation", _WEIGHTS["dynamic_exec"])

    if analysis_flags.get("base64_obfuscation"):
        add("Base64 obfuscation", _WEIGHTS["base64_obfuscation"])

    if analysis_flags.get("home_dir_access"):
        add("Home directory access", _WEIGHTS["home_dir_access"])

    if analysis_flags.get("env_access"):
        add("Env variable access", _WEIGHTS["env_access"])

    if analysis_flags.get("network_call"):
        network_expected = (
            classifier_context == "network_expected"
            or readme_context == "network_expected"
        )
        if classifier_context == "pure_python":
            add(
                "Network call in setup.py (unexpected for pure Python)",
                _WEIGHTS["network_call_full"],
            )
        elif network_expected:
            add(
                "Network call in setup.py (expected for this package type)",
                _WEIGHTS["network_call_discounted"],
            )
        else:
            add("Network call in setup.py", _WEIGHTS["network_call_full"])

    # Determine download tier and cap the raw (non-CVE) score
    last_month = download_stats.get("last_month") or 0
    tier = get_download_tier(last_month)
    capped_score = min(raw_score, TRUST_CAP[tier])

    # Post-cap bumps: recent version release and download spike
    spike_pct = download_stats.get("spike_pct")
    version_age_days = metadata.get("version_age_days")

    if version_age_days is not None and version_age_days < 7:
        capped_score += _WEIGHTS["recency_bump"]
        signals[f"Version released {version_age_days}d ago"] = _WEIGHTS["recency_bump"]

    if spike_pct and spike_pct > 300 and last_month < 50_000:
        capped_score += _WEIGHTS["spike_bump"]
        signals[f"Download spike +{spike_pct:.0f}%"] = _WEIGHTS["spike_bump"]

    # CVE score always applies on top, uncapped
    final_score = capped_score + cve_score

    if final_score <= 30:
        verdict = "LOW"
    elif final_score <= 60:
        verdict = "MEDIUM"
    else:
        verdict = "HIGH"

    return {
        "score": final_score,
        "verdict": verdict,
        "signals": signals,
        "tier": tier,
        "capped": raw_score > TRUST_CAP[tier],
    }


def compute_github(
    repo_meta: dict,
    contributor_count: int | None,
    vulns: list[dict],
    analysis_flags: dict,
) -> dict:
    """
    Score a GitHub repository using GitHub-specific signals.
    repo_meta comes from github.fetch_repo_metadata()
    contributor_count comes from github.fetch_contributor_count()
    """
    raw_score = 0
    cve_score = 0
    signals: dict[str, int] = {}

    def add(label: str, pts: int, *, cve: bool = False):
        nonlocal raw_score, cve_score
        if cve:
            cve_score += pts
        else:
            raw_score += pts
        signals[label] = pts

    if vulns:
        add(f"Known CVE ({vulns[0]['id']})", _WEIGHTS["known_cve"], cve=True)

    age_days = repo_meta.get("age_days", 0)
    if age_days < 30:
        add(f"Repo < 30 days old ({age_days}d)", _WEIGHTS["repo_new"])

    if not repo_meta.get("license"):
        add("No license specified", _WEIGHTS["no_license"])

    stars = repo_meta.get("stargazers_count", 0)
    if stars == 0 and age_days > 30:
        add("Zero stars (mature repo)", _WEIGHTS["zero_stars"])

    days_since_push = repo_meta.get("days_since_push", 0)
    if days_since_push > 730:  # 2 years
        add(f"Last push {days_since_push}d ago", _WEIGHTS["stale_repo"])

    if contributor_count == 1 and age_days > 90:
        add("Only 1 contributor (mature repo)", _WEIGHTS["solo_contributor"])

    # AST analysis flags
    if analysis_flags.get("shell_exec"):
        add("Shell execution in setup.py", _WEIGHTS["shell_exec"])

    if analysis_flags.get("dynamic_exec"):
        add("Dynamic execution / obfuscation", _WEIGHTS["dynamic_exec"])

    if analysis_flags.get("base64_obfuscation"):
        add("Base64 obfuscation", _WEIGHTS["base64_obfuscation"])

    if analysis_flags.get("home_dir_access"):
        add("Home directory access", _WEIGHTS["home_dir_access"])

    if analysis_flags.get("env_access"):
        add("Env variable access", _WEIGHTS["env_access"])

    if analysis_flags.get("network_call"):
        add("Network call in setup.py", _WEIGHTS["network_call_full"])

    # GitHub repos always use "github" tier with no cap
    final_score = raw_score + cve_score

    if final_score <= 30:
        verdict = "LOW"
    elif final_score <= 60:
        verdict = "MEDIUM"
    else:
        verdict = "HIGH"

    return {
        "score": final_score,
        "verdict": verdict,
        "signals": signals,
        "tier": "github",
        "capped": False,
    }
