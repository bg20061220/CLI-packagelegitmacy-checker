_WEIGHTS = {
    "known_cve": 50,
    "shell_exec": 40,
    "base64_obfuscation": 35,
    "package_new": 30,
    "home_dir_access": 30,
    "network_call_full": 25,       # pure Python package making network calls
    "network_call_discounted": 8,  # network calls expected for this package type
    "env_access": 20,
    "maintainer_new": 20,
    "download_spike": 15,
    "no_github": 10,
}


def compute(
    metadata: dict,
    download_stats: dict,
    vulns: list[dict],
    analysis_flags: dict,
    classifier_context: str,  # 'pure_python' | 'network_expected' | 'ambiguous'
    readme_context: str,       # 'network_expected' | 'pure_python' | 'unknown'
) -> dict:
    score = 0
    signals: dict[str, int] = {}

    def add(label: str, pts: int):
        nonlocal score
        score += pts
        signals[label] = pts

    if vulns:
        add(f"Known CVE ({vulns[0]['id']})", _WEIGHTS["known_cve"])

    age_days = metadata.get("age_days")
    if age_days is not None and age_days < 30:
        add(f"Package < 30 days old ({age_days}d)", _WEIGHTS["package_new"])

    spike_pct = download_stats.get("spike_pct")
    last_month = download_stats.get("last_month") or 0
    if spike_pct and spike_pct > 300 and last_month < 50_000:
        add(f"Download spike +{spike_pct:.0f}%", _WEIGHTS["download_spike"])

    if not metadata.get("github_url"):
        add("No GitHub repo linked", _WEIGHTS["no_github"])

    if analysis_flags.get("shell_exec"):
        add("Shell execution in setup.py", _WEIGHTS["shell_exec"])

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

    if score <= 30:
        verdict = "LOW"
    elif score <= 60:
        verdict = "MEDIUM"
    else:
        verdict = "HIGH"

    return {"score": score, "verdict": verdict, "signals": signals}
