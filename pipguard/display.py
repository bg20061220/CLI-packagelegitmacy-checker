from rich.console import Console
from rich.table import Table

console = Console()

_VERDICT_COLOR = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}
_VERDICT_LABEL = {"LOW": "LOW RISK", "MEDIUM": "MEDIUM RISK", "HIGH": "HIGH RISK"}


def show_report(
    package: str,
    metadata: dict,
    download_stats: dict,
    vulns: list[dict],
    analysis_flags: dict,
    breakdown: dict,
    cached: bool = False,
) -> None:
    cache_note = " [dim](cached)[/dim]" if cached else ""
    console.print(f"\nAnalyzing [bold]{package}[/bold]{cache_note}...\n")

    # ── Trust score ──────────────────────────────────────────────
    console.rule("[bold]TRUST SCORE[/bold]")
    t = Table(box=None, show_header=False, padding=(0, 2))
    t.add_column(width=28)
    t.add_column()

    is_github = metadata.get("source") == "github"

    # Initialize variables used later in active_flags
    age = metadata.get("age_days")
    spike = download_stats.get("spike_pct")
    last_month = download_stats.get("last_month") or 0

    if is_github:
        # GitHub-specific metrics
        age_str = f"{age}d" if age is not None else "unknown"
        if age is None:
            age_status = "[?]"
        elif age < 30:
            age_status = "[ALERT]"
        elif age < 90:
            age_status = "[WARN]"
        else:
            age_status = "[OK]"
        t.add_row("Repo age:", f"{age_str}  {age_status}")

        stars = metadata.get("stargazers_count", 0)
        if stars == 0:
            stars_status = "[ALERT]"
        elif stars < 10:
            stars_status = "[WARN]"
        else:
            stars_status = "[OK]"
        t.add_row("Stars:", f"{stars}  {stars_status}")

        from_meta = metadata.get("contributor_count", 0)
        if from_meta == 1 and age is not None and age > 90:
            contrib_status = "[ALERT]"
        elif from_meta is None or from_meta < 2:
            contrib_status = "[WARN]"
        else:
            contrib_status = "[OK]"
        contrib_str = str(from_meta) if from_meta is not None else "unknown"
        t.add_row("Contributors:", f"{contrib_str}  {contrib_status}")
    else:
        # PyPI metrics
        age_str = f"{age}d" if age is not None else "unknown"
        if age is None:
            age_status = "[?]"
        elif age < 30:
            age_status = "[ALERT]"
        elif age < 90:
            age_status = "[WARN]"
        else:
            age_status = "[OK]"
        t.add_row("Package age:", f"{age_str}  {age_status}")

        t.add_row(
            "GitHub repo:",
            "[OK] linked" if metadata.get("github_url") else "[ALERT] none",
        )

        spike = download_stats.get("spike_pct")
        last_month = download_stats.get("last_month") or 0
        if spike and spike > 300 and last_month < 50_000:
            t.add_row("Download spike:", f"+{spike:.0f}%  [WARN]")
        else:
            t.add_row("Download spike:", "normal  [OK]")

    if vulns:
        t.add_row("Known vulns:", f"[ALERT] {len(vulns)} found ({vulns[0]['id']})")
    else:
        t.add_row("Known vulns:", "[OK] none")

    console.print(t)

    # ── Code analysis ────────────────────────────────────────────
    console.rule("[bold]CODE ANALYSIS[/bold]")

    if not analysis_flags:
        console.print("  [dim]No source tarball available — code analysis skipped[/dim]")
    else:
        a = Table(box=None, show_header=False, padding=(0, 2))
        a.add_column(width=28)
        a.add_column()

        def flag_row(label: str, key: str):
            found = analysis_flags.get(key, False)
            a.add_row(label, "[ALERT] FOUND" if found else "[OK] NOT FOUND")

        flag_row("Network requests:", "network_call")
        flag_row("Env var access:", "env_access")
        flag_row("Shell execution:", "shell_exec")
        flag_row("Base64 obfuscation:", "base64_obfuscation")
        flag_row("Home dir access:", "home_dir_access")
        console.print(a)

    # ── Verdict ──────────────────────────────────────────────────
    verdict = breakdown["verdict"]
    score = breakdown["score"]
    color = _VERDICT_COLOR[verdict]

    # Collect every signal that actually fired
    active_flags: list[str] = []

    if is_github:
        # GitHub-specific flags
        age = metadata.get("age_days")
        if age is not None and age < 30:
            active_flags.append(f"Repo age only {age}d")
        elif age is not None and age < 90:
            active_flags.append(f"Repo age {age}d (relatively new)")

        stars = metadata.get("stargazers_count", 0)
        if stars == 0 and age is not None and age > 30:
            active_flags.append("Zero stars (mature repo)")

        contrib_count = metadata.get("contributor_count")
        if contrib_count == 1 and age is not None and age > 90:
            active_flags.append("Only 1 contributor (mature repo)")

        days_since_push = metadata.get("days_since_push")
        if days_since_push is not None and days_since_push > 730:
            active_flags.append(f"Last push {days_since_push}d ago (inactive)")

        if not metadata.get("license"):
            active_flags.append("No license specified")
    else:
        # PyPI-specific flags
        if age is not None and age < 30:
            active_flags.append(f"Package age only {age}d")
        elif age is not None and age < 90:
            active_flags.append(f"Package age {age}d (relatively new)")

        if not metadata.get("github_url"):
            active_flags.append("No linked GitHub repo")

        spike = download_stats.get("spike_pct")
        last_month = download_stats.get("last_month") or 0
        if spike and spike > 300 and last_month < 50_000:
            active_flags.append(f"Download spike +{spike:.0f}% (low-volume package)")

    if vulns:
        active_flags.append(f"{len(vulns)} known CVE(s) - {vulns[0]['id']}")

    flag_labels = {
        "network_call": "Network requests in setup code",
        "env_access": "Env var access in setup code",
        "shell_exec": "Shell execution in setup code",
        "base64_obfuscation": "Base64 obfuscation in setup code",
        "home_dir_access": "Home directory access in setup code",
    }
    for key, label in flag_labels.items():
        if analysis_flags.get(key):
            active_flags.append(label)

    tier = breakdown.get("tier", "unknown")
    capped = breakdown.get("capped", False)

    _TIER_TRUST = {
        "massive": "high-trust",
        "large":   "high-trust",
        "medium":  "medium-trust",
        "small":   "low-trust",
        "obscure": "low-trust",
        "unknown": "unknown-trust",
        "github":  "unverified",
    }
    trust_label = _TIER_TRUST[tier]
    cap_note = "  [dim](score capped by download tier)[/dim]" if capped else ""

    console.print("-" * 80)
    console.print(
        f"  VERDICT:  [{color}]{_VERDICT_LABEL[verdict]}[/{color}]"
        f"  (Score: [bold]{score}[/bold])"
        f"  [dim]- {tier} package, {trust_label}[/dim]{cap_note}"
    )
    if active_flags:
        console.print(f"  [dim]Contributing factors:[/dim]")
        for flag in active_flags:
            console.print(f"    [{color}]*[/{color}] {flag}")
    console.print("-" * 80)
    console.print()
