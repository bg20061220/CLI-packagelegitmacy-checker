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

    age = metadata.get("age_days")
    age_str = f"{age}d" if age is not None else "unknown"
    if age is None:
        age_icon = "❓"
    elif age < 30:
        age_icon = "🔴"
    elif age < 90:
        age_icon = "⚠️"
    else:
        age_icon = "✅"
    t.add_row("Package age:", f"{age_str}  {age_icon}")

    t.add_row(
        "GitHub repo:",
        "✅ linked" if metadata.get("github_url") else "🔴 none",
    )

    spike = download_stats.get("spike_pct")
    last_month = download_stats.get("last_month") or 0
    if spike and spike > 300 and last_month < 50_000:
        t.add_row("Download spike:", f"+{spike:.0f}%  ⚠️")
    else:
        t.add_row("Download spike:", "normal  ✅")

    if vulns:
        t.add_row("Known vulns:", f"🔴 {len(vulns)} found ({vulns[0]['id']})")
    else:
        t.add_row("Known vulns:", "✅ none")

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
            a.add_row(label, "🔴 FOUND" if found else "✅ NOT FOUND")

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

    if age is not None and age < 30:
        active_flags.append(f"Package age only {age}d")
    elif age is not None and age < 90:
        active_flags.append(f"Package age {age}d (relatively new)")

    if not metadata.get("github_url"):
        active_flags.append("No linked GitHub repo")

    if spike and spike > 300 and last_month < 50_000:
        active_flags.append(f"Download spike +{spike:.0f}% (low-volume package)")

    if vulns:
        active_flags.append(f"{len(vulns)} known CVE(s) — {vulns[0]['id']}")

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
    }
    trust_label = _TIER_TRUST[tier]
    cap_note = "  [dim](score capped by download tier)[/dim]" if capped else ""

    console.rule()
    console.print(
        f"  VERDICT:  [{color}]{_VERDICT_LABEL[verdict]}[/{color}]"
        f"  (Score: [bold]{score}[/bold])"
        f"  [dim]— {tier} package, {trust_label}[/dim]{cap_note}"
    )
    if active_flags:
        console.print(f"  [dim]Contributing factors:[/dim]")
        for flag in active_flags:
            console.print(f"    [{color}]•[/{color}] {flag}")
    console.rule()
    console.print()
