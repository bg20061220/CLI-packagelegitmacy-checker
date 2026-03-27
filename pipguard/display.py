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
    console.rule()
    console.print(
        f"  VERDICT:  [{color}]{_VERDICT_LABEL[verdict]}[/{color}]"
        f"  (Score: [bold]{score}[/bold])"
    )
    console.rule()
    console.print()
