import asyncio
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.prompt import Confirm

from pipguard import analyzer, cache, display, github, osv, pypi, scorer
from pipguard.display import console

app = typer.Typer(
    help="pipguard — supply chain attack prevention for pip installs.",
    add_completion=False,
)


async def _analyze(package: str, version: str | None, no_cache: bool) -> tuple[dict, bool]:
    """Core analysis pipeline. Returns (result_dict, was_cached)."""
    cache_key = f"full:{package}:{version or 'latest'}"

    if not no_cache:
        cached = cache.get(cache_key)
        if cached:
            return cached, True

    # Fetch metadata first to resolve the exact version, then query OSV with it
    metadata = await pypi.fetch_metadata(package, version)
    download_stats, vulns = await asyncio.gather(
        pypi.fetch_download_stats(package),
        osv.check_vulns(package, metadata["version"]),
    )

    # Classifier gating: decide whether to call GitHub README
    classifier_context = github.classify_from_classifiers(metadata["classifiers"])
    readme_context = "unknown"

    if classifier_context in ("ambiguous", "network_expected") and metadata.get("github_url"):
        readme_context = await github.fetch_readme_classification(metadata["github_url"])

    # Layer 2: AST analysis — only if source tarball exists
    analysis_flags: dict = {}
    if metadata.get("tarball_url"):
        analysis_flags = await analyzer.analyze_tarball(metadata["tarball_url"])

    breakdown = scorer.compute(
        metadata, download_stats, vulns, analysis_flags, classifier_context, readme_context
    )

    result = {
        "metadata": metadata,
        "download_stats": download_stats,
        "vulns": vulns,
        "analysis_flags": analysis_flags,
        "breakdown": breakdown,
    }

    cache.set(cache_key, result, cache.TTL_TRUST)
    return result, False


@app.command()
def install(
    package: str = typer.Argument(..., help="Package to analyze and install"),
    version: Optional[str] = typer.Option(None, "--version", "-v", help="Specific version"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass cache for this run"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
):
    """Analyze a package for supply chain risks, then install it."""
    try:
        result, cached = asyncio.run(_analyze(package, version, no_cache))
    except Exception as e:
        console.print(f"[red]Analysis failed: {e}[/red]")
        raise typer.Exit(1)

    display.show_report(
        package,
        result["metadata"],
        result["download_stats"],
        result["vulns"],
        result["analysis_flags"],
        result["breakdown"],
        cached=cached,
    )

    verdict = result["breakdown"]["verdict"]

    if verdict == "HIGH" and not yes:
        if not Confirm.ask("Proceed anyway?", default=False):
            raise typer.Exit(1)
    elif verdict == "MEDIUM" and not yes:
        if not Confirm.ask("Proceed anyway?", default=True):
            raise typer.Exit(1)

    pkg_spec = f"{package}=={result['metadata']['version']}"
    console.print(f"Installing [bold]{pkg_spec}[/bold]...")
    subprocess.run([sys.executable, "-m", "pip", "install", pkg_spec], check=True)


@app.command()
def info(
    package: str = typer.Argument(..., help="Package to inspect"),
    version: Optional[str] = typer.Option(None, "--version", "-v"),
    no_cache: bool = typer.Option(False, "--no-cache"),
):
    """Show a risk report without installing."""
    try:
        result, cached = asyncio.run(_analyze(package, version, no_cache))
    except Exception as e:
        console.print(f"[red]Analysis failed: {e}[/red]")
        raise typer.Exit(1)

    display.show_report(
        package,
        result["metadata"],
        result["download_stats"],
        result["vulns"],
        result["analysis_flags"],
        result["breakdown"],
        cached=cached,
    )


@app.command()
def scan(
    file: str = typer.Option("requirements.txt", "--file", "-f", help="Requirements file"),
    ci: bool = typer.Option(False, "--ci", help="Non-interactive CI mode"),
    fail_on: str = typer.Option("high", "--fail-on", help="Fail threshold: medium or high"),
    no_cache: bool = typer.Option(False, "--no-cache"),
):
    """Scan all packages in a requirements file."""
    req_path = Path(file)
    if not req_path.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    packages: list[tuple[str, str | None]] = []
    for line in req_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            name, ver = line.split("==", 1)
            packages.append((name.strip(), ver.strip()))
        else:
            packages.append((line, None))

    fail_score = {"medium": 31, "high": 61}.get(fail_on.lower(), 61)
    exit_code = 0

    for name, ver in packages:
        console.print(f"[dim]Scanning {name}...[/dim]")
        try:
            result, cached = asyncio.run(_analyze(name, ver, no_cache))
            bd = result["breakdown"]
            if bd["score"] >= fail_score:
                display.show_report(
                    name,
                    result["metadata"],
                    result["download_stats"],
                    result["vulns"],
                    result["analysis_flags"],
                    bd,
                    cached=cached,
                )
                if ci:
                    exit_code = 1
            else:
                verdict = bd["verdict"]
                color = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}[verdict]
                console.print(f"  [{color}]{verdict}[/{color}] {name} (score: {bd['score']})")
        except Exception as e:
            console.print(f"[yellow]  Warning: could not scan {name}: {e}[/yellow]")

    if ci and exit_code:
        raise typer.Exit(exit_code)


@app.command()
def history():
    """Show recent scan results from the local cache."""
    import json
    import sqlite3

    if not cache.CACHE_DB.exists():
        console.print("No scan history yet.")
        return

    con = sqlite3.connect(cache.CACHE_DB)
    rows = con.execute(
        "SELECT key, value FROM cache WHERE key LIKE 'full:%' ORDER BY expires_at DESC LIMIT 20"
    ).fetchall()
    con.close()

    if not rows:
        console.print("No scan history yet.")
        return

    from rich.table import Table

    t = Table(title="Recent Scans", show_lines=False)
    t.add_column("Package")
    t.add_column("Version")
    t.add_column("Score", justify="right")
    t.add_column("Verdict")

    for key, value in rows:
        data = json.loads(value)
        bd = data.get("breakdown", {})
        _, pkg, ver = key.split(":", 2)
        verdict = bd.get("verdict", "?")
        score = bd.get("score", "?")
        color = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}.get(verdict, "white")
        t.add_row(pkg, ver, str(score), f"[{color}]{verdict}[/{color}]")

    console.print(t)


@app.command()
def update(
    force: bool = typer.Option(False, "--force", help="Wipe and refresh all CVE cache entries"),
):
    """Manage the pipguard cache."""
    if force:
        cache.clear_vuln()
        console.print(
            "[green]CVE cache cleared.[/green] Fresh vulnerability data will be fetched on next scan."
        )
    else:
        console.print("Use [bold]pipguard update --force[/bold] to refresh CVE cache immediately.")


if __name__ == "__main__":
    app()
