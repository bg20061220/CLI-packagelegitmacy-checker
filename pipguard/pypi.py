from datetime import datetime, timezone

import httpx

PYPI_URL = "https://pypi.org/pypi/{package}/json"
PYPI_VERSION_URL = "https://pypi.org/pypi/{package}/{version}/json"
PYPISTATS_URL = "https://pypistats.org/api/packages/{package}/recent"


async def fetch_metadata(package: str, version: str | None = None) -> dict:
    url = (
        PYPI_VERSION_URL.format(package=package, version=version)
        if version
        else PYPI_URL.format(package=package)
    )
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url)
        r.raise_for_status()
        data = r.json()

    info = data["info"]
    releases = data.get("releases", {})

    # Earliest release date across all versions
    all_dates = []
    for files in releases.values():
        for f in files:
            if f.get("upload_time"):
                all_dates.append(
                    datetime.fromisoformat(f["upload_time"]).replace(tzinfo=timezone.utc)
                )
    first_release = min(all_dates) if all_dates else None
    age_days = (datetime.now(timezone.utc) - first_release).days if first_release else None

    # GitHub repo from project_urls or home_page
    project_urls = info.get("project_urls") or {}
    candidates = list(project_urls.values()) + [info.get("home_page") or ""]
    github_url = next((u for u in candidates if u and "github.com" in u), None)

    # Source tarball URL — version-specific endpoint puts files under data["urls"],
    # the non-version endpoint puts them under releases[version]
    target_version = version or info["version"]
    tarball_url = None
    candidate_files = data.get("urls") or releases.get(target_version, [])
    for f in candidate_files:
        if f.get("packagetype") == "sdist":
            tarball_url = f["url"]
            break

    return {
        "name": info["name"],
        "version": target_version,
        "age_days": age_days,
        "classifiers": info.get("classifiers") or [],
        "github_url": github_url,
        "maintainer": info.get("maintainer") or info.get("author"),
        "tarball_url": tarball_url,
        "release_count": len(releases),
    }


async def fetch_download_stats(package: str) -> dict:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(PYPISTATS_URL.format(package=package))
        if r.status_code != 200:
            return {"last_week": None, "last_month": None, "spike_pct": None}
        data = r.json()["data"]

    last_week = data.get("last_week") or 0
    last_month = data.get("last_month") or 0

    # Expected weekly = monthly / 4; spike = how much this week exceeds that
    expected_weekly = last_month / 4 if last_month else 0
    spike_pct = (
        (last_week - expected_weekly) / expected_weekly * 100
        if expected_weekly > 0
        else None
    )

    return {
        "last_week": last_week,
        "last_month": last_month,
        "spike_pct": spike_pct,
    }
