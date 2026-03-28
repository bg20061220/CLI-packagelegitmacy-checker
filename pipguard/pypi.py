from datetime import datetime, timezone

import httpx

PYPI_URL = "https://pypi.org/pypi/{package}/json"
PYPI_VERSION_URL = "https://pypi.org/pypi/{package}/{version}/json"
PYPISTATS_URL = "https://pypistats.org/api/packages/{package}/recent"


def _parse_upload_time(raw: str) -> datetime:
    timestamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp


def _compute_age_days(
    releases: dict[str, list[dict]], now: datetime | None = None
) -> int | None:
    all_dates = []
    for files in releases.values():
        for file_info in files:
            if file_info.get("upload_time"):
                all_dates.append(_parse_upload_time(file_info["upload_time"]))

    if not all_dates:
        return None

    current_time = now or datetime.now(timezone.utc)
    return (current_time - min(all_dates)).days


async def fetch_metadata(package: str, version: str | None = None) -> dict:
    async with httpx.AsyncClient(timeout=10) as client:
        if version:
            r = await client.get(PYPI_VERSION_URL.format(package=package, version=version))
            r.raise_for_status()
            data = r.json()

            releases_resp = await client.get(PYPI_URL.format(package=package))
            releases_resp.raise_for_status()
            releases = releases_resp.json().get("releases", {})
        else:
            r = await client.get(PYPI_URL.format(package=package))
            r.raise_for_status()
            data = r.json()
            releases = data.get("releases", {})

    info = data["info"]
    age_days = _compute_age_days(releases)

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
