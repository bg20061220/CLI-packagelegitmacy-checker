import re
from datetime import datetime, timezone

import httpx

# Classifiers that indicate a package has no business making network calls at install time
PURE_PYTHON_CLASSIFIERS = {
    "Programming Language :: Python :: Implementation :: CPython",
    "Topic :: Utilities",
    "Topic :: Text Processing",
    "Topic :: Software Development :: Libraries :: Python Modules",
}

# Classifiers where network calls are plausible
NETWORK_CLASSIFIERS = {
    "Topic :: Internet :: WWW/HTTP",
    "Topic :: System :: Networking",
    "Topic :: Scientific/Engineering :: Artificial Intelligence",
    "Topic :: Software Development :: Build Tools",
}

_NETWORK_KEYWORDS = [
    "download", "binary", "binaries", "pre-built", "native extension",
    "model weights", "fetches", "auto-update", "update check",
]
_PURE_KEYWORDS = ["pure python", "pure-python", "zero dependencies", "no network", "offline"]


def classify_from_classifiers(classifiers: list[str]) -> str:
    """
    Returns 'pure_python', 'network_expected', or 'ambiguous' based on PyPI classifiers.
    This is free — classifiers are already in the PyPI JSON response.
    """
    classifier_set = set(classifiers)
    has_pure = bool(classifier_set & PURE_PYTHON_CLASSIFIERS)
    has_network = bool(classifier_set & NETWORK_CLASSIFIERS)

    if has_pure and not has_network:
        return "pure_python"
    if has_network:
        return "network_expected"
    return "ambiguous"


async def fetch_readme_classification(github_url: str) -> str:
    """
    Only called when classifiers are ambiguous or network_expected.
    Returns 'network_expected', 'pure_python', or 'unknown'.
    """
    match = re.match(r"https://github\.com/([^/]+/[^/\s]+)", github_url)
    if not match:
        return "unknown"

    repo = match.group(1).rstrip("/")
    readme_url = f"https://raw.githubusercontent.com/{repo}/HEAD/README.md"

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(readme_url)
        if r.status_code != 200:
            return "unknown"
        text = r.text.lower()

    if any(kw in text for kw in _NETWORK_KEYWORDS):
        return "network_expected"
    if any(kw in text for kw in _PURE_KEYWORDS):
        return "pure_python"
    return "unknown"


def parse_github_url(spec: str) -> tuple[str, str, str] | None:
    """
    Parse GitHub URL in various formats.
    Handles: git+https://github.com/owner/repo.git@branch
             git+https://github.com/owner/repo@branch
             git+https://github.com/owner/repo
             https://github.com/owner/repo
    Returns (owner, repo, ref) where ref defaults to "main".
    Returns None if URL doesn't match a GitHub repo pattern.
    """
    if not spec:
        return None

    # Remove git+ prefix and @branch suffix
    url = spec
    if url.startswith("git+"):
        url = url[4:]

    # Extract branch/ref if specified with @
    ref = "main"
    if "@" in url:
        url, ref = url.rsplit("@", 1)

    # Normalize .git suffix
    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]

    # Match GitHub URL pattern
    match = re.match(r"https?://github\.com/([^/]+)/([^/]+)/?$", url)
    if not match:
        return None

    owner, repo = match.groups()
    return owner, repo, ref


async def fetch_repo_metadata(owner: str, repo: str) -> dict | None:
    """
    Fetch GitHub repo metadata from the API.
    Returns dict with repo info or None on 404/rate limit.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url)

            if r.status_code == 404:
                return None
            if r.status_code >= 400:
                return None

            data = r.json()

            # Compute age_days from created_at
            created_at = datetime.fromisoformat(data["created_at"].replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - created_at).days

            # Compute days_since_push from pushed_at
            pushed_at = datetime.fromisoformat(data["pushed_at"].replace("Z", "+00:00"))
            days_since_push = (datetime.now(timezone.utc) - pushed_at).days

            license_name = None
            if data.get("license"):
                license_name = data["license"].get("spdx_id")

            return {
                "created_at": data["created_at"],
                "pushed_at": data["pushed_at"],
                "stargazers_count": data.get("stargazers_count", 0),
                "forks_count": data.get("forks_count", 0),
                "open_issues_count": data.get("open_issues_count", 0),
                "license": license_name,
                "age_days": age_days,
                "days_since_push": days_since_push,
            }
    except Exception:
        return None


async def fetch_contributor_count(owner: str, repo: str) -> int | None:
    """
    Fetch contributor count from GitHub repo.
    Returns int or None on failure.
    Uses Link header to determine total page count (most efficient method).
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/contributors"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url, params={"per_page": 1, "anon": True})

            if r.status_code >= 400:
                return None

            # Check Link header for pagination info
            link_header = r.headers.get("Link")
            if link_header:
                # Link header format: <url?page=2>; rel="next", <url?page=N>; rel="last"
                match = re.search(r'page=(\d+)>.*rel="last"', link_header)
                if match:
                    return int(match.group(1))

            # If no Link header, just 1 page = 1 contributor
            return len(r.json()) if r.status_code == 200 else 1
    except Exception:
        return None
