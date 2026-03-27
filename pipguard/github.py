import re

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
