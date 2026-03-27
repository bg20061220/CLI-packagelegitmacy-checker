import httpx

OSV_URL = "https://api.osv.dev/v1/query"


async def check_vulns(package: str, version: str) -> list[dict]:
    payload = {
        "version": version,
        "package": {"name": package, "ecosystem": "PyPI"},
    }
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(OSV_URL, json=payload)
        r.raise_for_status()
        data = r.json()

    return [
        {"id": v["id"], "summary": v.get("summary", "No description")}
        for v in data.get("vulns", [])
    ]
