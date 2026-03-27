import json
import sqlite3
import time
from pathlib import Path

CACHE_DIR = Path.home() / ".pipguard"
CACHE_DB = CACHE_DIR / "cache.db"

TTL_TRUST = 86_400  # 24 hours
TTL_VULN = 21_600   # 6 hours


def _conn() -> sqlite3.Connection:
    CACHE_DIR.mkdir(exist_ok=True)
    con = sqlite3.connect(CACHE_DB)
    con.execute("""
        CREATE TABLE IF NOT EXISTS cache (
            key        TEXT PRIMARY KEY,
            value      TEXT NOT NULL,
            expires_at REAL NOT NULL
        )
    """)
    con.commit()
    return con


def get(key: str) -> dict | None:
    with _conn() as con:
        row = con.execute(
            "SELECT value, expires_at FROM cache WHERE key = ?", (key,)
        ).fetchone()
    if row is None:
        return None
    value, expires_at = row
    if time.time() > expires_at:
        return None
    return json.loads(value)


def set(key: str, value: dict, ttl: int) -> None:
    with _conn() as con:
        con.execute(
            "INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)",
            (key, json.dumps(value), time.time() + ttl),
        )


def clear_vuln() -> None:
    """Wipe all CVE/vulnerability cache entries (for pipguard update --force)."""
    with _conn() as con:
        con.execute("DELETE FROM cache WHERE key LIKE 'osv:%'")
