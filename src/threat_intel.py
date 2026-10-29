"""Local lookup against a cached public phishing-domain feed.

Only the feed is downloaded; checked hostnames are never sent to its provider.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


FEED_URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt"
FEED_NAME = "Phishing.Database active-domain community feed"
REFRESH_SECONDS = 12 * 60 * 60
MAX_STALE_SECONDS = 7 * 24 * 60 * 60
MAX_FEED_BYTES = 16 * 1024 * 1024
MAX_DOMAINS = 250_000
MIN_DOMAINS = 1_000
_SKIP_HOSTS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "uk", "co.uk", "org.uk",
    "ac.uk", "gov.uk", "in", "co.in", "org.in", "gov.in", "us", "ca", "au",
    "com.au", "org.au", "de", "fr", "jp", "co.jp", "cn", "ru", "br", "com.br",
    "io", "dev", "app", "xyz", "info", "biz", "github.io", "pages.dev", "workers.dev",
    "blogspot.com", "wordpress.com", "netlify.app", "vercel.app", "firebaseapp.com",
    "web.app", "wixsite.com", "herokuapp.com", "onrender.com",
}
_LOCK = threading.Lock()
_CACHE_RECORD: dict | None = None
_CACHE_DOMAINS: set[str] | None = None
_LAST_ATTEMPT = 0.0


def _cache_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") if os.name == "nt" else None
    root = Path(base) if base else Path.home() / ".cache"
    return root / "Alerter" / "phishing-domain-feed.json"


def _normalize_feed_line(line: str) -> str:
    candidate = line.strip()
    if not candidate or candidate.startswith("#"):
        return ""
    if candidate.startswith("||"):
        candidate = re.sub(r"\^.*$", "", candidate[2:])
    parts = candidate.split()
    if len(parts) > 1 and parts[0] in {"0.0.0.0", "127.0.0.1", "::1"}:
        candidate = parts[1]
    candidate = candidate.lower().rstrip(".")
    if not candidate or any(char in candidate for char in "*/") or len(candidate) > 253:
        return ""
    try:
        parsed = urlsplit(f"https://{candidate}")
        if parsed.path != "/" or parsed.username or parsed.password or parsed.port:
            return ""
        host = parsed.hostname or ""
    except ValueError:
        return ""
    if "." not in host or host in _SKIP_HOSTS:
        return ""
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", host):
        return ""
    try:
        ipaddress.ip_address(host)
        return ""
    except ValueError:
        return host


def _valid_record(value: object) -> tuple[dict, set[str]] | None:
    if not isinstance(value, dict):
        return None
    updated_at = value.get("updated_at")
    domains = value.get("domains")
    if not isinstance(updated_at, (int, float)) or not isinstance(domains, list):
        return None
    cleaned = {host for host in domains if isinstance(host, str) and _normalize_feed_line(host) == host}
    if not MIN_DOMAINS <= len(cleaned) <= MAX_DOMAINS:
        return None
    return ({"source": FEED_NAME, "updated_at": float(updated_at), "count": len(cleaned)}, cleaned)


def _read_cache() -> tuple[dict, set[str]] | None:
    try:
        return _valid_record(json.loads(_cache_path().read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError):
        return None


def _write_cache(record: dict, domains: list[str]) -> None:
    path = _cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps({**record, "domains": domains}, separators=(",", ":")),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _get_domains() -> tuple[dict, set[str]] | None:
    global _CACHE_RECORD, _CACHE_DOMAINS, _LAST_ATTEMPT
    now = time.time()
    if _CACHE_RECORD and _CACHE_DOMAINS and now - _CACHE_RECORD["updated_at"] < REFRESH_SECONDS:
        return _CACHE_RECORD, _CACHE_DOMAINS
    with _LOCK:
        now = time.time()
        if _CACHE_RECORD and _CACHE_DOMAINS and now - _CACHE_RECORD["updated_at"] < REFRESH_SECONDS:
            return _CACHE_RECORD, _CACHE_DOMAINS
        previous = (_CACHE_RECORD, _CACHE_DOMAINS) if _CACHE_RECORD and _CACHE_DOMAINS else _read_cache()
        if previous:
            _CACHE_RECORD, _CACHE_DOMAINS = previous
        if now - _LAST_ATTEMPT < 10 * 60:
            return previous if previous and now - previous[0]["updated_at"] <= MAX_STALE_SECONDS else None
        _LAST_ATTEMPT = now
        try:
            request = Request(FEED_URL, headers={"Accept": "text/plain", "User-Agent": "Alerter-local-threat-check/1.0"})
            with urlopen(request, timeout=4) as response:
                declared_size = int(response.headers.get("Content-Length") or 0)
                if declared_size > MAX_FEED_BYTES:
                    raise ValueError("Threat feed exceeded its size limit")
                payload = response.read(MAX_FEED_BYTES + 1)
            if len(payload) > MAX_FEED_BYTES:
                raise ValueError("Threat feed exceeded its size limit")
            domains = sorted({
                normalized
                for line in payload.decode("utf-8", errors="replace").splitlines()
                if (normalized := _normalize_feed_line(line))
            })
            if not MIN_DOMAINS <= len(domains) <= MAX_DOMAINS:
                raise ValueError("Threat feed did not pass validation")
            record = {"source": FEED_NAME, "updated_at": time.time(), "count": len(domains)}
            _write_cache(record, domains)
            _CACHE_RECORD, _CACHE_DOMAINS = record, set(domains)
            return record, _CACHE_DOMAINS
        except (OSError, ValueError, UnicodeError):
            if previous and now - previous[0]["updated_at"] <= MAX_STALE_SECONDS:
                _CACHE_RECORD, _CACHE_DOMAINS = previous
                return previous
            return None


def lookup_host(host: str) -> dict | None:
    """Return a feed match for a hostname or parent domain, if available."""
    candidate = (host or "").strip().lower().rstrip(".")
    if not candidate:
        return None
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    loaded = _get_domains()
    if not loaded:
        return None
    record, domains = loaded
    domain = candidate
    while "." in domain:
        if domain in domains:
            return {
                "type": "phishing",
                "source": record["source"],
                "updated_at": record["updated_at"],
                "matched_domain": domain,
            }
        domain = domain.split(".", 1)[1]
    return None
