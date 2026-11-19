"""AdGuard Home: DNS-Anfragen pro Gerät aus dem Abfrageprotokoll."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from aluco.adapters.base import AdapterError, JsonFetcher
from aluco.model import DnsQuery

# AdGuard liefert Nanosekunden; Python versteht höchstens Mikrosekunden.
_FRACTION_RE = re.compile(r"(\.\d{6})\d+")


def parse_time(value: str) -> datetime:
    dt = datetime.fromisoformat(_FRACTION_RE.sub(r"\1", value))
    if dt.tzinfo is None:
        raise ValueError(f"Zeitangabe ohne Zeitzone: {value!r}")
    return dt


class AdGuardHome:
    """Liest ``/control/querylog`` seitenweise rückwärts bis zum letzten Stand."""

    name = "adguardhome"

    def __init__(self, fetch: JsonFetcher, page_size: int = 500, max_pages: int = 20) -> None:
        self._fetch = fetch
        self._page_size = page_size
        self._max_pages = max_pages  # Schutz bei sehr langer Pause: höchstens N Seiten

    def fetch_queries(self, since: datetime | None) -> list[DnsQuery]:
        collected: list[DnsQuery] = []
        older_than = ""
        for _ in range(self._max_pages):
            params = {"limit": str(self._page_size)}
            if older_than:
                params["older_than"] = older_than
            page = self._fetch("GET", "/control/querylog", params)
            entries = _entries(page)
            if not entries:
                break
            reached_since = False
            for entry in entries:  # neueste zuerst
                query = _to_query(entry)
                if query is None:
                    continue
                if since is not None and query.at <= since:
                    reached_since = True
                    break
                collected.append(query)
            oldest = page.get("oldest") if isinstance(page, dict) else None
            if reached_since or not oldest or len(entries) < self._page_size:
                break
            older_than = str(oldest)
        collected.sort(key=lambda q: q.at)
        return collected


def _entries(page: Any) -> list[dict[str, Any]]:
    if not isinstance(page, dict) or not isinstance(page.get("data"), list):
        raise AdapterError("AdGuard: unerwartete Antwort von /control/querylog")
    return [e for e in page["data"] if isinstance(e, dict)]


def _to_query(entry: dict[str, Any]) -> DnsQuery | None:
    question = entry.get("question") or {}
    client = entry.get("client")
    name = question.get("name")
    time = entry.get("time")
    if not (client and name and time):
        return None
    try:
        at = parse_time(time)
    except ValueError:
        return None
    reason = str(entry.get("reason", ""))
    return DnsQuery(
        client_ip=str(client),
        domain=str(name),
        at=at,
        qtype=str(question.get("type", "")),
        blocked=reason.startswith("Filtered"),
        source=AdGuardHome.name,
    )
