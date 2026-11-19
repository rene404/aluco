from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import pytest

from aluco.adapters.adguard import AdGuardHome, parse_time
from aluco.adapters.base import AdapterError
from tests.conftest import IP_A


def entry(time: str, name: str = "example.com", reason: str = "NotFilteredNotFound") -> dict:
    return {
        "time": time,
        "client": IP_A,
        "question": {"name": name, "type": "A", "class": "IN"},
        "reason": reason,
    }


class FakeAdGuard:
    """Simuliert das seitenweise Abfrageprotokoll (neueste zuerst)."""

    def __init__(self, entries: list[dict[str, Any]]) -> None:
        self.entries = entries
        self.calls: list[Mapping[str, str]] = []

    def __call__(self, method: str, path: str, params: Mapping[str, str]) -> Any:
        assert (method, path) == ("GET", "/control/querylog")
        self.calls.append(dict(params))
        limit = int(params["limit"])
        items = self.entries
        if "older_than" in params:
            cutoff = parse_time(params["older_than"])
            items = [e for e in items if parse_time(e["time"]) < cutoff]
        page = items[:limit]
        return {"data": page, "oldest": page[-1]["time"] if page else ""}


def ts(minute: int) -> str:
    return f"2026-11-19T10:{minute:02d}:00.123456789Z"


def test_parse_time_handles_nanoseconds() -> None:
    assert parse_time("2026-11-19T10:00:00.123456789Z") == datetime(
        2026, 11, 19, 10, 0, 0, 123456, tzinfo=UTC
    )
    assert parse_time("2026-11-19T11:00:00+01:00").utcoffset() is not None
    with pytest.raises(ValueError):
        parse_time("2026-11-19T10:00:00")


def test_fetches_all_pages_oldest_first() -> None:
    fake = FakeAdGuard([entry(ts(m), f"d{m}.example") for m in range(9, -1, -1)])
    queries = AdGuardHome(fake, page_size=3).fetch_queries(since=None)
    assert [q.domain for q in queries] == [f"d{m}.example" for m in range(10)]
    assert len(fake.calls) == 4
    assert all(q.client_ip == IP_A and q.source == "adguardhome" for q in queries)


def test_stops_at_since_exclusive() -> None:
    fake = FakeAdGuard([entry(ts(m), f"d{m}.example") for m in range(9, -1, -1)])
    since = parse_time(ts(6))
    queries = AdGuardHome(fake, page_size=3).fetch_queries(since=since)
    assert [q.domain for q in queries] == ["d7.example", "d8.example", "d9.example"]
    assert len(fake.calls) == 2  # Seite 1 liegt komplett nach since, Seite 2 erreicht since


def test_max_pages_limits_backlog() -> None:
    fake = FakeAdGuard([entry(ts(m)) for m in range(9, -1, -1)])
    queries = AdGuardHome(fake, page_size=2, max_pages=2).fetch_queries(since=None)
    assert len(queries) == 4


def test_blocked_and_malformed_entries() -> None:
    fake = FakeAdGuard(
        [
            entry(ts(3), "ads.example", reason="FilteredBlackList"),
            {"time": ts(2), "question": {"name": "no-client.example"}},
            entry("not-a-time"),
            entry(ts(1)),
        ]
    )
    queries = AdGuardHome(fake).fetch_queries(since=None)
    assert [(q.domain, q.blocked) for q in queries] == [
        ("example.com", False),
        ("ads.example", True),
    ]


def test_unexpected_response_raises() -> None:
    with pytest.raises(AdapterError):
        AdGuardHome(lambda *_: {"oops": 1}).fetch_queries(since=None)
