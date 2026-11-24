"""MCP-Server über den In-Memory-Client des SDK (kein Prozess, kein Netz)."""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from mcp import Client

from aluco.devices import set_name, set_trust
from aluco.engine import Engine
from aluco.mcp_server import build_server
from aluco.model import DeviceSighting, DnsQuery, TrustLevel, utcnow
from aluco.store import Store
from tests.conftest import IP_A, IP_B, MAC_A, MAC_B

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def db(tmp_path: Path) -> Path:
    """Fernseher (IoT) mit DNS-Daten von heute, Arbeitsrechner, ein offener Vorfall."""
    path = tmp_path / "aluco.db"
    s = Store(path)
    now = utcnow()
    engine = Engine(s)
    start = now - timedelta(days=10)
    engine.process(
        sightings=[
            DeviceSighting(mac=MAC_A, at=start, ip=IP_A, vendor="Beispiel TV", online=True),
            DeviceSighting(mac=MAC_B, at=start, ip=IP_B, online=True),
        ],
        now=start,
        learn_only=True,
    )
    set_name(s, MAC_A, "Fernseher")
    set_trust(s, MAC_A, TrustLevel.IOT)
    set_name(s, MAC_B, "Arbeitsrechner")
    set_trust(s, MAC_B, TrustLevel.COMPANY)
    two_h = now - timedelta(hours=2)
    engine.process(
        sightings=[
            DeviceSighting(mac=MAC_A, at=two_h, ip=IP_A),
            DeviceSighting(mac=MAC_B, at=two_h, ip=IP_B),
        ],
        queries=[DnsQuery(client_ip=IP_A, domain="cdn.streaming.example", at=two_h)] * 3
        + [DnsQuery(client_ip=IP_A, domain="metrics.tv-vendor.example", at=two_h, blocked=True)]
        + [DnsQuery(client_ip=IP_B, domain="intranet.firma.example", at=two_h)],
        now=two_h,
    )
    s.close()
    return path


@pytest.fixture
async def client(db: Path) -> AsyncIterator[Client]:
    async with Client(build_server(db, "Europe/Berlin"), raise_exceptions=True) as c:
        yield c


async def call(client: Client, tool: str, **args: Any) -> Any:
    result = await client.call_tool(tool, args)
    assert not result.is_error, result.content
    data = result.structured_content
    return data.get("result", data) if isinstance(data, dict) else data


async def test_all_tools_are_read_only(client: Client) -> None:
    tools = (await client.list_tools()).tools
    names = {t.name for t in tools}
    assert names == {
        "get_overview", "list_incidents", "get_incident", "list_devices",
        "get_device", "device_activity", "timeline", "dns_top", "rule_quality",
    }  # fmt: skip
    assert all(t.annotations and t.annotations.read_only_hint for t in tools)


async def test_overview(client: Client) -> None:
    o = await call(client, "get_overview")
    assert o["lage"].startswith("2 Vorfälle")
    assert o["geraete"] == {"gesamt": 2, "online": 2, "offline": 0}
    assert o["dns_24h"] == {"anfragen": 4, "blockiert": 1}  # Firmengerät nicht gezählt


async def test_incidents(client: Client) -> None:
    items = await call(client, "list_incidents", status="alle")
    assert {i["schwere"] for i in items} == {"niedrig"}
    detail = await call(client, "get_incident", incident_id=items[0]["id"])
    assert detail["warum_auffaellig"] and "nur lesend" in detail["moegliche_aktionen"]


async def test_device_and_activity(client: Client) -> None:
    tv = await call(client, "get_device", name_or_mac="fernseher")
    assert tv["stufe"] == "IoT" and tv["hersteller"] == "Beispiel TV"
    assert {d["domain"] for d in tv["top_domains_7_tage"]} == {
        "streaming.example",
        "tv-vendor.example",
    }
    act = await call(client, "device_activity", name_or_mac=MAC_A, hours=6)
    assert act["anfragen_gesamt"] == 4 and act["blockiert_gesamt"] == 1
    assert act["domains_an_diesen_tagen"][0]["domain"] == "streaming.example"


async def test_company_device_shows_no_behaviour(client: Client) -> None:
    laptop = await call(client, "get_device", name_or_mac="Arbeitsrechner")
    assert "Firmengerät" in laptop["hinweis"] and "top_domains_7_tage" not in laptop
    act = await call(client, "device_activity", name_or_mac="Arbeitsrechner")
    assert set(act) == {"geraet", "hinweis"}
    dumped = str(await call(client, "dns_top")) + str(await call(client, "timeline", hours=48))
    assert "firma.example" not in dumped


async def test_tool_errors_are_readable(client: Client) -> None:
    result = await client.call_tool("get_device", {"name_or_mac": "toaster"})
    assert result.is_error and "Kein Gerät passt" in result.content[0].text
    result = await client.call_tool("list_incidents", {"status": "egal"})
    assert result.is_error
    result = await client.call_tool(
        "device_activity", {"name_or_mac": "fernseher", "start": "gestern abend"}
    )
    assert result.is_error and "Zeitangabe" in result.content[0].text


async def test_server_cannot_write(db: Path) -> None:
    s = Store(db, read_only=True)
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        s.set_cursor("x", "y")
    s.close()


async def test_missing_database(tmp_path: Path) -> None:
    async with Client(build_server(tmp_path / "fehlt.db")) as c:
        result = await c.call_tool("get_overview", {})
        assert result.is_error and "Aluco-Dienst" in result.content[0].text


async def test_rule_quality(client: Client) -> None:
    q = await call(client, "rule_quality", days=10000)
    assert q["zeitraum_tage"] == 400
    by_rule = {r["regel"]: r for r in q["regeln"]}
    assert by_rule["new_device"]["name"] == "Neues Gerät"
    assert "mac" not in str(q).lower() and "00:00:5e" not in str(q)
