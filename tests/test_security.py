"""Regressionstests zur Sicherheitsprüfung (Befunde M1–M3, L2–L5, I1–I2)."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from aluco.ai import AssessmentError, assess_incident, build_context
from aluco.devices import set_trust
from aluco.engine import Engine
from aluco.model import (
    DeviceSighting,
    DnsQuery,
    TrustLevel,
    clean_text,
    is_local_name,
)
from aluco.store import Store
from aluco.web import WebConfig, create_app
from aluco.web.app import _host_allowed
from aluco.web.auth import LoginThrottle
from tests.conftest import IP_A, MAC_A, MAC_B, T0

# --- M1: keine IPs/Hostnamen über lokale Namen an die KI ---------------------------


@pytest.mark.parametrize(
    "name",
    ["23.1.168.192.in-addr.arpa", "laptop-anna.fritz.box", "drucker.local", "nas.lan",
     "router.home.arpa", "tv.home", "wpad", "srv.internal"],
)  # fmt: skip
def test_local_names(name: str) -> None:
    assert is_local_name(name)


@pytest.mark.parametrize("name", ["example.com", "api.vendor.co.at", "box.example.org"])
def test_public_names(name: str) -> None:
    assert not is_local_name(name)


def test_local_names_never_become_domains_or_incidents(store: Store) -> None:
    engine = Engine(store)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A)], now=T0, learn_only=True)
    set_trust(store, MAC_A, TrustLevel.IOT)
    later = T0 + timedelta(days=10)
    result = engine.process(
        sightings=[DeviceSighting(mac=MAC_A, at=later, ip=IP_A)],
        queries=[
            DnsQuery(client_ip=IP_A, domain="23.1.168.192.in-addr.arpa", at=later),
            DnsQuery(client_ip=IP_A, domain="laptop-anna.fritz.box", at=later),
        ],
        now=later,
    )
    assert result.incidents == []
    assert store.device_domains(MAC_A) == []
    assert sum(t for _, t, _ in store.dns_hourly(since=T0, mac=MAC_A)) == 2  # nur gezählt


def test_ai_context_has_no_full_query(store: Store) -> None:
    engine = Engine(store)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A)], now=T0, learn_only=True)
    set_trust(store, MAC_A, TrustLevel.IOT)
    later = T0 + timedelta(days=10)
    engine.process(
        sightings=[DeviceSighting(mac=MAC_A, at=later, ip=IP_A)],
        queries=[DnsQuery(client_ip=IP_A, domain="user-4711.tracker.example", at=later)],
        now=later,
    )
    [incident] = store.incidents()
    dumped = json.dumps(build_context(incident, store.device(MAC_A), []))
    assert "user-4711" not in dumped and "tracker.example" in dumped


# --- I2: meistgenutzte statt alphabetische Domains ---------------------------------


class Capture:
    def __init__(self) -> None:
        self.ctx: dict[str, Any] = {}

    def judge(self, context: dict[str, Any]) -> Any:
        self.ctx = context
        raise AssessmentError("nur Kontext prüfen")


def test_known_domains_are_most_used(store: Store) -> None:
    engine = Engine(store)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A)], now=T0, learn_only=True)
    set_trust(store, MAC_A, TrustLevel.IOT)
    now = T0 + timedelta(days=10)
    queries = [DnsQuery(client_ip=IP_A, domain="aaa.example", at=now)]
    queries += [DnsQuery(client_ip=IP_A, domain="zzz.example", at=now)] * 5
    queries += [DnsQuery(client_ip=IP_A, domain="new.example", at=now)]
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=now, ip=IP_A)], queries=queries, now=now)
    incident = next(i for i in store.incidents() if i.details.get("domain") == "new.example")
    cap = Capture()
    with pytest.raises(AssessmentError):
        assess_incident(store, cap, incident.id or 0, now=now)
    assert cap.ctx["bisher_bekannte_domains"][0] == "zzz.example"


# --- M2: DNS nie einem falschen (z. B. fremden statt Firmen-)Gerät zuordnen ----------


def test_ip_moves_to_new_device(store: Store) -> None:
    engine = Engine(store)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A)], now=T0, learn_only=True)
    engine.process(sightings=[DeviceSighting(mac=MAC_B, at=T0 + timedelta(minutes=5), ip=IP_A)])
    assert store.device(MAC_A).ip is None  # type: ignore[union-attr]
    assert store.device_by_ip(IP_A).mac == MAC_B  # type: ignore[union-attr]


def test_queries_not_attributed_to_offline_or_stale_devices(store: Store) -> None:
    engine = Engine(store)
    engine.process(
        sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A, online=False)],
        now=T0,
        learn_only=True,
    )
    r1 = engine.process(queries=[DnsQuery(client_ip=IP_A, domain="a.example", at=T0)], now=T0)
    assert r1.queries_unmatched == 1
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A, online=True)], now=T0)
    late = T0 + timedelta(hours=3)
    r2 = engine.process(queries=[DnsQuery(client_ip=IP_A, domain="b.example", at=late)], now=late)
    assert r2.queries_unmatched == 1
    assert store.device_domains(MAC_A) == []


# --- L4: Steuerzeichen aus dem Netz ------------------------------------------------


def test_control_characters_are_stripped() -> None:
    evil = "tv\x1b]0;pwned\x07\x1b[2J" + "x" * 500
    s = DeviceSighting(mac=MAC_A, at=T0, hostname=evil, vendor="V\x00endor")
    assert "\x1b" not in (s.hostname or "") and len(s.hostname or "") <= 200
    assert s.vendor == "Vendor"
    assert clean_text("\x01\x02") is None
    assert DnsQuery(client_ip=IP_A, domain="a\x1b.example", at=T0).domain == "a.example"


# --- L2 / L3 / I1: Dashboard -------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "ok"),
    [("192.0.2.10:8088", True), ("[2001:db8::1]:8088", True), ("localhost:8088", True),
     ("aluco.lan:8088", True), ("evil.example", False), ("", False)],
)  # fmt: skip
def test_host_allowlist(host: str, ok: bool) -> None:
    assert _host_allowed(host, ("aluco.lan",)) is ok


def test_dns_rebinding_host_is_rejected(tmp_path: Path) -> None:
    Store(tmp_path / "a.db").close()
    client = TestClient(create_app(WebConfig(db_path=tmp_path / "a.db", password="x" * 12)))
    assert client.get("/login", headers={"Host": "evil.example"}).status_code == 400
    assert client.get("/login", headers={"Host": "192.0.2.10:8088"}).status_code == 200


def test_global_login_limit_and_no_memory_growth() -> None:
    t = LoginThrottle(max_failures=5, max_global=3)
    for i in range(3):
        t.fail(f"10.0.0.{i}")
    assert t.blocked("10.0.0.99")  # neue IP hilft nicht
    t2 = LoginThrottle()
    for i in range(100):
        t2.blocked(f"10.0.1.{i}")
    assert len(t2._failures) == 0


def test_url_parameters_are_validated(tmp_path: Path) -> None:
    path = tmp_path / "a.db"
    s = Store(path)
    Engine(s).process(sightings=[DeviceSighting(mac=MAC_A, at=T0)], now=T0, learn_only=True)
    s.close()
    client = TestClient(create_app(WebConfig(db_path=path, password="x" * 12)))
    client.post("/login", data={"password": "x" * 12}, headers={"Origin": "http://testserver"})
    spoof = client.get(f"/devices/{MAC_A}?saved=1&deleted=Ihr%20Konto%20wurde%20gesperrt").text
    assert "Konto wurde gesperrt" not in spoof
    assert client.get("/?events=%3Cscript%3E").status_code == 200


# --- L5: unerwartete Fehler beim KI-Aufruf ----------------------------------------


class Boom:
    def judge(self, context: dict[str, Any]) -> Any:
        raise ValueError("kaputte Antwort")


def test_unexpected_ai_error_becomes_assessment_error(store: Store) -> None:
    Engine(store).process(sightings=[DeviceSighting(mac=MAC_A, at=T0)], now=T0)
    [incident] = store.incidents()
    with pytest.raises(AssessmentError, match="ValueError"):
        assess_incident(store, Boom(), incident.id or 0)
