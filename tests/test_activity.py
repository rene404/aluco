"""Chronik, DNS-Statistik, Online-Status, Schema-Migration (Datenschicht für Dashboard v2)."""

from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path

from aluco.adapters.base import AdapterError
from aluco.devices import set_notes, set_trust
from aluco.engine import Engine
from aluco.incidents import IncidentService
from aluco.model import (
    DeviceSighting,
    DnsQuery,
    EventKind,
    IncidentStatus,
    Severity,
    TrustLevel,
)
from aluco.runner import Runner
from aluco.store import SCHEMA_VERSION, Store
from tests.conftest import IP_A, IP_B, MAC_A, MAC_B, T0


def _kinds(store: Store) -> list[EventKind]:
    return [e.kind for e in reversed(store.events())]


def test_learn_run_writes_one_inventory_event(store: Store) -> None:
    Engine(store).process(
        sightings=[DeviceSighting(mac=MAC_A, at=T0), DeviceSighting(mac=MAC_B, at=T0)],
        now=T0,
        learn_only=True,
    )
    [e] = store.events()
    assert e.kind is EventKind.INVENTORY
    assert "2 Geräte" in e.title


def test_new_device_and_online_changes_are_recorded(store: Store) -> None:
    engine = Engine(store)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, online=True)], now=T0)
    assert store.device(MAC_A).online is True  # type: ignore[union-attr]
    later = T0 + timedelta(hours=1)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=later, online=False)], now=later)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=later, online=False)], now=later)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=later, online=None)], now=later)
    assert _kinds(store) == [EventKind.INCIDENT, EventKind.DEVICE_OFFLINE]
    assert store.device(MAC_A).online is False  # type: ignore[union-attr] – None ändert nichts
    [incident_event] = store.events(kinds=frozenset({EventKind.INCIDENT}))
    assert incident_event.severity is Severity.HIGH
    assert incident_event.device_mac == MAC_A


def test_recent_agent_report_keeps_device_online(store: Store) -> None:
    """Agent berichtet, Inventar sieht den Laptop nicht: kein "offline" alle 10 Minuten."""
    from aluco.engine import AGENT_ONLINE_WINDOW

    engine = Engine(store)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, online=True)], now=T0)
    store.add_agent(MAC_A, "hash", T0)
    report = T0 + timedelta(minutes=5)
    store.update_agent_report(MAC_A, report, "laptop", "macOS", {})
    for minutes in (6, 16, 26):  # alle innerhalb des Fensters nach dem Bericht
        at = report + timedelta(minutes=minutes - 5)
        engine.process(sightings=[DeviceSighting(mac=MAC_A, at=at, online=False)], now=at)
    assert EventKind.DEVICE_OFFLINE not in _kinds(store)
    assert store.device(MAC_A).online is True  # type: ignore[union-attr]

    late = report + AGENT_ONLINE_WINDOW + timedelta(minutes=1)  # Agent schweigt
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=late, online=False)], now=late)
    assert _kinds(store)[-1] is EventKind.DEVICE_OFFLINE
    assert store.device(MAC_A).online is False  # type: ignore[union-attr]


def test_agent_laptop_away_from_lan_gets_no_dns_queries(store: Store) -> None:
    """Review: Agent hält den Laptop "online" – seine alte IP darf trotzdem keine DNS-Anfragen
    eines neuen Inhabers (DHCP, z. B. Firmengerät) mehr bekommen."""
    engine = Engine(store)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A, online=True)], now=T0)
    store.add_agent(MAC_A, "hash", T0)
    store.update_agent_report(MAC_A, T0 + timedelta(minutes=5), "laptop", "macOS", {})
    at = T0 + timedelta(minutes=10)
    away = DeviceSighting(mac=MAC_A, at=at, ip=IP_A, online=False)
    result = engine.process(
        sightings=[away],
        queries=[DnsQuery(at=at, client_ip=IP_A, domain="example.org")],
        now=at,
    )
    device = store.device(MAC_A)
    assert device is not None and device.online is True and device.ip is None
    assert result.queries_unmatched == 1


def test_manual_status_change_is_recorded(store: Store) -> None:
    engine = Engine(store)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0)], now=T0)
    [incident] = store.incidents()
    assert incident.id is not None
    with store.transaction():
        IncidentService(store).transition(incident.id, IncidentStatus.IGNORED, note="Gast")
    latest = store.events(limit=1)[0]
    assert latest.kind is EventKind.INCIDENT_STATUS
    assert "ignoriert" in latest.title and latest.detail == "Notiz: Gast"


def test_dns_statistics(store: Store) -> None:
    engine = Engine(store)
    engine.process(
        sightings=[
            DeviceSighting(mac=MAC_A, at=T0, ip=IP_A),
            DeviceSighting(mac=MAC_B, at=T0, ip=IP_B),
        ],
        now=T0,
        learn_only=True,
    )
    set_trust(store, MAC_B, TrustLevel.COMPANY)
    q = [
        DnsQuery(client_ip=IP_A, domain="a.example.com", at=T0),
        DnsQuery(client_ip=IP_A, domain="b.example.com", at=T0 + timedelta(minutes=5)),
        DnsQuery(client_ip=IP_A, domain="ads.tracker.example", at=T0, blocked=True),
        DnsQuery(client_ip=IP_A, domain="x.example.org", at=T0 + timedelta(hours=1)),
        DnsQuery(client_ip=IP_B, domain="intranet.example", at=T0),  # Firma: nicht gezählt
        DnsQuery(client_ip="192.0.2.250", domain="example.net", at=T0),  # ohne Gerät
    ]
    engine.process(queries=q, now=T0 + timedelta(hours=2))

    hourly = store.dns_hourly(since=T0)
    assert [(t, b) for _, t, b in hourly] == [(4, 1), (1, 0)]  # 3 von A + 1 ohne Gerät, dann 1
    assert store.dns_hourly(since=T0, mac=MAC_B) == []
    assert store.top_devices(since=T0) == [(MAC_A, 4)]
    assert store.top_blocked_domains(since=T0) == [("tracker.example", 1)]

    stats = {d: (n, b) for d, _, n, b in store.device_domain_stats(MAC_A, since=T0)}
    assert stats == {"example.com": (2, 0), "tracker.example": (1, 1), "example.org": (1, 0)}

    by_device = store.dns_hourly_by_device(since=T0)
    assert set(by_device) == {MAC_A}
    assert sum(by_device[MAC_A].values()) == 4


def test_company_marking_deletes_behaviour_events(store: Store) -> None:
    engine = Engine(store)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A)], now=T0)  # Vorfall
    assert store.events(device_mac=MAC_A)
    set_trust(store, MAC_A, TrustLevel.COMPANY)
    assert store.events(device_mac=MAC_A) == []


def test_company_marking_deletes_statistics(store: Store) -> None:
    engine = Engine(store)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A)], now=T0, learn_only=True)
    engine.process(queries=[DnsQuery(client_ip=IP_A, domain="example.com", at=T0)], now=T0)
    assert store.dns_hourly(since=T0, mac=MAC_A)
    set_trust(store, MAC_A, TrustLevel.COMPANY)
    assert store.dns_hourly(since=T0, mac=MAC_A) == []
    assert store.device_domain_stats(MAC_A, since=T0) == []


def test_notes(store: Store) -> None:
    Engine(store).process(sightings=[DeviceSighting(mac=MAC_A, at=T0)], now=T0, learn_only=True)
    assert set_notes(store, MAC_A, "  Wandmontage  ").notes == "Wandmontage"
    assert store.device(MAC_A).notes == "Wandmontage"  # type: ignore[union-attr]


def test_purge_events_and_stats(store: Store) -> None:
    engine = Engine(store)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A)], now=T0, learn_only=True)
    engine.process(queries=[DnsQuery(client_ip=IP_A, domain="example.com", at=T0)], now=T0)
    later = T0 + timedelta(days=40)
    assert store.purge_events(older_than=later) == 1
    store.purge_stats(older_than=later)
    assert store.dns_hourly(since=T0) == []
    # Domains bleiben bekannt (Grundlage für "neue Domain"), nur die Zahlen sind weg.
    assert [(d, n, b) for d, _, n, b in store.device_domain_stats(MAC_A, since=T0)] == [
        ("example.com", 0, 0)
    ]


def test_source_outage_and_recovery_events(store: Store) -> None:
    class Flaky:
        name = "netalertx"
        fail = True

        def fetch_sightings(self) -> list[DeviceSighting]:
            if self.fail:
                raise AdapterError("HTTP 403")
            return []

    src = Flaky()
    runner = Runner(store, [src], [])
    runner.run_once(now=T0)
    runner.run_once(now=T0)  # weiterhin kaputt: kein zweites Ereignis
    src.fail = False
    runner.run_once(now=T0)
    titles = [e.title for e in reversed(store.events())]
    assert titles == ["netalertx nicht erreichbar", "netalertx wieder erreichbar"]


def test_migration_from_v1_keeps_data(tmp_path: Path) -> None:
    path = tmp_path / "v1.db"
    db = sqlite3.connect(path)
    db.executescript(
        """
        CREATE TABLE devices (mac TEXT PRIMARY KEY, first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL, ip TEXT, hostname TEXT, vendor TEXT, name TEXT,
            trust TEXT NOT NULL, protected INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE device_domains (mac TEXT NOT NULL, domain TEXT NOT NULL,
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY (mac, domain));
        CREATE TABLE incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL
            UNIQUE, rule TEXT NOT NULL, severity INTEGER NOT NULL, title TEXT NOT NULL,
            status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            device_mac TEXT, details TEXT NOT NULL DEFAULT '{}',
            occurrences INTEGER NOT NULL DEFAULT 1, note TEXT NOT NULL DEFAULT '');
        CREATE TABLE cursors (source TEXT PRIMARY KEY, position TEXT NOT NULL);
        PRAGMA user_version = 1;
        """
    )
    db.execute(
        "INSERT INTO devices VALUES (?, ?, ?, ?, NULL, NULL, 'TV', 'iot', 0)",
        (MAC_A, T0.isoformat(), T0.isoformat(), IP_A),
    )
    db.commit()
    db.close()

    s = Store(path)
    d = s.device(MAC_A)
    assert d is not None and d.name == "TV" and d.online is None and d.notes == ""
    assert s._db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    s.close()
