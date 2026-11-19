from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

from aluco.engine import Engine
from aluco.model import DeviceSighting, DnsQuery, IncidentStatus, TrustLevel
from aluco.store import Store
from tests.conftest import IP_A, IP_B, MAC_A, MAC_B, T0


def test_new_device_creates_incident_once(store: Store) -> None:
    engine = Engine(store)
    s = DeviceSighting(mac=MAC_A, at=T0, ip=IP_A)

    first = engine.process(sightings=[s], now=T0)
    assert first.new_devices == 1
    assert [i.rule for i in first.incidents] == ["new_device"]

    second = engine.process(sightings=[replace(s, at=T0 + timedelta(minutes=5))], now=T0)
    assert second.new_devices == 0
    assert second.incidents == []
    assert store.device(MAC_A).last_seen == T0 + timedelta(minutes=5)  # type: ignore[union-attr]


def test_vendor_is_filled_in_later(store: Store) -> None:
    engine = Engine(store)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0)], now=T0)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, vendor="Beispiel")], now=T0)
    assert store.device(MAC_A).vendor == "Beispiel"  # type: ignore[union-attr]


def _setup_iot_device(store: Store, engine: Engine, trust: TrustLevel = TrustLevel.IOT) -> None:
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A)], now=T0)
    device = store.device(MAC_A)
    assert device is not None
    store.save_device(replace(device, trust=trust))


def test_dns_baseline_then_new_domain_alert(store: Store) -> None:
    engine = Engine(store)
    _setup_iot_device(store, engine)

    # Lernphase: alles still, Domains werden gemerkt.
    day1 = T0 + timedelta(days=1)
    learning = engine.process(
        queries=[DnsQuery(client_ip=IP_A, domain="api.vendor.example", at=day1)], now=day1
    )
    assert learning.incidents == []

    # Nach der Lernphase: bekannte Domain (anderer Host) still, neue Domain meldet sich.
    day10 = T0 + timedelta(days=10)
    result = engine.process(
        queries=[
            DnsQuery(client_ip=IP_A, domain="cdn.vendor.example", at=day10),
            DnsQuery(client_ip=IP_A, domain="x.unknown-tracker.example", at=day10),
            DnsQuery(client_ip=IP_A, domain="y.unknown-tracker.example", at=day10),
            DnsQuery(client_ip=IP_B, domain="other.example", at=day10),  # unbekannter Client
        ],
        now=day10,
    )
    assert result.queries_unmatched == 1
    [incident] = result.incidents
    assert incident.rule == "new_domain"
    assert incident.details["domain"] == "unknown-tracker.example"
    assert incident.status is IncidentStatus.NEW


def test_company_device_queries_are_not_evaluated_or_stored(store: Store) -> None:
    engine = Engine(store)
    _setup_iot_device(store, engine, trust=TrustLevel.COMPANY)
    later = T0 + timedelta(days=30)
    result = engine.process(
        queries=[DnsQuery(client_ip=IP_A, domain="intranet.example", at=later)], now=later
    )
    assert result.incidents == []
    assert store.device_domains(MAC_A) == []


def test_queries_of_device_seen_in_same_run_are_matched(store: Store) -> None:
    result = Engine(store).process(
        sightings=[DeviceSighting(mac=MAC_B, at=T0, ip=IP_B)],
        queries=[DnsQuery(client_ip=IP_B, domain="example.com", at=T0)],
        now=T0,
    )
    assert result.queries_unmatched == 0
    assert store.device_domains(MAC_B) == ["example.com"]


def test_learn_only_imports_inventory_without_incidents(store: Store) -> None:
    engine = Engine(store)
    result = engine.process(
        sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A)],
        queries=[DnsQuery(client_ip=IP_A, domain="example.com", at=T0)],
        now=T0,
        learn_only=True,
    )
    assert result.new_devices == 1
    assert result.incidents == []
    assert store.device_domains(MAC_A) == ["example.com"]

    # Danach normal: bekanntes Gerät still, wirklich neues Gerät meldet sich.
    later = engine.process(
        sightings=[DeviceSighting(mac=MAC_A, at=T0), DeviceSighting(mac=MAC_B, at=T0)], now=T0
    )
    assert [i.device_mac for i in later.incidents] == [MAC_B]
