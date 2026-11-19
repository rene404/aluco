from __future__ import annotations

from datetime import datetime, timedelta

from aluco.adapters.base import AdapterError
from aluco.model import DeviceSighting, DnsQuery, Incident, IncidentStatus, Severity
from aluco.runner import Runner
from aluco.store import Store
from tests.conftest import IP_A, IP_B, MAC_A, MAC_B, T0


class Devices:
    name = "devices"

    def __init__(self, *sightings: DeviceSighting) -> None:
        self.sightings = list(sightings)
        self.fail = False

    def fetch_sightings(self) -> list[DeviceSighting]:
        if self.fail:
            raise AdapterError("offline")
        return list(self.sightings)


class Dns:
    name = "dns"

    def __init__(self) -> None:
        self.queries: list[DnsQuery] = []
        self.fail = False
        self.since_calls: list[datetime | None] = []

    def fetch_queries(self, since: datetime | None) -> list[DnsQuery]:
        self.since_calls.append(since)
        if self.fail:
            raise AdapterError("offline")
        return [q for q in self.queries if since is None or q.at > since]


class Inbox:
    def __init__(self) -> None:
        self.sent: list[Incident] = []

    def send(self, incident: Incident, assessment: object = None) -> None:
        self.sent.append(incident)


def make(store: Store) -> tuple[Runner, Devices, Dns, Inbox]:
    devices = Devices(DeviceSighting(mac=MAC_A, at=T0, ip=IP_A))
    dns = Dns()
    inbox = Inbox()
    return Runner(store, [devices], [dns], notifier=inbox), devices, dns, inbox


def test_first_run_learns_then_reports_new_devices(store: Store) -> None:
    runner, devices, _, inbox = make(store)

    first = runner.run_once(now=T0)
    assert first.learn_only
    assert inbox.sent == []

    devices.sightings.append(DeviceSighting(mac=MAC_B, at=T0, ip=IP_B))
    second = runner.run_once(now=T0 + timedelta(minutes=5))
    assert not second.learn_only
    assert [i.device_mac for i in inbox.sent] == [MAC_B]

    # Gleicher Befund im nächsten Lauf: keine zweite Meldung.
    runner.run_once(now=T0 + timedelta(minutes=10))
    assert len(inbox.sent) == 1


def test_dns_cursor_advances_only_on_success(store: Store) -> None:
    runner, _, dns, _ = make(store)
    dns.queries = [DnsQuery(client_ip=IP_A, domain="example.com", at=T0)]
    runner.run_once(now=T0)
    assert store.cursor("dns") == T0.isoformat()

    dns.queries.append(DnsQuery(client_ip=IP_A, domain="example.org", at=T0 + timedelta(1)))
    dns.fail = True
    failed = runner.run_once(now=T0 + timedelta(days=1))
    assert failed.errors == ["dns: offline"]
    assert store.cursor("dns") == T0.isoformat()

    dns.fail = False
    runner.run_once(now=T0 + timedelta(days=1))
    assert dns.since_calls[-1] == T0
    assert store.cursor("dns") == (T0 + timedelta(days=1)).isoformat()


def test_failing_device_source_does_not_stop_dns(store: Store) -> None:
    runner, devices, dns, _ = make(store)
    runner.run_once(now=T0)  # Inventar lernen
    devices.fail = True
    dns.queries = [DnsQuery(client_ip=IP_A, domain="example.net", at=T0)]
    summary = runner.run_once(now=T0)
    assert summary.errors == ["devices: offline"]
    assert summary.result.queries_seen == 1
    assert "example.net" in store.device_domains(MAC_A)


def test_low_severity_not_notified_and_old_closed_incidents_purged(store: Store) -> None:
    runner, _, _, inbox = make(store)
    runner.run_once(now=T0)
    old = store.save_incident(
        Incident(
            id=None,
            fingerprint="old",
            rule="r",
            severity=Severity.LOW,
            title="alt",
            status=IncidentStatus.RESOLVED,
            created_at=T0,
            updated_at=T0,
        )
    )
    later = T0 + timedelta(days=60)
    summary = runner.run_once(now=later)
    assert summary.purged == 1
    assert store.incident_by_id(old.id or 0) is None
    assert inbox.sent == []
