from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from aluco.model import Device, Incident, IncidentStatus, Severity, TrustLevel
from aluco.store import Store
from tests.conftest import IP_A, IP_B, MAC_A, MAC_B, T0


def test_device_roundtrip_and_update(store: Store) -> None:
    d = Device(mac=MAC_A, first_seen=T0, last_seen=T0, ip=IP_A, trust=TrustLevel.IOT)
    store.save_device(d)
    assert store.device(MAC_A) == d

    moved = Device(mac=MAC_A, first_seen=T0, last_seen=T0 + timedelta(hours=1), ip=IP_B)
    store.save_device(moved)
    assert store.device(MAC_A) == moved
    assert store.device_by_ip(IP_B) == moved
    assert store.device_by_ip(IP_A) is None


def test_device_by_ip_prefers_most_recent(store: Store) -> None:
    store.save_device(Device(mac=MAC_A, first_seen=T0, last_seen=T0, ip=IP_A))
    newer = Device(mac=MAC_B, first_seen=T0, last_seen=T0 + timedelta(hours=1), ip=IP_A)
    store.save_device(newer)
    assert store.device_by_ip(IP_A) == newer


def test_naive_datetimes_are_rejected(store: Store) -> None:
    with pytest.raises(ValueError, match="Zeitzone"):
        store.save_device(Device(mac=MAC_A, first_seen=datetime(2026, 1, 1), last_seen=T0))


def test_record_domain_reports_first_time_only(store: Store) -> None:
    store.save_device(Device(mac=MAC_A, first_seen=T0, last_seen=T0))
    assert store.record_domain(MAC_A, "example.com", T0) is True
    assert store.record_domain(MAC_A, "example.com", T0) is False
    assert store.record_domain(MAC_A, "example.com", T0 + timedelta(hours=1)) is False
    assert store.record_domain(MAC_A, "example.org", T0) is True
    assert store.device_domains(MAC_A) == ["example.com", "example.org"]


def _incident(status: IncidentStatus, updated: datetime, fp: str) -> Incident:
    return Incident(
        id=None,
        fingerprint=fp,
        rule="r",
        severity=Severity.LOW,
        title="t",
        status=status,
        created_at=T0,
        updated_at=updated,
        details={"a": "b"},
    )


def test_incident_roundtrip_and_status_filter(store: Store) -> None:
    saved = store.save_incident(_incident(IncidentStatus.NEW, T0, "fp1"))
    assert saved.id is not None
    assert store.incident_by_fingerprint("fp1") == saved
    store.save_incident(_incident(IncidentStatus.RESOLVED, T0, "fp2"))
    assert [i.fingerprint for i in store.incidents(frozenset({IncidentStatus.NEW}))] == ["fp1"]
    assert len(store.incidents()) == 2


def test_purge_keeps_open_and_recent_incidents(store: Store) -> None:
    old = T0 - timedelta(days=60)
    store.save_incident(_incident(IncidentStatus.RESOLVED, old, "old-resolved"))
    store.save_incident(_incident(IncidentStatus.IGNORED, old, "old-ignored"))
    store.save_incident(_incident(IncidentStatus.NEW, old, "old-open"))
    store.save_incident(_incident(IncidentStatus.RESOLVED, T0, "recent-resolved"))
    assert store.purge_closed_incidents(older_than=T0 - timedelta(days=30)) == 2
    assert {i.fingerprint for i in store.incidents()} == {"old-open", "recent-resolved"}


def test_cursor_roundtrip(store: Store) -> None:
    assert store.cursor("adguardhome") is None
    store.set_cursor("adguardhome", "2026-11-01T12:00:00+00:00")
    store.set_cursor("adguardhome", "2026-11-01T13:00:00+00:00")
    assert store.cursor("adguardhome") == "2026-11-01T13:00:00+00:00"


def test_transaction_rolls_back_on_error(store: Store) -> None:
    with pytest.raises(RuntimeError), store.transaction():
        store.save_device(Device(mac=MAC_A, first_seen=T0, last_seen=T0))
        raise RuntimeError("boom")
    assert store.device(MAC_A) is None


def test_file_database_persists_and_rejects_newer_schema(tmp_path: Path) -> None:
    path = tmp_path / "aluco.db"
    s = Store(path)
    s.save_device(Device(mac=MAC_A, first_seen=T0, last_seen=T0))
    s.close()

    s = Store(path)
    assert s.device(MAC_A) is not None
    s._db.execute("PRAGMA user_version = 99")
    s.close()
    with pytest.raises(RuntimeError, match="neuer"):
        Store(path)
