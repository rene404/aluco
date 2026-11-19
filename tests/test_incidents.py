from __future__ import annotations

from datetime import timedelta

import pytest

from aluco.incidents import IncidentService, TransitionError
from aluco.model import Device, Finding, IncidentStatus, Severity, TrustLevel
from aluco.store import Store
from tests.conftest import MAC_A, T0


def finding(severity: Severity = Severity.MEDIUM, key: str = "") -> Finding:
    return Finding(rule="test", severity=severity, title="Test", device_mac=MAC_A, key=key)


@pytest.fixture
def service(store: Store) -> IncidentService:
    return IncidentService(store)


def test_new_finding_creates_new_incident(service: IncidentService) -> None:
    inc = service.ingest(finding(), at=T0)
    assert inc.id is not None
    assert inc.status is IncidentStatus.NEW
    assert inc.occurrences == 1


def test_repeated_finding_is_deduplicated_and_escalates(service: IncidentService) -> None:
    first = service.ingest(finding(Severity.LOW), at=T0)
    second = service.ingest(finding(Severity.HIGH), at=T0 + timedelta(minutes=5))
    assert second.id == first.id
    assert second.occurrences == 2
    assert second.severity is Severity.HIGH
    assert second.updated_at == T0 + timedelta(minutes=5)


def test_ignored_stays_ignored_when_finding_recurs(service: IncidentService) -> None:
    inc = service.ingest(finding(), at=T0)
    assert inc.id is not None
    service.transition(inc.id, IncidentStatus.IGNORED, note="bekannt")
    again = service.ingest(finding(), at=T0 + timedelta(hours=1))
    assert again.status is IncidentStatus.IGNORED
    assert again.occurrences == 2
    assert again.note == "bekannt"


def test_resolved_reopens_when_finding_recurs(service: IncidentService) -> None:
    inc = service.ingest(finding(), at=T0)
    assert inc.id is not None
    service.transition(inc.id, IncidentStatus.RESOLVED)
    again = service.ingest(finding(), at=T0 + timedelta(days=1))
    assert again.status is IncidentStatus.NEW


def test_invalid_transition_is_rejected(service: IncidentService) -> None:
    inc = service.ingest(finding(), at=T0)
    assert inc.id is not None
    service.transition(inc.id, IncidentStatus.RESOLVED)
    with pytest.raises(TransitionError):
        service.transition(inc.id, IncidentStatus.DISCONNECTED)


def test_unknown_incident_raises(service: IncidentService) -> None:
    with pytest.raises(KeyError):
        service.transition(999, IncidentStatus.RESOLVED)


@pytest.mark.parametrize(
    ("trust", "protected"),
    [(TrustLevel.COMPANY, False), (TrustLevel.KNOWN, True)],
)
def test_disconnect_refused_for_protected_or_company_devices(
    store: Store, service: IncidentService, trust: TrustLevel, protected: bool
) -> None:
    store.save_device(
        Device(mac=MAC_A, first_seen=T0, last_seen=T0, trust=trust, protected=protected)
    )
    inc = service.ingest(finding(), at=T0)
    assert inc.id is not None
    with pytest.raises(TransitionError, match="geschützt"):
        service.transition(inc.id, IncidentStatus.DISCONNECTED)
    assert store.incident_by_id(inc.id).status is IncidentStatus.NEW  # type: ignore[union-attr]


def test_disconnect_allowed_for_normal_device(store: Store, service: IncidentService) -> None:
    store.save_device(Device(mac=MAC_A, first_seen=T0, last_seen=T0))
    inc = service.ingest(finding(), at=T0)
    assert inc.id is not None
    done = service.transition(inc.id, IncidentStatus.DISCONNECTED, note="unbekannt, getrennt")
    assert done.status is IncidentStatus.DISCONNECTED
    assert done.note == "unbekannt, getrennt"


def test_disconnect_refused_without_device(service: IncidentService) -> None:
    inc = service.ingest(Finding(rule="net", severity=Severity.HIGH, title="Port-Scan"), at=T0)
    assert inc.id is not None
    with pytest.raises(TransitionError, match="ohne Gerät"):
        service.transition(inc.id, IncidentStatus.DISCONNECTED)


def test_disconnect_refused_for_device_not_in_inventory(service: IncidentService) -> None:
    inc = service.ingest(finding(), at=T0)
    assert inc.id is not None
    with pytest.raises(TransitionError, match="nicht im Inventar"):
        service.transition(inc.id, IncidentStatus.DISCONNECTED)
