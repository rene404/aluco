"""Ablauf für Vorfälle: Befund → Vorfall → bewerten → handeln.

- Gleiche Befunde (gleicher Fingerabdruck) erzeugen keinen neuen Vorfall, sondern
  zählen beim bestehenden hoch.
- "Ignorieren" ist dauerhaft: ein ignorierter Befund meldet sich nicht wieder.
- Ein erledigter Vorfall wird wieder geöffnet, wenn der Befund erneut auftritt.
- "Getrennt" ist nur für Geräte erlaubt, die getrennt werden dürfen (Schutzliste,
  Firmengeräte).
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Protocol

from aluco.model import Device, Finding, Incident, IncidentStatus, utcnow

S = IncidentStatus
ALLOWED_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    S.NEW: frozenset({S.INVESTIGATING, S.IGNORED, S.DISCONNECTED, S.RESOLVED}),
    S.INVESTIGATING: frozenset({S.IGNORED, S.DISCONNECTED, S.RESOLVED}),
    S.IGNORED: frozenset({S.NEW}),  # Ignorieren zurücknehmen
    S.DISCONNECTED: frozenset({S.RESOLVED}),
    S.RESOLVED: frozenset({S.NEW}),
}


class TransitionError(ValueError):
    pass


class IncidentStore(Protocol):
    def incident_by_fingerprint(self, fingerprint: str) -> Incident | None: ...
    def incident_by_id(self, incident_id: int) -> Incident | None: ...
    def save_incident(self, incident: Incident) -> Incident: ...
    def device(self, mac: str) -> Device | None: ...


class IncidentService:
    def __init__(self, store: IncidentStore) -> None:
        self._store = store

    def ingest(self, finding: Finding, at: datetime | None = None) -> Incident:
        """Befund aufnehmen; liefert den neuen oder aktualisierten Vorfall."""
        now = at or utcnow()
        existing = self._store.incident_by_fingerprint(finding.fingerprint)

        if existing is None:
            incident = Incident(
                id=None,
                fingerprint=finding.fingerprint,
                rule=finding.rule,
                severity=finding.severity,
                title=finding.title,
                status=IncidentStatus.NEW,
                created_at=now,
                updated_at=now,
                device_mac=finding.device_mac,
                details=dict(finding.details),
            )
            return self._store.save_incident(incident)

        status = existing.status
        if status is IncidentStatus.RESOLVED:
            status = IncidentStatus.NEW  # erneut aufgetreten
        updated = replace(
            existing,
            status=status,
            severity=max(existing.severity, finding.severity),
            occurrences=existing.occurrences + 1,
            updated_at=now,
            details={**existing.details, **finding.details},
        )
        return self._store.save_incident(updated)

    def transition(
        self,
        incident_id: int,
        new_status: IncidentStatus,
        note: str = "",
        at: datetime | None = None,
    ) -> Incident:
        incident = self._store.incident_by_id(incident_id)
        if incident is None:
            raise KeyError(incident_id)
        if new_status not in ALLOWED_TRANSITIONS[incident.status]:
            raise TransitionError(f"{incident.status} → {new_status} ist nicht erlaubt")
        if new_status is IncidentStatus.DISCONNECTED:
            self._check_disconnect_allowed(incident)

        updated = replace(
            incident,
            status=new_status,
            updated_at=at or utcnow(),
            note=note or incident.note,
        )
        return self._store.save_incident(updated)

    def _check_disconnect_allowed(self, incident: Incident) -> None:
        if incident.device_mac is None:
            raise TransitionError("Vorfall ohne Gerät kann nicht getrennt werden")
        device = self._store.device(incident.device_mac)
        if device is None:
            raise TransitionError("Gerät nicht im Inventar – Trennen nicht möglich")
        if not device.can_disconnect:
            raise TransitionError(
                f"{device.label} ist geschützt (Schutzliste oder Firmengerät) und wird nie getrennt"
            )
