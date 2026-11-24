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

from aluco.ai import Assessment
from aluco.i18n import _
from aluco.model import (
    Device,
    Event,
    EventKind,
    Finding,
    HistoryEntry,
    HistoryKind,
    Incident,
    IncidentStatus,
    utcnow,
)

S = IncidentStatus
ALLOWED_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    S.NEW: frozenset({S.INVESTIGATING, S.IGNORED, S.DISCONNECTED, S.RESOLVED}),
    S.INVESTIGATING: frozenset({S.IGNORED, S.DISCONNECTED, S.RESOLVED}),
    S.IGNORED: frozenset({S.NEW}),  # Ignorieren zurücknehmen
    S.DISCONNECTED: frozenset({S.RESOLVED}),
    S.RESOLVED: frozenset({S.NEW}),
}


STATUS_TEXT = {
    S.NEW: "wieder geöffnet",
    S.INVESTIGATING: "in Prüfung",
    S.IGNORED: "ignoriert",
    S.DISCONNECTED: "getrennt",
    S.RESOLVED: "erledigt",
}


class TransitionError(ValueError):
    pass


class IncidentStore(Protocol):
    def incident_by_fingerprint(self, fingerprint: str) -> Incident | None: ...
    def incident_by_id(self, incident_id: int) -> Incident | None: ...
    def save_incident(self, incident: Incident) -> Incident: ...
    def device(self, mac: str) -> Device | None: ...
    def add_event(self, event: Event) -> None: ...
    def add_history(self, entry: HistoryEntry) -> None: ...
    def assessment(self, incident_id: int) -> Assessment | None: ...


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
            saved = self._store.save_incident(incident)
            self._log(saved, HistoryKind.OPENED, now)
            return saved

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
        saved = self._store.save_incident(updated)
        if existing.status is IncidentStatus.RESOLVED:
            self._log(saved, HistoryKind.REOPENED, now)
        return saved

    def transition(
        self,
        incident_id: int,
        new_status: IncidentStatus,
        note: str = "",
        at: datetime | None = None,
        manual: bool = True,
    ) -> Incident:
        """Status ändern. ``manual=False`` für automatische Wechsel (z. B. durch den Agent)."""
        incident = self._store.incident_by_id(incident_id)
        if incident is None:
            raise KeyError(incident_id)
        if new_status not in ALLOWED_TRANSITIONS[incident.status]:
            raise TransitionError(
                _("{old} → {new} ist nicht erlaubt", old=incident.status, new=new_status)
            )
        if new_status is IncidentStatus.DISCONNECTED:
            self._check_disconnect_allowed(incident)

        now = at or utcnow()
        updated = replace(incident, status=new_status, updated_at=now, note=note or incident.note)
        self._store.add_event(
            Event(
                id=None,
                at=now,
                kind=EventKind.INCIDENT_STATUS,
                title=_(
                    "Vorfall {status}: {title}",
                    status=_(STATUS_TEXT[new_status]),
                    title=incident.title,
                ),
                device_mac=incident.device_mac,
                detail=_("Notiz: {note}", note=note) if note else "",
                tag=new_status.value,
            )
        )
        saved = self._store.save_incident(updated)
        assessment = self._store.assessment(incident_id)
        self._log(
            saved,
            HistoryKind.STATUS,
            now,
            manual=manual,
            ai_verdict=assessment.verdict if assessment else None,
        )
        return saved

    def _log(
        self,
        incident: Incident,
        kind: HistoryKind,
        at: datetime,
        manual: bool = False,
        ai_verdict: str | None = None,
    ) -> None:
        if incident.id is None:
            return
        self._store.add_history(
            HistoryEntry(
                at=at,
                incident_id=incident.id,
                rule=incident.rule,
                kind=kind,
                status=incident.status,
                manual=manual,
                ai_verdict=ai_verdict,
            )
        )

    def _check_disconnect_allowed(self, incident: Incident) -> None:
        if incident.device_mac is None:
            raise TransitionError(_("Vorfall ohne Gerät kann nicht getrennt werden"))
        device = self._store.device(incident.device_mac)
        if device is None:
            raise TransitionError(_("Gerät nicht im Inventar – Trennen nicht möglich"))
        if not device.can_disconnect:
            raise TransitionError(
                _(
                    "{label} ist geschützt (Schutzliste oder Firmengerät) und wird nie getrennt",
                    label=device.label,
                )
            )
