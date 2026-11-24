"""Trennen und Freigeben über die Firewall – immer von Hand, mit Schutzliste.

Grundsätze (docs/architecture.md): Trennen nur auf Knopfdruck mit Bestätigung; Geräte auf
der Schutzliste und Firmengeräte werden nie getrennt; Firewall bleibt Quelle der Wahrheit.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from aluco.i18n import _
from aluco.incidents import ALLOWED_TRANSITIONS, IncidentService, TransitionError
from aluco.model import Event, EventKind, IncidentStatus, utcnow


class Blocker(Protocol):
    def block(self, ip: str) -> None: ...
    def unblock(self, ip: str) -> None: ...
    def blocked(self) -> set[str]: ...


class QuarantineError(RuntimeError):
    pass


def disconnect(
    store: Any, blocker: Blocker, incident_id: int, note: str = "", now: datetime | None = None
) -> Any:
    """Gerät eines Vorfalls trennen: Firewall zuerst, dann Status – nie umgekehrt."""
    now = now or utcnow()
    incident = store.incident_by_id(incident_id)
    if incident is None:
        raise KeyError(incident_id)
    if IncidentStatus.DISCONNECTED not in ALLOWED_TRANSITIONS[incident.status]:
        raise TransitionError(f"{incident.status} → getrennt ist nicht erlaubt")
    device = store.device(incident.device_mac) if incident.device_mac else None
    if device is None:
        raise TransitionError(_("Gerät nicht im Inventar – Trennen nicht möglich"))
    if not device.can_disconnect:
        raise TransitionError(f"{device.label} ist geschützt (Schutzliste oder Firmengerät)")
    if not device.ip:
        raise QuarantineError(f"{device.label} hat keine bekannte IP-Adresse")
    blocker.block(device.ip)  # wirft AdapterError → nichts wird als getrennt markiert
    with store.transaction():
        updated = IncidentService(store).transition(
            incident_id, IncidentStatus.DISCONNECTED, note=note, at=now
        )
        store.save_block(device.mac, device.ip, now, incident_id)
        store.add_event(
            Event(
                id=None,
                at=now,
                kind=EventKind.INCIDENT_STATUS,
                title=_("{label} über die Firewall getrennt", label=device.label),
                device_mac=device.mac,
                detail=_("IP {ip} im Quarantäne-Alias", ip=device.ip),
                tag="disconnected",
            )
        )
    return updated


def release(store: Any, blocker: Blocker, mac: str, now: datetime | None = None) -> None:
    """Freigeben: Firewall-Eintrag entfernen, dann Vermerk löschen."""
    now = now or utcnow()
    block = store.block(mac)
    if block is None:
        raise QuarantineError(_("Gerät ist nicht getrennt"))
    blocker.unblock(str(block["ip"]))
    device = store.device(mac)
    with store.transaction():
        store.delete_block(mac)
        store.add_event(
            Event(
                id=None,
                at=now,
                kind=EventKind.INCIDENT_STATUS,
                title=_("{label} wieder freigegeben", label=device.label if device else mac),
                device_mac=mac,
                tag="released",
            )
        )


def resync(store: Any, blocker: Blocker) -> list[str]:
    """Getrennte Geräte mit neuer IP (DHCP) auch unter der neuen IP sperren."""
    changes = []
    for mac, block in store.blocks().items():
        device = store.device(mac)
        if device is None or not device.ip or device.ip == block["ip"]:
            continue
        blocker.block(device.ip)
        blocker.unblock(str(block["ip"]))
        with store.transaction():
            store.save_block(mac, device.ip, utcnow(), block["incident_id"])  # type: ignore[arg-type]
        changes.append(f"{device.label}: {block['ip']} → {device.ip}")
    return changes
