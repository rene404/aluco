"""Geräte verwalten: Vertrauensstufe, Schutzliste, Name.

Wird ein Gerät als Firmengerät markiert, löscht Aluco alles, was es über dessen
DNS-Verhalten schon gespeichert hat – Firmengeräte werden nur passiv beobachtet.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from aluco.model import Device, EventKind, TrustLevel, normalize_mac
from aluco.store import Store

# Regeln, deren Vorfälle Inhalte über das Verhalten eines Geräts enthalten.
BEHAVIOUR_RULES = frozenset({"new_domain"})


class DeviceNotFoundError(LookupError):
    pass


@dataclass(frozen=True, slots=True)
class TrustChange:
    device: Device
    previous: TrustLevel
    domains_deleted: int = 0
    incidents_deleted: int = 0


def _get(store: Store, mac: str) -> Device:
    normalized = normalize_mac(mac)
    device = store.device(normalized)
    if device is None:
        raise DeviceNotFoundError(f"Gerät {normalized} ist nicht im Inventar")
    return device


def set_trust(store: Store, mac: str, trust: TrustLevel) -> TrustChange:
    with store.transaction():
        device = _get(store, mac)
        updated = store.save_device(replace(device, trust=trust))
        domains = incidents = 0
        if trust is TrustLevel.COMPANY:
            domains = store.delete_device_domains(device.mac)
            store.delete_device_assessments(device.mac)  # Bewertungen nennen Verhalten
            incidents = store.delete_incidents(device.mac, BEHAVIOUR_RULES)
            store.delete_device_stats(device.mac)
            store.delete_agent(device.mac)  # auf Firmengeräten läuft nie ein Agent
            # Vorfall-Ereignisse nennen z. B. angefragte Domains → ebenfalls entfernen.
            store.delete_device_events(
                device.mac, frozenset({EventKind.INCIDENT, EventKind.INCIDENT_STATUS})
            )
    return TrustChange(updated, device.trust, domains, incidents)


def set_protected(store: Store, mac: str, protected: bool) -> Device:
    with store.transaction():
        return store.save_device(replace(_get(store, mac), protected=protected))


def set_name(store: Store, mac: str, name: str | None) -> Device:
    with store.transaction():
        return store.save_device(replace(_get(store, mac), name=(name or "").strip() or None))


def set_notes(store: Store, mac: str, notes: str) -> Device:
    with store.transaction():
        return store.save_device(replace(_get(store, mac), notes=notes.strip()[:2000]))
