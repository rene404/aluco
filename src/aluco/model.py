"""Datenmodell von Aluco: Geräte, Beobachtungen, Vorfälle.

Bewusst ohne Abhängigkeiten (nur Standardbibliothek), damit der Kern unabhängig
von Web-Framework, Datenbank und Datenquellen bleibt.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import IntEnum, StrEnum

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# Namen, die nur im Heimnetz existieren (Reverse-DNS, mDNS, Router-Domains). Sie verraten
# IP-Adressen oder Gerätenamen und werden nie als "Domain" ausgewertet oder weitergegeben.
LOCAL_SUFFIXES = (
    ".arpa", ".local", ".lan", ".home", ".internal", ".localdomain", ".intranet",
    ".corp", ".private", ".fritz.box", ".box", ".localhost",
)  # fmt: skip


def clean_text(value: str | None, max_len: int = 200) -> str | None:
    """Steuerzeichen (z. B. Terminal-Escapes aus präparierten Hostnamen) entfernen, kürzen."""
    if value is None:
        return None
    cleaned = _CONTROL_RE.sub("", value).strip()[:max_len]
    return cleaned or None


def is_local_name(domain: str) -> bool:
    d = domain.rstrip(".").lower()
    return "." not in d or any(d.endswith(sfx) or d == sfx[1:] for sfx in LOCAL_SUFFIXES)


def utcnow() -> datetime:
    return datetime.now(UTC)


def normalize_mac(mac: str) -> str:
    """MAC-Adresse in einheitliche Form bringen: ``aa:bb:cc:dd:ee:ff``."""
    hexdigits = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(hexdigits) != 12:
        raise ValueError(f"Ungültige MAC-Adresse: {mac!r}")
    return ":".join(hexdigits[i : i + 2] for i in range(0, 12, 2))


def is_randomized_mac(mac: str) -> bool:
    """Lokal verwaltete MAC (z. B. private WLAN-Adresse von Handys)."""
    return bool(int(normalize_mac(mac)[:2], 16) & 0b10)


class TrustLevel(StrEnum):
    """Vertrauensstufe eines Geräts."""

    KNOWN = "known"  # eigenes, bekanntes Gerät
    IOT = "iot"  # Fernseher, Kamera, Steckdose …
    GUEST = "guest"
    UNKNOWN = "unknown"  # noch nicht eingeordnet
    COMPANY = "company"  # Firmengerät: nur passiv beobachten


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class IncidentStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    IGNORED = "ignored"
    DISCONNECTED = "disconnected"
    RESOLVED = "resolved"


OPEN_STATUSES = frozenset({IncidentStatus.NEW, IncidentStatus.INVESTIGATING})


class HistoryKind(StrEnum):
    OPENED = "opened"  # neuer Vorfall
    REOPENED = "reopened"  # erledigter Befund trat erneut auf
    STATUS = "status"  # Status geändert (von Hand oder automatisch)


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    """Ein Schritt im Leben eines Vorfalls – ohne Gerät, Domain oder Titel (#28)."""

    at: datetime
    incident_id: int
    rule: str
    kind: HistoryKind
    status: IncidentStatus
    manual: bool = False
    ai_verdict: str | None = None  # KI-Einstufung zum Zeitpunkt der Entscheidung


@dataclass(frozen=True, slots=True)
class Device:
    mac: str
    first_seen: datetime
    last_seen: datetime
    ip: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    name: str | None = None  # vom Menschen vergeben
    trust: TrustLevel = TrustLevel.UNKNOWN
    protected: bool = False  # Schutzliste: nie trennbar (Infrastruktur, markierte Geräte)
    online: bool | None = None  # None = unbekannt (Quelle liefert keinen Status)
    notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "mac", normalize_mac(self.mac))

    @property
    def label(self) -> str:
        return self.name or self.hostname or self.ip or self.mac

    @property
    def is_company(self) -> bool:
        return self.trust is TrustLevel.COMPANY

    @property
    def can_disconnect(self) -> bool:
        """Firmengeräte und Geräte auf der Schutzliste werden nie getrennt."""
        return not (self.protected or self.is_company)

    def seen(self, at: datetime, ip: str | None = None, hostname: str | None = None) -> Device:
        return replace(
            self,
            last_seen=max(self.last_seen, at),
            ip=ip or self.ip,
            hostname=hostname or self.hostname,
        )


# --- Beobachtungen: normalisierte Daten aus den Adaptern -----------------------------


@dataclass(frozen=True, slots=True)
class DeviceSighting:
    """Ein Gerät wurde im Netz gesehen (z. B. von NetAlertX)."""

    mac: str
    at: datetime
    ip: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    online: bool | None = None
    source: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "mac", normalize_mac(self.mac))
        object.__setattr__(self, "hostname", clean_text(self.hostname))
        object.__setattr__(self, "vendor", clean_text(self.vendor))
        object.__setattr__(self, "ip", clean_text(self.ip, 64))


@dataclass(frozen=True, slots=True)
class DnsQuery:
    """Eine DNS-Anfrage (z. B. aus dem AdGuard-Protokoll)."""

    client_ip: str
    domain: str
    at: datetime
    qtype: str = "A"
    blocked: bool = False
    source: str = ""

    def __post_init__(self) -> None:
        domain = clean_text(self.domain, 253) or ""
        object.__setattr__(self, "domain", domain.rstrip(".").lower())


# --- Vorfälle -----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Finding:
    """Ergebnis einer Regel, bevor daraus ein Vorfall wird.

    ``key`` unterscheidet gleichartige Befunde (z. B. die Domain); gleiche Regel +
    Gerät + key ergibt denselben Fingerabdruck und damit keinen doppelten Vorfall.
    """

    rule: str
    severity: Severity
    title: str
    device_mac: str | None = None
    key: str = ""
    details: dict[str, str] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        raw = "\x1f".join((self.rule, self.device_mac or "", self.key))
        return hashlib.sha256(raw.encode()).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class Incident:
    id: int | None
    fingerprint: str
    rule: str
    severity: Severity
    title: str
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime
    device_mac: str | None = None
    details: dict[str, str] = field(default_factory=dict)
    occurrences: int = 1
    note: str = ""

    @property
    def is_open(self) -> bool:
        return self.status in OPEN_STATUSES


# --- Chronik ------------------------------------------------------------------------


class EventKind(StrEnum):
    DEVICE_NEW = "device_new"
    DEVICE_ONLINE = "device_online"
    DEVICE_OFFLINE = "device_offline"
    INVENTORY = "inventory"  # erster Lauf: Inventar übernommen
    INCIDENT = "incident"  # neuer oder wieder geöffneter Vorfall
    INCIDENT_STATUS = "incident_status"  # Status von Hand geändert
    SOURCE = "source"  # Datenquelle ausgefallen / wieder da


@dataclass(frozen=True, slots=True)
class Event:
    id: int | None
    at: datetime
    kind: EventKind
    title: str
    device_mac: str | None = None
    detail: str = ""
    severity: Severity | None = None
