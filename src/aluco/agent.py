"""Laptop-Agent (osquery): Berichte prüfen, mit Bekanntem vergleichen, Vorfälle ableiten.

Der Agent (``agent/aluco-agent.sh``) schickt alle paar Minuten die Ergebnisse fester,
nur lesender osquery-Abfragen. Aluco merkt sich offene Ports, Autostart-Einträge und
Anmeldungen pro Gerät; Neues nach dem ersten Bericht wird ein Vorfall. Dazu werden die
Sicherheitsgrundlagen geprüft (Firewall, FileVault, Gatekeeper, SIP).

Nur für private Geräte: Firmengeräte können keinen Agenten haben.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import secrets
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

from aluco.i18n import _
from aluco.incidents import IncidentService
from aluco.model import (
    Device,
    Event,
    EventKind,
    Finding,
    IncidentStatus,
    Severity,
    clean_text,
    normalize_mac,
    utcnow,
)

AGENT_SECTIONS = (
    "system", "os", "listening_ports", "autostart", "logged_in_users",
    "firewall", "filevault", "gatekeeper", "sip",
)  # fmt: skip
MAX_ROWS = 500  # pro Abschnitt
MAX_VALUE = 500  # Zeichen pro Wert
PROTOCOLS = {"6": "tcp", "17": "udp"}
DYNAMIC_PORTS = 49152  # IANA: ab hier vergibt das System Ports zufällig

POSTURE_CHECKS: dict[str, tuple[str, Severity, str]] = {
    # Schlüssel: (Anzeigename, Schwere wenn aus, Erklärung)
    "firewall": ("Firewall", Severity.MEDIUM, "Die macOS-Firewall ist ausgeschaltet."),
    "filevault": ("FileVault", Severity.HIGH, "Die Festplatte ist nicht verschlüsselt."),
    "gatekeeper": ("Gatekeeper", Severity.HIGH, "Gatekeeper prüft Programme nicht mehr."),
    "sip": ("Systemintegritätsschutz", Severity.HIGH, "SIP ist ausgeschaltet."),
}


class AgentError(ValueError):
    """Bericht ungültig (Format, Größe)."""


def new_token() -> tuple[str, str]:
    """(Token für den Agenten, Hash für die Datenbank). Das Token wird nie gespeichert."""
    token = secrets.token_urlsafe(32)
    return token, hash_token(token)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# --- Bericht prüfen ---------------------------------------------------------------


def validate_report(raw: Any) -> dict[str, list[dict[str, str]]]:
    """Nur bekannte Abschnitte; Listen von Zeilen mit kurzen, bereinigten Textwerten."""
    if not isinstance(raw, dict):
        raise AgentError("Bericht muss ein JSON-Objekt sein")
    out: dict[str, list[dict[str, str]]] = {}
    for section in AGENT_SECTIONS:
        rows = raw.get(section, [])
        if not isinstance(rows, list):
            raise AgentError(f"Abschnitt {section} muss eine Liste sein")
        if len(rows) > MAX_ROWS:
            raise AgentError(f"Abschnitt {section}: mehr als {MAX_ROWS} Zeilen")
        clean_rows = []
        for row in rows:
            if not isinstance(row, dict):
                raise AgentError(f"Abschnitt {section}: Zeilen müssen Objekte sein")
            clean_rows.append(
                {
                    str(k)[:64]: clean_text(str(v), MAX_VALUE) or ""
                    for k, v in row.items()
                    if v is not None and isinstance(v, str | int | float | bool)
                }
            )
        out[section] = clean_rows
    return out


# --- Auswerten --------------------------------------------------------------------


def _is_loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address.split("%")[0]).is_loopback
    except ValueError:
        return False


def _short(path: str) -> str:
    """Programmpfad kürzen, Benutzernamen entfernen: /Users/anna/x → ~/x."""
    return re.sub(r"^/Users/[^/]+", "~", path)


def ports(report: dict[str, list[dict[str, str]]]) -> dict[str, dict[str, str]]:
    out = {}
    for r in report["listening_ports"]:
        if not r.get("port") or r.get("port") == "0" or _is_loopback(r.get("address", "")):
            continue
        proto = PROTOCOLS.get(r.get("protocol", ""), r.get("protocol", "?"))
        program = r.get("name") or _short(r.get("path", "")) or "unbekannt"
        port = r["port"]
        if port.isdigit() and int(port) >= DYNAMIC_PORTS:
            # Zufällige Ports (Browser, AirPlay …) pro Programm zusammenfassen – sonst wäre
            # jeder neue Zufallsport ein Fehlalarm.
            port = "dynamisch"
        out[f"{port}/{proto} {program}"] = {
            "port": port,
            "protocol": proto,
            "program": program,
            "path": _short(r.get("path", "")),
            "address": r.get("address", ""),
        }
    return out


def autostart(report: dict[str, list[dict[str, str]]]) -> dict[str, dict[str, str]]:
    out = {}
    for r in report["autostart"]:
        path = r.get("path", "")
        if path.startswith("/System/"):
            continue  # Teil von macOS
        key = r.get("label") or _short(path)
        if not key:
            continue
        out[key] = {
            "label": r.get("label", ""),
            "path": _short(path),
            "program": _short(r.get("program") or r.get("program_arguments", "").split(" ")[0]),
        }
    return out


def logins(report: dict[str, list[dict[str, str]]]) -> dict[str, dict[str, str]]:
    out = {}
    for r in report["logged_in_users"]:
        user = r.get("user", "")
        if not user or r.get("type") not in {"user", "login", ""}:
            continue
        host = r.get("host", "")
        remote = bool(host) and host not in {"localhost", "console"} and not _is_loopback(host)
        out[f"{user}@{host or 'lokal'}"] = {
            "user": user,
            "host": host,
            "remote": "true" if remote else "false",
        }
    return out


def posture(report: dict[str, list[dict[str, str]]]) -> dict[str, bool | None]:
    """True = an, False = aus, None = unbekannt (Tabelle fehlt auf diesem System)."""

    def flag(section: str, column: str) -> bool | None:
        rows = report[section]
        if not rows:
            return None
        values = [r.get(column, "") for r in rows]
        return any(v not in {"", "0"} for v in values)

    return {
        "firewall": flag("firewall", "global_state"),
        "filevault": flag("filevault", "encrypted"),
        "gatekeeper": flag("gatekeeper", "assessments_enabled"),
        "sip": flag("sip", "enabled"),
    }


@dataclass
class ReportResult:
    device: Device
    learn_only: bool
    new_items: list[str] = field(default_factory=list)
    incidents: int = 0
    posture: dict[str, bool | None] = field(default_factory=dict)


def process_report(
    store: Any, agent_mac: str, raw: Any, now: datetime | None = None
) -> ReportResult:
    """Bericht übernehmen – in einer Transaktion. Erster Bericht = nur lernen."""
    now = now or utcnow()
    report = validate_report(raw)
    mac = normalize_mac(agent_mac)
    service = IncidentService(store)
    with store.transaction():
        device = store.device(mac)
        if device is None or device.is_company:
            raise AgentError("Gerät unbekannt oder Firmengerät – Agent nicht zulässig")
        agent = store.agent(mac)
        learn_only = agent is None or agent["last_report_at"] is None
        result = ReportResult(device=device, learn_only=learn_only)

        groups = [
            ("port", ports(report), Severity.MEDIUM, _("Neuer offener Port")),
            ("autostart", autostart(report), Severity.MEDIUM, _("Neuer Autostart-Eintrag")),
            ("login", logins(report), Severity.MEDIUM, _("Neue Anmeldung")),
        ]
        for kind, items, severity, label in groups:
            for key, data in items.items():
                is_new = store.upsert_host_item(mac, kind, key, data, now)
                if not is_new or learn_only:
                    continue
                if kind == "login" and data["remote"] != "true":
                    continue  # lokale Anmeldungen sind normal
                result.new_items.append(f"{label}: {key}")
                finding = Finding(
                    rule=f"agent_{kind}",
                    severity=severity,
                    title=f"{device.label}: {label} – {key}",
                    device_mac=mac,
                    key=key,
                    details={"kind": kind, "item": key, **data},
                )
                _ingest(store, service, finding, now, result)

        state = posture(report)
        result.posture = state
        for check, on in state.items():
            name, severity, text = POSTURE_CHECKS[check]
            finding = Finding(
                rule="agent_posture",
                severity=severity,
                title=_("{label}: {name} ist aus", label=device.label, name=_(name)),
                device_mac=mac,
                key=check,
                details={"check": check, "name": name, "text": text},
            )
            if on is False:
                _ingest(store, service, finding, now, result)
            elif on is True:
                _auto_resolve(store, service, finding, now)

        system = report["system"][0] if report["system"] else {}
        os_row = report["os"][0] if report["os"] else {}
        os_text = " ".join(filter(None, [os_row.get("name"), os_row.get("version")])) or None
        store.update_agent_report(mac, now, system.get("hostname"), os_text, state)
        store.save_device(replace(device, last_seen=max(device.last_seen, now), online=True))
    return result


def _ingest(
    store: Any, service: IncidentService, finding: Finding, now: datetime, result: ReportResult
) -> None:
    before = store.incident_by_fingerprint(finding.fingerprint)
    incident = service.ingest(finding, at=now)
    if before is None or before.status is IncidentStatus.RESOLVED:
        result.incidents += 1
        store.add_event(
            Event(
                id=None,
                at=now,
                kind=EventKind.INCIDENT,
                title=incident.title,
                device_mac=incident.device_mac,
                detail="Laptop-Agent",
                severity=incident.severity,
            )
        )


def _auto_resolve(store: Any, service: IncidentService, finding: Finding, now: datetime) -> None:
    """Sicherheitsgrundlage wieder an → offenen Vorfall automatisch erledigen."""
    incident = store.incident_by_fingerprint(finding.fingerprint)
    if incident is not None and incident.is_open and incident.id is not None:
        service.transition(
            incident.id,
            IncidentStatus.RESOLVED,
            note="Laut Agent wieder eingeschaltet",
            at=now,
            manual=False,
        )
