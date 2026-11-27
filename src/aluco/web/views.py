"""Aufbereitung für die Ansichten: Diagramme, relative Zeiten, Kürzel, Erklärungen.

Reine Funktionen ohne Datenbank- und Web-Abhängigkeit, damit sie einfach testbar sind.
Diagramme liefern Zahlen für SVG-Attribute (kein Inline-CSS – die CSP verbietet es).
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from aluco.agent import POSTURE_CHECKS
from aluco.ai import RULE_NAME
from aluco.i18n import _, ngettext
from aluco.i18n import fmt_int as fmt_int
from aluco.model import Device, Event, EventKind, Incident, Severity

WEEKDAYS_DE = ["Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"]  # Schlüssel, Anzeige über _()

RULE_NAME_DE = RULE_NAME


def duration(td: timedelta | None) -> str:
    """Kurze Dauer für Laien: '–', '12 Min.', '3 Std.', '2 Tage'."""
    if td is None:
        return "–"
    minutes = td.total_seconds() / 60
    if minutes < 1:
        return _("< 1 Min.")
    if minutes < 60:
        return _("{n} Min.", n=round(minutes))
    hours = minutes / 60
    if hours < 48:
        return _("{n} Std.", n=round(hours))
    return _("{n} Tage", n=round(hours / 24))


def relative(dt: datetime, now: datetime, tz: ZoneInfo) -> str:
    seconds = (now - dt).total_seconds()
    local, local_now = dt.astimezone(tz), now.astimezone(tz)
    if seconds < 60:
        return _("gerade eben")
    if seconds < 3600:
        return _("vor {n} Min.", n=int(seconds // 60))
    if local.date() == local_now.date():
        return _("vor {n} Std.", n=int(seconds // 3600))
    if local.date() == (local_now - timedelta(days=1)).date():
        return _("gestern {time}", time=f"{local:%H:%M}")
    return local.strftime(_("%d.%m. %H:%M"))


def abbreviation(device: Device) -> str:
    """Zwei Zeichen fürs Gerätesymbol: 'Laptop Wohnzimmer' → 'LW', 'Fernseher' → 'FE'."""
    label = device.name or device.hostname or ""
    words = re.findall(r"[A-Za-zÄÖÜäöüß]+", label)
    if not words:
        return "??"
    if len(words) >= 2:
        return (words[0][0] + words[1][0]).upper()
    return words[0][:2].upper()


# --- Diagramme --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Bar:
    x: float
    width: float
    y_allowed: float
    h_allowed: float
    y_blocked: float
    h_blocked: float
    tip: str


@dataclass(frozen=True, slots=True)
class Chart:
    bars: list[Bar]
    axis: list[str]
    total: int
    blocked: int
    peak_label: str
    height: int = 100
    width: int = 1000


def _bars(buckets: list[tuple[str, int, int]], height: int = 100, width: int = 1000) -> list[Bar]:
    """(Beschriftung, Anfragen, blockiert) → gestapelte Balken in Viewbox-Einheiten."""
    if not buckets:
        return []
    peak = max(t for _, t, _ in buckets) or 1
    slot = width / len(buckets)
    gap = slot * 0.18
    bars = []
    for i, (label, total, blocked) in enumerate(buckets):
        h_total = total / peak * height
        h_blocked = blocked / peak * height
        h_allowed = h_total - h_blocked
        bars.append(
            Bar(
                x=round(i * slot + gap / 2, 2),
                width=round(slot - gap, 2),
                y_allowed=round(height - h_allowed, 2),
                h_allowed=round(h_allowed, 2),
                y_blocked=round(height - h_total, 2),
                h_blocked=round(h_blocked, 2),
                tip=_(
                    "{label}: {total} Anfragen, {blocked} blockiert",
                    label=label,
                    total=fmt_int(total),
                    blocked=fmt_int(blocked),
                ),
            )
        )
    return bars


def hourly_chart(
    rows: list[tuple[datetime, int, int]], now: datetime, tz: ZoneInfo, hours: int = 24
) -> Chart:
    """Die letzten ``hours`` Stunden bis einschließlich der laufenden."""
    by_hour = {h: (t, b) for h, t, b in rows}
    end = now.replace(minute=0, second=0, microsecond=0)
    buckets = []
    for i in range(hours - 1, -1, -1):
        h = end - timedelta(hours=i)
        t, b = by_hour.get(h, (0, 0))
        buckets.append((f"{h.astimezone(tz):%H}:00", t, b))
    return _chart(buckets, axis_every=6)


def daily_chart(
    rows: list[tuple[datetime, int, int]], now: datetime, tz: ZoneInfo, days: int = 7
) -> Chart:
    """Die letzten ``days`` Kalendertage (lokale Zeit), heute eingeschlossen."""
    per_day: dict[object, list[int]] = defaultdict(lambda: [0, 0])
    for h, t, b in rows:
        d = h.astimezone(tz).date()
        per_day[d][0] += t
        per_day[d][1] += b
    today = now.astimezone(tz).date()
    buckets = []
    for i in range(days - 1, -1, -1):
        d = today - timedelta(days=i)
        t, b = per_day.get(d, [0, 0])
        name = _("heute") if i == 0 else _(WEEKDAYS_DE[d.weekday()])
        buckets.append((name, t, b))
    return _chart(buckets, axis_every=1)


def _chart(buckets: list[tuple[str, int, int]], axis_every: int) -> Chart:
    total = sum(t for _, t, _ in buckets)
    blocked = sum(b for _, _, b in buckets)
    peak = max(buckets, key=lambda x: x[1]) if buckets else ("", 0, 0)
    axis = [label for i, (label, _, _) in enumerate(buckets) if i % axis_every == 0]
    if axis_every > 1 and buckets:
        axis.append(buckets[-1][0])
    peak_label = _("{label} ({n} Anfragen)", label=peak[0], n=fmt_int(peak[1])) if peak[1] else ""
    return Chart(_bars(buckets), axis, total, blocked, peak_label)


def sparkline(per_hour: dict[datetime, int], now: datetime, hours: int = 24) -> list[float]:
    """Höhen 0–100 für die letzten ``hours`` Stunden (Mini-Verlauf auf Gerätekarten)."""
    end = now.replace(minute=0, second=0, microsecond=0)
    values = [per_hour.get(end - timedelta(hours=i), 0) for i in range(hours - 1, -1, -1)]
    peak = max(values) or 1
    return [round(v / peak * 100, 1) for v in values]


def active_hours(rows: list[tuple[datetime, int, int]], tz: ZoneInfo) -> str:
    """'aktiv 07–23 Uhr' aus Stunden mit nennenswerter Aktivität (≥ 10 % des Maximums)."""
    per_hour = [0] * 24
    for h, t, _blocked in rows:
        per_hour[h.astimezone(tz).hour] += t
    peak = max(per_hour)
    if not peak:
        return ""
    active = [h for h, v in enumerate(per_hour) if v >= peak * 0.1]
    quiet_night = all(per_hour[h] < peak * 0.1 for h in (1, 2, 3, 4))
    text = _("aktiv {start}–{end} Uhr", start=f"{active[0]:02d}", end=f"{active[-1] + 1:02d}")
    return text + " · " + (_("nachts ruhig") if quiet_night else _("auch nachts aktiv"))


# --- Lagebild und Chronik ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Situation:
    level: str  # ok | info | warn | alert
    title: str


def situation(open_incidents: list[Incident]) -> Situation:
    if not open_incidents:
        return Situation("ok", _("Alles ruhig – keine offenen Vorfälle"))
    worst = max(i.severity for i in open_incidents)
    n = len(open_incidents)
    level = {Severity.CRITICAL: "alert", Severity.HIGH: "warn"}.get(worst, "info")
    title = ngettext(
        "{n} Vorfall braucht deine Aufmerksamkeit", "{n} Vorfälle brauchen deine Aufmerksamkeit", n
    )
    return Situation(level, title)


EVENT_GROUPS: dict[str, frozenset[EventKind]] = {
    "incidents": frozenset({EventKind.INCIDENT, EventKind.INCIDENT_STATUS}),
    "devices": frozenset(
        {
            EventKind.DEVICE_NEW,
            EventKind.DEVICE_ONLINE,
            EventKind.DEVICE_OFFLINE,
            EventKind.INVENTORY,
        }
    ),
    "system": frozenset({EventKind.SOURCE}),
}


@dataclass(frozen=True, slots=True)
class EventRow:
    """Eine Zeile der Chronik: gleiche Ereignisse direkt hintereinander zusammengefasst."""

    event: Event  # das neueste
    count: int = 1
    first_at: datetime | None = None  # das älteste der Gruppe (nur bei count > 1)


def collapse_events(events: list[Event], limit: int) -> list[EventRow]:
    """Gleiche Ereignisse in Folge (Art, Gerät, Titel) zu einer Zeile mit ×n bündeln.

    ``events`` ist neueste zuerst. So verdrängt ein Gerät, das immer wieder an- und abgeht,
    nicht alles andere aus der Chronik.
    """
    rows: list[EventRow] = []
    for e in events:
        prev = rows[-1] if rows else None
        if prev and (prev.event.kind, prev.event.device_mac, prev.event.title) == (
            e.kind, e.device_mac, e.title,
        ):  # fmt: skip
            rows[-1] = EventRow(prev.event, prev.count + 1, e.at)
            continue
        if len(rows) == limit:
            break
        rows.append(EventRow(e))
    return rows


def event_tone(e: Event) -> str:
    """CSS-Ton für den Punkt in der Chronik."""
    if e.kind is EventKind.INCIDENT and e.severity is not None:
        return f"sev-{e.severity.name.lower()}"
    if e.kind is EventKind.DEVICE_ONLINE or e.tag in ("resolved", "released"):
        return "ok"
    if e.tag in ("source_down", "disk_low"):
        return "sev-medium"
    if e.kind is EventKind.INVENTORY:
        return "accent"
    return "muted"


def since_summary(events: list[Event]) -> str:
    """'1 neuer Vorfall · 3 Geräte offline' für den Hinweis seit dem letzten Besuch."""
    counts: dict[EventKind, int] = defaultdict(int)
    for e in events:
        counts[e.kind] += 1
    parts = []
    if n := counts[EventKind.INCIDENT]:
        parts.append(ngettext("{n} neuer Vorfall", "{n} neue Vorfälle", n))
    if n := counts[EventKind.DEVICE_OFFLINE]:
        parts.append(_("{n} × offline", n=n))
    if n := counts[EventKind.DEVICE_ONLINE]:
        parts.append(_("{n} × online", n=n))
    if n := counts[EventKind.SOURCE]:
        parts.append(ngettext("{n} Meldung zu Datenquellen", "{n} Meldungen zu Datenquellen", n))
    return " · ".join(parts)


# --- Erklärung zu Vorfällen --------------------------------------------------------


def explain(incident: Incident) -> list[str]:
    """Warum ist das auffällig? Aus Regel und Details, in Klartext."""
    d = incident.details
    facts: list[str] = []
    asked = d.get("query") if d.get("query") and d.get("query") != d.get("domain") else None
    if incident.rule == "new_device":
        facts.append(_("MAC-Adresse war bisher nicht im Inventar"))
        if d.get("randomized_mac") == "true":
            facts.append(_("Private (zufällige) MAC-Adresse – typisch für Handys und Gastgeräte"))
        facts.append(
            _("Hersteller: {vendor}", vendor=d["vendor"])
            if d.get("vendor")
            else _("Hersteller unbekannt")
        )
        if d.get("hostname"):
            facts.append(_("Hostname: {name}", name=d["hostname"]))
        if d.get("ip"):
            facts.append(_("IP-Adresse: {ip}", ip=d["ip"]))
    elif incident.rule == "new_domain":
        facts.append(
            _("Domain {domain} von diesem Gerät noch nie angefragt", domain=d.get("domain", "?"))
        )
        facts.append(
            _("IoT-Gerät: verhält sich normalerweise vorhersehbar, Lernphase abgeschlossen")
        )
        if asked:
            facts.append(_("Angefragt: {query}", query=asked))
    elif incident.rule == "bad_domain":
        facts.append(
            _(
                "{domain} steht auf der Bedrohungsliste „{list}“",
                domain=d.get("domain", "?"),
                list=d.get("list", "?"),
            )
        )
        if asked:
            facts.append(_("Angefragt: {query}", query=asked))
        facts.append(
            _(
                "AdGuard hat die Anfrage blockiert – der Versuch deutet trotzdem auf "
                "Schadsoftware oder einen Phishing-Link hin"
            )
            if d.get("blocked") == "true"
            else _("Die Anfrage wurde NICHT blockiert – Domain in AdGuard sperren")
        )
    elif incident.rule == "newly_registered_domain":
        facts.append(
            _("{domain} wurde in den letzten 14 Tagen registriert", domain=d.get("domain", "?"))
        )
        if asked:
            facts.append(_("Angefragt: {query}", query=asked))
        facts.append(
            _(
                "Neue Domains nutzen Betrüger gern für Phishing und Schadsoftware – viele sind "
                "aber harmlos. Kennst du die Seite nicht, Domain in AdGuard sperren."
            )
            if d.get("blocked") != "true"
            else _("AdGuard hat die Anfrage bereits blockiert")
        )
    elif incident.rule == "agent_port":
        facts.append(
            _(
                "{program} nimmt Verbindungen auf Port {port}/{protocol} an – das war vorher "
                "nicht so",
                program=d.get("program", "?"),
                port=d.get("port"),
                protocol=d.get("protocol"),
            )
        )
        facts.append(_("Programm: {path}", path=d.get("path") or d.get("program")))
        facts.append(_("Prüfen, ob du das Programm kennst und der Port nötig ist"))
    elif incident.rule == "agent_autostart":
        facts.append(
            _(
                "Neuer Eintrag startet automatisch: {entry}",
                entry=d.get("label") or d.get("path"),
            )
        )
        if d.get("program"):
            facts.append(_("Programm: {path}", path=d["program"]))
        facts.append(_("Autostart ist ein typischer Weg, wie sich Schadsoftware festsetzt"))
    elif incident.rule == "agent_login":
        facts.append(
            _(
                "Anmeldung von {host} als {user}",
                host=d.get("host") or _("unbekannt"),
                user=d.get("user"),
            )
        )
        facts.append(_("Fern-Anmeldungen (z. B. SSH) sind auf privaten Laptops selten"))
    elif incident.rule == "agent_posture":
        check = POSTURE_CHECKS.get(d.get("check", ""))
        facts.append(
            _(check[2])
            if check
            else d.get("text") or _("Eine Sicherheitsgrundlage ist ausgeschaltet.")
        )
        facts.append(_("Wird automatisch erledigt, sobald der Agent sie wieder als an meldet"))
    else:
        facts += [f"{k}: {v}" for k, v in sorted(d.items())]
    if incident.occurrences > 1:
        facts.append(_("{n}× aufgetreten", n=incident.occurrences))
    return facts
