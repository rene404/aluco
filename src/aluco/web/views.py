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

from aluco.model import Device, Event, EventKind, Incident, Severity

WEEKDAYS_DE = ["Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"]


def fmt_int(n: int) -> str:
    """1234567 → '1.234.567'."""
    return f"{n:,}".replace(",", ".")


def relative(dt: datetime, now: datetime, tz: ZoneInfo) -> str:
    seconds = (now - dt).total_seconds()
    local, local_now = dt.astimezone(tz), now.astimezone(tz)
    if seconds < 60:
        return "gerade eben"
    if seconds < 3600:
        return f"vor {int(seconds // 60)} Min."
    if local.date() == local_now.date():
        return f"vor {int(seconds // 3600)} Std."
    if local.date() == (local_now - timedelta(days=1)).date():
        return f"gestern {local:%H:%M}"
    return f"{local:%d.%m.} {local:%H:%M}"


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
                tip=f"{label}: {fmt_int(total)} Anfragen, {fmt_int(blocked)} blockiert",
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
        name = "heute" if i == 0 else WEEKDAYS_DE[d.weekday()]
        buckets.append((name, t, b))
    return _chart(buckets, axis_every=1)


def _chart(buckets: list[tuple[str, int, int]], axis_every: int) -> Chart:
    total = sum(t for _, t, _ in buckets)
    blocked = sum(b for _, _, b in buckets)
    peak = max(buckets, key=lambda x: x[1]) if buckets else ("", 0, 0)
    axis = [label for i, (label, _, _) in enumerate(buckets) if i % axis_every == 0]
    if axis_every > 1 and buckets:
        axis.append(buckets[-1][0])
    peak_label = f"{peak[0]} ({fmt_int(peak[1])} Anfragen)" if peak[1] else ""
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
    for h, t, _ in rows:
        per_hour[h.astimezone(tz).hour] += t
    peak = max(per_hour)
    if not peak:
        return ""
    active = [h for h, v in enumerate(per_hour) if v >= peak * 0.1]
    quiet_night = all(per_hour[h] < peak * 0.1 for h in (1, 2, 3, 4))
    text = f"aktiv {active[0]:02d}–{active[-1] + 1:02d} Uhr"
    return text + (" · nachts ruhig" if quiet_night else " · auch nachts aktiv")


# --- Lagebild und Chronik ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Situation:
    level: str  # ok | info | warn | alert
    title: str


def situation(open_incidents: list[Incident]) -> Situation:
    if not open_incidents:
        return Situation("ok", "Alles ruhig – keine offenen Vorfälle")
    worst = max(i.severity for i in open_incidents)
    n = len(open_incidents)
    noun = "Vorfall braucht" if n == 1 else "Vorfälle brauchen"
    level = {Severity.CRITICAL: "alert", Severity.HIGH: "warn"}.get(worst, "info")
    return Situation(level, f"{n} {noun} deine Aufmerksamkeit")


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


def event_tone(e: Event) -> str:
    """CSS-Ton für den Punkt in der Chronik."""
    if e.kind is EventKind.INCIDENT and e.severity is not None:
        return f"sev-{e.severity.name.lower()}"
    if e.kind is EventKind.DEVICE_ONLINE or (
        e.kind is EventKind.INCIDENT_STATUS and "erledigt" in e.title
    ):
        return "ok"
    if e.kind is EventKind.SOURCE and "nicht erreichbar" in e.title:
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
        parts.append(f"{n} {'neuer Vorfall' if n == 1 else 'neue Vorfälle'}")
    if n := counts[EventKind.DEVICE_OFFLINE]:
        parts.append(f"{n} × offline")
    if n := counts[EventKind.DEVICE_ONLINE]:
        parts.append(f"{n} × online")
    if n := counts[EventKind.SOURCE]:
        parts.append(f"{n} Meldung{'en' if n > 1 else ''} zu Datenquellen")
    return " · ".join(parts)


# --- Erklärung zu Vorfällen --------------------------------------------------------


def explain(incident: Incident) -> list[str]:
    """Warum ist das auffällig? Aus Regel und Details, in Klartext."""
    d = incident.details
    facts: list[str] = []
    if incident.rule == "new_device":
        facts.append("MAC-Adresse war bisher nicht im Inventar")
        if d.get("randomized_mac") == "true":
            facts.append("Private (zufällige) MAC-Adresse – typisch für Handys und Gastgeräte")
        facts.append(f"Hersteller: {d['vendor']}" if d.get("vendor") else "Hersteller unbekannt")
        if d.get("hostname"):
            facts.append(f"Hostname: {d['hostname']}")
        if d.get("ip"):
            facts.append(f"IP-Adresse: {d['ip']}")
    elif incident.rule == "new_domain":
        facts.append(f"Domain {d.get('domain', '?')} von diesem Gerät noch nie angefragt")
        facts.append("IoT-Gerät: verhält sich normalerweise vorhersehbar, Lernphase abgeschlossen")
        if d.get("query") and d.get("query") != d.get("domain"):
            facts.append(f"Angefragt: {d['query']}")
    else:
        facts += [f"{k}: {v}" for k, v in sorted(d.items())]
    if incident.occurrences > 1:
        facts.append(f"{incident.occurrences}× aufgetreten")
    return facts
