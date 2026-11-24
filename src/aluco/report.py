"""Wochenbericht (#27): ein ruhiges „alles in Ordnung“ – oder was diese Woche los war.

Der Bericht enthält nur **Zahlen**, keine Gerätenamen, IPs oder Domains. Er darf darum
auch über einen externen ntfy-Server gehen (wie ``ALUCO_NOTIFY_MINIMAL``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from aluco.i18n import _, fmt_dec, fmt_int, ngettext
from aluco.model import OPEN_STATUSES, EventKind, HistoryKind, IncidentStatus, Severity
from aluco.store import Store

WEEK = timedelta(days=7)
WEEKDAYS = ("mo", "di", "mi", "do", "fr", "sa", "so")
_WEEKDAYS_EN = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_SEVERITY_DE = {
    Severity.CRITICAL: "kritisch",
    Severity.HIGH: "hoch",
    Severity.MEDIUM: "mittel",
    Severity.LOW: "niedrig",
    Severity.INFO: "Info",
}
REPORT_CURSOR = "report:last_sent"
OUTAGE_MIN = timedelta(minutes=30)  # kürzere Ausfälle einer Datenquelle zählen nicht


def parse_weekday(raw: str) -> int:
    """'so', 'Sonntag', 'sun', '6' → 6 (Montag = 0)."""
    value = raw.strip().lower()
    if value.isdigit() and 0 <= int(value) <= 6:
        return int(value)
    for names in (WEEKDAYS, _WEEKDAYS_EN):
        for i, name in enumerate(names):
            if value.startswith(name):
                return i
    raise ValueError(f"unbekannter Wochentag: {raw!r} (mo … so)")


@dataclass(frozen=True, slots=True)
class Schedule:
    weekday: int = 6  # Sonntag
    hour: int = 18
    tz: str = "UTC"

    def last_due(self, now: datetime) -> datetime:
        """Der letzte geplante Zeitpunkt, der nicht nach ``now`` liegt."""
        local = now.astimezone(ZoneInfo(self.tz))
        candidate = local.replace(hour=self.hour, minute=0, second=0, microsecond=0)
        candidate -= timedelta(days=(local.weekday() - self.weekday) % 7)
        if candidate > local:
            candidate -= WEEK
        return candidate

    def is_due(self, now: datetime, last_sent: datetime | None) -> bool:
        return last_sent is not None and last_sent < self.last_due(now) <= now


@dataclass(slots=True)
class WeeklyReport:
    start: datetime
    end: datetime
    new_devices: int = 0
    incidents: dict[Severity, int] = field(default_factory=dict)  # neu in der Woche
    ignored: int = 0
    resolved: int = 0
    disconnected: int = 0
    open_now: int = 0
    blocked_devices: int = 0
    dns_total: int = 0
    dns_blocked: int = 0
    laptops: int = 0
    laptops_reporting: int = 0
    posture_open: int = 0
    outages: list[str] = field(default_factory=list)  # Datenquellen, ≥ 30 Min. ausgefallen

    @property
    def incidents_total(self) -> int:
        return sum(self.incidents.values())

    @property
    def notable(self) -> int:
        """Vorfälle ab „mittel“ – das, was eine Woche unruhig macht."""
        return sum(n for sev, n in self.incidents.items() if sev >= Severity.MEDIUM)

    @property
    def quiet(self) -> bool:
        return self.notable == 0 and self.open_now == 0 and not self.outages

    @property
    def headline(self) -> str:
        if self.quiet:
            return _("Ruhige Woche – alles normal")
        parts = []
        if self.notable:
            parts.append(ngettext("{n} Auffälligkeit", "{n} Auffälligkeiten", self.notable))
        if self.open_now:
            parts.append(_("{n} offen", n=self.open_now))
        if self.outages:
            n = len(self.outages)
            parts.append(ngettext("{n} Datenquelle gestört", "{n} Datenquellen gestört", n))
        return ", ".join(parts)

    @property
    def blocked_pct(self) -> float:
        return round(self.dns_blocked / self.dns_total * 100, 1) if self.dns_total else 0.0

    def lines(self) -> list[str]:
        """Der Bericht als kurze Zeilen (ntfy, Dashboard)."""
        out = [ngettext("{n} neues Gerät", "{n} neue Geräte", self.new_devices)]
        if self.incidents_total:
            by_sev = ", ".join(
                f"{count} {_(_SEVERITY_DE[sev])}"
                for sev, count in sorted(self.incidents.items(), reverse=True)
                if count
            )
            out.append(
                ngettext(
                    "{n} neuer Vorfall ({detail})",
                    "{n} neue Vorfälle ({detail})",
                    self.incidents_total,
                    detail=by_sev,
                )
            )
        else:
            out.append(_("0 Auffälligkeiten"))
        decided = [
            f"{v} {_(k)}"
            for k, v in (
                ("erledigt", self.resolved),
                ("ignoriert", self.ignored),
                ("getrennt", self.disconnected),
            )
            if v
        ]
        if decided:
            out.append(_("Entschieden: {list}", list=", ".join(decided)))
        out.append(_("Offen: {n}", n=self.open_now) if self.open_now else _("Nichts offen"))
        if self.blocked_devices:
            out.append(_("Vom Internet getrennt: {n} Gerät(e)", n=self.blocked_devices))
        out.append(
            _(
                "DNS: {total} Anfragen, {pct} % blockiert",
                total=fmt_int(self.dns_total),
                pct=fmt_dec(self.blocked_pct),
            )
        )
        if self.laptops:
            laptop = _(
                "Laptops: {reporting} von {total} melden sich",
                reporting=self.laptops_reporting,
                total=self.laptops,
            )
            if self.posture_open:
                laptop += ", " + _("{n} Sicherheitsgrundlage(n) aus", n=self.posture_open)
            out.append(laptop)
        if self.outages:
            out.append(_("Länger als 30 Min. ausgefallen: {list}", list=", ".join(self.outages)))
        return out

    def text(self) -> str:
        return "\n".join(self.lines()) + "\n\n" + _("Details im Dashboard.")


def build_report(store: Store, end: datetime) -> WeeklyReport:
    start = end - WEEK
    r = WeeklyReport(start=start, end=end)
    for i in store.incidents():
        if start <= i.created_at < end:
            r.incidents[i.severity] = r.incidents.get(i.severity, 0) + 1
            r.new_devices += i.rule == "new_device"
        if i.status in OPEN_STATUSES:
            r.open_now += 1
            r.posture_open += i.rule == "agent_posture"
    for h in store.history(since=start):
        if not (start <= h.at < end) or h.kind is not HistoryKind.STATUS or not h.manual:
            continue
        if h.status is IncidentStatus.IGNORED:
            r.ignored += 1
        elif h.status is IncidentStatus.RESOLVED:
            r.resolved += 1
        elif h.status is IncidentStatus.DISCONNECTED:
            r.disconnected += 1
    r.blocked_devices = len(store.blocks())
    for hour, total, blocked in store.dns_hourly(since=start):
        if hour < end:
            r.dns_total += total
            r.dns_blocked += blocked
    agents = store.agents()
    r.laptops = len(agents)
    for a in agents.values():
        last = a.get("last_report_at")
        r.laptops_reporting += isinstance(last, datetime) and last >= start
    r.outages = long_outages(store, start, end)
    return r


def long_outages(store: Store, start: datetime, end: datetime) -> list[str]:
    """Datenquellen, die in der Woche mindestens ``OUTAGE_MIN`` am Stück ausgefallen waren.

    Kurze Aussetzer (z. B. wenn der Rechner kurz schläft oder ein Download einmal scheitert)
    sind im Alltag normal und machen eine Woche nicht unruhig. Ein Ausfall, der vor der Woche
    begann, zählt mit seinem Teil in der Woche; ein noch laufender bis ``end``.
    """
    events = store.events(
        limit=5000, kinds=frozenset({EventKind.SOURCE}), since=start - timedelta(days=30)
    )
    down: dict[str, datetime] = {}
    longest: dict[str, timedelta] = {}
    for e in sorted(events, key=lambda e: e.at):
        if e.at >= end:
            break
        if e.tag == "source_down":
            down.setdefault(e.subject, e.at)
        elif e.tag == "source_up":
            began = down.pop(e.subject, None)
            name = e.subject
            if began is not None and e.at > start:
                span = e.at - max(began, start)
                longest[name] = max(longest.get(name, timedelta(0)), span)
    for name, began in down.items():  # noch nicht wieder erreichbar
        span = end - max(began, start)
        longest[name] = max(longest.get(name, timedelta(0)), span)
    return sorted(name for name, span in longest.items() if span >= OUTAGE_MIN)
