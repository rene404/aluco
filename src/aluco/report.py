"""Wochenbericht (#27): ein ruhiges „alles in Ordnung“ – oder was diese Woche los war.

Der Bericht enthält nur **Zahlen**, keine Gerätenamen, IPs oder Domains. Er darf darum
auch über einen externen ntfy-Server gehen (wie ``ALUCO_NOTIFY_MINIMAL``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

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
    outages: list[str] = field(default_factory=list)  # Datenquellen, die ausgefallen waren

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
            return "Ruhige Woche – alles normal"
        parts = []
        if self.notable:
            parts.append(f"{self.notable} Auffälligkeit{'en' if self.notable != 1 else ''}")
        if self.open_now:
            parts.append(f"{self.open_now} offen")
        if self.outages:
            parts.append(
                f"{len(self.outages)} Datenquelle{'n' if len(self.outages) != 1 else ''} gestört"
            )
        return ", ".join(parts)

    @property
    def blocked_pct(self) -> float:
        return round(self.dns_blocked / self.dns_total * 100, 1) if self.dns_total else 0.0

    def lines(self) -> list[str]:
        """Der Bericht als kurze Zeilen (ntfy, Dashboard)."""
        n = self.new_devices
        out = [f"{n} neue{'s' if n == 1 else ''} Gerät{'e' if n != 1 else ''}"]
        if self.incidents_total:
            by_sev = ", ".join(
                f"{count} {_SEVERITY_DE[sev]}"
                for sev, count in sorted(self.incidents.items(), reverse=True)
                if count
            )
            out.append(f"{self.incidents_total} neue Vorfälle ({by_sev})")
        else:
            out.append("0 Auffälligkeiten")
        decided = [
            f"{v} {k}"
            for k, v in (
                ("erledigt", self.resolved),
                ("ignoriert", self.ignored),
                ("getrennt", self.disconnected),
            )
            if v
        ]
        if decided:
            out.append("Entschieden: " + ", ".join(decided))
        out.append(f"Offen: {self.open_now}" if self.open_now else "Nichts offen")
        if self.blocked_devices:
            out.append(f"Vom Internet getrennt: {self.blocked_devices} Gerät(e)")
        total = f"{self.dns_total:,}".replace(",", ".")
        pct = f"{self.blocked_pct:.1f}".replace(".", ",")
        out.append(f"DNS: {total} Anfragen, {pct} % blockiert")
        if self.laptops:
            laptop = f"Laptops: {self.laptops_reporting} von {self.laptops} melden sich"
            if self.posture_open:
                laptop += f", {self.posture_open} Sicherheitsgrundlage(n) aus"
            out.append(laptop)
        if self.outages:
            out.append("Ausgefallen: " + ", ".join(self.outages))
        return out

    def text(self) -> str:
        return "\n".join(self.lines()) + "\n\nDetails im Dashboard."


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
    outages = {
        e.title.removesuffix(" nicht erreichbar")
        for e in store.events(limit=1000, kinds=frozenset({EventKind.SOURCE}), since=start)
        if e.at < end and e.title.endswith("nicht erreichbar")
    }
    r.outages = sorted(outages)
    return r
