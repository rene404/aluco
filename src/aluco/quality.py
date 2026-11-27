"""Regel-Qualität (#28): Wie oft löst jede Regel aus, und was wird daraus?

Grundlage ist der Verlauf ``incident_history`` – nur Regel, Zeitpunkt und Status, ohne
Gerät oder Domain. Eine Regel, deren Vorfälle meist ignoriert werden, stumpft ab und
gehört nachgeschärft.

Gezählt werden nur **Entscheidungen von Hand** (ignoriert, erledigt, getrennt);
automatisch erledigte Vorfälle (z. B. Sicherheitsgrundlage laut Agent wieder an)
erscheinen getrennt und zählen nicht zur Ignorier-Quote.

Pro Vorfall und Episode (vom Auftreten bzw. erneuten Auftreten bis zum nächsten) zählt
nur die **letzte** Entscheidung: Wird "ignoriert" von Hand zurückgenommen und der Vorfall
danach erledigt, zählt er als erledigt. Die Wartezeit läuft bis zur ersten Entscheidung.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from statistics import median

from aluco.model import HistoryEntry, HistoryKind, IncidentStatus

S = IncidentStatus
DECISIONS = frozenset({S.IGNORED, S.RESOLVED, S.DISCONNECTED})
IGNORE_WARN_RATE = 0.7  # ab hier hervorheben
MIN_DECISIONS = 3  # darunter ist eine Quote nicht aussagekräftig


@dataclass(slots=True)
class RuleQuality:
    rule: str
    triggered: int = 0  # neue Vorfälle
    reopened: int = 0  # erledigt und erneut aufgetreten
    ignored: int = 0
    resolved: int = 0
    disconnected: int = 0
    auto_resolved: int = 0
    ai_suspect_ignored: int = 0  # KI sagte "verdächtig", Mensch hat ignoriert
    ai_harmless_disconnected: int = 0  # KI sagte "harmlos", Mensch hat getrennt
    _waits: list[float] = field(default_factory=list, repr=False)

    @property
    def decided(self) -> int:
        return self.ignored + self.resolved + self.disconnected

    @property
    def ignore_rate(self) -> float | None:
        return self.ignored / self.decided if self.decided else None

    @property
    def flagged(self) -> bool:
        rate = self.ignore_rate
        return rate is not None and self.decided >= MIN_DECISIONS and rate > IGNORE_WARN_RATE

    @property
    def median_wait(self) -> timedelta | None:
        """Mittlere Zeit (Median) vom Auftreten bis zur Entscheidung von Hand."""
        return timedelta(seconds=median(self._waits)) if self._waits else None


def rule_quality(
    history: list[HistoryEntry], since: datetime, rules: tuple[str, ...] = ()
) -> list[RuleQuality]:
    """Kennzahlen je Regel für alles ab ``since``.

    ``history`` muss chronologisch sein und darf ältere Einträge enthalten – sie dienen nur
    als Startpunkt für die Wartezeit. ``rules`` erscheinen auch ohne Vorfälle (mit Nullen).
    """
    stats: dict[str, RuleQuality] = {r: RuleQuality(r) for r in rules}
    opened_at: dict[int, datetime] = {}  # Beginn der laufenden Episode
    pending: dict[int, HistoryEntry] = {}  # letzte Entscheidung der laufenden Episode

    def stat(rule: str) -> RuleQuality:
        return stats.setdefault(rule, RuleQuality(rule))

    def count(h: HistoryEntry) -> None:
        if h.at < since:
            return
        q = stat(h.rule)
        if not h.manual:
            q.auto_resolved += h.status is S.RESOLVED
        elif h.status is S.IGNORED:
            q.ignored += 1
            q.ai_suspect_ignored += h.ai_verdict == "verdaechtig"
        elif h.status is S.RESOLVED:
            q.resolved += 1
        else:
            q.disconnected += 1
            q.ai_harmless_disconnected += h.ai_verdict == "harmlos"

    for h in history:
        if h.kind in (HistoryKind.OPENED, HistoryKind.REOPENED):
            # neue Episode: die Entscheidung der vorigen bleibt bestehen
            if (done := pending.pop(h.incident_id, None)) is not None:
                count(done)
            opened_at[h.incident_id] = h.at
            if h.at >= since:
                q = stat(h.rule)
                if h.kind is HistoryKind.OPENED:
                    q.triggered += 1
                else:
                    q.reopened += 1
        elif h.status in DECISIONS:
            # nur die letzte Entscheidung einer Episode zählt (#28-Folgefehler: vorher
            # zählte jedes Ignorieren, auch wenn es später zurückgenommen wurde)
            pending[h.incident_id] = h
            start = opened_at.pop(h.incident_id, None)  # Wartezeit bis zur ersten
            if h.manual and start is not None and h.at >= since:
                stat(h.rule)._waits.append((h.at - start).total_seconds())
        else:
            # wieder geöffnet oder "in Prüfung": vorherige Entscheidung zurückgenommen
            pending.pop(h.incident_id, None)
            if h.status is S.NEW and h.incident_id not in opened_at and h.at < since:
                opened_at[h.incident_id] = h.at  # einziger Eintrag vor dem Zeitraum
    for done in pending.values():
        count(done)
    return sorted(stats.values(), key=lambda q: (-(q.triggered + q.reopened), q.rule))
