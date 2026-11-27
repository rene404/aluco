from __future__ import annotations

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from aluco.model import Device, Event, EventKind, Incident, IncidentStatus, Severity
from aluco.web import views
from tests.conftest import MAC_A, MAC_B, T0

TZ = ZoneInfo("Europe/Berlin")


def test_fmt_int() -> None:
    assert views.fmt_int(1234567) == "1.234.567"


def test_relative_times() -> None:
    now = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
    assert views.relative(now - timedelta(seconds=20), now, TZ) == "gerade eben"
    assert views.relative(now - timedelta(minutes=5), now, TZ) == "vor 5 Min."
    assert views.relative(now - timedelta(hours=3), now, TZ) == "vor 3 Std."
    assert views.relative(now - timedelta(hours=20), now, TZ).startswith("gestern ")
    assert views.relative(now - timedelta(days=5), now, TZ) == "14.11. 13:00"


def test_abbreviation() -> None:
    def dev(name: str | None = None, hostname: str | None = None) -> Device:
        return Device(mac=MAC_A, first_seen=T0, last_seen=T0, name=name, hostname=hostname)

    assert views.abbreviation(dev("Laptop Wohnzimmer")) == "LW"
    assert views.abbreviation(dev("Fernseher")) == "FE"
    assert views.abbreviation(dev(hostname="tv-wohnzimmer")) == "TW"
    assert views.abbreviation(dev()) == "??"


def test_hourly_chart_fills_gaps_and_stacks() -> None:
    now = datetime(2026, 11, 19, 12, 30, tzinfo=UTC)
    hour = now.replace(minute=0)
    rows = [(hour, 100, 20), (hour - timedelta(hours=2), 50, 0)]
    chart = views.hourly_chart(rows, now, TZ)
    assert len(chart.bars) == 24
    assert chart.total == 150 and chart.blocked == 20
    last = chart.bars[-1]
    assert last.h_allowed + last.h_blocked == 100  # Spitze = volle Höhe
    assert chart.bars[-2].h_allowed == 0
    assert chart.axis[-1] == "13:00"  # lokale Zeit


def test_daily_chart_groups_by_local_day() -> None:
    now = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
    rows = [(now - timedelta(days=1), 10, 1), (now - timedelta(days=1, hours=1), 5, 0), (now, 7, 0)]
    chart = views.daily_chart(rows, now, TZ)
    assert len(chart.bars) == 7
    assert chart.axis[-1] == "heute" and chart.axis[-2] == "Mi"
    assert chart.total == 22


def test_empty_chart() -> None:
    chart = views.hourly_chart([], datetime(2026, 11, 19, tzinfo=UTC), TZ)
    assert chart.total == 0 and chart.peak_label == ""


def test_sparkline_and_active_hours() -> None:
    now = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
    spark = views.sparkline({now: 10, now - timedelta(hours=1): 5}, now)
    assert spark[-1] == 100 and spark[-2] == 50 and len(spark) == 24
    rows = [(datetime(2026, 11, 18, h, tzinfo=UTC), 100, 0) for h in range(6, 22)]
    assert views.active_hours(rows, TZ) == "aktiv 07–23 Uhr · nachts ruhig"
    assert views.active_hours([], TZ) == ""


def _incident(sev: Severity, rule: str = "new_device", **details: str) -> Incident:
    return Incident(
        id=1, fingerprint="f", rule=rule, severity=sev, title="t",
        status=IncidentStatus.NEW, created_at=T0, updated_at=T0, details=details,
    )  # fmt: skip


def test_situation_levels() -> None:
    assert views.situation([]).level == "ok"
    assert views.situation([_incident(Severity.LOW)]).level == "info"
    s = views.situation([_incident(Severity.LOW), _incident(Severity.HIGH)])
    assert s.level == "warn" and s.title == "2 Vorfälle brauchen deine Aufmerksamkeit"
    assert views.situation([_incident(Severity.CRITICAL)]).level == "alert"


def test_explain_rules() -> None:
    facts = views.explain(_incident(Severity.HIGH, randomized_mac="true", ip="192.0.2.9"))
    assert any("Private (zufällige)" in f for f in facts)
    assert "Hersteller unbekannt" in facts
    domain = views.explain(
        _incident(Severity.LOW, "new_domain", domain="x.example", query="a.x.example")
    )
    assert domain[0].startswith("Domain x.example")


def test_since_summary_and_tone() -> None:
    def ev(kind: EventKind, tag: str = "", sev: Severity | None = None) -> Event:
        return Event(id=None, at=T0, kind=kind, title="t", severity=sev, tag=tag)

    text = views.since_summary(
        [ev(EventKind.INCIDENT), ev(EventKind.DEVICE_OFFLINE), ev(EventKind.DEVICE_OFFLINE)]
    )
    assert text == "1 neuer Vorfall · 2 × offline"
    assert views.event_tone(ev(EventKind.INCIDENT, sev=Severity.HIGH)) == "sev-high"
    assert views.event_tone(ev(EventKind.SOURCE, "source_down")) == "sev-medium"
    assert views.event_tone(ev(EventKind.SOURCE, "source_up")) == "muted"
    assert views.event_tone(ev(EventKind.INCIDENT_STATUS, "resolved")) == "ok"
    assert views.event_tone(ev(EventKind.DEVICE_ONLINE)) == "ok"


def test_collapse_events_groups_repeats_in_a_row() -> None:
    def ev(minutes: int, kind: EventKind = EventKind.DEVICE_OFFLINE, title: str = "L ist offline",
           mac: str | None = MAC_A) -> Event:  # fmt: skip
        return Event(id=None, at=T0 - timedelta(minutes=minutes), kind=kind, title=title,
                     device_mac=mac)  # fmt: skip

    events = [
        ev(0),
        ev(10),
        ev(20),  # 3× dasselbe in Folge
        ev(25, EventKind.INCIDENT, "Neuer offener Port"),
        ev(30),
        ev(40),  # wieder offline: eigene Gruppe, weil unterbrochen
        ev(50, title="Anderes Gerät ist offline", mac=None),
    ]
    rows = views.collapse_events(events, limit=10)
    assert [(r.event.title, r.count) for r in rows] == [
        ("L ist offline", 3), ("Neuer offener Port", 1), ("L ist offline", 2),
        ("Anderes Gerät ist offline", 1),
    ]  # fmt: skip
    assert rows[0].event.at == T0 and rows[0].first_at == T0 - timedelta(minutes=20)
    assert rows[1].first_at is None
    assert len(views.collapse_events(events, limit=2)) == 2
    assert views.collapse_events([], limit=5) == []


def test_collapse_events_groups_on_off_of_one_device() -> None:
    """Review: ein Gerät, das ständig an- und abgeht, ergibt eine Zeile."""
    on, off = EventKind.DEVICE_ONLINE, EventKind.DEVICE_OFFLINE
    events = [
        Event(id=None, at=T0 - timedelta(minutes=m), kind=k, title=t, device_mac=MAC_A)
        for m, k, t in [(0, on, "L ist online"), (5, off, "L ist offline"),
                        (10, on, "L ist online"), (15, off, "L ist offline")]
    ] + [Event(id=None, at=T0 - timedelta(minutes=20), kind=off, title="B ist offline",
               device_mac=MAC_B)]  # fmt: skip
    rows = views.collapse_events(events, limit=10)
    assert [(r.event.title, r.count, r.toggles) for r in rows] == [
        ("L ist online", 4, True), ("B ist offline", 1, False),
    ]  # fmt: skip
