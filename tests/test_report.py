"""Wochenbericht (#27): Zeitplan, Inhalt ohne Kennungen, Versand, Konfiguration, Dashboard."""

from __future__ import annotations

import urllib.error
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from aluco.config import Config, ConfigError
from aluco.incidents import IncidentService
from aluco.model import Device, Event, EventKind, Finding, IncidentStatus, Severity
from aluco.report import REPORT_CURSOR, Schedule, build_report, parse_weekday
from aluco.runner import Runner, build_runner
from aluco.store import Store
from aluco.web import WebConfig, create_app
from tests.conftest import IP_A, MAC_A, MAC_B, T0

# T0 = Sonntag, 1. November 2026, 12:00 UTC (13:00 in Berlin)
assert T0.weekday() == 6


class Outbox:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str, str]] = []
        self.fail = False

    def send_text(self, title: str, body: str, priority: str = "2") -> None:
        if self.fail:
            raise urllib.error.URLError("offline")
        self.sent.append((title, body, priority))


# --- Zeitplan --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "day"),
    [("so", 6), ("Sonntag", 6), ("sun", 6), ("MO", 0), ("Mittwoch", 2), ("do", 3), ("4", 4)],
)
def test_parse_weekday(raw: str, day: int) -> None:
    assert parse_weekday(raw) == day


def test_parse_weekday_rejects_nonsense() -> None:
    with pytest.raises(ValueError, match="Wochentag"):
        parse_weekday("Feiertag")
    with pytest.raises(ValueError):
        parse_weekday("7")


def test_schedule_in_local_time() -> None:
    sunday_18 = Schedule(weekday=6, hour=18, tz="Europe/Berlin")
    before = T0  # So 13:00 Berlin → letzter Termin war der Sonntag davor
    assert sunday_18.last_due(before) == datetime(2026, 10, 25, 17, 0, tzinfo=UTC)  # noch MESZ
    at = datetime(2026, 11, 1, 17, 0, tzinfo=UTC)  # So 18:00 Berlin
    assert sunday_18.last_due(at) == at
    wednesday = Schedule(weekday=2, hour=7, tz="Europe/Berlin")
    assert wednesday.last_due(T0) == datetime(2026, 10, 28, 6, 0, tzinfo=UTC)


def test_is_due() -> None:
    s = Schedule(weekday=6, hour=18, tz="UTC")
    evening = datetime(2026, 11, 1, 18, 5, tzinfo=UTC)
    assert not s.is_due(evening, None)  # erster Lauf: nur merken
    assert s.is_due(evening, T0)  # mittags gemerkt, abends fällig
    assert not s.is_due(evening, evening)  # gerade gesendet
    assert not s.is_due(T0, T0 - timedelta(hours=1))  # 12 Uhr: noch nicht fällig
    assert s.is_due(T0 + timedelta(days=3), T0 - timedelta(days=5))  # verpasst → nachholen


# --- Inhalt ----------------------------------------------------------------------------


def test_quiet_week(store: Store) -> None:
    r = build_report(store, end=T0)
    assert r.quiet and r.headline == "Ruhige Woche – alles normal"
    assert r.lines()[:2] == ["0 neue Geräte", "0 Auffälligkeiten"]
    assert "Details im Dashboard." in r.text()


def _source(store: Store, name: str, down: datetime, up: datetime | None) -> None:
    store.add_event(Event(None, down, EventKind.SOURCE, f"{name} nicht erreichbar"))
    if up is not None:
        store.add_event(Event(None, up, EventKind.SOURCE, f"{name} wieder erreichbar"))


def test_only_long_outages_count(store: Store) -> None:
    day, minute = timedelta(days=1), timedelta(minutes=1)
    _source(store, "kurz", T0 - 2 * day, T0 - 2 * day + 10 * minute)
    _source(store, "kurz", T0 - day, T0 - day + 20 * minute)  # zweimal kurz → zählt nicht
    _source(store, "grenze", T0 - day, T0 - day + 30 * minute)
    _source(store, "laeuft", T0 - 20 * minute, None)  # noch aus, aber erst 20 Min.
    _source(store, "lange", T0 - 3 * day, None)  # noch aus
    _source(store, "davor", T0 - 8 * day, T0 - 7 * day + 40 * minute)  # 40 Min. in der Woche
    _source(store, "davor-kurz", T0 - 8 * day, T0 - 7 * day + 5 * minute)
    r = build_report(store, end=T0)
    assert r.outages == ["davor", "grenze", "lange"]
    assert "Länger als 30 Min. ausgefallen: davor, grenze, lange" in r.lines()
    assert r.headline.endswith("3 Datenquellen gestört")


def test_short_outages_keep_the_week_quiet(store: Store) -> None:
    _source(store, "adguardhome", T0 - timedelta(days=1), T0 - timedelta(days=1, minutes=-5))
    r = build_report(store, end=T0)
    assert r.quiet and r.outages == []


def _busy_store(store: Store) -> None:
    for mac, name in ((MAC_A, "Laptop von Alex"), (MAC_B, "Kamera")):
        store.save_device(
            Device(mac=mac, first_seen=T0, last_seen=T0, ip=IP_A, hostname="alex-mbp", name=name)
        )
    service = IncidentService(store)
    day = timedelta(days=1)

    def incident(rule: str, sev: Severity, at: datetime, key: str = "") -> int:
        f = Finding(
            rule=rule, severity=sev, title=f"{rule} evil.example", device_mac=MAC_A, key=key
        )
        inc = service.ingest(f, at=at)
        assert inc.id is not None
        return inc.id

    a = incident("new_device", Severity.HIGH, T0 - 2 * day)
    service.transition(a, IncidentStatus.RESOLVED, at=T0 - day)
    b = incident("bad_domain", Severity.HIGH, T0 - 3 * day, "evil.example")
    service.transition(b, IncidentStatus.IGNORED, at=T0 - 2 * day)
    incident("new_domain", Severity.LOW, T0 - day, "x.example")  # bleibt offen
    p = incident("agent_posture", Severity.MEDIUM, T0 - day, "filevault")
    service.transition(p, IncidentStatus.RESOLVED, at=T0, manual=False)  # zählt nicht
    incident("new_device", Severity.HIGH, T0 - 10 * day, "alt")  # vor der Woche
    store.count_query(MAC_A, "evil.example", T0 - day, blocked=True)
    for _ in range(3):
        store.count_query(MAC_A, "ok.example", T0 - day, blocked=False)
    store.add_agent(MAC_A, "hash", T0 - 30 * day)
    store.update_agent_report(MAC_A, T0 - day, "alex-mbp", "macOS", {})
    store.add_agent(MAC_B, "hash2", T0 - 30 * day)  # meldet sich nicht
    store.save_block(MAC_B, IP_A, T0 - day, None)
    hour = timedelta(hours=1)
    _source(store, "adguard", T0 - day, T0 - day + 2 * hour)  # 2 Std. → zählt
    _source(store, "netalertx", T0 - 9 * day, T0 - 9 * day + hour)  # vor der Woche


def test_busy_week_counts(store: Store) -> None:
    _busy_store(store)
    r = build_report(store, end=T0 + timedelta(minutes=1))
    assert r.new_devices == 1
    assert r.incidents == {Severity.HIGH: 2, Severity.LOW: 1, Severity.MEDIUM: 1}
    assert (r.resolved, r.ignored, r.disconnected) == (1, 1, 0)
    assert (r.open_now, r.posture_open) == (2, 0)  # neue Domain + alter Vorfall
    assert (r.dns_total, r.dns_blocked, r.blocked_pct) == (4, 1, 25.0)
    assert (r.laptops, r.laptops_reporting, r.blocked_devices) == (2, 1, 1)
    assert r.outages == ["adguard"]
    assert not r.quiet
    assert r.headline == "3 Auffälligkeiten, 2 offen, 1 Datenquelle gestört"
    text = r.text()
    assert "4 neue Vorfälle (2 hoch, 1 mittel, 1 niedrig)" in text
    assert "Entschieden: 1 erledigt, 1 ignoriert" in text
    assert "Laptops: 1 von 2 melden sich" in text
    assert "DNS: 4 Anfragen, 25,0 % blockiert" in text
    r.dns_total, r.dns_blocked = 1234567, 1234
    assert "DNS: 1.234.567 Anfragen, 0,1 % blockiert" in r.lines()


def test_report_contains_no_identifiers(store: Store) -> None:
    _busy_store(store)
    text = build_report(store, end=T0).text()
    for secret in (MAC_A, MAC_B, IP_A, "alex", "Alex", "Kamera", "evil.example", "x.example"):
        assert secret not in text


# --- Versand ---------------------------------------------------------------------------


def test_runner_sends_once_per_week(store: Store) -> None:
    outbox = Outbox()
    runner = Runner(store, [], [], report=(Schedule(6, 18, "UTC"), outbox))
    runner.run_once(now=T0)  # erster Lauf: nur Startpunkt merken
    assert outbox.sent == [] and store.cursor(REPORT_CURSOR) == T0.isoformat()
    runner.run_once(now=T0 + timedelta(hours=5))  # 17 Uhr
    assert outbox.sent == []
    summary = runner.run_once(now=T0 + timedelta(hours=6, minutes=2))  # 18:02
    assert summary.report_sent
    [(title, body, priority)] = outbox.sent
    assert title == "Aluco: Ruhige Woche – alles normal" and priority == "2"
    assert "0 Auffälligkeiten" in body
    runner.run_once(now=T0 + timedelta(hours=7))
    assert len(outbox.sent) == 1
    runner.run_once(now=T0 + timedelta(days=7, hours=6))
    assert len(outbox.sent) == 2


def test_send_failure_does_not_retry_every_run(store: Store) -> None:
    outbox = Outbox()
    outbox.fail = True
    runner = Runner(store, [], [], report=(Schedule(6, 18, "UTC"), outbox))
    runner.run_once(now=T0)
    summary = runner.run_once(now=T0 + timedelta(hours=7))
    assert not summary.report_sent
    outbox.fail = False
    runner.run_once(now=T0 + timedelta(hours=8))
    assert outbox.sent == []  # erst nächste Woche wieder


# --- Konfiguration ---------------------------------------------------------------------

BASE = {"NETALERTX_URL": "http://n", "NETALERTX_API_TOKEN": "t"}


def test_config_defaults_and_values() -> None:
    cfg = Config.from_env(BASE)
    assert (cfg.report_enabled, cfg.report_weekday, cfg.report_hour, cfg.timezone) == (
        True,
        6,
        18,
        "UTC",
    )
    cfg = Config.from_env(
        BASE
        | {
            "ALUCO_REPORT": "off",
            "ALUCO_REPORT_WEEKDAY": "Montag",
            "ALUCO_REPORT_HOUR": "7",
            "TZ": "Europe/Berlin",
        }
    )
    assert (cfg.report_enabled, cfg.report_weekday, cfg.report_hour, cfg.timezone) == (
        False,
        0,
        7,
        "Europe/Berlin",
    )


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"ALUCO_REPORT_WEEKDAY": "bald"}, "ALUCO_REPORT_WEEKDAY"),
        ({"ALUCO_REPORT_HOUR": "24"}, "ALUCO_REPORT_HOUR"),
        ({"ALUCO_REPORT_HOUR": "-1"}, "ALUCO_REPORT_HOUR"),
        ({"TZ": "Mars/Olympus"}, "TZ"),
    ],
)
def test_config_rejects_invalid(env: dict[str, str], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        Config.from_env(BASE | env)


def test_report_only_with_ntfy(store: Store, tmp_path: Path) -> None:
    env = BASE | {"ALUCO_DB_PATH": str(tmp_path / "a.db"), "ALUCO_THREAT_FEEDS": "off"}
    env |= {"ALUCO_NRD_FEEDS": "off"}
    assert build_runner(Config.from_env(env), store)._report is None
    with_ntfy = build_runner(Config.from_env(env | {"NTFY_URL": "https://ntfy.example/t"}), store)
    assert with_ntfy._report is not None
    off = Config.from_env(env | {"NTFY_URL": "https://ntfy.example/t", "ALUCO_REPORT": "off"})
    assert build_runner(off, store)._report is None


# --- Dashboard -------------------------------------------------------------------------


def test_overview_shows_weekly_report(tmp_path: Path) -> None:
    path = tmp_path / "aluco.db"
    Store(path).close()
    client = TestClient(
        create_app(WebConfig(db_path=path, password="richtig-langes-passwort")),
        follow_redirects=False,
    )
    client.post(
        "/login",
        data={"password": "richtig-langes-passwort"},
        headers={"Origin": "http://testserver"},
    )
    html = client.get("/").text
    assert "Wochenbericht" in html and "Ruhige Woche – alles normal" in html
