"""Regel-Qualität (#28): Verlauf, Auswertung, Dashboard-Seite, MCP."""

from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from aluco.ai import Assessment
from aluco.incidents import IncidentService
from aluco.model import Finding, HistoryEntry, HistoryKind, IncidentStatus, Severity
from aluco.quality import rule_quality
from aluco.runner import HISTORY_RETENTION, Runner
from aluco.store import SCHEMA_VERSION, Store
from aluco.web import WebConfig, create_app
from aluco.web.views import duration
from tests.conftest import MAC_A, T0

S = IncidentStatus
H = HistoryKind


def _finding(rule: str = "new_device", key: str = "") -> Finding:
    return Finding(
        rule=rule, severity=Severity.MEDIUM, title="Testvorfall", device_mac=MAC_A, key=key
    )


def _entry(
    minutes: int,
    incident: int,
    kind: HistoryKind = H.STATUS,
    status: IncidentStatus = S.NEW,
    rule: str = "new_device",
    manual: bool = True,
    ai: str | None = None,
) -> HistoryEntry:
    return HistoryEntry(T0 + timedelta(minutes=minutes), incident, rule, kind, status, manual, ai)


# --- Verlauf ---------------------------------------------------------------------------


def test_service_logs_lifecycle_without_identifiers(store: Store) -> None:
    service = IncidentService(store)
    inc = service.ingest(_finding(), at=T0)
    assert inc.id is not None
    store.save_assessment(
        Assessment(inc.id, T0, "fake", "verdaechtig", "hoch", "pruefen", "Kurz.", ["Grund"])
    )
    service.transition(inc.id, S.INVESTIGATING, at=T0 + timedelta(minutes=1))
    service.transition(inc.id, S.RESOLVED, at=T0 + timedelta(minutes=5))
    service.ingest(_finding(), at=T0 + timedelta(hours=1))  # erneut aufgetreten
    service.transition(inc.id, S.IGNORED, at=T0 + timedelta(hours=2))
    service.ingest(_finding(), at=T0 + timedelta(hours=3))  # ignoriert bleibt ignoriert

    rows = store.history()
    assert [(h.kind, h.status) for h in rows] == [
        (H.OPENED, S.NEW),
        (H.STATUS, S.INVESTIGATING),
        (H.STATUS, S.RESOLVED),
        (H.REOPENED, S.NEW),
        (H.STATUS, S.IGNORED),
    ]
    assert all(h.manual for h in rows if h.kind is H.STATUS)
    assert rows[-1].ai_verdict == "verdaechtig"
    columns = {c[1] for c in store._db.execute("PRAGMA table_info(incident_history)")}
    assert not columns & {"device_mac", "title", "details", "domain", "note"}


def test_automatic_transitions_are_marked(store: Store) -> None:
    service = IncidentService(store)
    inc = service.ingest(_finding("agent_posture"), at=T0)
    assert inc.id is not None
    service.transition(inc.id, S.RESOLVED, at=T0, manual=False)
    assert store.history()[-1].manual is False


def test_history_survives_incident_purge_and_is_purged_later(store: Store) -> None:
    service = IncidentService(store)
    inc = service.ingest(_finding(), at=T0)
    assert inc.id is not None
    service.transition(inc.id, S.RESOLVED, at=T0)
    Runner(store, [], []).run_once(now=T0 + timedelta(days=40))
    assert store.incidents() == [] and len(store.history()) == 2
    Runner(store, [], []).run_once(now=T0 + HISTORY_RETENTION + timedelta(days=1))
    assert store.history() == [] and store.history_start() is None


def test_history_since_includes_the_previous_entry_per_incident(store: Store) -> None:
    for h in [_entry(0, 1, H.OPENED), _entry(10, 2, H.OPENED), _entry(100, 1, status=S.IGNORED)]:
        store.add_history(h)
    rows = store.history(since=T0 + timedelta(minutes=50))
    assert [(h.incident_id, h.kind) for h in rows] == [(1, H.OPENED), (1, H.STATUS)]
    assert store.history_start() == T0


def test_migration_backfills_existing_incidents(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    s = Store(path)
    IncidentService(s).ingest(_finding(), at=T0)
    s._db.execute("DROP TABLE incident_history")
    s._db.execute("ALTER TABLE events DROP COLUMN tag")
    s._db.execute("ALTER TABLE events DROP COLUMN subject")
    s._db.execute("PRAGMA user_version = 5")
    s.close()
    s = Store(path)
    assert s._db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    [h] = s.history()
    assert (h.kind, h.rule, h.at) == (H.OPENED, "new_device", T0)
    s.close()


# --- Auswertung ------------------------------------------------------------------------


def test_rule_quality_counts_and_flags() -> None:
    history = [
        # new_device: 4 ausgelöst, 3 ignoriert (eins trotz KI "verdächtig"), 1 erledigt → 75 %
        *[_entry(i, i, H.OPENED) for i in range(4)],
        _entry(10, 0, status=S.IGNORED, ai="verdaechtig"),
        _entry(20, 1, status=S.IGNORED),
        _entry(60, 2, status=S.IGNORED),
        _entry(30, 3, status=S.RESOLVED),
        # bad_domain: getrennt trotz KI "harmlos", dazu ein Status "in Prüfung" (zählt nicht)
        _entry(0, 10, H.OPENED, rule="bad_domain"),
        _entry(2, 10, status=S.INVESTIGATING, rule="bad_domain"),
        _entry(90, 10, status=S.DISCONNECTED, rule="bad_domain", ai="harmlos"),
        # agent_posture: automatisch erledigt → nicht in der Quote
        _entry(0, 20, H.OPENED, rule="agent_posture"),
        _entry(5, 20, status=S.RESOLVED, rule="agent_posture", manual=False),
        # new_device erneut: erledigt → wieder aufgetreten → erledigt
        _entry(200, 3, H.REOPENED),
        _entry(260, 3, status=S.RESOLVED),
    ]
    history.sort(key=lambda h: h.at)
    by_rule = {q.rule: q for q in rule_quality(history, T0, rules=("new_device", "agent_login"))}
    nd = by_rule["new_device"]
    assert (nd.triggered, nd.reopened, nd.ignored, nd.resolved) == (4, 1, 3, 2)
    assert nd.ignore_rate == pytest.approx(0.6)
    assert not nd.flagged  # 60 % liegt unter 70 %
    assert nd.ai_suspect_ignored == 1
    assert nd.median_wait == timedelta(minutes=27)  # 10, 19, 27, 58, 60 → 27

    bd = by_rule["bad_domain"]
    assert (bd.disconnected, bd.ai_harmless_disconnected) == (1, 1)
    assert bd.median_wait == timedelta(minutes=90)

    ap = by_rule["agent_posture"]
    assert (ap.auto_resolved, ap.resolved, ap.ignore_rate, ap.median_wait) == (1, 0, None, None)

    login = by_rule["agent_login"]  # ohne Vorfälle, trotzdem aufgeführt
    assert (login.triggered, login.ignore_rate, login.flagged) == (0, None, False)


def test_flag_needs_enough_decisions_and_more_than_70_percent() -> None:
    def ignored(n_ignored: int, n_resolved: int) -> list[HistoryEntry]:
        out = [_entry(0, i, H.OPENED) for i in range(n_ignored + n_resolved)]
        out += [_entry(1, i, status=S.IGNORED) for i in range(n_ignored)]
        out += [_entry(1, n_ignored + i, status=S.RESOLVED) for i in range(n_resolved)]
        return out

    assert rule_quality(ignored(4, 1), T0)[0].flagged  # 80 %
    assert not rule_quality(ignored(7, 3), T0)[0].flagged  # genau 70 %
    assert not rule_quality(ignored(2, 0), T0)[0].flagged  # 100 %, aber nur 2 Entscheidungen


def test_window_uses_older_start_for_wait_but_does_not_count_it() -> None:
    history = [_entry(0, 1, H.OPENED), _entry(24 * 60, 1, status=S.IGNORED)]
    [q] = rule_quality(history, since=T0 + timedelta(hours=12))
    assert (q.triggered, q.ignored, q.median_wait) == (0, 1, timedelta(days=1))


def test_revoked_decision_counts_only_the_last_one() -> None:
    history = [
        _entry(0, 1, H.OPENED),
        _entry(10, 1, status=S.IGNORED),
        _entry(100, 1, status=S.NEW),  # Ignorieren zurückgenommen
        _entry(130, 1, status=S.RESOLVED),
    ]
    [q] = rule_quality(history, T0)
    assert (q.ignored, q.resolved, q.decided) == (0, 1, 1)
    assert q.median_wait == timedelta(minutes=10)  # bis zur ersten Entscheidung


def test_revoked_and_still_open_counts_no_decision() -> None:
    history = [
        _entry(0, 1, H.OPENED),
        _entry(10, 1, status=S.IGNORED, ai="verdaechtig"),
        _entry(20, 1, status=S.INVESTIGATING),  # zurückgenommen, noch offen
    ]
    [q] = rule_quality(history, T0)
    assert (q.triggered, q.decided, q.ai_suspect_ignored) == (1, 0, 0)


def test_real_world_case_is_no_longer_flagged() -> None:
    """Stand lokal 2026-11-26: 5 × ignoriert, davon 4 zurückgenommen (2 dann erledigt,
    2 wieder offen) – vorher 5 ignoriert/2 erledigt (71 %, "abgestumpft?")."""
    history = [_entry(0, i, H.OPENED) for i in range(5)]
    history += [_entry(10, i, status=S.IGNORED) for i in range(5)]
    history += [_entry(20, i, status=S.NEW) for i in range(1, 5)]
    history += [_entry(30, i, status=S.RESOLVED) for i in (1, 2)]
    history.sort(key=lambda h: h.at)
    [q] = rule_quality(history, T0)
    assert (q.ignored, q.resolved) == (1, 2)
    assert not q.flagged


@pytest.mark.parametrize(
    ("td", "text"),
    [
        (None, "–"),
        (timedelta(seconds=20), "< 1 Min."),
        (timedelta(minutes=12), "12 Min."),
        (timedelta(hours=5), "5 Std."),
        (timedelta(days=3), "3 Tage"),
    ],
)
def test_duration(td: timedelta | None, text: str) -> None:
    assert duration(td) == text


# --- Dashboard -------------------------------------------------------------------------


def test_rules_page(tmp_path: Path) -> None:
    from aluco.model import utcnow

    path = tmp_path / "aluco.db"
    s = Store(path)
    service = IncidentService(s)
    now = utcnow()
    for i in range(4):
        inc = service.ingest(_finding(key=str(i)), at=now - timedelta(days=2))
        assert inc.id is not None
        service.transition(inc.id, S.IGNORED, at=now - timedelta(days=1))
    s.close()

    client = TestClient(
        create_app(WebConfig(db_path=path, password="richtig-langes-passwort")),
        follow_redirects=False,
    )
    assert client.get("/rules").status_code in (302, 303)  # nur mit Anmeldung
    client.post(
        "/login",
        data={"password": "richtig-langes-passwort"},
        headers={"Origin": "http://testserver"},
    )
    html = client.get("/rules").text
    assert "Regel-Qualität" in html and "Neues Gerät" in html
    assert "abgestumpft?" in html and "100 %" in html
    assert "Laptop: Fern-Anmeldung" in html  # Regel ohne Vorfälle steht trotzdem da
    assert 'href="/rules"' in html
    assert "90 Tage" in client.get("/rules?days=90").text


def test_deleting_incidents_keeps_history(tmp_path: Path) -> None:
    """Der Verlauf hat keine Fremdschlüssel: Vorfälle löschen bricht ihn nicht."""
    s = Store(tmp_path / "x.db")
    inc = IncidentService(s).ingest(_finding(), at=T0)
    try:
        s._db.execute("DELETE FROM incidents WHERE id = ?", (inc.id,))
    except sqlite3.IntegrityError:  # pragma: no cover
        pytest.fail("Verlauf darf das Löschen von Vorfällen nicht verhindern")
    assert len(s.history()) == 1
    s.close()
