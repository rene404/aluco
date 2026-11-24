"""Englische Oberfläche (#29): Katalog vollständig, keine festen Texte, Seiten auf Englisch."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from aluco import i18n
from aluco.locale_en import EN

SRC = Path(__file__).resolve().parent.parent / "src" / "aluco"
TEMPLATES = SRC / "web" / "templates"
# Python-Module, deren _()-Texte übersetzt sein müssen (die Oberfläche).
TRANSLATED_MODULES = (
    "i18n.py",
    "report.py",
    "web/views.py",
    "web/app.py",
    "runner.py",
    "engine.py",
    "rules.py",
    "incidents.py",
    "quarantine.py",
    "agent.py",
    "notify.py",
)
_TEMPLATE_CALL = re.compile(r"""\b(?:_|ngettext)\(\s*(["'])(.*?)\1(?:\s*,\s*(["'])(.*?)\3)?""")


def _python_msgids(path: Path) -> Iterator[str]:
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        count = {"_": 1, "ngettext": 2}.get(name or "")
        for arg in node.args[: count or 0]:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                yield arg.value


def _template_msgids(path: Path) -> Iterator[str]:
    for m in _TEMPLATE_CALL.finditer(path.read_text(encoding="utf-8")):
        yield m.group(2)
        if m.group(4) is not None:
            yield m.group(4)


def _value_msgids() -> Iterator[str]:
    """Texte, die über Tabellen in _() landen (Schweregrad, Status, Regeln …)."""
    from aluco.agent import POSTURE_CHECKS
    from aluco.ai import ACTION_DE as AI_ACTION
    from aluco.ai import RULE_NAME, VERDICT_DE
    from aluco.web.app import ACTION_DE, SEVERITY_DE, STATUS_DE, TRUST_DE
    from aluco.web.views import WEEKDAYS_DE

    for table in (SEVERITY_DE, STATUS_DE, ACTION_DE, TRUST_DE, RULE_NAME, VERDICT_DE, AI_ACTION):
        yield from table.values()
    yield from (v[0] for v in POSTURE_CHECKS.values())
    yield from (v[2] for v in POSTURE_CHECKS.values())
    from aluco.incidents import STATUS_TEXT

    yield from STATUS_TEXT.values()
    yield from WEEKDAYS_DE
    yield from ("niedrig", "mittel", "hoch")  # Risiko der KI
    yield from ("erledigt", "ignoriert", "getrennt")  # Wochenbericht


def all_msgids() -> set[str]:
    ids = set(_value_msgids())
    for rel in TRANSLATED_MODULES:
        ids.update(_python_msgids(SRC / rel))
    for tpl in TEMPLATES.glob("*.html"):
        ids.update(_template_msgids(tpl))
    return ids


@pytest.fixture
def english() -> Iterator[None]:
    i18n.set_language("en")
    yield
    i18n.set_language("de")


# --- Katalog ---------------------------------------------------------------------------


def test_every_text_has_an_english_translation() -> None:
    missing = sorted(all_msgids() - EN.keys())
    assert missing == [], "Ohne Übersetzung:\n" + "\n".join(missing)


def test_no_stale_translations() -> None:
    stale = sorted(EN.keys() - all_msgids())
    assert stale == [], "Übersetzt, aber nicht mehr verwendet:\n" + "\n".join(stale)


def test_placeholders_match() -> None:
    field = re.compile(r"\{(\w*)\}")
    for de, en in EN.items():
        assert sorted(field.findall(de)) == sorted(field.findall(en)), de
        assert en.strip(), de


def test_templates_have_no_hardcoded_text() -> None:
    """Abnahme #29: Sichtbarer Text in Vorlagen steht nur noch in _()."""
    allowed = {"Aluco", "24 h", "IP", "MAC", "DNS"}
    for tpl in TEMPLATES.glob("*.html"):
        s = tpl.read_text(encoding="utf-8")
        for pattern in (r"\{#.*?#\}", r"\{%.*?%\}", r"\{\{.*?\}\}", r"<svg.*?</svg>"):
            s = re.sub(pattern, " ", s, flags=re.S)
        attrs = re.findall(r'\b(?:title|aria-label|placeholder|alt|hx-confirm)="([^"]*)"', s)
        visible = re.sub(r"<[^>]+>", "\n", s).split("\n") + attrs
        for text in visible:
            words = [w for w in re.findall(r"[A-Za-zÄÖÜäöüß]{2,}", text) if w not in allowed]
            assert not words, f"{tpl.name}: fest eingebauter Text {text.strip()!r}"


# --- Sprache ---------------------------------------------------------------------------


def test_language_switch_and_formats(english: None) -> None:
    assert i18n._("Geräte") == "Devices"
    assert i18n._("{n} offen", n=3) == "3 open"
    assert i18n.ngettext("{n} neues Gerät", "{n} neue Geräte", 1) == "1 new device"
    assert i18n.ngettext("{n} neues Gerät", "{n} neue Geräte", 2) == "2 new devices"
    assert (i18n.fmt_int(1234567), i18n.fmt_dec(2.5)) == ("1,234,567", "2.5")
    i18n.set_language("de")
    assert i18n._("Geräte") == "Geräte"
    assert (i18n.fmt_int(1234567), i18n.fmt_dec(2.5)) == ("1.234.567", "2,5")


@pytest.mark.parametrize(("raw", "lang"), [(None, "de"), ("", "de"), ("EN", "en"), ("en_US", "en")])
def test_parse_language(raw: str | None, lang: str) -> None:
    assert i18n.parse_language(raw) == lang


def test_parse_language_rejects_unknown() -> None:
    with pytest.raises(i18n.LanguageError):
        i18n.parse_language("fr")


def test_service_config_reads_language() -> None:
    from aluco.config import Config, ConfigError

    base = {"NETALERTX_URL": "http://n", "NETALERTX_API_TOKEN": "t"}
    assert Config.from_env(base).language == "de"
    assert Config.from_env(base | {"ALUCO_LANGUAGE": "en"}).language == "en"
    with pytest.raises(ConfigError, match="ALUCO_LANGUAGE"):
        Config.from_env(base | {"ALUCO_LANGUAGE": "klingonisch"})


def test_web_config_reads_language() -> None:
    from aluco.config import ConfigError
    from aluco.web import WebConfig

    base = {"ALUCO_DASHBOARD_PASSWORD": "richtig-langes-passwort"}
    assert WebConfig.from_env(base).language == "de"
    assert WebConfig.from_env(base | {"ALUCO_LANGUAGE": "en"}).language == "en"
    with pytest.raises(ConfigError, match="ALUCO_LANGUAGE"):
        WebConfig.from_env(base | {"ALUCO_LANGUAGE": "fr"})


# --- Dashboard auf Englisch ------------------------------------------------------------

GERMAN = re.compile(
    r"[äöüÄÖÜß]|\b(?:und|oder|nicht|keine?|Gerät|Geräte|Vorfall|Vorfälle|noch|seit|"
    r"erledigt|ignoriert|Übersicht|Regeln|blockiert|Anfragen)\b"
)


def _visible_text(html: str) -> str:
    html = re.sub(r"<(script|style|svg)\b.*?</\1>", " ", html, flags=re.S)
    attrs = " ".join(re.findall(r'\b(?:title|aria-label|placeholder|hx-confirm)="([^"]*)"', html))
    return re.sub(r"<[^>]+>", " ", html) + " " + attrs


def test_dashboard_pages_render_in_english(tmp_path: Path) -> None:
    from datetime import timedelta

    from aluco.engine import Engine
    from aluco.model import DeviceSighting, DnsQuery, TrustLevel, utcnow
    from aluco.store import Store
    from aluco.web import WebConfig, create_app
    from tests.conftest import IP_A, IP_B, MAC_A, MAC_B

    path = tmp_path / "aluco.db"
    s = Store(path)
    now = utcnow()
    engine = Engine(s)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=now, ip=IP_A)], now=now, learn_only=True)
    from aluco.devices import set_trust

    set_trust(s, MAC_A, TrustLevel.IOT)
    later = now + timedelta(days=8)
    engine.process(
        sightings=[DeviceSighting(mac=MAC_B, at=later, ip=IP_B)],
        queries=[DnsQuery(client_ip=IP_A, domain="tracker.example", at=later)],
        now=later,
    )
    s.close()
    app = create_app(WebConfig(db_path=path, password="richtig-langes-passwort", language="en"))
    try:
        client = TestClient(app, follow_redirects=False)
        login = client.get("/login").text
        assert 'lang="en"' in login and "Password" in login
        client.post(
            "/login",
            data={"password": "richtig-langes-passwort"},
            headers={"Origin": "http://testserver"},
        )
        pages = ["/", "/incidents?status=all", "/devices", f"/devices/{MAC_A}", "/rules"]
        for url in pages:
            html = client.get(url).text
            text = _visible_text(html)
            # Titel von Vorfällen und Ereignissen sind gespeicherte Daten (Sprache bei Entstehung).
            for stored in ("Neues Gerät im Netz", "fragt neue Domain an", "Inventar übernommen"):
                text = re.sub(rf"[^<>\n]*{stored}[^<>\n]*", " ", text)
            hits = sorted({m.group(0) for m in GERMAN.finditer(text)})
            assert hits == [], f"{url}: deutsch geblieben: {hits}"
        assert "Overview" in client.get("/").text
    finally:
        i18n.set_language("de")


# --- Teil 2: Meldungen, neue Titel, sprachneutrale Ereignisse --------------------------


def test_migration_v7_classifies_existing_german_events(tmp_path: Path) -> None:
    import sqlite3

    from aluco.store import SCHEMA_VERSION, Store

    path = tmp_path / "old.db"
    Store(path).close()
    db = sqlite3.connect(path)
    db.execute("ALTER TABLE events DROP COLUMN tag")
    db.execute("ALTER TABLE events DROP COLUMN subject")
    rows = [
        ("source", "netalertx nicht erreichbar"),
        ("source", "threatintel/hagezi-tif wieder erreichbar"),
        ("source", "Speicherplatz knapp"),
        ("incident_status", "Vorfall erledigt: Neues Gerät im Netz: x"),
        ("incident_status", "Vorfall ignoriert: y"),
        ("incident_status", "Laptop über die Firewall getrennt"),
        ("incident_status", "Laptop wieder freigegeben"),
        ("device_online", "Laptop ist online"),
    ]
    for kind, title in rows:
        db.execute(
            "INSERT INTO events (at, kind, title) VALUES ('2026-11-20T10:00:00+00:00', ?, ?)",
            (kind, title),
        )
    db.execute("PRAGMA user_version = 6")
    db.commit()
    db.close()

    s = Store(path)
    assert s._db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    got = {e.title: (e.tag, e.subject) for e in s.events(limit=50)}
    s.close()
    assert got == {
        "netalertx nicht erreichbar": ("source_down", "netalertx"),
        "threatintel/hagezi-tif wieder erreichbar": ("source_up", "threatintel/hagezi-tif"),
        "Speicherplatz knapp": ("disk_low", ""),
        "Vorfall erledigt: Neues Gerät im Netz: x": ("resolved", ""),
        "Vorfall ignoriert: y": ("ignored", ""),
        "Laptop über die Firewall getrennt": ("disconnected", ""),
        "Laptop wieder freigegeben": ("released", ""),
        "Laptop ist online": ("", ""),
    }


def test_english_source_events_still_drive_the_weekly_report(english: None) -> None:
    """Ausfälle werden über tag/subject erkannt – nicht über den (übersetzten) Titel."""
    from datetime import timedelta

    from aluco.report import build_report
    from aluco.runner import Runner
    from aluco.store import Store
    from aluco.web import views
    from tests.conftest import T0

    store = Store()
    runner = Runner(store, [], [])
    runner._record_source_changes(["adguardhome: timeout"], T0)
    store.set_cursor("runner:last_errors", "adguardhome: timeout")
    runner._record_source_changes([], T0 + timedelta(hours=2))
    events = sorted(store.events(limit=10), key=lambda e: e.at)
    assert [e.title for e in events] == ["adguardhome unreachable", "adguardhome reachable again"]
    assert [views.event_tone(e) for e in events] == ["sev-medium", "muted"]
    report = build_report(store, end=T0 + timedelta(hours=3))
    assert report.outages == ["adguardhome"]
    assert "Down for more than 30 min: adguardhome" in report.lines()


def test_english_incident_titles_and_ntfy(english: None) -> None:
    from aluco.engine import Engine
    from aluco.model import DeviceSighting
    from aluco.notify import NtfyNotifier
    from aluco.store import Store
    from tests.conftest import IP_A, IP_B, MAC_A, MAC_B, T0

    store = Store()
    engine = Engine(store)
    first = engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A)], learn_only=True)
    assert first.new_devices == 1
    assert store.events(limit=1)[0].title == "Inventory adopted: 1 device"
    result = engine.process(sightings=[DeviceSighting(mac=MAC_B, at=T0, ip=IP_B, hostname="tv")])
    [incident] = result.alerts
    assert incident.title == "New device on the network: tv"
    assert "MAC address was not in the inventory before" in views_explain(incident)

    sent: list[tuple[dict[str, str], bytes]] = []
    NtfyNotifier("https://ntfy.example/t", post=lambda u, b, h: sent.append((h, b))).send(incident)
    NtfyNotifier(
        "https://ntfy.example/t", minimal=True, post=lambda u, b, h: sent.append((h, b))
    ).send(incident)
    assert sent[0][0]["Title"] == "Aluco (high)"
    assert sent[1][0]["Title"] == "Aluco: new incident"
    assert sent[1][1].decode() == "Severity high. Details in the dashboard."


def views_explain(incident: object) -> list[str]:
    from aluco.web import views

    return views.explain(incident)  # type: ignore[arg-type]


def test_posture_explanation_follows_language(english: None) -> None:
    from aluco.model import Incident, IncidentStatus, Severity
    from aluco.web import views
    from tests.conftest import T0

    inc = Incident(
        id=1,
        fingerprint="f",
        rule="agent_posture",
        severity=Severity.HIGH,
        title="Laptop: FileVault ist aus",
        status=IncidentStatus.NEW,
        created_at=T0,
        updated_at=T0,
        details={"check": "filevault", "name": "FileVault", "text": "Die Festplatte ist …"},
    )
    assert views.explain(inc)[0] == "The disk is not encrypted."
