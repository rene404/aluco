from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from aluco.config import ConfigError
from aluco.engine import Engine
from aluco.model import DeviceSighting, DnsQuery, IncidentStatus, TrustLevel, utcnow
from aluco.store import Store
from aluco.web import WebConfig, create_app
from tests.conftest import IP_A, IP_B, MAC_A, MAC_B, T0

PASSWORD = "richtig-langes-passwort"
ORIGIN = {"Origin": "http://testserver"}
HX = {"HX-Request": "true"} | ORIGIN


@pytest.fixture
def db(tmp_path: Path) -> Path:
    """Ein IoT-Gerät mit Domains + Vorfall "neue Domain", ein neues unbekanntes Gerät."""
    path = tmp_path / "aluco.db"
    s = Store(path)
    engine = Engine(s)
    engine.process(
        sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A, hostname="<script>x</script>")],
        now=T0,
        learn_only=True,
    )
    from aluco.devices import set_trust

    set_trust(s, MAC_A, TrustLevel.IOT)
    later = T0 + timedelta(days=10)
    engine.process(
        sightings=[
            DeviceSighting(mac=MAC_B, at=later, ip=IP_B),
            DeviceSighting(mac=MAC_A, at=later, ip=IP_A),
        ],
        queries=[DnsQuery(client_ip=IP_A, domain="tracker.example", at=later)],
        now=later,
    )
    s.close()
    return path


@pytest.fixture
def client(db: Path) -> TestClient:
    app = create_app(WebConfig(db_path=db, password=PASSWORD, timezone="Europe/Berlin"))
    return TestClient(app, follow_redirects=False)


def login(client: TestClient) -> TestClient:
    r = client.post("/login", data={"password": PASSWORD}, headers=ORIGIN)
    assert r.status_code == 303
    return client


# --- Zugriffsschutz -----------------------------------------------------------------


def test_pages_require_login(client: TestClient) -> None:
    for path in ["/", "/incidents", "/devices", f"/devices/{MAC_A}"]:
        r = client.get(path)
        assert r.status_code == 303
        assert r.headers["location"] == "/login"
    r = client.get("/devices", headers={"HX-Request": "true"})
    assert r.status_code == 401
    assert r.headers["HX-Redirect"] == "/login"


def test_public_paths(client: TestClient) -> None:
    assert client.get("/healthz").text == "ok"
    assert client.get("/login").status_code == 200
    assert client.get("/static/aluco.css").status_code == 200


def test_login_cookie_flags_and_logout(client: TestClient) -> None:
    r = client.post("/login", data={"password": PASSWORD}, headers=ORIGIN)
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert client.get("/").status_code == 200

    client.post("/logout", headers=ORIGIN)
    assert client.get("/").status_code == 303


def test_wrong_password_and_throttle(client: TestClient) -> None:
    for _ in range(5):
        assert client.post("/login", data={"password": "falsch"}, headers=ORIGIN).status_code == 401
    r = client.post("/login", data={"password": PASSWORD}, headers=ORIGIN)
    assert r.status_code == 429  # auch das richtige Passwort wird jetzt gebremst


def test_post_without_or_with_foreign_origin_is_rejected(client: TestClient) -> None:
    login(client)
    url = "/incidents/1/status"
    assert client.post(url, data={"status": "resolved"}).status_code == 403
    evil = {"Origin": "http://evil.example"}
    assert client.post(url, data={"status": "resolved"}, headers=evil).status_code == 403


def test_security_headers(client: TestClient) -> None:
    r = client.get("/login")
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


# --- Seiten -------------------------------------------------------------------------


def test_overview_counts(client: TestClient) -> None:
    html = login(client).get("/").text
    assert "Offene Vorfälle" in html
    assert "1 hoch" in html and "1 niedrig" in html
    assert "noch keiner" in html  # Runner lief in diesem Test nie


def test_output_is_escaped(client: TestClient) -> None:
    html = login(client).get("/devices").text
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;x&lt;/script&gt;" in html


def test_incident_workflow_via_htmx(client: TestClient, db: Path) -> None:
    login(client)
    s = Store(db)
    incident = next(i for i in s.incidents() if i.rule == "new_device")
    s.close()
    url = f"/incidents/{incident.id}/status"

    r = client.post(url, data={"status": "investigating"}, headers=HX)
    assert r.status_code == 200
    assert "in Prüfung" in r.text and r.text.lstrip().startswith("<li")

    assert client.post(url, data={"status": "disconnected"}, headers=HX).status_code == 400
    assert client.post(url, data={"status": "quatsch"}, headers=HX).status_code == 400
    assert client.post(url, data={"status": "new"}, headers=HX).status_code == 409
    assert (
        client.post("/incidents/999/status", data={"status": "resolved"}, headers=HX).status_code
        == 404
    )

    client.post(url, data={"status": "ignored", "note": "Handy Gast"}, headers=HX)
    assert "Handy Gast" in client.get("/incidents?status=ignored").text
    assert incident.title not in client.get("/incidents?status=open").text


def test_mark_company_deletes_domains(client: TestClient, db: Path) -> None:
    login(client)
    assert "tracker.example" in client.get(f"/devices/{MAC_A}").text

    r = client.post(
        f"/devices/{MAC_A}",
        data={"trust": "company", "name": "Firmenrechner", "protected": "on", "notes": "Büro"},
        headers=ORIGIN,
    )
    assert r.status_code == 303
    assert r.headers["location"] == f"/devices/{MAC_A}?saved=1&deleted=1-1"

    detail = client.get(r.headers["location"]).text
    assert "1 gespeicherte Domains und 1 Vorfälle gelöscht" in detail
    assert "tracker.example" not in detail
    assert "keine Domains und keine DNS-Statistik" in detail
    s = Store(db)
    d = s.device(MAC_A)
    s.close()
    assert d is not None and d.protected and d.name == "Firmenrechner" and d.notes == "Büro"


def test_device_errors(client: TestClient) -> None:
    login(client)
    assert client.get("/devices/kaputt").status_code == 400
    assert client.get("/devices/00:00:5e:00:53:99").status_code == 404
    r = client.post(f"/devices/{MAC_A}", data={"trust": "chef"}, headers=HX)
    assert r.status_code == 400


def test_incident_status_untouched_after_rejected_post(client: TestClient, db: Path) -> None:
    login(client)
    client.post("/incidents/1/status", data={"status": "resolved"})  # ohne Origin → 403
    s = Store(db)
    assert s.incident_by_id(1).status is IncidentStatus.NEW  # type: ignore[union-attr]
    s.close()


# --- Konfiguration ------------------------------------------------------------------


def test_web_config_validation() -> None:
    with pytest.raises(ConfigError, match="12 Zeichen"):
        WebConfig.from_env({"ALUCO_DASHBOARD_PASSWORD": "kurz"})
    with pytest.raises(ConfigError, match="Zeitzone"):
        WebConfig.from_env({"ALUCO_DASHBOARD_PASSWORD": PASSWORD, "TZ": "Mars/Olymp"})
    cfg = WebConfig.from_env({"ALUCO_DASHBOARD_PASSWORD": PASSWORD, "ALUCO_WEB_PORT": "9000"})
    assert cfg.port == 9000
    assert PASSWORD not in repr(cfg)


# --- Dashboard v2 -------------------------------------------------------------------


def test_overview_v2_sections(client: TestClient, db: Path) -> None:
    s = Store(db)  # aktuelle DNS-Daten, damit das Diagramm etwas zeigt
    s.count_query(MAC_A, "example.com", utcnow(), blocked=False)
    s.count_query(MAC_A, "ads.example", utcnow(), blocked=True)
    s.close()
    html = login(client).get("/").text
    for text in [
        "Offene Vorfälle",
        "DNS-Aktivität",
        "Chronik",
        "Aktivste Geräte",
        "Meistblockiert",
    ]:
        assert text in html
    assert "Vorfälle brauchen deine Aufmerksamkeit" in html
    assert 'class="bar-allowed"' in html  # Diagramm gerendert
    assert "style=" not in html  # CSP: keine Inline-Styles
    week = client.get("/?range=7d").text
    assert "heute" in week


def test_overview_event_filter(client: TestClient) -> None:
    login(client)
    incidents_only = client.get("/?events=incidents").text
    assert "Neues Gerät im Netz" in incidents_only
    assert "Inventar übernommen" not in incidents_only
    assert "Inventar übernommen" in client.get("/?events=devices").text


def test_since_last_visit(client: TestClient) -> None:
    login(client)
    first = client.get("/").text
    assert "Willkommen" in first  # erster Besuch


def test_devices_search_and_filter(client: TestClient) -> None:
    login(client)
    assert IP_B in client.get("/devices?q=192.0.2.11").text
    assert IP_A not in client.get("/devices?q=192.0.2.11").text
    iot = client.get("/devices?trust=iot").text
    assert MAC_A in iot and MAC_B not in iot
    assert "Kein Gerät passt" in client.get("/devices?q=gibtsnicht").text


def test_device_detail_v2(client: TestClient) -> None:
    html = login(client).get(f"/devices/{MAC_A}").text
    assert "Aktivität · 7 Tage" in html and "Angefragte Domains" in html and "Verlauf" in html
    assert "tracker.example" in client.get(f"/devices/{MAC_A}?new=1").text
    assert "style=" not in html


def test_no_inline_styles_anywhere(client: TestClient) -> None:
    login(client)
    for path in ["/", "/incidents", "/incidents?status=all", "/devices", f"/devices/{MAC_A}"]:
        assert "style=" not in client.get(path).text, path
