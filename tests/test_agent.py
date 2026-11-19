"""Laptop-Agent: Bericht prüfen, Lernlauf, neue Einträge, Sicherheitsgrundlagen, API, CLI."""

from __future__ import annotations

import copy
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from aluco.__main__ import main
from aluco.agent import AgentError, hash_token, new_token, process_report, validate_report
from aluco.ai import build_context
from aluco.devices import set_trust
from aluco.model import Device, IncidentStatus, TrustLevel
from aluco.store import Store
from aluco.web import WebConfig, create_app
from tests.conftest import MAC_A, MAC_B, T0

REPORT: dict[str, Any] = {
    "agent_version": "1",
    "system": [{"hostname": "mac-anna.local", "computer_name": "Annas MacBook"}],
    "os": [{"name": "macOS", "version": "26.6.2"}],
    "listening_ports": [
        {"port": "5000", "protocol": "6", "address": "0.0.0.0", "name": "ControlCenter",
         "path": "/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter"},
        {"port": "8080", "protocol": "6", "address": "127.0.0.1", "name": "dev", "path": "/x"},
    ],
    "autostart": [
        {"label": "com.apple.foo", "path": "/System/Library/LaunchDaemons/foo.plist"},
        {"label": "com.vendor.updater", "path": "/Library/LaunchDaemons/com.vendor.updater.plist",
         "program": "/Library/Vendor/updater"},
    ],
    "logged_in_users": [{"user": "anna", "type": "user", "host": ""}],
    "firewall": [{"global_state": "1"}],
    "filevault": [{"encrypted": "1"}],
    "gatekeeper": [{"assessments_enabled": "1"}],
    "sip": [{"enabled": "1"}],
}  # fmt: skip


@pytest.fixture
def laptop(store: Store) -> Store:
    store.save_device(Device(mac=MAC_A, first_seen=T0, last_seen=T0, name="Laptop"))
    store.add_agent(MAC_A, hash_token("x" * 30), T0)
    return store


def report(**changes: Any) -> dict[str, Any]:
    r = copy.deepcopy(REPORT)
    r.update(changes)
    return r


def test_validate_report_rejects_garbage() -> None:
    with pytest.raises(AgentError):
        validate_report([])
    with pytest.raises(AgentError):
        validate_report({"listening_ports": "x"})
    with pytest.raises(AgentError):
        validate_report({"autostart": [{"label": "x"}] * 501})
    clean = validate_report({"system": [{"hostname": "a\x1b[2Jb" + "x" * 900}], "evil": [1]})
    assert set(clean) >= {"system", "autostart"} and "evil" not in clean
    assert (
        "\x1b" not in clean["system"][0]["hostname"] and len(clean["system"][0]["hostname"]) == 500
    )


def test_first_report_learns_then_new_items_become_incidents(laptop: Store) -> None:
    first = process_report(laptop, MAC_A, REPORT, now=T0)
    assert first.learn_only and first.incidents == 0
    items = laptop.host_items(MAC_A)
    assert {i["key"] for i in items if i["kind"] == "port"} == {
        "5000/tcp ControlCenter"
    }  # loopback weg
    assert {i["key"] for i in items if i["kind"] == "autostart"} == {
        "com.vendor.updater"
    }  # /System weg

    later = T0 + timedelta(minutes=10)
    r = report()
    r["listening_ports"].append(
        {
            "port": "4444",
            "protocol": "6",
            "address": "0.0.0.0",
            "name": "nc",
            "path": "/Users/anna/nc",
        }
    )
    r["autostart"].append(
        {"label": "com.evil.persist", "path": "/Users/anna/Library/LaunchAgents/x.plist"}
    )
    r["logged_in_users"].append({"user": "anna", "type": "user", "host": "192.0.2.66"})
    second = process_report(laptop, MAC_A, r, now=later)
    assert not second.learn_only and second.incidents == 3
    rules = sorted(i.rule for i in laptop.incidents())
    assert rules == ["agent_autostart", "agent_login", "agent_port"]
    port = next(i for i in laptop.incidents() if i.rule == "agent_port")
    assert port.details["path"] == "~/nc"  # Benutzername entfernt
    ctx = json.dumps(build_context(port, laptop.device(MAC_A), []))
    assert "anna" not in ctx and "4444/tcp" in ctx

    again = process_report(laptop, MAC_A, r, now=later + timedelta(minutes=10))
    assert again.incidents == 0  # schon bekannt


def test_posture_incident_and_auto_resolve(laptop: Store) -> None:
    process_report(laptop, MAC_A, report(firewall=[{"global_state": "0"}]), now=T0)
    [inc] = laptop.incidents()
    assert inc.rule == "agent_posture" and "Firewall" in inc.title
    assert laptop.agent(MAC_A)["posture"]["firewall"] is False  # type: ignore[index]
    process_report(laptop, MAC_A, REPORT, now=T0 + timedelta(minutes=10))
    resolved = laptop.incident_by_id(inc.id or 0)
    assert resolved is not None and resolved.status is IncidentStatus.RESOLVED
    assert "wieder eingeschaltet" in resolved.note


def test_unknown_posture_is_not_an_incident(laptop: Store) -> None:
    process_report(laptop, MAC_A, report(firewall=[], sip=[]), now=T0)
    assert laptop.incidents() == []
    assert laptop.agent(MAC_A)["posture"]["firewall"] is None  # type: ignore[index]


def test_company_device_cannot_report(laptop: Store) -> None:
    set_trust(laptop, MAC_A, TrustLevel.COMPANY)
    assert laptop.agent(MAC_A) is None  # Agent beim Markieren entfernt
    with pytest.raises(AgentError, match="Firmengerät"):
        process_report(laptop, MAC_A, REPORT, now=T0)


# --- API ------------------------------------------------------------------------


@pytest.fixture
def api(tmp_path: Path) -> tuple[TestClient, str, Path]:
    path = tmp_path / "a.db"
    s = Store(path)
    s.save_device(Device(mac=MAC_A, first_seen=T0, last_seen=T0, name="Laptop"))
    token, token_hash = new_token()
    s.add_agent(MAC_A, token_hash, T0)
    s.close()
    client = TestClient(create_app(WebConfig(db_path=path, password="x" * 12)))
    return client, token, path


def test_api_report_flow(api: tuple[TestClient, str, Path]) -> None:
    client, token, path = api
    auth = {"Authorization": f"Bearer {token}"}
    assert client.post("/api/agent/report", json=REPORT).status_code == 401
    assert (
        client.post(
            "/api/agent/report", json=REPORT, headers={"Authorization": "Bearer falsch"}
        ).status_code
        == 401
    )
    r = client.post("/api/agent/report", json=REPORT, headers=auth)  # ohne Origin: erlaubt (Token)
    assert r.status_code == 200 and r.json()["lernlauf"] is True
    assert client.post("/api/agent/report", json=REPORT, headers=auth).status_code == 429
    s = Store(path)
    assert s.agent(MAC_A)["hostname"] == "mac-anna.local"  # type: ignore[index]
    s.close()


def test_api_rejects_bad_and_huge_reports(api: tuple[TestClient, str, Path]) -> None:
    client, token, _ = api
    auth = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    assert client.post("/api/agent/report", content=b"kein json", headers=auth).status_code == 400
    huge = b'{"system": [{"x": "' + b"a" * (1024 * 1024) + b'"}]}'
    assert client.post("/api/agent/report", content=huge, headers=auth).status_code == 413


def test_dashboard_shows_laptop_section(api: tuple[TestClient, str, Path]) -> None:
    client, token, _ = api
    client.post(
        "/api/agent/report",
        json=report(firewall=[{"global_state": "0"}]),
        headers={"Authorization": f"Bearer {token}"},
    )
    client.post("/login", data={"password": "x" * 12}, headers={"Origin": "http://testserver"})
    html = client.get(f"/devices/{MAC_A}").text
    assert "Laptop" in html and "Firewall: aus" in html and "com.vendor.updater" in html
    assert "style=" not in html
    assert ">Agent<" in client.get("/devices").text


# --- CLI ------------------------------------------------------------------------


def test_cli_agent_add_list_remove(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "a.db"
    monkeypatch.setenv("ALUCO_DB_PATH", str(path))
    s = Store(path)
    s.save_device(Device(mac=MAC_A, first_seen=T0, last_seen=T0, name="Laptop Wohnzimmer"))
    s.save_device(
        Device(
            mac=MAC_B, first_seen=T0, last_seen=T0, name="Arbeitsrechner", trust=TrustLevel.COMPANY
        )
    )
    s.close()
    assert main(["agent", "add", "wohnzimmer"]) == 0
    token = capsys.readouterr().out.strip().splitlines()[-1]
    s = Store(path)
    assert s.agent_by_token_hash(hash_token(token)) is not None
    s.close()
    assert main(["agent", "add", MAC_B]) == 1
    assert "Firmengeräte" in capsys.readouterr().err
    assert main(["agent", "list"]) == 0 and MAC_A in capsys.readouterr().out
    assert main(["agent", "remove", MAC_A]) == 0 and "entfernt" in capsys.readouterr().out
