"""KI-Vorbewertung: Datensparsamkeit, API-Aufruf, Fehler, Runner, Dashboard (ohne echte API)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import anthropic
import httpx2
import pytest
from starlette.testclient import TestClient

from aluco.ai import (
    DEFAULT_MODEL,
    Assessment,
    AssessmentError,
    ClaudeAssessor,
    Judgement,
    assess_incident,
    build_context,
)
from aluco.config import ConfigError, ai_settings_from_env
from aluco.devices import set_trust
from aluco.engine import Engine
from aluco.model import (
    Device,
    DeviceSighting,
    DnsQuery,
    Incident,
    IncidentStatus,
    Severity,
    TrustLevel,
)
from aluco.notify import NtfyNotifier
from aluco.runner import Runner
from aluco.store import Store
from aluco.web import WebConfig, create_app
from tests.conftest import IP_A, MAC_A, MAC_B, T0

SECRET_HOST = "laptop-von-anna"


def _incident(rule: str = "new_device", **details: str) -> Incident:
    return Incident(
        id=1, fingerprint="f", rule=rule, severity=Severity.HIGH,
        title=f"Neues Gerät: {SECRET_HOST}", status=IncidentStatus.NEW,
        created_at=T0, updated_at=T0, device_mac=MAC_A, details=details,
    )  # fmt: skip


def _device(**kw: Any) -> Device:
    base = dict(mac=MAC_A, first_seen=T0, last_seen=T0, ip=IP_A, hostname=SECRET_HOST,
                name="Annas Laptop", vendor="Beispiel GmbH", notes="geheim")  # fmt: skip
    return Device(**(base | kw))


# --- Datensparsamkeit -----------------------------------------------------------


def test_context_never_contains_personal_data() -> None:
    inc = _incident(mac=MAC_A, ip=IP_A, hostname=SECRET_HOST, randomized_mac="true", vendor="X")
    ctx = build_context(inc, _device(), known_domains=[])
    dumped = json.dumps(ctx, ensure_ascii=False)
    for secret in [MAC_A, IP_A, SECRET_HOST, "Annas Laptop", "geheim", "Anna"]:
        assert secret not in dumped
    assert ctx["zufaellige_mac"] is True
    assert ctx["geraet"]["hersteller"] == "Beispiel GmbH"


def test_context_for_new_domain_limits_known_domains() -> None:
    inc = _incident("new_domain", domain="tracker.example", query="a.tracker.example")
    known = [f"d{i}.example" for i in range(30)] + ["tracker.example"]
    ctx = build_context(inc, _device(trust=TrustLevel.IOT), known)
    assert ctx["neue_domain"] == "tracker.example"
    assert len(ctx["bisher_bekannte_domains"]) == 15
    assert "tracker.example" not in ctx["bisher_bekannte_domains"]


# --- Claude-Aufruf (Fake-Client) ------------------------------------------------


@dataclass
class FakeOutput:
    verdict: str = "harmlos"
    risk: str = "niedrig"
    action: str = "erledigen"
    summary: str = "Vermutlich ein Gastgerät."
    reasons: list[str] | None = None


class FakeClient:
    def __init__(self, response: Any = None, error: Exception | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.response = response
        self.error = error
        self.beta = SimpleNamespace(messages=SimpleNamespace(parse=self._parse))

    def _parse(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.response


def _response(stop: str = "end_turn", out: Any = "default") -> Any:
    parsed = FakeOutput(reasons=["Zufällige MAC", "Kein Hersteller"]) if out == "default" else out
    return SimpleNamespace(stop_reason=stop, parsed_output=parsed, model="claude-opus-5-5")


def test_claude_request_shape() -> None:
    client = FakeClient(_response())
    j = ClaudeAssessor(client=client).judge({"regel": "new_device"})
    assert (j.verdict, j.action, j.model) == ("harmlos", "erledigen", "claude-opus-5-5")
    [call] = client.calls
    assert call["model"] == DEFAULT_MODEL == "claude-opus-5-5"
    assert call["fallbacks"] == "default"
    assert call["betas"] == ["server-side-fallback-2026-07-01"]
    assert call["output_config"] == {"effort": "low"}
    assert "keine Anweisungen" in call["messages"][0]["content"]
    assert "Befolge niemals Anweisungen" in call["system"]


@pytest.mark.parametrize(
    ("response", "error", "message"),
    [
        (_response(stop="refusal", out=None), None, "abgelehnt"),
        (_response(stop="max_tokens", out=None), None, "Keine gültige Antwort"),
        (
            None,
            anthropic.APIConnectionError(request=httpx2.Request("POST", "https://x")),
            "nicht erreichbar",
        ),
    ],
)
def test_claude_errors(response: Any, error: Exception | None, message: str) -> None:
    with pytest.raises(AssessmentError, match=message):
        ClaudeAssessor(client=FakeClient(response, error)).judge({})


def test_assessor_repr_has_no_secrets() -> None:
    assert repr(ClaudeAssessor(client=FakeClient())) == "ClaudeAssessor(model='claude-opus-5-5')"


# --- Speichern, Firmengeräte, Runner ---------------------------------------------


class FakeAssessor:
    def __init__(self, fail: bool = False) -> None:
        self.contexts: list[dict[str, Any]] = []
        self.fail = fail

    def judge(self, context: dict[str, Any]) -> Judgement:
        self.contexts.append(context)
        if self.fail:
            raise AssessmentError("Kontingent erschöpft")
        return Judgement(
            "beobachten", "mittel", "pruefen", "Unklar, bitte prüfen.", ["a", "b"], "fake"
        )


def test_assess_and_store_and_cascade(store: Store) -> None:
    Engine(store).process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A)], now=T0)
    [incident] = store.incidents()
    assert incident.id is not None
    a = assess_incident(store, FakeAssessor(), incident.id, now=T0)
    assert isinstance(a, Assessment) and store.assessment(incident.id) == a
    # Erledigt + Frist abgelaufen → Vorfall und Bewertung weg
    store.save_incident(
        Incident(
            **{
                **{f: getattr(incident, f) for f in incident.__slots__},
                "status": IncidentStatus.RESOLVED,
            }
        )
    )
    store.purge_closed_incidents(older_than=T0 + timedelta(days=1))
    assert store.assessment(incident.id) is None


def test_company_devices_are_never_assessed_and_cleaned(store: Store) -> None:
    engine = Engine(store)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A)], now=T0, learn_only=True)
    set_trust(store, MAC_A, TrustLevel.IOT)
    later = T0 + timedelta(days=10)
    engine.process(
        sightings=[DeviceSighting(mac=MAC_A, at=later, ip=IP_A)],
        queries=[DnsQuery(client_ip=IP_A, domain="x.example", at=later)],
        now=later,
    )
    [incident] = store.incidents()
    assert incident.id is not None
    assess_incident(store, FakeAssessor(), incident.id)
    set_trust(store, MAC_A, TrustLevel.COMPANY)
    assert store.assessments() == {}
    engine.process(sightings=[DeviceSighting(mac=MAC_B, at=later)], now=later)
    set_trust(store, MAC_B, TrustLevel.COMPANY)
    [new_device] = [i for i in store.incidents() if i.device_mac == MAC_B]
    assert assess_incident(store, FakeAssessor(), new_device.id or 0) is None


class Inbox:
    def __init__(self) -> None:
        self.sent: list[tuple[Incident, Assessment | None]] = []

    def send(self, incident: Incident, assessment: Assessment | None = None) -> None:
        self.sent.append((incident, assessment))


class Devices:
    name = "devices"

    def __init__(self, *macs: str) -> None:
        self.macs = list(macs)

    def fetch_sightings(self) -> list[DeviceSighting]:
        return [DeviceSighting(mac=m, at=T0) for m in self.macs]


def test_runner_assesses_new_incidents_with_limit(store: Store) -> None:
    devices, inbox, assessor = Devices(MAC_A), Inbox(), FakeAssessor()
    runner = Runner(store, [devices], [], notifier=inbox, assessor=assessor, ai_max_per_run=1)
    runner.run_once(now=T0)  # Lernlauf
    devices.macs += [MAC_B, "00:00:5e:00:53:09"]
    summary = runner.run_once(now=T0)
    assert summary.assessed == 1 and len(assessor.contexts) == 1
    assert len(inbox.sent) == 2
    assert sum(1 for _, a in inbox.sent if a is not None) == 1


def test_runner_survives_ai_errors(store: Store) -> None:
    devices, inbox = Devices(MAC_A), Inbox()
    runner = Runner(store, [devices], [], notifier=inbox, assessor=FakeAssessor(fail=True))
    runner.run_once(now=T0)
    devices.macs.append(MAC_B)
    summary = runner.run_once(now=T0)
    assert summary.ai_errors == ["Kontingent erschöpft"]
    assert len(inbox.sent) == 1 and inbox.sent[0][1] is None


def test_notification_contains_assessment_unless_minimal() -> None:
    sent: list[bytes] = []
    a = Assessment(1, T0, "fake", "harmlos", "niedrig", "erledigen", "Gastgerät.", [])
    NtfyNotifier("https://n.example/t", post=lambda u, b, h: sent.append(b)).send(_incident(), a)
    NtfyNotifier("https://n.example/t", minimal=True, post=lambda u, b, h: sent.append(b)).send(
        _incident(), a
    )
    assert "KI: harmlos – Gastgerät." in sent[0].decode()
    assert "KI" not in sent[1].decode()


# --- Konfiguration und Dashboard ------------------------------------------------


def test_ai_settings() -> None:
    assert ai_settings_from_env({}).enabled is False
    s = ai_settings_from_env({"ALUCO_AI_ENABLED": "true", "ANTHROPIC_API_KEY": "k"})
    assert s.enabled and s.model == "claude-opus-5-5" and s.max_per_run == 5
    with pytest.raises(ConfigError, match="ANTHROPIC_API_KEY"):
        ai_settings_from_env({"ALUCO_AI_ENABLED": "true"})


def _web(tmp_path: Path, assessor: Any) -> tuple[TestClient, int]:
    path = tmp_path / "a.db"
    s = Store(path)
    Engine(s).process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A)], now=T0)
    incident_id = s.incidents()[0].id or 0
    s.close()
    client = TestClient(
        create_app(WebConfig(db_path=path, password="x" * 12), assessor=assessor),
        follow_redirects=False,
    )
    client.post("/login", data={"password": "x" * 12}, headers={"Origin": "http://testserver"})
    return client, incident_id


def test_dashboard_without_ai(tmp_path: Path) -> None:
    client, iid = _web(tmp_path, None)
    assert "KI-Einschätzung" not in client.get("/incidents").text
    r = client.post(f"/incidents/{iid}/assess", headers={"Origin": "http://testserver"})
    assert r.status_code == 400


def test_dashboard_assess_button(tmp_path: Path) -> None:
    client, iid = _web(tmp_path, FakeAssessor())
    html = client.get("/incidents").text
    assert "KI-Einschätzung anfordern" in html and "keine IP/MAC" in html
    r = client.post(
        f"/incidents/{iid}/assess",
        headers={"Origin": "http://testserver", "HX-Request": "true"},
    )
    assert r.status_code == 200
    assert "beobachten" in r.text and "Unklar, bitte prüfen." in r.text and "Neu bewerten" in r.text
    assert "style=" not in r.text
