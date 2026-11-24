"""KI-Vorbewertung über OpenRouter (OpenAI-kompatibel) – ohne Netz, mit Attrappe."""

from __future__ import annotations

import json
from typing import Any

import pytest

from aluco.ai import AssessmentError, OpenRouterAssessor, build_assessor
from aluco.config import ConfigError, ai_settings_from_env

ANSWER = {
    "verdict": "beobachten",
    "risk": "niedrig",
    "action": "pruefen",
    "summary": "Ein neues Gerät mit privater MAC-Adresse.",
    "reasons": ["Zufällige MAC", "Kein Hersteller"],
}


class Fake:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.bodies: list[dict[str, Any]] = []

    def __call__(self, body: dict[str, Any]) -> Any:
        self.bodies.append(body)
        return self.response


def _ok(content: Any = ANSWER) -> dict[str, Any]:
    text = content if isinstance(content, str) else json.dumps(content)
    return {"model": "anthropic/claude-opus-5.5", "choices": [{"message": {"content": text}}]}


def test_judge_sends_schema_privacy_and_parses() -> None:
    fake = Fake(_ok())
    j = OpenRouterAssessor("sk-or-test", "anthropic/claude-opus-5.5", post=fake).judge(
        {"regel": "new_device", "zufaellige_mac": True}
    )
    assert (j.verdict, j.action, j.model) == (
        "beobachten",
        "pruefen",
        "openrouter/anthropic/claude-opus-5.5",
    )
    [body] = fake.bodies
    assert body["temperature"] == 0
    assert body["provider"] == {"require_parameters": True, "data_collection": "deny"}
    schema = body["response_format"]["json_schema"]
    assert schema["strict"] is True and schema["schema"]["additionalProperties"] is False
    assert body["messages"][0]["role"] == "system" and "Aluco" in body["messages"][0]["content"]
    assert "zufaellige_mac" in body["messages"][1]["content"]


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (_ok("kein json"), "kein gültiges JSON"),
        ({"error": {"message": "No endpoints found"}}, "No endpoints found"),
        (_ok({**ANSWER, "verdict": "egal"}), "verdict"),
        (_ok({**ANSWER, "action": "abschalten"}), "action"),
    ],
)
def test_bad_answers_are_rejected(response: Any, message: str) -> None:
    a = OpenRouterAssessor("k", "anthropic/claude-haiku-5.5", post=Fake(response))
    with pytest.raises(AssessmentError, match=message):
        a.judge({"regel": "new_device"})


def test_constructor_checks_and_repr() -> None:
    with pytest.raises(AssessmentError, match="Schlüssel"):
        OpenRouterAssessor("", "anthropic/claude-opus-5.5")
    with pytest.raises(AssessmentError, match="Anbieter"):
        OpenRouterAssessor("k", "claude-opus-5-5")
    assert "sk-or-geheim" not in repr(OpenRouterAssessor("sk-or-geheim", "anthropic/x"))


def test_settings_and_builder(monkeypatch: pytest.MonkeyPatch) -> None:
    base = {"ALUCO_AI_ENABLED": "true", "ALUCO_AI_PROVIDER": "openrouter"}
    with pytest.raises(ConfigError, match="OPENROUTER_API_KEY"):
        ai_settings_from_env(base)
    settings = ai_settings_from_env(base | {"OPENROUTER_API_KEY": "k"})
    assert settings.model == "anthropic/claude-opus-5.5"
    with pytest.raises(ConfigError, match="mit Anbieter"):
        ai_settings_from_env(
            base | {"OPENROUTER_API_KEY": "k", "ALUCO_AI_MODEL": "claude-opus-5-5"}
        )
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    assert isinstance(build_assessor(settings), OpenRouterAssessor)


def test_cli_openrouter(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from aluco import __main__ as cli

    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert cli.main(["ai-eval", "--provider", "openrouter"]) == 2
    assert "OPENROUTER_API_KEY" in capsys.readouterr().err
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    monkeypatch.setattr(OpenRouterAssessor, "judge", lambda self, ctx: _fake_judgement())
    assert cli.main(["ai-eval", "--provider", "openrouter", "--case", "schad-oft"]) == 0
    assert "openrouter/anthropic/claude-opus-5.5" in capsys.readouterr().out


def _fake_judgement() -> Any:
    from aluco.ai import Judgement

    return Judgement("verdaechtig", "hoch", "sperren", "s", ["r"], model="x")
