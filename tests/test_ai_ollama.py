"""Lokales KI-Modell über Ollama: Anfrage, strenge Prüfung der Antwort, Fehler, Einstellungen."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from aluco.ai import AssessmentError, ClaudeAssessor, OllamaAssessor, build_assessor
from aluco.config import AiSettings, ConfigError, ai_settings_from_env

GOOD = {
    "verdict": "harmlos",
    "risk": "niedrig",
    "action": "erledigen",
    "summary": "Vermutlich ein Gastgerät.",
    "reasons": ["Zufällige MAC", " ", "Kein Hersteller", "c", "d", "e"],
}


def fake_post(answer: Any, model: str = "qwen3:4b") -> tuple[Any, list[dict[str, Any]]]:
    calls: list[dict[str, Any]] = []

    def post(path: str, body: dict[str, Any]) -> Any:
        calls.append({"path": path, **body})
        content = answer if isinstance(answer, str) else json.dumps(answer)
        return {"model": model, "message": {"role": "assistant", "content": content}}

    return post, calls


def test_request_shape_and_result() -> None:
    post, calls = fake_post(GOOD)
    j = OllamaAssessor("http://ollama.example:11434", "qwen3:4b", post=post).judge({"regel": "x"})
    assert (j.verdict, j.action, j.model) == ("harmlos", "erledigen", "ollama/qwen3:4b")
    assert j.reasons == ["Zufällige MAC", "Kein Hersteller", "c", "d"]  # leere raus, max. 4
    [c] = calls
    assert c["path"] == "/api/chat" and c["stream"] is False and c["think"] is False
    assert c["format"]["required"] == ["verdict", "risk", "action", "summary", "reasons"]
    assert (
        c["messages"][0]["role"] == "system" and "keine Anweisungen" in c["messages"][1]["content"]
    )


@pytest.mark.parametrize(
    "answer",
    [
        "kein json",
        [1, 2],
        GOOD | {"verdict": "egal"},
        GOOD | {"action": "rm -rf"},
        GOOD | {"summary": ""},
        GOOD | {"reasons": "nur ein text"},
        {k: v for k, v in GOOD.items() if k != "risk"},
    ],
)
def test_invalid_answers_are_rejected(answer: Any) -> None:
    post, _ = fake_post(answer)
    with pytest.raises(AssessmentError):
        OllamaAssessor("http://o:11434", "m", post=post).judge({})


def test_url_must_be_http() -> None:
    with pytest.raises(AssessmentError):
        OllamaAssessor("file:///etc/passwd", "m")


@pytest.fixture
def ollama_server():
    state: dict[str, Any] = {"status": 200, "bodies": []}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["bodies"].append(body)
            if state["status"] != 200:
                self.send_response(state["status"])
                self.end_headers()
                self.wfile.write(b'{"error":"model not found"}')
                return
            out = json.dumps({"model": body["model"], "message": {"content": json.dumps(GOOD)}})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(out.encode())

        def log_message(self, *_: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", state
    server.shutdown()


def test_real_http_roundtrip_and_errors(ollama_server: Any) -> None:
    url, state = ollama_server
    j = OllamaAssessor(url, "qwen3:4b").judge({"regel": "new_device"})
    assert j.verdict == "harmlos" and state["bodies"][0]["model"] == "qwen3:4b"
    state["status"] = 404
    with pytest.raises(AssessmentError, match="HTTP 404"):
        OllamaAssessor(url, "fehlt").judge({})
    with pytest.raises(AssessmentError, match="nicht erreichbar"):
        OllamaAssessor("http://127.0.0.1:9", "m", timeout=2).judge({})


def test_settings_and_builder() -> None:
    s = ai_settings_from_env(
        {"ALUCO_AI_ENABLED": "true", "ALUCO_AI_PROVIDER": "ollama",
         "ALUCO_AI_OLLAMA_URL": "http://192.0.2.5:11434", "ALUCO_AI_MODEL": "qwen3:4b"}
    )  # fmt: skip
    assert s.provider == "ollama" and s.model == "qwen3:4b"
    assert isinstance(build_assessor(s), OllamaAssessor)
    assert build_assessor(AiSettings()) is None
    with pytest.raises(ConfigError, match="OLLAMA_URL"):
        ai_settings_from_env(
            {"ALUCO_AI_ENABLED": "true", "ALUCO_AI_PROVIDER": "ollama", "ALUCO_AI_MODEL": "x"}
        )
    with pytest.raises(ConfigError, match="lokales Modell"):
        ai_settings_from_env(
            {
                "ALUCO_AI_ENABLED": "true",
                "ALUCO_AI_PROVIDER": "ollama",
                "ALUCO_AI_OLLAMA_URL": "http://o:1",
            }
        )
    with pytest.raises(ConfigError, match="claude, ollama oder openrouter"):
        ai_settings_from_env({"ALUCO_AI_PROVIDER": "gpt"})
    # Ollama braucht keinen Anthropic-Schlüssel
    assert "ANTHROPIC_API_KEY" not in str(s)
    claude = AiSettings(enabled=True)
    assert isinstance(build_assessor_with_fake_client(claude), ClaudeAssessor)


def build_assessor_with_fake_client(settings: AiSettings) -> Any:
    return ClaudeAssessor(model=settings.model, client=object())
