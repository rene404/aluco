"""Beispielsatz für die KI-Vorbewertung (#24): Fälle, Datenschutz, Auswertung, Kommandozeile."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from aluco import __main__ as cli
from aluco.ai import RULE_TEXT, AssessmentError, Judgement, OllamaAssessor
from aluco.ai_eval import (
    EXAMPLE_MAC,
    CaseError,
    evaluate,
    load_cases,
    summarize,
    suspect_claims,
)

IPV4 = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")


def judgement(verdict: str, risk: str, action: str, summary: str = "Kurz.") -> Judgement:
    return Judgement(verdict, risk, action, summary, ["Grund"], model="fake")


class Perfect:
    """Antwortet je Fall mit dem ersten erlaubten Wert – muss alles bestehen."""

    def __init__(self) -> None:
        self.by_context = {json.dumps(c.context(), sort_keys=True): c for c in load_cases()}

    def judge(self, context: dict[str, Any]) -> Judgement:
        case = self.by_context[json.dumps(context, sort_keys=True)]
        e = case.expected
        return judgement(e["verdict"][0], e.get("risk", ("mittel",))[0], e["action"][0])


class Alarmist:
    def judge(self, context: dict[str, Any]) -> Judgement:
        return judgement("verdaechtig", "hoch", "sperren")


# --- Beispielsatz ----------------------------------------------------------------------


def test_cases_cover_every_rule_and_known_weak_spots() -> None:
    cases = load_cases()
    assert len(cases) >= 20
    assert {c.incident.rule for c in cases} == set(RULE_TEXT)
    ids = {c.id for c in cases}
    assert "geraet-zufaellige-mac" in ids  # Fehler aus #19
    assert sum("einschleusung" in i for i in ids) >= 3
    assert sum(bool(c.history) for c in cases) >= 4  # Zusammenhänge pro Gerät (#26)


def test_contexts_contain_no_identifiers() -> None:
    """Der Beispielsatz prüft nebenbei die Datensparsamkeit von build_context."""
    for case in load_cases():
        text = json.dumps(case.context(), ensure_ascii=False)
        assert EXAMPLE_MAC not in text, case.id
        assert not IPV4.search(text), case.id
        assert case.title not in text, case.id


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda f: f.append(dict(f[0])), "doppelt"),
        (lambda f: f[0].update(regel="gibt_es_nicht"), "unbekannte Regel"),
        (lambda f: f[0].update(erwartet={"verdict": ["harmlos"]}), "verdict und action"),
        (lambda f: f[0]["erwartet"].update(action=["abschalten"]), "ungültige Erwartung"),
        (lambda f: f[0]["geraet"].update(trust="company"), "Firmengeräte"),
        (lambda f: f[0].update(vorgeschichte=[{"regel": "x", "status": "new"}]), "Vorgeschichte"),
        (
            lambda f: f[0].update(
                vorgeschichte=[{"regel": "bad_domain", "status": "new", "ki": "?"}]
            ),
            "KI-Einstufung",
        ),
    ],
)
def test_broken_case_files_are_rejected(tmp_path: Path, change: Any, message: str) -> None:
    from aluco.ai_eval import default_path

    data = json.loads(default_path().read_text(encoding="utf-8"))
    change(data["faelle"])
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(CaseError, match=message):
        load_cases(path)


# --- Auswertung ------------------------------------------------------------------------


def test_perfect_assessor_passes_everything() -> None:
    results = evaluate(Perfect(), load_cases(), repeat=2)
    s = summarize(results)
    assert s["rate"] == 1.0 and s["total"] == 2 * len(load_cases())
    assert set(s["by_rule"]) == set(RULE_TEXT)


def test_alarmist_fails_the_random_mac_case() -> None:
    [case] = [c for c in load_cases() if c.id == "geraet-zufaellige-mac"]
    [r] = evaluate(Alarmist(), [case])
    assert not r.passed
    assert "verdict=verdaechtig (erwartet: harmlos/beobachten)" in r.misses
    assert any(m.startswith("action=sperren") for m in r.misses)


def test_model_errors_count_as_failed() -> None:
    class Broken:
        def judge(self, context: dict[str, Any]) -> Judgement:
            raise AssessmentError("Ollama: Antwort ist kein gültiges JSON")

    results = evaluate(Broken(), load_cases()[:3])
    s = summarize(results)
    assert s["errors"] == 3 and s["passed"] == 0
    assert results[0].error and not results[0].passed


@pytest.mark.parametrize(
    ("text", "flag"),
    [
        ("Die Domain ist bekannt für Malware- und Phishing-Aktivitäten.", True),
        ("Der Hersteller gilt als berüchtigt.", True),
        ("Laut Berichten nutzen Angreifer diese Adresse.", True),
        ("Die Domain steht auf einer Bedrohungsliste.", False),
        ("Ein bekanntes Gerät hat eine neue Domain angefragt.", False),
        ("Gerät ist bekannt und von Apple hergestellt", False),  # Vertrauensstufe
        ("Das Label ist bekannt und autorisiert.", True),
    ],
)
def test_suspect_claims(text: str, flag: bool) -> None:
    assert bool(suspect_claims(judgement("beobachten", "mittel", "pruefen", text))) is flag


# --- Kommandozeile ---------------------------------------------------------------------


def test_cli_claude_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ALUCO_AI_PROVIDER", raising=False)
    assert cli.main(["ai-eval"]) == 2


def test_cli_ollama_needs_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALUCO_AI_MODEL", raising=False)
    assert cli.main(["ai-eval", "--provider", "ollama", "--ollama-url", "http://x:1"]) == 2


def test_cli_json_and_min_rate(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(OllamaAssessor, "judge", lambda self, ctx: Alarmist().judge(ctx))
    base = ["ai-eval", "--provider", "ollama", "--ollama-url", "http://x:1", "--model", "m"]
    one = ["--case", "geraet-zufaellige-mac", "--case", "schad-oft"]
    assert cli.main([*base, *one, "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert (out["passed"], out["total"]) == (1, 2)  # Schad-Domain richtig, Zufalls-MAC falsch
    assert cli.main([*base, *one, "--min-rate", "0.9"]) == 1
    assert "Treffer 1/2" in capsys.readouterr().out
    assert cli.main([*base, "--case", "gibt-es-nicht"]) == 2
