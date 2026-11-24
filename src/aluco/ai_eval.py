"""Beispielsatz für die KI-Vorbewertung: Qualität messen und Modelle vergleichen (Issue #24).

Die Fälle stehen in ``ai_eval_cases.json``. Jeder Fall wird wie ein echter Vorfall über
``aluco.ai.build_context`` aufbereitet – geprüft wird also auch, was die KI wirklich bekommt.
``erwartet`` nennt je Feld die Werte, die noch als richtig gelten.

Läuft nicht in der normalen CI (braucht ein Modell): ``aluco ai-eval --provider ollama``.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from aluco.ai import RULE_TEXT, AssessmentError, Assessor, Judgement, build_context
from aluco.model import Device, Incident, IncidentStatus, Severity, TrustLevel, utcnow

ALLOWED = {
    "verdict": ("harmlos", "beobachten", "verdaechtig"),
    "risk": ("niedrig", "mittel", "hoch"),
    "action": ("erledigen", "ignorieren", "pruefen", "sperren"),
}
# Dokumentations-MAC (RFC 7042) – wird ohnehin nie an die KI gesendet.
EXAMPLE_MAC = "00:00:5e:00:53:01"

# Formulierungen, die Wissen von außen behaupten („die Domain ist bekannt für …“). „Gerät
# ist bekannt“ allein meint meist die Vertrauensstufe und zählt nicht. Die KI
# bekommt nur die Vorfallsdaten – solche Sätze sind oft erfunden. Kein Fehler, aber zu prüfen.
_SUSPECT = re.compile(
    r"\b(bekannt|berüchtigt)\s+(für|als|dafür)\b"
    r"|\bberüchtigt"
    r"|\bbekannt\s+und\s+(autorisiert|legitim|vertrauenswürdig|harmlos|seriös)"
    r"|\blaut\s+(berichten|quellen|experten)\b"
    r"|\b(sicherheitsforscher|berichte|studien)\s+(zeigen|belegen|melden)\b",
    re.IGNORECASE,
)


class CaseError(ValueError):
    """Beispielsatz fehlerhaft."""


@dataclass(frozen=True)
class Case:
    id: str
    title: str
    incident: Incident
    device: Device | None
    known_domains: list[str]
    expected: dict[str, tuple[str, ...]]

    def context(self) -> dict[str, Any]:
        return build_context(self.incident, self.device, self.known_domains)


@dataclass
class CaseResult:
    case: Case
    judgement: Judgement | None = None
    error: str | None = None
    misses: list[str] = field(default_factory=list)
    suspect: list[str] = field(default_factory=list)
    seconds: float = 0.0

    @property
    def passed(self) -> bool:
        return self.error is None and not self.misses


def default_path() -> Path:
    return Path(str(resources.files("aluco") / "ai_eval_cases.json"))


def load_cases(path: Path | None = None) -> list[Case]:
    raw = json.loads((path or default_path()).read_text(encoding="utf-8"))
    now = utcnow()
    cases: list[Case] = []
    seen: set[str] = set()
    for item in raw.get("faelle", []):
        cid = str(item.get("id", ""))
        if not cid or cid in seen:
            raise CaseError(f"Fall-ID fehlt oder doppelt: {cid!r}")
        seen.add(cid)
        rule = item.get("regel")
        if rule not in RULE_TEXT:
            raise CaseError(f"{cid}: unbekannte Regel {rule!r}")
        expected = {k: tuple(v) for k, v in item.get("erwartet", {}).items()}
        if not {"verdict", "action"} <= expected.keys() or not expected.keys() <= ALLOWED.keys():
            raise CaseError(f"{cid}: 'erwartet' braucht verdict und action (optional risk)")
        for key, values in expected.items():
            if not values or not set(values) <= set(ALLOWED[key]):
                raise CaseError(f"{cid}: ungültige Erwartung für {key}: {values}")
        dev = item.get("geraet")
        device = None
        if dev is not None:
            device = Device(
                mac=EXAMPLE_MAC,
                first_seen=now,
                last_seen=now,
                vendor=dev.get("vendor"),
                trust=TrustLevel(dev.get("trust", "unknown")),
                online=dev.get("online"),
            )
            if device.is_company:
                raise CaseError(f"{cid}: Firmengeräte werden nie bewertet")
        incident = Incident(
            id=None,
            fingerprint=f"eval:{cid}",
            rule=rule,
            severity=Severity[str(item.get("schwere", "medium")).upper()],
            title=str(item.get("titel", cid)),
            status=IncidentStatus.NEW,
            created_at=now,
            updated_at=now,
            device_mac=EXAMPLE_MAC if device else None,
            details={k: str(v) for k, v in item.get("details", {}).items()},
            occurrences=int(item.get("anzahl", 1)),
        )
        cases.append(
            Case(
                id=cid,
                title=incident.title,
                incident=incident,
                device=device,
                known_domains=list(item.get("bekannte_domains", [])),
                expected=expected,
            )
        )
    if not cases:
        raise CaseError("Keine Fälle gefunden")
    return cases


def suspect_claims(j: Judgement) -> list[str]:
    return [text for text in [j.summary, *j.reasons] if _SUSPECT.search(text)]


def check(case: Case, j: Judgement) -> list[str]:
    misses = []
    for key, allowed in case.expected.items():
        value = getattr(j, key)
        if value not in allowed:
            misses.append(f"{key}={value} (erwartet: {'/'.join(allowed)})")
    return misses


def evaluate(
    assessor: Assessor,
    cases: Iterable[Case],
    repeat: int = 1,
    on_result: Callable[[CaseResult], None] | None = None,
) -> list[CaseResult]:
    """Jeden Fall ``repeat``-mal bewerten. Fehler des Modells zählen als nicht bestanden."""
    results = []
    for case in cases:
        for _ in range(repeat):
            start = time.monotonic()
            result = CaseResult(case=case)
            try:
                result.judgement = assessor.judge(case.context())
            except AssessmentError as e:
                result.error = str(e)
            result.seconds = time.monotonic() - start
            if result.judgement is not None:
                result.misses = check(case, result.judgement)
                result.suspect = suspect_claims(result.judgement)
            results.append(result)
            if on_result:
                on_result(result)
    return results


def summarize(results: list[CaseResult]) -> dict[str, Any]:
    by_rule: dict[str, list[int]] = {}
    for r in results:
        stats = by_rule.setdefault(r.case.incident.rule, [0, 0])
        stats[0] += r.passed
        stats[1] += 1
    total = len(results)
    passed = sum(r.passed for r in results)
    return {
        "total": total,
        "passed": passed,
        "rate": passed / total if total else 0.0,
        "errors": sum(r.error is not None for r in results),
        "suspect": sum(bool(r.suspect) for r in results),
        "seconds": sum(r.seconds for r in results),
        "by_rule": {rule: {"passed": p, "total": t} for rule, (p, t) in sorted(by_rule.items())},
    }
