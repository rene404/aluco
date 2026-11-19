"""Meldungen über neue Vorfälle (Start: ntfy)."""

from __future__ import annotations

import logging
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Protocol

from aluco.ai import Assessment
from aluco.model import Incident, Severity

log = logging.getLogger(__name__)

# ntfy-Priorität 1 (min) … 5 (max)
_PRIORITY = {
    Severity.INFO: "1",
    Severity.LOW: "2",
    Severity.MEDIUM: "3",
    Severity.HIGH: "4",
    Severity.CRITICAL: "5",
}
_SEVERITY_DE = {
    Severity.INFO: "Info",
    Severity.LOW: "niedrig",
    Severity.MEDIUM: "mittel",
    Severity.HIGH: "hoch",
    Severity.CRITICAL: "kritisch",
}


class Notifier(Protocol):
    def send(self, incident: Incident, assessment: Assessment | None = None) -> None: ...


# (URL, Body, Header) → None; austauschbar für Tests.
Poster = Callable[[str, bytes, dict[str, str]], None]


def _http_post(url: str, body: bytes, headers: dict[str, str]) -> None:
    if not url.startswith(("https://", "http://")):
        raise ValueError(f"Ungültige ntfy-URL: {url!r}")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")  # noqa: S310
    with urllib.request.urlopen(req, timeout=10):  # noqa: S310 – Schema oben geprüft
        pass


class NtfyNotifier:
    """Sendet an ein ntfy-Topic. Der Inhalt verlässt das Heimnetz, wenn der ntfy-Server
    extern ist – dann ``minimal=True`` erwägen (keine Geräte-/Domainnamen)."""

    def __init__(
        self,
        url: str,
        token: str | None = None,
        minimal: bool = False,
        post: Poster = _http_post,
    ) -> None:
        self._url = url
        self._token = token
        self._minimal = minimal
        self._post = post

    def __repr__(self) -> str:
        return "NtfyNotifier(…)"

    def send(self, incident: Incident, assessment: Assessment | None = None) -> None:
        severity = _SEVERITY_DE[incident.severity]
        if self._minimal:
            title, body = "Aluco: neuer Vorfall", f"Schweregrad {severity}. Details im Dashboard."
        else:
            title = f"Aluco ({severity})"
            body = incident.title
            if assessment is not None:
                body += (
                    f"\n\nKI: {assessment.verdict_de} – {assessment.summary}"
                    f"\nEmpfehlung: {assessment.action_de}"
                )
        headers = {
            "Title": title,
            "Priority": _PRIORITY[incident.severity],
            "Tags": "owl",
            "Content-Type": "text/plain; charset=utf-8",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        self._post(self._url, body.encode(), headers)


def notify_all(
    notifier: Notifier,
    incidents: list[Incident],
    min_severity: Severity,
    assessments: dict[int, Assessment] | None = None,
) -> tuple[int, int]:
    """Meldet Vorfälle ab ``min_severity``. Fehler beim Senden stoppen den Lauf nicht.

    Liefert (gesendet, fehlgeschlagen).
    """
    sent = failed = 0
    for incident in incidents:
        if incident.severity < min_severity:
            continue
        try:
            notifier.send(incident, (assessments or {}).get(incident.id or -1))
            sent += 1
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            failed += 1
            log.warning("Meldung für Vorfall %s fehlgeschlagen: %s", incident.id, e)
    return sent, failed
