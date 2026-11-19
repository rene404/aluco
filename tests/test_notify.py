from __future__ import annotations

import urllib.error

from aluco.model import Incident, IncidentStatus, Severity
from aluco.notify import NtfyNotifier, notify_all
from tests.conftest import MAC_A, T0


def incident(severity: Severity = Severity.HIGH, iid: int = 1) -> Incident:
    return Incident(
        id=iid,
        fingerprint=f"fp{iid}",
        rule="new_device",
        severity=severity,
        title="Neues Gerät im Netz: Fernseher",
        status=IncidentStatus.NEW,
        created_at=T0,
        updated_at=T0,
        device_mac=MAC_A,
    )


class Recorder:
    def __init__(self, fail: bool = False) -> None:
        self.calls: list[tuple[str, bytes, dict[str, str]]] = []
        self.fail = fail

    def __call__(self, url: str, body: bytes, headers: dict[str, str]) -> None:
        if self.fail:
            raise urllib.error.URLError("offline")
        self.calls.append((url, body, headers))


def test_ntfy_message_contents() -> None:
    rec = Recorder()
    NtfyNotifier("https://ntfy.example/aluco", token="tok", post=rec).send(incident())
    [(url, body, headers)] = rec.calls
    assert url == "https://ntfy.example/aluco"
    assert body.decode() == "Neues Gerät im Netz: Fernseher"
    assert headers["Priority"] == "4"
    assert headers["Title"] == "Aluco (hoch)"
    assert headers["Authorization"] == "Bearer tok"


def test_ntfy_minimal_hides_details() -> None:
    rec = Recorder()
    NtfyNotifier("https://ntfy.example/aluco", minimal=True, post=rec).send(incident())
    [(_, body, headers)] = rec.calls
    assert "Fernseher" not in body.decode()
    assert "Fernseher" not in headers["Title"]
    assert "Authorization" not in headers


def test_notify_all_filters_by_severity_and_survives_errors() -> None:
    rec = Recorder()
    notifier = NtfyNotifier("https://ntfy.example/a", post=rec)
    sent, failed = notify_all(
        notifier, [incident(Severity.LOW, 1), incident(Severity.HIGH, 2)], Severity.MEDIUM
    )
    assert (sent, failed) == (1, 0)

    broken = NtfyNotifier("https://ntfy.example/a", post=Recorder(fail=True))
    assert notify_all(broken, [incident()], Severity.INFO) == (0, 1)


def test_ntfy_repr_hides_url_and_token() -> None:
    n = NtfyNotifier("https://ntfy.example/geheimes-topic", token="tok")
    assert "geheimes-topic" not in repr(n)
    assert "tok" not in repr(n)
