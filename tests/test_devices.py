from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from aluco.__main__ import main
from aluco.devices import DeviceNotFoundError, set_name, set_protected, set_trust
from aluco.engine import Engine
from aluco.model import Device, DeviceSighting, DnsQuery, TrustLevel
from aluco.store import Store
from tests.conftest import IP_A, MAC_A, MAC_B, T0


def _company_candidate(store: Store) -> None:
    """IoT-Gerät mit gespeicherten Domains und einem Vorfall "neue Domain"."""
    engine = Engine(store)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A)], now=T0)
    set_trust(store, MAC_A, TrustLevel.IOT)
    later = T0 + timedelta(days=10)
    engine.process(
        queries=[DnsQuery(client_ip=IP_A, domain="intranet.example", at=later)], now=later
    )
    assert store.device_domains(MAC_A)
    assert any(i.rule == "new_domain" for i in store.incidents())


def test_set_trust_company_deletes_behaviour_data(store: Store) -> None:
    _company_candidate(store)
    change = set_trust(store, MAC_A, TrustLevel.COMPANY)
    assert change.previous is TrustLevel.IOT
    assert change.domains_deleted == 1
    assert change.incidents_deleted == 1
    assert store.device_domains(MAC_A) == []
    # Der Vorfall "neues Gerät" bleibt – er sagt nichts über das Verhalten.
    assert [i.rule for i in store.incidents()] == ["new_device"]
    assert store.device(MAC_A).can_disconnect is False  # type: ignore[union-attr]


def test_set_trust_other_levels_keep_data(store: Store) -> None:
    _company_candidate(store)
    change = set_trust(store, MAC_A, TrustLevel.KNOWN)
    assert (change.domains_deleted, change.incidents_deleted) == (0, 0)
    assert store.device_domains(MAC_A)


def test_unknown_device_and_mac_formats(store: Store) -> None:
    with pytest.raises(DeviceNotFoundError):
        set_trust(store, MAC_B, TrustLevel.IOT)
    with pytest.raises(ValueError):
        set_trust(store, "kein-mac", TrustLevel.IOT)
    store.save_device(Device(mac=MAC_A, first_seen=T0, last_seen=T0))
    assert set_trust(store, MAC_A.upper().replace(":", "-"), TrustLevel.IOT).device.mac == MAC_A


def test_protect_and_name(store: Store) -> None:
    store.save_device(Device(mac=MAC_A, first_seen=T0, last_seen=T0))
    assert set_protected(store, MAC_A, True).protected
    assert not set_protected(store, MAC_A, False).protected
    assert set_name(store, MAC_A, "  Fernseher ").name == "Fernseher"
    assert set_name(store, MAC_A, "").name is None


# --- Kommandozeile ------------------------------------------------------------------


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "aluco.db"
    monkeypatch.setenv("ALUCO_DB_PATH", str(path))
    s = Store(path)
    s.save_device(Device(mac=MAC_A, first_seen=T0, last_seen=T0, ip=IP_A, hostname="laptop"))
    s.close()
    return path


def test_cli_list_and_set_trust(db: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["device", "list"]) == 0
    out = capsys.readouterr().out
    assert MAC_A in out and "unbekannt" in out and "laptop" in out

    assert main(["device", "set-trust", MAC_A, "company"]) == 0
    out = capsys.readouterr().out
    assert "unbekannt → Firma" in out and "nur passiv" in out


def test_cli_protect_name_and_errors(db: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["device", "protect", MAC_A]) == 0
    assert "Schutzliste" in capsys.readouterr().out
    assert main(["device", "name", MAC_A, "Arbeitszimmer"]) == 0
    assert "Arbeitszimmer" in capsys.readouterr().out
    assert main(["device", "set-trust", MAC_B, "iot"]) == 1
    assert "nicht im Inventar" in capsys.readouterr().err


def test_cli_missing_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ALUCO_DB_PATH", str(tmp_path / "fehlt.db"))
    assert main(["device", "list"]) == 2
    assert "Keine Datenbank" in capsys.readouterr().err
