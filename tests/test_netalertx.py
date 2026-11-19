from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import pytest

from aluco.adapters.base import AdapterError, HttpJsonClient
from aluco.adapters.netalertx import NetAlertX, parse_time
from tests.conftest import IP_A, MAC_A, MAC_B


def device(**overrides: Any) -> dict[str, Any]:
    """Auszug aus einer echten /devices-Antwort (NetAlertX 26.10)."""
    base = {
        "devMac": MAC_A,
        "devName": "Testgerät",
        "devVendor": "Beispiel",
        "devFirstConnection": "2026-11-19 13:00:00",
        "devLastConnection": "2026-11-19 13:59:19",
        "devLastIP": IP_A,
        "devPrimaryIPv4": None,
        "devIsArchived": 0,
        "devSourcePlugin": "ARPSCAN",
    }
    return base | overrides


def fake(devices: list[dict[str, Any]]):
    def fetch(method: str, path: str, params: Mapping[str, str]) -> Any:
        assert (method, path) == ("GET", "/devices")
        return {"success": True, "devices": devices}

    return fetch


def test_parse_time_is_utc() -> None:
    assert parse_time("2026-11-19 13:59:19") == datetime(2026, 11, 19, 13, 59, 19, tzinfo=UTC)


def test_maps_device_fields() -> None:
    [s] = NetAlertX(fake([device()])).fetch_sightings()
    assert s.mac == MAC_A
    assert s.at == datetime(2026, 11, 19, 13, 59, 19, tzinfo=UTC)
    assert (s.ip, s.hostname, s.vendor, s.source) == (IP_A, "Testgerät", "Beispiel", "netalertx")


def test_prefers_primary_ipv4_and_drops_placeholder_names() -> None:
    [s] = NetAlertX(
        fake([device(devPrimaryIPv4="192.0.2.99", devName="(unknown)", devVendor="")])
    ).fetch_sightings()
    assert (s.ip, s.hostname, s.vendor) == ("192.0.2.99", None, None)


def test_skips_pseudo_devices_and_missing_times() -> None:
    sightings = NetAlertX(
        fake(
            [
                device(devMac="Internet"),
                device(devMac=MAC_B, devLastConnection=None, devFirstConnection=None),
                device(devMac=MAC_B, devLastConnection="kaputt"),
                device(devMac="00-00-5E-00-53-01"),
            ]
        )
    ).fetch_sightings()
    assert [s.mac for s in sightings] == [MAC_A]


def test_unexpected_response_raises() -> None:
    with pytest.raises(AdapterError):
        NetAlertX(lambda *_: {"success": False, "error": "Forbidden"}).fetch_sightings()


def test_client_repr_hides_credentials() -> None:
    client = HttpJsonClient("http://127.0.0.1:20212", bearer_token="geheim", password="pw")
    assert "geheim" not in repr(client)
    assert "pw" not in repr(client)


def test_online_status_from_last_scan() -> None:
    online, offline, unknown = NetAlertX(
        fake(
            [
                device(devPresentLastScan=1),
                device(devMac=MAC_B, devPresentLastScan=0),
                device(devMac="00:00:5e:00:53:09"),
            ]
        )
    ).fetch_sightings()
    assert (online.online, offline.online, unknown.online) == (True, False, None)
