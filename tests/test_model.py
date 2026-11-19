from __future__ import annotations

from datetime import timedelta

import pytest

from aluco.model import (
    Device,
    DnsQuery,
    Finding,
    Severity,
    TrustLevel,
    is_randomized_mac,
    normalize_mac,
)
from tests.conftest import MAC_A, MAC_RANDOM, T0


@pytest.mark.parametrize(
    "raw",
    ["00:00:5E:00:53:01", "00-00-5e-00-53-01", "0000.5e00.5301", "00005e005301"],
)
def test_normalize_mac_accepts_common_formats(raw: str) -> None:
    assert normalize_mac(raw) == MAC_A


@pytest.mark.parametrize("raw", ["", "00:00:5e:00:53", "zz:00:5e:00:53:01", "00:00:5e:00:53:01:02"])
def test_normalize_mac_rejects_invalid(raw: str) -> None:
    with pytest.raises(ValueError):
        normalize_mac(raw)


def test_randomized_mac_detection() -> None:
    assert is_randomized_mac(MAC_RANDOM)
    assert not is_randomized_mac(MAC_A)


def test_device_normalizes_mac_and_label_fallbacks() -> None:
    d = Device(mac="00-00-5E-00-53-01", first_seen=T0, last_seen=T0)
    assert d.mac == MAC_A
    assert d.label == MAC_A
    assert Device(mac=MAC_A, first_seen=T0, last_seen=T0, ip="192.0.2.1").label == "192.0.2.1"
    assert Device(mac=MAC_A, first_seen=T0, last_seen=T0, name="Fernseher").label == "Fernseher"


@pytest.mark.parametrize(
    ("trust", "protected", "expected"),
    [
        (TrustLevel.KNOWN, False, True),
        (TrustLevel.UNKNOWN, False, True),
        (TrustLevel.KNOWN, True, False),
        (TrustLevel.COMPANY, False, False),
    ],
)
def test_can_disconnect_respects_protection_and_company(
    trust: TrustLevel, protected: bool, expected: bool
) -> None:
    d = Device(mac=MAC_A, first_seen=T0, last_seen=T0, trust=trust, protected=protected)
    assert d.can_disconnect is expected


def test_device_seen_never_moves_last_seen_backwards() -> None:
    d = Device(mac=MAC_A, first_seen=T0, last_seen=T0 + timedelta(hours=1))
    assert d.seen(T0).last_seen == T0 + timedelta(hours=1)
    assert d.seen(T0 + timedelta(hours=2), ip="192.0.2.5").ip == "192.0.2.5"


def test_dns_query_normalizes_domain() -> None:
    q = DnsQuery(client_ip="192.0.2.1", domain="Example.COM.", at=T0)
    assert q.domain == "example.com"


def test_finding_fingerprint_depends_on_rule_device_and_key_only() -> None:
    a = Finding(rule="r", severity=Severity.LOW, title="x", device_mac=MAC_A, key="k")
    b = Finding(rule="r", severity=Severity.HIGH, title="y", device_mac=MAC_A, key="k")
    c = Finding(rule="r", severity=Severity.LOW, title="x", device_mac=MAC_A, key="other")
    assert a.fingerprint == b.fingerprint
    assert a.fingerprint != c.fingerprint
