from __future__ import annotations

from datetime import timedelta

import pytest

from aluco.model import Device, DeviceSighting, DnsQuery, Severity, TrustLevel
from aluco.rules import DnsContext, NewDeviceRule, NewDomainRule, base_domain
from tests.conftest import IP_A, MAC_A, MAC_RANDOM, T0


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("example.com", "example.com"),
        ("a.b.cdn.example.com.", "example.com"),
        ("www.example.co.at", "example.co.at"),
        ("api.example.co.uk", "example.co.uk"),
        ("localhost", "localhost"),
        ("WWW.Example.Org", "example.org"),
    ],
)
def test_base_domain(domain: str, expected: str) -> None:
    assert base_domain(domain) == expected


def test_new_device_rule_fires_only_for_unknown_mac() -> None:
    rule = NewDeviceRule()
    s = DeviceSighting(mac=MAC_A, at=T0, ip=IP_A, vendor="Beispiel GmbH")
    [f] = list(rule.check(s, known=None))
    assert f.severity is Severity.HIGH
    assert f.device_mac == MAC_A
    assert f.details["vendor"] == "Beispiel GmbH"
    assert f.details["randomized_mac"] == "false"

    known = Device(mac=MAC_A, first_seen=T0, last_seen=T0)
    assert list(rule.check(s, known=known)) == []


def test_new_device_rule_flags_randomized_mac() -> None:
    [f] = list(NewDeviceRule().check(DeviceSighting(mac=MAC_RANDOM, at=T0), known=None))
    assert f.details["randomized_mac"] == "true"


def ctx(
    trust: TrustLevel = TrustLevel.IOT,
    first_time: bool = True,
    device_age: timedelta = timedelta(days=30),
) -> DnsContext:
    now = T0 + device_age
    device = Device(mac=MAC_A, first_seen=T0, last_seen=now, trust=trust, name="Fernseher")
    query = DnsQuery(client_ip=IP_A, domain="tracker.example.net", at=now)
    return DnsContext(
        device=device,
        query=query,
        domain="example.net",
        first_time_for_device=first_time,
        now=now,
    )


def test_new_domain_rule_fires_for_iot_after_learning() -> None:
    [f] = list(NewDomainRule().check(ctx()))
    assert f.severity is Severity.LOW
    assert f.key == "example.net"
    assert "Fernseher" in f.title


@pytest.mark.parametrize(
    "context",
    [
        ctx(first_time=False),
        ctx(device_age=timedelta(days=3)),  # noch in der Lernphase
        ctx(trust=TrustLevel.KNOWN),  # Laptops/Handys fragen ständig Neues an
        ctx(trust=TrustLevel.COMPANY),
    ],
)
def test_new_domain_rule_stays_quiet(context: DnsContext) -> None:
    assert list(NewDomainRule().check(context)) == []
