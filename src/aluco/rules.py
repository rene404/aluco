"""Erkennungsregeln (Start: wenig Fehlalarme).

Jede Regel bekommt eine Beobachtung plus den bekannten Zustand und liefert
Befunde. Regeln speichern nichts selbst; das erledigt die Engine.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol

from aluco.i18n import _
from aluco.model import (
    Device,
    DeviceSighting,
    DnsQuery,
    Finding,
    Severity,
    TrustLevel,
    is_randomized_mac,
)

# Mehrteilige Endungen, unter denen eine Ebene mehr zur "Domain" gehört.
# Näherung ohne Public-Suffix-Liste; reicht für die Gruppierung im Heimnetz.
_MULTI_PART_SUFFIXES = frozenset(
    {
        "co.at", "or.at", "gv.at", "ac.at",
        "co.uk", "org.uk", "ac.uk", "gov.uk",
        "com.au", "net.au", "org.au",
        "co.jp", "ne.jp", "or.jp",
        "com.br", "com.cn", "com.tr", "co.nz", "co.za", "co.in",
    }
)  # fmt: skip


def base_domain(domain: str) -> str:
    """``cdn3.api.example.co.at`` → ``example.co.at``; ``a.b.example.com`` → ``example.com``."""
    labels = domain.rstrip(".").lower().split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


class DeviceRule(Protocol):
    name: str

    def check(self, sighting: DeviceSighting, known: Device | None) -> Iterable[Finding]: ...


@dataclass(frozen=True, slots=True)
class DnsContext:
    device: Device
    query: DnsQuery
    domain: str  # base_domain(query.domain)
    first_time_for_device: bool
    now: datetime


class DnsRule(Protocol):
    name: str

    def check(self, ctx: DnsContext) -> Iterable[Finding]: ...


class NewDeviceRule:
    """Unbekannte MAC-Adresse im Netz."""

    name = "new_device"

    def check(self, sighting: DeviceSighting, known: Device | None) -> Iterable[Finding]:
        if known is not None:
            return
        randomized = is_randomized_mac(sighting.mac)
        label = sighting.hostname or sighting.ip or sighting.mac
        details = {"mac": sighting.mac, "randomized_mac": str(randomized).lower()}
        if sighting.ip:
            details["ip"] = sighting.ip
        if sighting.vendor:
            details["vendor"] = sighting.vendor
        if sighting.hostname:
            details["hostname"] = sighting.hostname
        yield Finding(
            rule=self.name,
            severity=Severity.HIGH,
            title=_("Neues Gerät im Netz: {label}", label=label),
            device_mac=sighting.mac,
            details=details,
        )


@dataclass(slots=True)
class NewDomainRule:
    """Gerät fragt eine Domain an, die es noch nie angefragt hat.

    Nur für IoT-Geräte (verhalten sich vorhersehbar) und erst nach einer Lernphase,
    sonst wäre jede Anfrage in der ersten Woche ein Alarm.
    """

    learning_period: timedelta = timedelta(days=7)
    trust_levels: frozenset[TrustLevel] = frozenset({TrustLevel.IOT})
    name: str = "new_domain"

    def check(self, ctx: DnsContext) -> Iterable[Finding]:
        if not ctx.first_time_for_device:
            return
        if ctx.device.trust not in self.trust_levels:
            return
        if ctx.now - ctx.device.first_seen < self.learning_period:
            return
        yield Finding(
            rule=self.name,
            severity=Severity.LOW,
            title=_(
                "{label} fragt neue Domain an: {domain}", label=ctx.device.label, domain=ctx.domain
            ),
            device_mac=ctx.device.mac,
            key=ctx.domain,
            details={"domain": ctx.domain, "query": ctx.query.domain},
        )


class ThreatMatcher(Protocol):
    def match(self, domain: str) -> Any: ...


@dataclass(slots=True)
class KnownBadDomainRule:
    """Gerät fragt eine Domain von einer Bedrohungsliste an (Malware, Phishing, C2).

    Gilt für alle Geräte außer Firmengeräten (deren Anfragen wertet Aluco nie aus) und
    auch dann, wenn AdGuard die Anfrage blockiert hat – der Versuch selbst ist das Signal.
    """

    intel: ThreatMatcher
    name: str = "bad_domain"

    def check(self, ctx: DnsContext) -> Iterable[Finding]:
        hit = self.intel.match(ctx.query.domain)
        if hit is None:
            return
        yield Finding(
            rule=self.name,
            severity=Severity.HIGH,
            title=_(
                "{label} fragt bekannte Schad-Domain an: {domain}",
                label=ctx.device.label,
                domain=hit.entry,
            ),
            device_mac=ctx.device.mac,
            key=hit.entry,
            details={
                "domain": hit.entry,
                "query": ctx.query.domain,
                "list": hit.feed,
                "blocked": "true" if ctx.query.blocked else "false",
            },
        )


@dataclass(slots=True)
class NewlyRegisteredDomainRule:
    """Gerät fragt eine neu registrierte Domain an (jünger als ~14 Tage).

    Neue Domains sind ein häufiges Werkzeug für Phishing, Schadsoftware und
    Command-and-Control, aber nicht jede ist schädlich – darum nur mittlere Schwere.
    Steht die Domain zugleich auf einer Bedrohungsliste, meldet nur ``bad_domain``.
    Ein Vorfall je Gerät und registrierter Domain; Wiederholungen zählen hoch.
    """

    nrd: ThreatMatcher
    threats: ThreatMatcher | None = None
    name: str = "newly_registered_domain"

    def check(self, ctx: DnsContext) -> Iterable[Finding]:
        hit = self.nrd.match(ctx.query.domain)
        if hit is None:
            return
        if self.threats is not None and self.threats.match(ctx.query.domain) is not None:
            return
        yield Finding(
            rule=self.name,
            severity=Severity.MEDIUM,
            title=_(
                "{label} fragt neu registrierte Domain an: {domain}",
                label=ctx.device.label,
                domain=hit.entry,
            ),
            device_mac=ctx.device.mac,
            key=hit.entry,
            details={
                "domain": hit.entry,
                "query": ctx.query.domain,
                "list": hit.feed,
                "blocked": "true" if ctx.query.blocked else "false",
            },
        )


def default_device_rules() -> list[DeviceRule]:
    return [NewDeviceRule()]


def default_dns_rules() -> list[DnsRule]:
    return [NewDomainRule()]
