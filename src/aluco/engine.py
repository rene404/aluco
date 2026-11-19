"""Engine: Beobachtungen aus den Adaptern → Inventar aktualisieren → Regeln → Vorfälle."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime

from aluco.incidents import IncidentService
from aluco.model import Device, DeviceSighting, DnsQuery, Incident, utcnow
from aluco.rules import (
    DeviceRule,
    DnsContext,
    DnsRule,
    base_domain,
    default_device_rules,
    default_dns_rules,
)
from aluco.store import Store


@dataclass(slots=True)
class RunResult:
    devices_seen: int = 0
    new_devices: int = 0
    queries_seen: int = 0
    queries_unmatched: int = 0  # Client-IP keinem Gerät zuordenbar
    incidents: list[Incident] = field(default_factory=list)


class Engine:
    def __init__(
        self,
        store: Store,
        device_rules: Sequence[DeviceRule] | None = None,
        dns_rules: Sequence[DnsRule] | None = None,
    ) -> None:
        self._store = store
        self._incidents = IncidentService(store)
        self._device_rules = list(device_rules or default_device_rules())
        self._dns_rules = list(dns_rules or default_dns_rules())

    def process(
        self,
        sightings: Iterable[DeviceSighting] = (),
        queries: Iterable[DnsQuery] = (),
        now: datetime | None = None,
        learn_only: bool = False,
    ) -> RunResult:
        """Geräte zuerst, damit DNS-Anfragen neuer Geräte schon zugeordnet werden können.

        ``learn_only``: Inventar und Domains übernehmen, aber keine Regeln auswerten –
        für den ersten Lauf, sonst wäre jedes vorhandene Gerät ein "neues Gerät".
        """
        now = now or utcnow()
        result = RunResult()
        with self._store.transaction():
            for s in sightings:
                self._process_sighting(s, now, result, evaluate=not learn_only)
            for q in queries:
                self._process_query(q, now, result, evaluate=not learn_only)
        return result

    def _process_sighting(
        self, s: DeviceSighting, now: datetime, result: RunResult, *, evaluate: bool
    ) -> None:
        result.devices_seen += 1
        known = self._store.device(s.mac)
        if evaluate:
            for rule in self._device_rules:
                for finding in rule.check(s, known):
                    result.incidents.append(self._incidents.ingest(finding, at=now))
        if known is None:
            result.new_devices += 1
            device = Device(
                mac=s.mac,
                first_seen=s.at,
                last_seen=s.at,
                ip=s.ip,
                hostname=s.hostname,
                vendor=s.vendor,
            )
        else:
            device = known.seen(s.at, ip=s.ip, hostname=s.hostname)
            if s.vendor and not device.vendor:
                device = replace(device, vendor=s.vendor)
        self._store.save_device(device)

    def _process_query(
        self, q: DnsQuery, now: datetime, result: RunResult, *, evaluate: bool
    ) -> None:
        result.queries_seen += 1
        device = self._store.device_by_ip(q.client_ip)
        if device is None:
            result.queries_unmatched += 1
            return
        if device.is_company:
            return  # Firmengeräte: nur passiv, keine Auswertung ihrer Anfragen
        domain = base_domain(q.domain)
        first_time = self._store.record_domain(device.mac, domain, q.at)
        if not evaluate:
            return
        ctx = DnsContext(
            device=device, query=q, domain=domain, first_time_for_device=first_time, now=now
        )
        for rule in self._dns_rules:
            for finding in rule.check(ctx):
                result.incidents.append(self._incidents.ingest(finding, at=now))
