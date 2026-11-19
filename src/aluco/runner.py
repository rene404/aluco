"""Ein Durchlauf: Datenquellen abfragen → Engine → aufräumen → melden."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from aluco.adapters.base import AdapterError, DeviceSource, DnsSource
from aluco.ai import Assessment, AssessmentError, Assessor, assess_incident
from aluco.config import Config
from aluco.engine import Engine, RunResult
from aluco.model import DeviceSighting, DnsQuery, Event, EventKind, Incident, Severity, utcnow
from aluco.notify import Notifier, notify_all
from aluco.store import Store

log = logging.getLogger(__name__)


@dataclass(slots=True)
class RunSummary:
    result: RunResult
    learn_only: bool
    errors: list[str] = field(default_factory=list)
    purged: int = 0
    notified: int = 0
    notify_failed: int = 0
    assessed: int = 0
    ai_errors: list[str] = field(default_factory=list)


class Runner:
    def __init__(
        self,
        store: Store,
        device_sources: list[DeviceSource],
        dns_sources: list[DnsSource],
        notifier: Notifier | None = None,
        notify_min_severity: Severity = Severity.MEDIUM,
        retention: timedelta = timedelta(days=30),
        engine: Engine | None = None,
        assessor: Assessor | None = None,
        ai_max_per_run: int = 5,
    ) -> None:
        self._assessor = assessor
        self._ai_max = ai_max_per_run
        self._store = store
        self._device_sources = device_sources
        self._dns_sources = dns_sources
        self._notifier = notifier
        self._min_severity = notify_min_severity
        self._retention = retention
        self._engine = engine or Engine(store)

    def run_once(self, now: datetime | None = None) -> RunSummary:
        now = now or utcnow()
        errors: list[str] = []

        sightings: list[DeviceSighting] = []
        for device_source in self._device_sources:
            try:
                sightings.extend(device_source.fetch_sightings())
            except AdapterError as e:
                errors.append(f"{device_source.name}: {e}")

        queries: list[DnsQuery] = []
        new_cursors: dict[str, str] = {}
        for dns_source in self._dns_sources:
            since_raw = self._store.cursor(dns_source.name)
            since = datetime.fromisoformat(since_raw) if since_raw else None
            try:
                fetched = dns_source.fetch_queries(since)
            except AdapterError as e:
                errors.append(f"{dns_source.name}: {e}")
                continue
            queries.extend(fetched)
            if fetched:
                new_cursors[dns_source.name] = max(q.at for q in fetched).isoformat()

        # Erster Lauf (leeres Inventar): nur lernen, sonst ist jedes Gerät "neu".
        learn_only = not self._store.devices()
        result = self._engine.process(sightings, queries, now=now, learn_only=learn_only)

        # Lesepositionen erst nach erfolgreicher Verarbeitung weiterschieben.
        for source, position in new_cursors.items():
            self._store.set_cursor(source, position)

        # Für das Dashboard: wann lief Aluco zuletzt, welche Quellen fehlten?
        self._record_source_changes(errors, now)
        self._store.set_cursor("runner:last_run", now.isoformat())
        self._store.set_cursor("runner:last_errors", "\n".join(errors))

        summary = RunSummary(result=result, learn_only=learn_only, errors=errors)
        cutoff = now - self._retention
        summary.purged = self._store.purge_closed_incidents(older_than=cutoff)
        self._store.purge_events(older_than=cutoff)
        self._store.purge_stats(older_than=cutoff)

        assessments = self._assess(result.alerts, now, summary)
        if self._notifier and result.alerts:
            summary.notified, summary.notify_failed = notify_all(
                self._notifier, result.alerts, self._min_severity, assessments
            )

        for err in errors:
            log.warning("Datenquelle nicht erreichbar: %s", err)
        log.info(
            "Lauf%s: %d Geräte (%d neu), %d DNS-Anfragen (%d ohne Gerät), "
            "%d Vorfälle aktualisiert, %d gemeldet",
            " (Lernmodus)" if learn_only else "",
            result.devices_seen,
            result.new_devices,
            result.queries_seen,
            result.queries_unmatched,
            len(result.incidents),
            summary.notified,
        )
        return summary

    def _assess(
        self, alerts: list[Incident], now: datetime, summary: RunSummary
    ) -> dict[int, Assessment]:
        """Neue Vorfälle vorbewerten – höchstens ``ai_max_per_run`` pro Lauf (Kosten)."""
        done: dict[int, Assessment] = {}
        if self._assessor is None:
            return done
        for incident in sorted(alerts, key=lambda i: -i.severity)[: self._ai_max]:
            if incident.id is None:
                continue
            try:
                a = assess_incident(self._store, self._assessor, incident.id, now)
            except AssessmentError as e:
                summary.ai_errors.append(str(e))
                log.warning("KI-Vorbewertung von Vorfall %s fehlgeschlagen: %s", incident.id, e)
                continue
            if a is not None:
                done[incident.id] = a
                summary.assessed += 1
        return done

    def _record_source_changes(self, errors: list[str], now: datetime) -> None:
        """Nur Wechsel in die Chronik: Quelle fällt aus bzw. ist wieder erreichbar."""
        before = {
            e.split(":", 1)[0]
            for e in (self._store.cursor("runner:last_errors") or "").split("\n")
            if e
        }
        after = {e.split(":", 1)[0] for e in errors}
        for name in sorted(after - before):
            detail = next(e for e in errors if e.startswith(name + ":"))
            self._store.add_event(
                Event(
                    id=None,
                    at=now,
                    kind=EventKind.SOURCE,
                    title=f"{name} nicht erreichbar",
                    detail=detail,
                )
            )
        for name in sorted(before - after):
            self._store.add_event(
                Event(id=None, at=now, kind=EventKind.SOURCE, title=f"{name} wieder erreichbar")
            )


def build_runner(cfg: Config, store: Store) -> Runner:
    """Runner aus der Konfiguration zusammenbauen."""
    from aluco.adapters.adguard import AdGuardHome
    from aluco.adapters.base import HttpJsonClient
    from aluco.adapters.netalertx import NetAlertX
    from aluco.notify import NtfyNotifier

    device_sources: list[DeviceSource] = []
    dns_sources: list[DnsSource] = []
    if cfg.netalertx_url:
        client = HttpJsonClient(cfg.netalertx_url, bearer_token=cfg.netalertx_token)
        device_sources.append(NetAlertX(client))
    if cfg.adguard_url:
        client = HttpJsonClient(cfg.adguard_url, cfg.adguard_user, cfg.adguard_password)
        dns_sources.append(AdGuardHome(client))
    notifier = (
        NtfyNotifier(cfg.ntfy_url, cfg.ntfy_token, minimal=cfg.notify_minimal)
        if cfg.ntfy_url
        else None
    )
    assessor = None
    if cfg.ai.enabled:
        from aluco.ai import ClaudeAssessor

        assessor = ClaudeAssessor(model=cfg.ai.model)
    return Runner(
        store,
        device_sources,
        dns_sources,
        notifier=notifier,
        notify_min_severity=cfg.notify_min_severity,
        retention=timedelta(days=cfg.retention_days),
        assessor=assessor,
        ai_max_per_run=cfg.ai.max_per_run,
    )
