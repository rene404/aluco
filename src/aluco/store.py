"""Speicher auf Basis von SQLite (Standardbibliothek, keine Abhängigkeit)."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from aluco.model import (
    Device,
    Incident,
    IncidentStatus,
    Severity,
    TrustLevel,
)

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac         TEXT PRIMARY KEY,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    ip          TEXT,
    hostname    TEXT,
    vendor      TEXT,
    name        TEXT,
    trust       TEXT NOT NULL,
    protected   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS devices_ip ON devices(ip);

CREATE TABLE IF NOT EXISTS device_domains (
    mac         TEXT NOT NULL REFERENCES devices(mac) ON DELETE CASCADE,
    domain      TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    PRIMARY KEY (mac, domain)
);

CREATE TABLE IF NOT EXISTS incidents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    rule        TEXT NOT NULL,
    severity    INTEGER NOT NULL,
    title       TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    device_mac  TEXT,
    details     TEXT NOT NULL DEFAULT '{}',
    occurrences INTEGER NOT NULL DEFAULT 1,
    note        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS incidents_status ON incidents(status, severity);

CREATE TABLE IF NOT EXISTS cursors (
    source      TEXT PRIMARY KEY,
    position    TEXT NOT NULL
);
"""


def _ts(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("Zeitangaben müssen eine Zeitzone haben")
    return dt.isoformat()


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


class Store:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._db = sqlite3.connect(path, isolation_level=None)  # autocommit; Transaktionen explizit
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        if str(path) != ":memory:":
            self._db.execute("PRAGMA journal_mode = WAL")
        self._migrate()

    def close(self) -> None:
        self._db.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self._db.execute("BEGIN")
        try:
            yield
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        self._db.execute("COMMIT")

    def _migrate(self) -> None:
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(f"Datenbank ist neuer (v{version}) als diese Aluco-Version")
        if version < 1:
            self._db.executescript(_SCHEMA)
            self._db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    # --- Geräte -------------------------------------------------------------------

    def device(self, mac: str) -> Device | None:
        row = self._db.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
        return _device(row) if row else None

    def device_by_ip(self, ip: str) -> Device | None:
        row = self._db.execute(
            "SELECT * FROM devices WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)
        ).fetchone()
        return _device(row) if row else None

    def devices(self) -> list[Device]:
        rows = self._db.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
        return [_device(r) for r in rows]

    def save_device(self, d: Device) -> Device:
        self._db.execute(
            """
            INSERT INTO devices (mac, first_seen, last_seen, ip, hostname, vendor, name,
                                 trust, protected)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                first_seen = excluded.first_seen, last_seen = excluded.last_seen,
                ip = excluded.ip, hostname = excluded.hostname, vendor = excluded.vendor,
                name = excluded.name, trust = excluded.trust, protected = excluded.protected
            """,
            (
                d.mac, _ts(d.first_seen), _ts(d.last_seen), d.ip, d.hostname, d.vendor,
                d.name, d.trust.value, int(d.protected),
            ),
        )  # fmt: skip
        return d

    # --- Domains pro Gerät (Grundlage für "neue Domain") --------------------------

    def record_domain(self, mac: str, domain: str, at: datetime) -> bool:
        """Domain für ein Gerät vermerken. True, wenn das Gerät sie zum ersten Mal anfragt."""
        cur = self._db.execute(
            "INSERT INTO device_domains (mac, domain, first_seen, last_seen) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(mac, domain) DO NOTHING",
            (mac, domain, _ts(at), _ts(at)),
        )
        if cur.rowcount == 1:
            return True
        self._db.execute(
            "UPDATE device_domains SET last_seen = max(last_seen, ?) WHERE mac = ? AND domain = ?",
            (_ts(at), mac, domain),
        )
        return False

    def device_domains(self, mac: str) -> list[str]:
        rows = self._db.execute(
            "SELECT domain FROM device_domains WHERE mac = ? ORDER BY domain", (mac,)
        ).fetchall()
        return [r[0] for r in rows]

    # --- Vorfälle -----------------------------------------------------------------

    def incident_by_id(self, incident_id: int) -> Incident | None:
        row = self._db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return _incident(row) if row else None

    def incident_by_fingerprint(self, fingerprint: str) -> Incident | None:
        row = self._db.execute(
            "SELECT * FROM incidents WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return _incident(row) if row else None

    def incidents(self, statuses: frozenset[IncidentStatus] | None = None) -> list[Incident]:
        sql = "SELECT * FROM incidents"
        params: tuple[str, ...] = ()
        if statuses:
            sql += f" WHERE status IN ({','.join('?' * len(statuses))})"
            params = tuple(s.value for s in statuses)
        sql += " ORDER BY severity DESC, updated_at DESC"
        return [_incident(r) for r in self._db.execute(sql, params).fetchall()]

    def save_incident(self, i: Incident) -> Incident:
        values = (
            i.fingerprint, i.rule, int(i.severity), i.title, i.status.value,
            _ts(i.created_at), _ts(i.updated_at), i.device_mac,
            json.dumps(i.details, sort_keys=True), i.occurrences, i.note,
        )  # fmt: skip
        if i.id is None:
            cur = self._db.execute(
                """
                INSERT INTO incidents (fingerprint, rule, severity, title, status, created_at,
                                       updated_at, device_mac, details, occurrences, note)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            new_id = cur.lastrowid
            assert new_id is not None  # noqa: S101 – sqlite liefert immer eine ID
            return self.incident_by_id(new_id) or i
        self._db.execute(
            """
            UPDATE incidents SET fingerprint = ?, rule = ?, severity = ?, title = ?, status = ?,
                created_at = ?, updated_at = ?, device_mac = ?, details = ?, occurrences = ?,
                note = ?
            WHERE id = ?
            """,
            (*values, i.id),
        )
        return i

    def purge_closed_incidents(self, older_than: datetime) -> int:
        """Ignorierte/erledigte Vorfälle löschen, die seit ``older_than`` unverändert sind.

        Tritt ein ignorierter Befund weiter auf, wird ``updated_at`` laufend erneuert und
        der Vorfall bleibt erhalten; "ignorieren" geht also nur verloren, wenn der Befund
        die ganze Aufbewahrungsfrist lang nicht mehr aufgetreten ist.
        """
        cur = self._db.execute(
            "DELETE FROM incidents WHERE status IN (?, ?) AND updated_at < ?",
            (IncidentStatus.RESOLVED.value, IncidentStatus.IGNORED.value, _ts(older_than)),
        )
        return cur.rowcount

    # --- Lesepositionen der Datenquellen ------------------------------------------

    def cursor(self, source: str) -> str | None:
        row = self._db.execute(
            "SELECT position FROM cursors WHERE source = ?", (source,)
        ).fetchone()
        return row[0] if row else None

    def set_cursor(self, source: str, position: str) -> None:
        self._db.execute(
            "INSERT INTO cursors (source, position) VALUES (?, ?) "
            "ON CONFLICT(source) DO UPDATE SET position = excluded.position",
            (source, position),
        )


def _device(r: sqlite3.Row) -> Device:
    return Device(
        mac=r["mac"],
        first_seen=_dt(r["first_seen"]),
        last_seen=_dt(r["last_seen"]),
        ip=r["ip"],
        hostname=r["hostname"],
        vendor=r["vendor"],
        name=r["name"],
        trust=TrustLevel(r["trust"]),
        protected=bool(r["protected"]),
    )


def _incident(r: sqlite3.Row) -> Incident:
    return Incident(
        id=r["id"],
        fingerprint=r["fingerprint"],
        rule=r["rule"],
        severity=Severity(r["severity"]),
        title=r["title"],
        status=IncidentStatus(r["status"]),
        created_at=_dt(r["created_at"]),
        updated_at=_dt(r["updated_at"]),
        device_mac=r["device_mac"],
        details=json.loads(r["details"]),
        occurrences=r["occurrences"],
        note=r["note"],
    )
