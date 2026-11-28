"""Speicher auf Basis von SQLite (Standardbibliothek, keine Abhängigkeit)."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from aluco.ai import Assessment
from aluco.model import (
    Device,
    Event,
    EventKind,
    HistoryEntry,
    HistoryKind,
    Incident,
    IncidentStatus,
    Severity,
    TrustLevel,
)

SCHEMA_VERSION = 8

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

# v2: Online-Status und Notiz, Chronik, DNS-Statistik (nur Zahlen pro Stunde/Tag).
_SCHEMA_V2 = """
ALTER TABLE devices ADD COLUMN online INTEGER;
ALTER TABLE devices ADD COLUMN notes TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          TEXT NOT NULL,
    kind        TEXT NOT NULL,
    title       TEXT NOT NULL,
    device_mac  TEXT,
    detail      TEXT NOT NULL DEFAULT '',
    severity    INTEGER
);
CREATE INDEX IF NOT EXISTS events_at ON events(at);

-- Anfragen pro Gerät und Stunde; mac '' = Client keinem Gerät zuordenbar
CREATE TABLE IF NOT EXISTS dns_hourly (
    hour        TEXT NOT NULL,
    mac         TEXT NOT NULL,
    total       INTEGER NOT NULL DEFAULT 0,
    blocked     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (hour, mac)
);

-- Anfragen pro Gerät, Hauptdomain und Tag (UTC)
CREATE TABLE IF NOT EXISTS domain_daily (
    day         TEXT NOT NULL,
    mac         TEXT NOT NULL,
    domain      TEXT NOT NULL,
    total       INTEGER NOT NULL DEFAULT 0,
    blocked     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, mac, domain)
);
CREATE INDEX IF NOT EXISTS domain_daily_mac ON domain_daily(mac, day);
"""

# v3: KI-Vorbewertung pro Vorfall (wird mit dem Vorfall gelöscht).
_SCHEMA_V3 = """
CREATE TABLE IF NOT EXISTS ai_assessments (
    incident_id INTEGER PRIMARY KEY REFERENCES incidents(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    model       TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    risk        TEXT NOT NULL,
    action      TEXT NOT NULL,
    summary     TEXT NOT NULL,
    reasons     TEXT NOT NULL DEFAULT '[]'
);
"""

# v4: Laptop-Agent (osquery): Agenten mit Token und gesehene Einträge (Ports, Autostart …).
_SCHEMA_V4 = """
CREATE TABLE IF NOT EXISTS agents (
    device_mac     TEXT PRIMARY KEY REFERENCES devices(mac) ON DELETE CASCADE,
    token_hash     TEXT NOT NULL UNIQUE,
    created_at     TEXT NOT NULL,
    last_report_at TEXT,
    hostname       TEXT,
    os             TEXT,
    posture        TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS host_items (
    device_mac  TEXT NOT NULL REFERENCES devices(mac) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    key         TEXT NOT NULL,
    data        TEXT NOT NULL DEFAULT '{}',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    PRIMARY KEY (device_mac, kind, key)
);
"""

# v5: über die Firewall getrennte Geräte.
_SCHEMA_V5 = """
CREATE TABLE IF NOT EXISTS blocks (
    device_mac  TEXT PRIMARY KEY REFERENCES devices(mac) ON DELETE CASCADE,
    ip          TEXT NOT NULL,
    blocked_at  TEXT NOT NULL,
    incident_id INTEGER
);
"""

# v6: Verlauf je Vorfall für die Regel-Qualität (#28). Ohne Gerät, Domain oder Titel –
# nur Regel, Zeitpunkt und Status –, darum länger aufbewahrt als die Vorfälle selbst.
_SCHEMA_V6 = """
CREATE TABLE IF NOT EXISTS incident_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          TEXT NOT NULL,
    incident_id INTEGER NOT NULL,
    rule        TEXT NOT NULL,
    kind        TEXT NOT NULL,
    status      TEXT NOT NULL,
    manual      INTEGER NOT NULL DEFAULT 0,
    ai_verdict  TEXT
);
CREATE INDEX IF NOT EXISTS incident_history_at ON incident_history(at);
INSERT INTO incident_history (at, incident_id, rule, kind, status)
    SELECT created_at, id, rule, 'opened', 'new' FROM incidents;
"""

# v7: sprachneutrale Merkmale für Ereignisse (#29) – Titel sind übersetzt und werden nicht mehr
# ausgewertet. Bestehende (deutsche) Einträge werden einmalig eingeordnet.
_SCHEMA_V7 = """
ALTER TABLE events ADD COLUMN tag TEXT NOT NULL DEFAULT '';
ALTER TABLE events ADD COLUMN subject TEXT NOT NULL DEFAULT '';
UPDATE events SET tag = 'source_down', subject = substr(title, 1, length(title) - 17)
    WHERE kind = 'source' AND title LIKE '% nicht erreichbar';
UPDATE events SET tag = 'source_up', subject = substr(title, 1, length(title) - 18)
    WHERE kind = 'source' AND title LIKE '% wieder erreichbar';
UPDATE events SET tag = 'disk_low' WHERE kind = 'source' AND title = 'Speicherplatz knapp';
UPDATE events SET tag = 'disk_ok'
    WHERE kind = 'source' AND title = 'Speicherplatz wieder ausreichend';
UPDATE events SET tag = 'resolved'
    WHERE kind = 'incident_status' AND title LIKE 'Vorfall erledigt:%';
UPDATE events SET tag = 'ignored'
    WHERE kind = 'incident_status' AND title LIKE 'Vorfall ignoriert:%';
UPDATE events SET tag = 'investigating'
    WHERE kind = 'incident_status' AND title LIKE 'Vorfall in Prüfung:%';
UPDATE events SET tag = 'new'
    WHERE kind = 'incident_status' AND title LIKE 'Vorfall wieder geöffnet:%';
UPDATE events SET tag = 'disconnected'
    WHERE kind = 'incident_status'
      AND (title LIKE 'Vorfall getrennt:%' OR title LIKE '% über die Firewall getrennt');
UPDATE events SET tag = 'released'
    WHERE kind = 'incident_status' AND title LIKE '% wieder freigegeben';
"""

# v8: Laptop-Agent – welche Arten (port, autostart, login) seit wann gelernt sind.
# Bestehende Agenten: ab dem ersten gespeicherten Eintrag jeder Art.
_SCHEMA_V8 = """
ALTER TABLE agents ADD COLUMN learned TEXT NOT NULL DEFAULT '{}';
UPDATE agents SET learned = COALESCE((
    SELECT json_group_object(kind, first) FROM (
        SELECT device_mac, kind, MIN(first_seen) AS first FROM host_items
        GROUP BY device_mac, kind
    ) AS k WHERE k.device_mac = agents.device_mac
), '{}');
"""

_MIGRATIONS = {
    1: _SCHEMA, 2: _SCHEMA_V2, 3: _SCHEMA_V3, 4: _SCHEMA_V4, 5: _SCHEMA_V5, 6: _SCHEMA_V6,
    7: _SCHEMA_V7, 8: _SCHEMA_V8,
}  # fmt: skip


def hour_key(at: datetime) -> str:
    return at.astimezone(UTC).strftime("%Y-%m-%dT%H:00:00+00:00")


def day_key(at: datetime) -> str:
    return at.astimezone(UTC).strftime("%Y-%m-%d")


def _ts(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("Zeitangaben müssen eine Zeitzone haben")
    return dt.isoformat()


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


class Store:
    def __init__(self, path: str | Path = ":memory:", read_only: bool = False) -> None:
        if read_only:
            # Nur lesen (MCP-Server): SQLite verweigert jeden Schreibversuch selbst.
            uri = f"file:{Path(path).resolve()}?mode=ro"
            self._db = sqlite3.connect(uri, uri=True, isolation_level=None)
        else:
            self._db = sqlite3.connect(path, isolation_level=None)  # Transaktionen explizit
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        if read_only:
            version = self._db.execute("PRAGMA user_version").fetchone()[0]
            if version != SCHEMA_VERSION:
                raise RuntimeError(
                    f"Datenbank hat Schema v{version}, erwartet v{SCHEMA_VERSION} – "
                    "erst den Aluco-Dienst starten"
                )
            return
        if str(path) != ":memory:":
            self._db.execute("PRAGMA journal_mode = WAL")
        self._migrate()

    def close(self) -> None:
        self._db.close()

    def backup_to(self, target: str | Path) -> None:
        """Konsistente Kopie im laufenden Betrieb (SQLite-Online-Backup)."""
        dest = sqlite3.connect(target)
        try:
            self._db.backup(dest)
        finally:
            dest.close()

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
        for target in range(version + 1, SCHEMA_VERSION + 1):
            # Jede Stufe atomar: Schema-Änderung und Versionsnummer gemeinsam.
            script = _MIGRATIONS[target]
            self._db.executescript(f"BEGIN; {script} PRAGMA user_version = {target}; COMMIT;")

    # --- Geräte -------------------------------------------------------------------

    def device(self, mac: str) -> Device | None:
        row = self._db.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
        return _device(row) if row else None

    def device_by_ip(self, ip: str) -> Device | None:
        row = self._db.execute(
            "SELECT * FROM devices WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)
        ).fetchone()
        return _device(row) if row else None

    def release_ip(self, ip: str, keep_mac: str) -> int:
        """IP gehört jetzt ``keep_mac``: bei allen anderen Geräten entfernen (DHCP-Wechsel)."""
        return self._db.execute(
            "UPDATE devices SET ip = NULL WHERE ip = ? AND mac != ?", (ip, keep_mac)
        ).rowcount

    def devices(self) -> list[Device]:
        rows = self._db.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
        return [_device(r) for r in rows]

    def save_device(self, d: Device) -> Device:
        self._db.execute(
            """
            INSERT INTO devices (mac, first_seen, last_seen, ip, hostname, vendor, name,
                                 trust, protected, online, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                first_seen = excluded.first_seen, last_seen = excluded.last_seen,
                ip = excluded.ip, hostname = excluded.hostname, vendor = excluded.vendor,
                name = excluded.name, trust = excluded.trust, protected = excluded.protected,
                online = excluded.online, notes = excluded.notes
            """,
            (
                d.mac, _ts(d.first_seen), _ts(d.last_seen), d.ip, d.hostname, d.vendor,
                d.name, d.trust.value, int(d.protected),
                None if d.online is None else int(d.online), d.notes,
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

    def delete_device_domains(self, mac: str) -> int:
        cur = self._db.execute("DELETE FROM device_domains WHERE mac = ?", (mac,))
        return cur.rowcount

    # --- DNS-Statistik (nur Zahlen) ----------------------------------------------

    def count_query(self, mac: str, domain: str | None, at: datetime, blocked: bool) -> None:
        """Eine Anfrage zählen: pro Stunde und – mit Domain – pro Tag und Hauptdomain."""
        b = int(blocked)
        self._db.execute(
            "INSERT INTO dns_hourly (hour, mac, total, blocked) VALUES (?, ?, 1, ?) "
            "ON CONFLICT(hour, mac) DO UPDATE SET total = total + 1, blocked = blocked + ?",
            (hour_key(at), mac, b, b),
        )
        if domain:
            self._db.execute(
                "INSERT INTO domain_daily (day, mac, domain, total, blocked) "
                "VALUES (?, ?, ?, 1, ?) ON CONFLICT(day, mac, domain) "
                "DO UPDATE SET total = total + 1, blocked = blocked + ?",
                (day_key(at), mac, domain, b, b),
            )

    def dns_hourly(
        self, since: datetime, mac: str | None = None
    ) -> list[tuple[datetime, int, int]]:
        """(Stunde, Anfragen, blockiert) ab ``since``; ohne ``mac`` über alle Clients."""
        sql = "SELECT hour, sum(total), sum(blocked) FROM dns_hourly WHERE hour >= ?"
        params: list[str] = [hour_key(since)]
        if mac is not None:
            sql += " AND mac = ?"
            params.append(mac)
        sql += " GROUP BY hour ORDER BY hour"
        return [(_dt(h), t, b) for h, t, b in self._db.execute(sql, params).fetchall()]

    def dns_hourly_by_device(self, since: datetime) -> dict[str, dict[datetime, int]]:
        """Pro Gerät: Stunde → Anfragen (für Mini-Verläufe)."""
        out: dict[str, dict[datetime, int]] = {}
        rows = self._db.execute(
            "SELECT mac, hour, total FROM dns_hourly WHERE hour >= ? AND mac != ''",
            (hour_key(since),),
        ).fetchall()
        for mac, hour, total in rows:
            out.setdefault(mac, {})[_dt(hour)] = total
        return out

    def top_devices(self, since: datetime, limit: int = 5) -> list[tuple[str, int]]:
        rows = self._db.execute(
            "SELECT mac, sum(total) AS n FROM dns_hourly WHERE hour >= ? AND mac != '' "
            "GROUP BY mac ORDER BY n DESC LIMIT ?",
            (hour_key(since), limit),
        ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def top_blocked_domains(self, since: datetime, limit: int = 5) -> list[tuple[str, int]]:
        rows = self._db.execute(
            "SELECT domain, sum(blocked) AS n FROM domain_daily WHERE day >= ? "
            "GROUP BY domain HAVING n > 0 ORDER BY n DESC LIMIT ?",
            (day_key(since), limit),
        ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def device_domain_stats(
        self, mac: str, since: datetime
    ) -> list[tuple[str, datetime, int, int]]:
        """(Hauptdomain, zuerst gesehen, Anfragen, blockiert) für ein Gerät, neueste zuerst."""
        rows = self._db.execute(
            """
            SELECT d.domain, d.first_seen,
                   coalesce(sum(s.total), 0), coalesce(sum(s.blocked), 0)
            FROM device_domains d
            LEFT JOIN domain_daily s
                   ON s.mac = d.mac AND s.domain = d.domain AND s.day >= ?
            WHERE d.mac = ?
            GROUP BY d.domain, d.first_seen
            ORDER BY d.first_seen DESC, d.domain
            """,
            (day_key(since), mac),
        ).fetchall()
        return [(r[0], _dt(r[1]), r[2], r[3]) for r in rows]

    def delete_device_stats(self, mac: str) -> None:
        self._db.execute("DELETE FROM dns_hourly WHERE mac = ?", (mac,))
        self._db.execute("DELETE FROM domain_daily WHERE mac = ?", (mac,))

    def purge_stats(self, older_than: datetime) -> None:
        self._db.execute("DELETE FROM dns_hourly WHERE hour < ?", (hour_key(older_than),))
        self._db.execute("DELETE FROM domain_daily WHERE day < ?", (day_key(older_than),))

    # --- Chronik ------------------------------------------------------------------

    def add_event(self, e: Event) -> None:
        self._db.execute(
            "INSERT INTO events (at, kind, title, device_mac, detail, severity, tag, subject) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                _ts(e.at), e.kind.value, e.title, e.device_mac, e.detail,
                None if e.severity is None else int(e.severity), e.tag, e.subject,
            ),
        )  # fmt: skip

    def events(
        self,
        limit: int = 50,
        kinds: frozenset[EventKind] | None = None,
        device_mac: str | None = None,
        since: datetime | None = None,
    ) -> list[Event]:
        sql = "SELECT * FROM events WHERE 1 = 1"
        params: list[str | int] = []
        if kinds:
            sql += f" AND kind IN ({','.join('?' * len(kinds))})"
            params += sorted(k.value for k in kinds)
        if device_mac is not None:
            sql += " AND device_mac = ?"
            params.append(device_mac)
        if since is not None:
            sql += " AND at > ?"
            params.append(_ts(since))
        sql += " ORDER BY at DESC, id DESC LIMIT ?"
        params.append(limit)
        return [_event(r) for r in self._db.execute(sql, params).fetchall()]

    def delete_device_events(self, mac: str, kinds: frozenset[EventKind]) -> int:
        """Ereignisse eines Geräts löschen (Firmengerät: Vorfälle verraten Verhalten)."""
        if not kinds:
            return 0
        placeholders = ",".join("?" * len(kinds))  # nur Platzhalter, Werte als Parameter
        return self._db.execute(
            f"DELETE FROM events WHERE device_mac = ? AND kind IN ({placeholders})",  # noqa: S608
            (mac, *sorted(k.value for k in kinds)),
        ).rowcount

    def purge_events(self, older_than: datetime) -> int:
        return self._db.execute("DELETE FROM events WHERE at < ?", (_ts(older_than),)).rowcount

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

    def delete_incidents(self, device_mac: str, rules: frozenset[str]) -> int:
        """Vorfälle eines Geräts zu bestimmten Regeln löschen (z. B. bei Firmengeräten)."""
        if not rules:
            return 0
        placeholders = ",".join("?" * len(rules))  # nur Platzhalter, Werte als Parameter
        cur = self._db.execute(
            f"DELETE FROM incidents WHERE device_mac = ? AND rule IN ({placeholders})",  # noqa: S608
            (device_mac, *sorted(rules)),
        )
        return cur.rowcount

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

    # --- Verlauf für die Regel-Qualität ---------------------------------------------

    def add_history(self, h: HistoryEntry) -> None:
        self._db.execute(
            """
            INSERT INTO incident_history (at, incident_id, rule, kind, status, manual, ai_verdict)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _ts(h.at), h.incident_id, h.rule, h.kind.value, h.status.value,
                int(h.manual), h.ai_verdict,
            ),
        )  # fmt: skip

    def history(self, since: datetime | None = None) -> list[HistoryEntry]:
        """Verlauf ab ``since`` (alles ohne) – plus für jeden Vorfall darin den letzten
        Eintrag davor, damit sich die Zeit bis zur Entscheidung berechnen lässt."""
        if since is None:
            rows = self._db.execute("SELECT * FROM incident_history ORDER BY at, id").fetchall()
        else:
            rows = self._db.execute(
                """
                SELECT * FROM incident_history
                WHERE at >= ?1
                   OR id IN (SELECT MAX(id) FROM incident_history WHERE at < ?1
                             AND incident_id IN (SELECT incident_id FROM incident_history
                                                 WHERE at >= ?1)
                             GROUP BY incident_id)
                ORDER BY at, id
                """,
                (_ts(since),),
            ).fetchall()
        return [_history(r) for r in rows]

    def history_start(self) -> datetime | None:
        row = self._db.execute("SELECT MIN(at) FROM incident_history").fetchone()
        return _dt(row[0]) if row and row[0] else None

    def purge_history(self, older_than: datetime) -> int:
        return self._db.execute(
            "DELETE FROM incident_history WHERE at < ?", (_ts(older_than),)
        ).rowcount

    # --- KI-Vorbewertung ----------------------------------------------------------

    def save_assessment(self, a: Assessment) -> None:
        self._db.execute(
            """
            INSERT INTO ai_assessments (incident_id, created_at, model, verdict, risk, action,
                                        summary, reasons)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
                created_at = excluded.created_at, model = excluded.model,
                verdict = excluded.verdict, risk = excluded.risk, action = excluded.action,
                summary = excluded.summary, reasons = excluded.reasons
            """,
            (
                a.incident_id, _ts(a.created_at), a.model, a.verdict, a.risk, a.action,
                a.summary, json.dumps(a.reasons, ensure_ascii=False),
            ),
        )  # fmt: skip

    def assessment(self, incident_id: int) -> Assessment | None:
        row = self._db.execute(
            "SELECT * FROM ai_assessments WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        return _assessment(row) if row else None

    def assessments(self) -> dict[int, Assessment]:
        rows = self._db.execute("SELECT * FROM ai_assessments").fetchall()
        return {r["incident_id"]: _assessment(r) for r in rows}

    def delete_device_assessments(self, mac: str) -> int:
        return self._db.execute(
            "DELETE FROM ai_assessments WHERE incident_id IN "
            "(SELECT id FROM incidents WHERE device_mac = ?)",
            (mac,),
        ).rowcount

    # --- Laptop-Agent ---------------------------------------------------------------

    def add_agent(self, mac: str, token_hash: str, at: datetime) -> None:
        self._db.execute(
            "INSERT INTO agents (device_mac, token_hash, created_at) VALUES (?, ?, ?) "
            "ON CONFLICT(device_mac) DO UPDATE SET token_hash = excluded.token_hash, "
            "created_at = excluded.created_at",
            (mac, token_hash, _ts(at)),
        )

    def agent_by_token_hash(self, token_hash: str) -> dict[str, object] | None:
        row = self._db.execute(
            "SELECT * FROM agents WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        return _agent(row) if row else None

    def agent(self, mac: str) -> dict[str, object] | None:
        row = self._db.execute("SELECT * FROM agents WHERE device_mac = ?", (mac,)).fetchone()
        return _agent(row) if row else None

    def agents(self) -> dict[str, dict[str, object]]:
        rows = self._db.execute("SELECT * FROM agents").fetchall()
        return {r["device_mac"]: _agent(r) for r in rows}

    def update_agent_report(
        self, mac: str, at: datetime, hostname: str | None, os: str | None, posture: dict
    ) -> None:
        self._db.execute(
            "UPDATE agents SET last_report_at = ?, hostname = ?, os = ?, posture = ? "
            "WHERE device_mac = ?",
            (_ts(at), hostname, os, json.dumps(posture, sort_keys=True), mac),
        )

    def delete_agent(self, mac: str) -> int:
        n = self._db.execute("DELETE FROM agents WHERE device_mac = ?", (mac,)).rowcount
        self._db.execute("DELETE FROM host_items WHERE device_mac = ?", (mac,))
        return n

    def upsert_host_item(
        self, mac: str, kind: str, key: str, data: dict[str, str], at: datetime
    ) -> bool:
        """Eintrag vermerken. True, wenn er für dieses Gerät neu ist."""
        payload = json.dumps(data, sort_keys=True, ensure_ascii=False)
        cur = self._db.execute(
            "INSERT INTO host_items (device_mac, kind, key, data, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(device_mac, kind, key) DO NOTHING",
            (mac, kind, key, payload, _ts(at), _ts(at)),
        )
        if cur.rowcount == 1:
            return True
        self._db.execute(
            "UPDATE host_items SET data = ?, last_seen = ? "
            "WHERE device_mac = ? AND kind = ? AND key = ?",
            (payload, _ts(at), mac, kind, key),
        )
        return False

    def set_agent_learned(self, mac: str, learned: dict[str, datetime]) -> None:
        """Arten, deren Bestand gelernt ist – mit Zeitpunkt (Beginn des Lernzeitraums)."""
        payload = json.dumps({k: _ts(v) for k, v in learned.items()}, sort_keys=True)
        self._db.execute("UPDATE agents SET learned = ? WHERE device_mac = ?", (payload, mac))

    def host_items(
        self, mac: str, kind: str | None = None, seen_since: datetime | None = None
    ) -> list[dict[str, object]]:
        sql = "SELECT * FROM host_items WHERE device_mac = ?"
        params: list[str] = [mac]
        if kind:
            sql += " AND kind = ?"
            params.append(kind)
        if seen_since is not None:
            sql += " AND last_seen >= ?"
            params.append(_ts(seen_since))
        sql += " ORDER BY kind, key"
        return [
            {
                "kind": r["kind"],
                "key": r["key"],
                "data": json.loads(r["data"]),
                "first_seen": _dt(r["first_seen"]),
                "last_seen": _dt(r["last_seen"]),
            }
            for r in self._db.execute(sql, params).fetchall()
        ]

    def purge_host_items(self, older_than: datetime) -> int:
        """Nur Einträge löschen, die in einem späteren Bericht fehlten (wirklich weg). Ist ein
        Laptop bloß länger nicht da, bleibt sein Bestand – sonst wäre bei der Rückkehr alles
        "neu" (Alarmflut) oder müsste still neu gelernt werden (Lücke)."""
        return self._db.execute(
            "DELETE FROM host_items WHERE last_seen < ? AND last_seen < COALESCE(("
            "SELECT last_report_at FROM agents a WHERE a.device_mac = host_items.device_mac"
            "), '9999')",
            (_ts(older_than),),
        ).rowcount

    # --- Getrennte Geräte (Firewall) -----------------------------------------------

    def save_block(self, mac: str, ip: str, at: datetime, incident_id: int | None) -> None:
        self._db.execute(
            "INSERT INTO blocks (device_mac, ip, blocked_at, incident_id) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(device_mac) DO UPDATE SET ip = excluded.ip",
            (mac, ip, _ts(at), incident_id),
        )

    def block(self, mac: str) -> dict[str, object] | None:
        r = self._db.execute("SELECT * FROM blocks WHERE device_mac = ?", (mac,)).fetchone()
        return _block(r) if r else None

    def blocks(self) -> dict[str, dict[str, object]]:
        return {r["device_mac"]: _block(r) for r in self._db.execute("SELECT * FROM blocks")}

    def delete_block(self, mac: str) -> int:
        return self._db.execute("DELETE FROM blocks WHERE device_mac = ?", (mac,)).rowcount

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
        online=None if r["online"] is None else bool(r["online"]),
        notes=r["notes"],
    )


def _event(r: sqlite3.Row) -> Event:
    return Event(
        id=r["id"],
        at=_dt(r["at"]),
        kind=EventKind(r["kind"]),
        title=r["title"],
        device_mac=r["device_mac"],
        detail=r["detail"],
        severity=None if r["severity"] is None else Severity(r["severity"]),
        tag=r["tag"],
        subject=r["subject"],
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


def _history(r: sqlite3.Row) -> HistoryEntry:
    return HistoryEntry(
        at=_dt(r["at"]),
        incident_id=r["incident_id"],
        rule=r["rule"],
        kind=HistoryKind(r["kind"]),
        status=IncidentStatus(r["status"]),
        manual=bool(r["manual"]),
        ai_verdict=r["ai_verdict"],
    )


def _assessment(r: sqlite3.Row) -> Assessment:
    return Assessment(
        incident_id=r["incident_id"],
        created_at=_dt(r["created_at"]),
        model=r["model"],
        verdict=r["verdict"],
        risk=r["risk"],
        action=r["action"],
        summary=r["summary"],
        reasons=json.loads(r["reasons"]),
    )


def _agent(r: sqlite3.Row) -> dict[str, object]:
    return {
        "device_mac": r["device_mac"],
        "created_at": _dt(r["created_at"]),
        "last_report_at": _dt(r["last_report_at"]) if r["last_report_at"] else None,
        "hostname": r["hostname"],
        "os": r["os"],
        "posture": json.loads(r["posture"]),
        "learned": {k: _dt(v) for k, v in json.loads(r["learned"]).items()},
    }


def _block(r: sqlite3.Row) -> dict[str, object]:
    return {
        "device_mac": r["device_mac"],
        "ip": r["ip"],
        "blocked_at": _dt(r["blocked_at"]),
        "incident_id": r["incident_id"],
    }
