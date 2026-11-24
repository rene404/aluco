"""MCP-Server: Aluco-Daten für Claude Desktop, Claude Code und andere MCP-Hosts.

- **Nur lesend:** Die Datenbank wird schreibgeschützt geöffnet; kein Werkzeug ändert etwas.
- **stdio:** Der Host startet den Server als Prozess, z. B. per SSH auf dem Pi
  (``ssh pi docker exec -i aluco python -m aluco mcp``). Es wird kein Port geöffnet.
- **Firmengeräte:** Es gibt über sie nur Online-Status und Stammdaten – Aluco speichert
  zu ihnen weder Domains noch DNS-Statistik.

Wer den Server mit einem Cloud-Modell nutzt, gibt die abgefragten Daten an dessen
Anbieter weiter (siehe docs/mcp.md).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from aluco import __version__
from aluco.i18n import _, get_language
from aluco.model import OPEN_STATUSES, Device, Event, Incident, utcnow
from aluco.store import Store
from aluco.web import views
from aluco.web.app import SEVERITY_DE, STATUS_DE, STATUS_FILTERS, TRUST_DE

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)

INSTRUCTIONS = """\
Aluco überwacht ein privates Heimnetz: Geräteinventar, DNS-Anfragen pro Gerät, Vorfälle
(z. B. neues Gerät, neue Domain bei IoT-Geräten, bekannte Schad-Domain) und eine Chronik.
Antworte auf {sprache} und für Laien. Zeiten sind lokale Zeit. DNS-Daten liegen stündlich als
Anzahl und täglich pro Hauptdomain vor – nicht als einzelne Anfragen mit Uhrzeit.
Firmengeräte werden nur passiv beobachtet: zu ihnen gibt es keine Domains oder Statistik.
"""

FILTER_ALIASES = {
    "offen": "open",
    "open": "open",
    "ignoriert": "ignored",
    "ignored": "ignored",
    "erledigt": "resolved",
    "resolved": "resolved",
    "alle": "all",
    "all": "all",
}


def build_server(db_path: Path, tz_name: str = "UTC") -> MCPServer:
    tz = ZoneInfo(tz_name)
    mcp = MCPServer(
        "Aluco",
        title="Aluco – Hausradar für dein Netz",
        instructions=INSTRUCTIONS.format(
            sprache="Englisch (English)" if get_language() == "en" else "Deutsch"
        ),
        version=__version__,
    )

    @contextmanager
    def store() -> Iterator[Store]:
        if not db_path.exists():
            raise ToolError("Noch keine Daten – läuft der Aluco-Dienst?")
        s = Store(db_path, read_only=True)
        try:
            yield s
        finally:
            s.close()

    def local(dt: datetime) -> str:
        return dt.astimezone(tz).strftime("%Y-%m-%d %H:%M")

    def parse_local(value: str) -> datetime:
        try:
            dt = datetime.fromisoformat(value)
        except ValueError as e:
            raise ToolError(f"Zeitangabe nicht lesbar: {value!r} (Format 2026-11-18T22:00)") from e
        return dt.replace(tzinfo=tz) if dt.tzinfo is None else dt

    def device_brief(d: Device) -> dict[str, Any]:
        return {
            "name": d.label,
            "mac": d.mac,
            "ip": d.ip,
            "hersteller": d.vendor,
            "stufe": _(TRUST_DE[d.trust]),
            "online": d.online,
            "zuletzt_gesehen": local(d.last_seen),
            "schutzliste": d.protected,
        }

    def incident_brief(i: Incident, devices: dict[str, Device], ai: dict[int, Any]) -> dict:
        d = devices.get(i.device_mac or "")
        a = ai.get(i.id or -1)
        return {
            "id": i.id,
            "titel": i.title,
            "schwere": _(SEVERITY_DE[i.severity]),
            "status": _(STATUS_DE[i.status]),
            "geraet": d.label if d else i.device_mac,
            "zuletzt": local(i.updated_at),
            "anzahl": i.occurrences,
            "ki_einschaetzung": a.verdict_de if a else None,
        }

    def event_brief(e: Event, devices: dict[str, Device]) -> dict[str, Any]:
        d = devices.get(e.device_mac or "")
        return {
            "zeit": local(e.at),
            "art": e.kind.value,
            "titel": e.title,
            "detail": e.detail or None,
            "geraet": d.label if d else None,
        }

    def find_device(s: Store, name_or_mac: str) -> Device:
        needle = name_or_mac.strip().lower()
        if not needle:
            raise ToolError("Bitte Gerätename oder MAC-Adresse angeben")
        devices = s.devices()
        exact = [d for d in devices if needle in {d.mac, (d.name or "").lower(), d.label.lower()}]
        if len(exact) == 1:
            return exact[0]
        hits = exact or [
            d
            for d in devices
            if needle in " ".join(filter(None, [d.label, d.hostname, d.ip, d.mac])).lower()
        ]
        if len(hits) == 1:
            return hits[0]
        if not hits:
            raise ToolError(f"Kein Gerät passt zu {name_or_mac!r}. list_devices zeigt alle.")
        names = ", ".join(f"{d.label} ({d.mac})" for d in hits[:10])
        raise ToolError(f"Mehrere Geräte passen: {names}. Bitte genauer angeben.")

    # --- Werkzeuge -------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    def get_overview() -> dict[str, Any]:
        """Lagebild des Heimnetzes: offene Vorfälle, Geräte online/offline, DNS der letzten
        24 Stunden, Zustand der Datenquellen. Guter Einstieg für jede Frage."""
        now = utcnow()
        with store() as s:
            devices = s.devices()
            open_incidents = s.incidents(OPEN_STATUSES)
            dev = {d.mac: d for d in devices}
            ai = s.assessments()
            hourly = s.dns_hourly(since=now - timedelta(hours=24))
            last_run = s.cursor("runner:last_run")
            errors = [e for e in (s.cursor("runner:last_errors") or "").split("\n") if e]
        return {
            "lage": views.situation(open_incidents).title,
            "offene_vorfaelle": [incident_brief(i, dev, ai) for i in open_incidents[:10]],
            "geraete": {
                "gesamt": len(devices),
                "online": sum(1 for d in devices if d.online),
                "offline": sum(1 for d in devices if d.online is False),
            },
            "dns_24h": {
                "anfragen": sum(t for _, t, _ in hourly),
                "blockiert": sum(b for _, _, b in hourly),
            },
            "letzter_lauf": local(datetime.fromisoformat(last_run)) if last_run else None,
            "gestoerte_datenquellen": errors,
        }

    @mcp.tool(annotations=READ_ONLY)
    def rule_quality(days: int = 30) -> dict[str, Any]:
        """Regel-Qualität: je Erkennungsregel, wie oft sie ausgelöst hat und wie oft ihre
        Vorfälle ignoriert, erledigt oder zum Trennen geführt haben (nur Entscheidungen von
        Hand). Regeln mit über 70 % ignorierten Vorfällen gelten als abgestumpft."""
        from aluco.ai import RULE_TEXT
        from aluco.quality import rule_quality as compute

        days = max(1, min(days, 400))
        since = utcnow() - timedelta(days=days)
        with store() as s:
            history = s.history(since=since)
            started = s.history_start()
        stats = compute(history, since, rules=tuple(RULE_TEXT))
        return {
            "zeitraum_tage": days,
            "aufgezeichnet_seit": local(started) if started else None,
            "regeln": [
                {
                    "regel": q.rule,
                    "name": _(views.RULE_NAME_DE.get(q.rule, q.rule)),
                    "ausgeloest": q.triggered,
                    "erneut_aufgetreten": q.reopened,
                    "ignoriert": q.ignored,
                    "erledigt": q.resolved,
                    "automatisch_erledigt": q.auto_resolved,
                    "getrennt": q.disconnected,
                    "ignorier_quote": round(q.ignore_rate, 2)
                    if q.ignore_rate is not None
                    else None,
                    "abgestumpft": q.flagged,
                    "zeit_bis_entscheidung": views.duration(q.median_wait),
                    "ki_verdaechtig_aber_ignoriert": q.ai_suspect_ignored,
                    "ki_harmlos_aber_getrennt": q.ai_harmless_disconnected,
                }
                for q in stats
            ],
        }

    @mcp.tool(annotations=READ_ONLY)
    def list_incidents(status: str = "offen", limit: int = 20) -> list[dict[str, Any]]:
        """Vorfälle auflisten, schwerste zuerst. status: offen, ignoriert, erledigt oder alle."""
        key = FILTER_ALIASES.get(status.strip().lower())
        if key is None:
            raise ToolError("status muss offen, ignoriert, erledigt oder alle sein")
        with store() as s:
            items = s.incidents(STATUS_FILTERS[key])
            dev = {d.mac: d for d in s.devices()}
            ai = s.assessments()
        return [incident_brief(i, dev, ai) for i in items[: max(1, min(limit, 100))]]

    @mcp.tool(annotations=READ_ONLY)
    def get_incident(incident_id: int) -> dict[str, Any]:
        """Ein Vorfall im Detail: warum er auffällig ist, Notiz, KI-Einschätzung, Gerät."""
        with store() as s:
            i = s.incident_by_id(incident_id)
            if i is None:
                raise ToolError(f"Kein Vorfall mit Nummer {incident_id}")
            dev = {d.mac: d for d in s.devices()}
            a = s.assessment(incident_id)
        d = dev.get(i.device_mac or "")
        return {
            **incident_brief(i, dev, {incident_id: a} if a else {}),
            "erstellt": local(i.created_at),
            "warum_auffaellig": views.explain(i),
            "notiz": i.note or None,
            "geraet_details": device_brief(d) if d else None,
            "ki": None
            if a is None
            else {
                "einschaetzung": a.verdict_de,
                "risiko": a.risk,
                "empfehlung": a.action_de,
                "zusammenfassung": a.summary,
                "gruende": a.reasons,
            },
            "moegliche_aktionen": "Status ändern geht nur im Dashboard (dieser Zugang ist "
            "nur lesend).",
        }

    @mcp.tool(annotations=READ_ONLY)
    def list_devices(search: str = "", trust: str = "") -> list[dict[str, Any]]:
        """Geräteinventar. Optional Suche (Name, IP, MAC, Hersteller) und Stufe
        (bekannt, IoT, Gast, unbekannt, Firma)."""
        q, t = search.strip().lower(), trust.strip().lower()
        with store() as s:
            devices = s.devices()
        out = []
        for d in devices:
            hay = " ".join(filter(None, [d.label, d.hostname, d.ip, d.mac, d.vendor])).lower()
            if q and q not in hay:
                continue
            if t and t not in {
                d.trust.value,
                TRUST_DE[d.trust].lower(),
                _(TRUST_DE[d.trust]).lower(),
            }:
                continue
            out.append(device_brief(d))
        return out

    @mcp.tool(annotations=READ_ONLY)
    def get_device(name_or_mac: str) -> dict[str, Any]:
        """Ein Gerät im Detail: Stammdaten, Aktivität der letzten 7 Tage, meistgenutzte
        Domains, Vorfälle und Verlauf."""
        now = utcnow()
        week_ago = now - timedelta(days=7)
        with store() as s:
            d = find_device(s, name_or_mac)
            incidents = [i for i in s.incidents() if i.device_mac == d.mac]
            history = s.events(limit=15, device_mac=d.mac)
            rows = [] if d.is_company else s.dns_hourly(since=week_ago, mac=d.mac)
            domains = [] if d.is_company else s.device_domain_stats(d.mac, since=week_ago)
        info: dict[str, Any] = {
            **device_brief(d),
            "hostname": d.hostname,
            "zuerst_gesehen": local(d.first_seen),
            "notiz": d.notes or None,
            "vorfaelle": [
                {
                    "id": i.id,
                    "titel": i.title,
                    "schwere": _(SEVERITY_DE[i.severity]),
                    "status": _(STATUS_DE[i.status]),
                }
                for i in incidents
            ],
            "verlauf": [{"zeit": local(e.at), "titel": e.title} for e in history],
        }
        if d.is_company:
            info["hinweis"] = "Firmengerät: nur passiv beobachtet, keine DNS-Daten gespeichert."
            return info
        per_day: dict[str, list[int]] = {}
        for h, t, b in rows:
            day = per_day.setdefault(h.astimezone(tz).strftime("%Y-%m-%d"), [0, 0])
            day[0] += t
            day[1] += b
        info["aktivitaet_7_tage"] = [
            {"tag": day, "anfragen": t, "blockiert": b} for day, (t, b) in sorted(per_day.items())
        ]
        info["typisches_verhalten"] = views.active_hours(rows, tz) or None
        info["top_domains_7_tage"] = [
            {
                "domain": name,
                "anfragen": n,
                "blockiert": b,
                "zuerst_gesehen": local(first),
                "neu": first >= week_ago,
            }
            for name, first, n, b in sorted(domains, key=lambda x: -x[2])[:25]
        ]
        return info

    @mcp.tool(annotations=READ_ONLY)
    def device_activity(
        name_or_mac: str, start: str = "", end: str = "", hours: int = 24
    ) -> dict[str, Any]:
        """Was hat ein Gerät in einem Zeitraum gemacht? Entweder start/end als lokale Zeit
        (z. B. "2026-11-18T22:00" bis "2026-11-19T06:00" für "letzte Nacht") oder die
        letzten ``hours`` Stunden. Liefert Anfragen pro Stunde und die Domains der
        betroffenen Tage (Domains gibt es nur pro Tag, nicht pro Stunde)."""
        now = utcnow()
        until = parse_local(end) if end else now
        since = parse_local(start) if start else until - timedelta(hours=max(1, min(hours, 720)))
        if since >= until:
            raise ToolError("start muss vor end liegen")
        with store() as s:
            d = find_device(s, name_or_mac)
            if d.is_company:
                return {
                    "geraet": d.label,
                    "hinweis": "Firmengerät: nur passiv beobachtet, keine DNS-Daten gespeichert.",
                }
            rows = [r for r in s.dns_hourly(since=since, mac=d.mac) if r[0] < until]
            day_start = since.astimezone(tz).replace(hour=0, minute=0, second=0, microsecond=0)
            domains = s.device_domain_stats(d.mac, since=day_start)
            history = [
                e for e in s.events(limit=200, device_mac=d.mac, since=since) if e.at < until
            ]
        return {
            "geraet": d.label,
            "zeitraum": f"{local(since)} – {local(until)}",
            "anfragen_gesamt": sum(t for _, t, _ in rows),
            "blockiert_gesamt": sum(b for _, _, b in rows),
            "pro_stunde": [
                {"stunde": local(h), "anfragen": t, "blockiert": b} for h, t, b in rows if t
            ],
            "domains_an_diesen_tagen": [
                {"domain": n, "anfragen": c, "blockiert": b, "neu_seit": local(first)}
                for n, first, c, b in sorted(domains, key=lambda x: -x[2])
                if c
            ][:40],
            "ereignisse": [{"zeit": local(e.at), "titel": e.title} for e in history],
        }

    @mcp.tool(annotations=READ_ONLY)
    def timeline(hours: int = 24, kind: str = "alle") -> list[dict[str, Any]]:
        """Chronik der letzten Stunden: Vorfälle, Geräte online/offline, Datenquellen.
        kind: alle, vorfaelle, geraete oder system."""
        groups = {"vorfaelle": "incidents", "geraete": "devices", "system": "system"}
        key = kind.strip().lower()
        if key not in {"alle", *groups}:
            raise ToolError("kind muss alle, vorfaelle, geraete oder system sein")
        kinds = views.EVENT_GROUPS.get(groups.get(key, ""))
        since = utcnow() - timedelta(hours=max(1, min(hours, 24 * 30)))
        with store() as s:
            events = s.events(limit=200, kinds=kinds, since=since)
            dev = {d.mac: d for d in s.devices()}
        return [event_brief(e, dev) for e in events]

    @mcp.tool(annotations=READ_ONLY)
    def dns_top(hours: int = 24) -> dict[str, Any]:
        """Aktivste Geräte und meistblockierte Domains im Zeitraum."""
        since = utcnow() - timedelta(hours=max(1, min(hours, 24 * 30)))
        with store() as s:
            top = s.top_devices(since=since, limit=10)
            blocked = s.top_blocked_domains(since=since, limit=10)
            dev = {d.mac: d for d in s.devices()}
        return {
            "aktivste_geraete": [
                {"geraet": dev[m].label if m in dev else m, "anfragen": n} for m, n in top
            ],
            "meistblockierte_domains": [{"domain": d, "blockiert": n} for d, n in blocked],
        }

    return mcp
