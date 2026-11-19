"""Dashboard: Übersicht, Vorfälle, Geräte.

Sicherheit: Login mit Passwort, Sitzungs-Cookie (HttpOnly, SameSite=Strict),
Herkunftsprüfung bei POST (CSRF), strikte Content-Security-Policy, keine externen
Ressourcen. Gedacht nur fürs Heimnetz bzw. VPN – nie direkt ins Internet.
"""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from aluco import __version__
from aluco.ai import AssessmentError, Assessor, assess_incident
from aluco.config import AiSettings, ConfigError, ai_settings_from_env, db_path_from_env
from aluco.devices import (
    DeviceNotFoundError,
    set_name,
    set_notes,
    set_protected,
    set_trust,
)
from aluco.incidents import ALLOWED_TRANSITIONS, IncidentService, TransitionError
from aluco.model import (
    OPEN_STATUSES,
    IncidentStatus,
    Severity,
    TrustLevel,
    normalize_mac,
    utcnow,
)
from aluco.store import Store
from aluco.web import views
from aluco.web.auth import LoginThrottle, Sessions, check_password

HERE = Path(__file__).parent
COOKIE = "aluco_session"
PUBLIC_PATHS = ("/login", "/static/", "/healthz")

SEVERITY_DE = {
    Severity.INFO: "Info",
    Severity.LOW: "niedrig",
    Severity.MEDIUM: "mittel",
    Severity.HIGH: "hoch",
    Severity.CRITICAL: "kritisch",
}
STATUS_DE = {
    IncidentStatus.NEW: "neu",
    IncidentStatus.INVESTIGATING: "in Prüfung",
    IncidentStatus.IGNORED: "ignoriert",
    IncidentStatus.DISCONNECTED: "getrennt",
    IncidentStatus.RESOLVED: "erledigt",
}
ACTION_DE = {
    IncidentStatus.INVESTIGATING: "Prüfen",
    IncidentStatus.IGNORED: "Ignorieren",
    IncidentStatus.RESOLVED: "Erledigt",
    IncidentStatus.NEW: "Wieder öffnen",
}
TRUST_DE = {
    TrustLevel.KNOWN: "bekannt",
    TrustLevel.IOT: "IoT",
    TrustLevel.GUEST: "Gast",
    TrustLevel.UNKNOWN: "unbekannt",
    TrustLevel.COMPANY: "Firma",
}
STATUS_FILTERS: dict[str, frozenset[IncidentStatus] | None] = {
    "open": OPEN_STATUSES,
    "ignored": frozenset({IncidentStatus.IGNORED}),
    "resolved": frozenset({IncidentStatus.RESOLVED, IncidentStatus.DISCONNECTED}),
    "all": None,
}


@dataclass(frozen=True, slots=True)
class WebConfig:
    db_path: Path
    password: str = field(repr=False)
    host: str = "0.0.0.0"  # noqa: S104 – im Heimnetz erreichbar; Zugriff nur mit Login
    port: int = 8088
    secure_cookies: bool = False  # True, sobald das Dashboard per HTTPS erreichbar ist
    session_hours: int = 12
    timezone: str = "UTC"
    ai: AiSettings = field(default_factory=AiSettings)
    # Zusätzlich erlaubte Hostnamen (IP-Adressen und localhost sind immer erlaubt).
    allowed_hosts: tuple[str, ...] = ()

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> WebConfig:
        e = dict(os.environ) if env is None else env
        password = e.get("ALUCO_DASHBOARD_PASSWORD", "")
        if len(password) < 12:
            raise ConfigError("ALUCO_DASHBOARD_PASSWORD fehlt oder ist kürzer als 12 Zeichen")
        try:
            port = int(e.get("ALUCO_WEB_PORT", "") or 8088)
        except ValueError as exc:
            raise ConfigError("ALUCO_WEB_PORT muss eine Zahl sein") from exc
        tz = e.get("TZ", "") or "UTC"
        try:
            ZoneInfo(tz)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ConfigError(f"Unbekannte Zeitzone TZ={tz!r}") from exc
        return cls(
            db_path=db_path_from_env(e),
            password=password,
            host=e.get("ALUCO_WEB_HOST", "") or "0.0.0.0",  # noqa: S104
            port=port,
            secure_cookies=e.get("ALUCO_WEB_SECURE_COOKIES", "").lower() in {"1", "true", "yes"},
            timezone=tz,
            ai=ai_settings_from_env(e),
            allowed_hosts=tuple(
                h.strip().lower()
                for h in e.get("ALUCO_WEB_ALLOWED_HOSTS", "").replace(",", " ").split()
                if h.strip()
            ),
        )


def create_app(cfg: WebConfig, assessor: Assessor | None = None) -> Starlette:
    """``assessor``: KI-Bewerter (Tests); sonst aus ``cfg.ai`` erzeugt, falls aktiviert."""
    if assessor is None and cfg.ai.enabled:
        from aluco.ai import ClaudeAssessor

        assessor = ClaudeAssessor(model=cfg.ai.model)
    sessions = Sessions(cfg.session_hours * 3600)
    throttle = LoginThrottle()
    tz = ZoneInfo(cfg.timezone)

    templates = Environment(
        loader=FileSystemLoader(HERE / "templates"),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    templates.globals.update(
        version=__version__,
        SEVERITY_DE=SEVERITY_DE,
        STATUS_DE=STATUS_DE,
        ACTION_DE=ACTION_DE,
        TRUST_DE=TRUST_DE,
        TrustLevel=TrustLevel,
        transitions=lambda s: [t for t in ACTION_DE if t in ALLOWED_TRANSITIONS[s]],
        rel=lambda dt: views.relative(dt, utcnow(), tz),
        fmt_int=views.fmt_int,
        abbr=views.abbreviation,
        tone=views.event_tone,
        explain=views.explain,
        ai_enabled=assessor is not None,
    )
    templates.filters["local"] = lambda dt: dt.astimezone(tz).strftime("%d.%m.%Y %H:%M")
    templates.filters["localdate"] = lambda dt: dt.astimezone(tz).strftime("%d.%m.%Y")

    def render(request: Request, name: str, status_code: int = 200, **ctx: Any) -> HTMLResponse:
        if "nav_open" not in ctx and request.url.path != "/login":
            with store() as s:
                ctx["nav_open"] = len(s.incidents(OPEN_STATUSES))
        html = templates.get_template(name).render(request=request, path=request.url.path, **ctx)
        return HTMLResponse(html, status_code=status_code)

    @contextmanager
    def store() -> Iterator[Store]:
        s = Store(cfg.db_path)
        try:
            yield s
        finally:
            s.close()

    def is_htmx(request: Request) -> bool:
        return request.headers.get("HX-Request") == "true"

    # --- Anmeldung ----------------------------------------------------------------

    async def login_page(request: Request) -> Response:
        return render(request, "login.html")

    async def login(request: Request) -> Response:
        client = request.client.host if request.client else "?"
        if throttle.blocked(client):
            return render(
                request, "login.html", 429, error="Zu viele Versuche. Bitte später erneut."
            )
        form = await request.form()
        if not check_password(str(form.get("password", "")), cfg.password):
            throttle.fail(client)
            return render(request, "login.html", 401, error="Passwort falsch.")
        throttle.reset(client)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            COOKIE,
            sessions.create(),
            max_age=cfg.session_hours * 3600,
            httponly=True,
            samesite="strict",
            secure=cfg.secure_cookies,
        )
        return response

    async def logout(request: Request) -> Response:
        sessions.drop(request.cookies.get(COOKIE))
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(COOKIE)
        return response

    async def healthz(_: Request) -> Response:
        return PlainTextResponse("ok")

    # --- Seiten -------------------------------------------------------------------

    async def overview(request: Request) -> Response:
        rng = "7d" if request.query_params.get("range") == "7d" else "24h"
        flt = request.query_params.get("events", "all")
        if flt not in views.EVENT_GROUPS:
            flt = "all"
        kinds = views.EVENT_GROUPS.get(flt)
        now = utcnow()
        day_ago = now - timedelta(hours=24)
        with store() as s:
            devices = {d.mac: d for d in s.devices()}
            open_incidents = s.incidents(OPEN_STATUSES)
            last_run_raw = s.cursor("runner:last_run")
            last_errors = [e for e in (s.cursor("runner:last_errors") or "").split("\n") if e]
            week = s.dns_hourly(since=now - timedelta(days=8))
            events = s.events(limit=12, kinds=kinds)
            top = s.top_devices(since=day_ago)
            top_blocked = s.top_blocked_domains(since=day_ago)
            # "Seit deinem letzten Besuch": ein Besuch endet nach 30 Min. Pause.
            last_visit_raw, prev_raw = s.cursor("web:last_visit"), s.cursor("web:prev_visit")
            last_visit = datetime.fromisoformat(last_visit_raw) if last_visit_raw else None
            if last_visit is None or now - last_visit > timedelta(minutes=30):
                prev_raw = last_visit_raw
                if prev_raw:
                    s.set_cursor("web:prev_visit", prev_raw)
            s.set_cursor("web:last_visit", now.isoformat())
            prev_visit = datetime.fromisoformat(prev_raw) if prev_raw else None
            since_events = s.events(limit=500, since=prev_visit) if prev_visit else []

        chart = (
            views.hourly_chart(week, now, tz) if rng == "24h" else views.daily_chart(week, now, tz)
        )
        last24 = [(t, b) for h, t, b in week if h > day_ago - timedelta(hours=1)]
        prev24 = [t for h, t, _ in week if day_ago - timedelta(hours=25) < h <= day_ago]
        total24 = sum(t for t, _ in last24)
        blocked24 = sum(b for _, b in last24)
        change = round((total24 - sum(prev24)) / sum(prev24) * 100) if sum(prev24) else None
        by_severity = {sev: 0 for sev in sorted(Severity, reverse=True)}
        for i in open_incidents:
            by_severity[i.severity] += 1
        online = [d for d in devices.values() if d.online]
        offline = [d for d in devices.values() if d.online is False]
        peak_top = top[0][1] if top else 1
        return render(
            request,
            "overview.html",
            nav_open=len(open_incidents),
            situation=views.situation(open_incidents),
            since_text=views.since_summary(since_events),
            prev_visit=prev_visit,
            devices=devices,
            online=len(online),
            offline=len(offline),
            by_severity=by_severity,
            open_count=len(open_incidents),
            total24=total24,
            blocked24=blocked24,
            blocked_pct=round(blocked24 / total24 * 100, 1) if total24 else 0,
            change=change,
            last_run=datetime.fromisoformat(last_run_raw) if last_run_raw else None,
            last_errors=last_errors,
            chart=chart,
            rng=rng,
            events=events,
            event_filter=flt,
            top=[(devices.get(mac), n, round(n / peak_top * 100, 1)) for mac, n in top],
            top_blocked=top_blocked,
        )

    async def incidents(request: Request) -> Response:
        flt = request.query_params.get("status", "open")
        if flt not in STATUS_FILTERS:
            flt = "open"
        with store() as s:
            everything = s.incidents()
            devices = {d.mac: d for d in s.devices()}
            assessments = s.assessments()
        counts = {
            key: sum(1 for i in everything if statuses is None or i.status in statuses)
            for key, statuses in STATUS_FILTERS.items()
        }
        statuses = STATUS_FILTERS[flt]
        items = [i for i in everything if statuses is None or i.status in statuses]
        return render(
            request,
            "incidents.html",
            incidents=items,
            devices=devices,
            filter=flt,
            counts=counts,
            nav_open=counts["open"],
            assessments=assessments,
        )

    async def incident_status(request: Request) -> Response:
        incident_id = request.path_params["incident_id"]
        form = await request.form()
        try:
            new_status = IncidentStatus(str(form.get("status", "")))
        except ValueError:
            return PlainTextResponse("Unbekannter Status", status_code=400)
        if new_status is IncidentStatus.DISCONNECTED:
            # Echtes Trennen kommt mit der Firewall (Stufe 1); bis dahin kein Schein-Status.
            return PlainTextResponse("Trennen ist noch nicht verfügbar", status_code=400)
        note = str(form.get("note", ""))[:500]
        with store() as s:
            try:
                with s.transaction():
                    updated = IncidentService(s).transition(incident_id, new_status, note=note)
            except KeyError:
                return PlainTextResponse("Vorfall nicht gefunden", status_code=404)
            except TransitionError as e:
                return PlainTextResponse(str(e), status_code=409)
            devices = {d.mac: d for d in s.devices()}
            assessments = s.assessments()
        if is_htmx(request):
            return render(
                request,
                "_incident_card.html",
                i=updated,
                devices=devices,
                assessments=assessments,
                open=True,
            )
        return RedirectResponse("/incidents", status_code=303)

    async def incident_assess(request: Request) -> Response:
        """KI-Einschätzung von Hand anfordern (oder erneuern)."""
        if assessor is None:
            return PlainTextResponse("KI-Vorbewertung ist nicht aktiviert", status_code=400)
        incident_id = request.path_params["incident_id"]
        error = ""
        with store() as s:
            try:
                result = assess_incident(s, assessor, incident_id)  # schreibt nur am Ende
                if result is None:
                    error = "Firmengeräte werden nicht von der KI bewertet."
            except KeyError:
                return PlainTextResponse("Vorfall nicht gefunden", status_code=404)
            except AssessmentError as e:
                error = str(e)
            incident = s.incident_by_id(incident_id)
            devices = {d.mac: d for d in s.devices()}
            assessments = s.assessments()
        if is_htmx(request):
            return render(
                request,
                "_incident_card.html",
                i=incident,
                devices=devices,
                assessments=assessments,
                ai_error=error,
                open=True,
            )
        return RedirectResponse("/incidents", status_code=303)

    async def devices_page(request: Request) -> Response:
        q = request.query_params.get("q", "").strip()[:100]
        trust_filter = request.query_params.get("trust", "all")
        now = utcnow()
        with store() as s:
            all_devices = s.devices()
            hourly = s.dns_hourly_by_device(since=now - timedelta(hours=24))
            open_incidents = s.incidents(OPEN_STATUSES)
        worst: dict[str, Severity] = {}
        open_count: dict[str, int] = {}
        for i in open_incidents:
            if i.device_mac:
                open_count[i.device_mac] = open_count.get(i.device_mac, 0) + 1
                worst[i.device_mac] = max(worst.get(i.device_mac, i.severity), i.severity)

        def matches(d: Any) -> bool:
            hay = " ".join(filter(None, [d.label, d.ip, d.mac, d.vendor, d.hostname])).lower()
            return (trust_filter == "all" or d.trust.value == trust_filter) and (
                not q or q.lower() in hay
            )

        shown = [d for d in all_devices if matches(d)]
        # Offene Vorfälle zuerst, dann online, dann Name
        shown.sort(key=lambda d: (-worst.get(d.mac, -1), not d.online, d.label.lower()))
        counts = {t.value: sum(1 for d in all_devices if d.trust is t) for t in TrustLevel}
        counts["all"] = len(all_devices)
        return render(
            request,
            "devices.html",
            devices=shown,
            total=len(all_devices),
            online=sum(1 for d in all_devices if d.online),
            offline=sum(1 for d in all_devices if d.online is False),
            spark={
                d.mac: views.sparkline(hourly.get(d.mac, {}), now)
                for d in shown
                if not d.is_company
            },
            worst=worst,
            open_count=open_count,
            q=q,
            trust_filter=trust_filter,
            counts=counts,
        )

    async def device_detail(request: Request) -> Response:
        try:
            mac = normalize_mac(request.path_params["mac"])
        except ValueError:
            return PlainTextResponse("Ungültige MAC-Adresse", status_code=400)
        only_new = request.query_params.get("new") == "1"
        now = utcnow()
        week_ago = now - timedelta(days=7)
        with store() as s:
            device = s.device(mac)
            if device is None:
                return PlainTextResponse("Gerät nicht gefunden", status_code=404)
            rows = [] if device.is_company else s.dns_hourly(since=week_ago, mac=mac)
            domains = [] if device.is_company else s.device_domain_stats(mac, since=week_ago)
            items = [i for i in s.incidents() if i.device_mac == mac]
            history = s.events(limit=10, device_mac=mac)
        if only_new:
            domains = [d for d in domains if d[1] >= week_ago]
        return render(
            request,
            "device.html",
            d=device,
            chart=views.daily_chart(rows, now, tz),
            behaviour=views.active_hours(rows, tz),
            domains=domains,
            domain_count=len({x[0] for x in domains}),
            week_ago=week_ago,
            only_new=only_new,
            incidents=items,
            history=history,
            saved=request.query_params.get("saved") == "1",
            deleted=(
                request.query_params.get("deleted", "")
                if re.fullmatch(r"\d{1,6}-\d{1,6}", request.query_params.get("deleted", ""))
                else ""
            ),
        )

    async def device_update(request: Request) -> Response:
        form = await request.form()
        try:
            mac = normalize_mac(request.path_params["mac"])
            trust = TrustLevel(str(form.get("trust", "")))
            with store() as s:
                set_name(s, mac, str(form.get("name", ""))[:100])
                set_protected(s, mac, form.get("protected") == "on")
                set_notes(s, mac, str(form.get("notes", "")))
                change = set_trust(s, mac, trust)
        except (ValueError, DeviceNotFoundError) as e:
            return PlainTextResponse(str(e), status_code=400)
        target = f"/devices/{mac}?saved=1"
        if trust is TrustLevel.COMPANY and change.previous is not TrustLevel.COMPANY:
            target += f"&deleted={change.domains_deleted}-{change.incidents_deleted}"
        return RedirectResponse(target, status_code=303)

    # --- Middleware ---------------------------------------------------------------

    async def guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if not _host_allowed(request.headers.get("host", ""), cfg.allowed_hosts):
            # Schutz gegen DNS-Rebinding: fremde Hostnamen gar nicht erst bedienen.
            return PlainTextResponse("Unbekannter Hostname", status_code=400)
        path = request.url.path
        if not path.startswith(PUBLIC_PATHS) and not sessions.valid(request.cookies.get(COOKIE)):
            if is_htmx(request):
                return Response(status_code=401, headers={"HX-Redirect": "/login"})
            return RedirectResponse("/login", status_code=303)
        if request.method == "POST" and not _same_origin(request):
            return PlainTextResponse("Herkunft der Anfrage ungültig", status_code=403)
        response = await call_next(request)
        response.headers.update(
            {
                "Content-Security-Policy": (
                    "default-src 'self'; script-src 'self'; style-src 'self'; "
                    "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; "
                    "base-uri 'none'; object-src 'none'"
                ),
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "same-origin",
                "Cache-Control": "no-store",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            }
        )
        return response

    routes = [
        Route("/login", login_page, methods=["GET"]),
        Route("/login", login, methods=["POST"]),
        Route("/logout", logout, methods=["POST"]),
        Route("/healthz", healthz),
        Route("/", overview),
        Route("/incidents", incidents),
        Route("/incidents/{incident_id:int}/status", incident_status, methods=["POST"]),
        Route("/incidents/{incident_id:int}/assess", incident_assess, methods=["POST"]),
        Route("/devices", devices_page),
        Route("/devices/{mac}", device_detail),
        Route("/devices/{mac}", device_update, methods=["POST"]),
        Mount("/static", StaticFiles(directory=HERE / "static"), name="static"),
    ]
    return Starlette(routes=routes, middleware=[Middleware(BaseHTTPMiddleware, dispatch=guard)])


def _host_allowed(host_header: str, extra: tuple[str, ...]) -> bool:
    """IP-Adressen, localhost und ausdrücklich eingetragene Namen."""
    host = host_header.strip().lower()
    if host.startswith("["):  # [IPv6]:port
        host = host[1 : host.find("]")] if "]" in host else host
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]
    if not host:
        return False
    if host in {"localhost", "testserver"} or host in extra:
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _same_origin(request: Request) -> bool:
    """POST nur, wenn Origin (oder ersatzweise Referer) zum eigenen Host passt."""
    source = request.headers.get("origin") or request.headers.get("referer")
    if not source:
        return False
    return urlsplit(source).netloc == request.headers.get("host")
