"""Dashboard: Übersicht, Vorfälle, Geräte.

Sicherheit: Login mit Passwort, Sitzungs-Cookie (HttpOnly, SameSite=Strict),
Herkunftsprüfung bei POST (CSRF), strikte Content-Security-Policy, keine externen
Ressourcen. Gedacht nur fürs Heimnetz bzw. VPN – nie direkt ins Internet.
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
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
from aluco.config import ConfigError, db_path_from_env
from aluco.devices import DeviceNotFoundError, set_name, set_protected, set_trust
from aluco.incidents import ALLOWED_TRANSITIONS, IncidentService, TransitionError
from aluco.model import OPEN_STATUSES, IncidentStatus, Severity, TrustLevel, normalize_mac
from aluco.store import Store
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
        )


def create_app(cfg: WebConfig) -> Starlette:
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
    )
    templates.filters["local"] = lambda dt: dt.astimezone(tz).strftime("%d.%m.%Y %H:%M")

    def render(request: Request, name: str, status_code: int = 200, **ctx: Any) -> HTMLResponse:
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
        with store() as s:
            devices = s.devices()
            open_incidents = s.incidents(OPEN_STATUSES)
            last_run_raw = s.cursor("runner:last_run")
            last_errors = s.cursor("runner:last_errors") or ""
        by_severity = {sev: 0 for sev in sorted(Severity, reverse=True)}
        for i in open_incidents:
            by_severity[i.severity] += 1
        by_trust = {t: 0 for t in TrustLevel}
        for d in devices:
            by_trust[d.trust] += 1
        return render(
            request,
            "overview.html",
            devices=devices,
            by_trust=by_trust,
            by_severity=by_severity,
            open_count=len(open_incidents),
            top_incidents=open_incidents[:5],
            last_run=datetime.fromisoformat(last_run_raw) if last_run_raw else None,
            last_errors=[e for e in last_errors.split("\n") if e],
        )

    async def incidents(request: Request) -> Response:
        flt = request.query_params.get("status", "open")
        statuses = STATUS_FILTERS.get(flt, OPEN_STATUSES)
        with store() as s:
            items = s.incidents(statuses)
            devices = {d.mac: d for d in s.devices()}
        return render(request, "incidents.html", incidents=items, devices=devices, filter=flt)

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
        if is_htmx(request):
            return render(request, "_incident_row.html", i=updated, devices=devices)
        return RedirectResponse("/incidents", status_code=303)

    async def devices_page(request: Request) -> Response:
        with store() as s:
            items = s.devices()
        return render(request, "devices.html", devices=items)

    async def device_detail(request: Request) -> Response:
        try:
            mac = normalize_mac(request.path_params["mac"])
        except ValueError:
            return PlainTextResponse("Ungültige MAC-Adresse", status_code=400)
        with store() as s:
            device = s.device(mac)
            if device is None:
                return PlainTextResponse("Gerät nicht gefunden", status_code=404)
            domains = [] if device.is_company else s.device_domains(mac)
            items = [i for i in s.incidents() if i.device_mac == mac]
        return render(request, "device.html", d=device, domains=domains, incidents=items)

    async def device_update(request: Request) -> Response:
        """Ein Formular pro Gerät: Name, Stufe, Schutzliste."""
        form = await request.form()
        message = ""
        try:
            mac = normalize_mac(request.path_params["mac"])
            trust = TrustLevel(str(form.get("trust", "")))
            with store() as s:
                set_name(s, mac, str(form.get("name", ""))[:100])
                set_protected(s, mac, form.get("protected") == "on")
                change = set_trust(s, mac, trust)
        except (ValueError, DeviceNotFoundError) as e:
            return PlainTextResponse(str(e), status_code=400)
        device = change.device
        if trust is TrustLevel.COMPANY and change.previous is not TrustLevel.COMPANY:
            message = (
                f"Firmengerät: {change.domains_deleted} Domains und "
                f"{change.incidents_deleted} Vorfälle gelöscht."
            )
        else:
            message = "Gespeichert."
        if is_htmx(request):
            return render(request, "_device_row.html", d=device, message=message)
        return RedirectResponse("/devices", status_code=303)

    # --- Middleware ---------------------------------------------------------------

    async def guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
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
        Route("/devices", devices_page),
        Route("/devices/{mac}", device_detail),
        Route("/devices/{mac}", device_update, methods=["POST"]),
        Mount("/static", StaticFiles(directory=HERE / "static"), name="static"),
    ]
    return Starlette(routes=routes, middleware=[Middleware(BaseHTTPMiddleware, dispatch=guard)])


def _same_origin(request: Request) -> bool:
    """POST nur, wenn Origin (oder ersatzweise Referer) zum eigenen Host passt."""
    source = request.headers.get("origin") or request.headers.get("referer")
    if not source:
        return False
    return urlsplit(source).netloc == request.headers.get("host")
