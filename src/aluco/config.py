"""Einstellungen aus Umgebungsvariablen (Docker Compose liest sie aus ``.env``)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from aluco.model import Severity

DEFAULT_DB_PATH = Path("data/aluco/aluco.db")
DEFAULT_INTERVAL_SECONDS = 300
DEFAULT_RETENTION_DAYS = 30


class ConfigError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AiSettings:
    enabled: bool = False
    provider: str = "claude"  # claude | ollama
    model: str = "claude-opus-5-5"
    max_per_run: int = 5
    ollama_url: str = ""


def ai_settings_from_env(env: Mapping[str, str] | None = None) -> AiSettings:
    """KI-Vorbewertung: Claude (API-Schlüssel nötig) oder lokales Modell über Ollama."""
    e = os.environ if env is None else env
    enabled = e.get("ALUCO_AI_ENABLED", "").strip().lower() in {"1", "true", "yes"}
    provider = e.get("ALUCO_AI_PROVIDER", "").strip().lower() or "claude"
    if provider not in {"claude", "ollama"}:
        raise ConfigError("ALUCO_AI_PROVIDER muss claude oder ollama sein")
    model = e.get("ALUCO_AI_MODEL", "").strip()
    ollama_url = e.get("ALUCO_AI_OLLAMA_URL", "").strip()
    if enabled and provider == "claude" and not e.get("ANTHROPIC_API_KEY", "").strip():
        raise ConfigError("ALUCO_AI_ENABLED=true, aber ANTHROPIC_API_KEY fehlt")
    if enabled and provider == "ollama":
        if not ollama_url.startswith(("http://", "https://")):
            raise ConfigError("ALUCO_AI_OLLAMA_URL fehlt (z. B. http://192.0.2.5:11434)")
        if not model or model.startswith("claude"):
            raise ConfigError("ALUCO_AI_MODEL: lokales Modell angeben (z. B. qwen3:4b)")
    raw_max = e.get("ALUCO_AI_MAX_PER_RUN", "").strip() or "5"
    if not raw_max.isdigit():
        raise ConfigError("ALUCO_AI_MAX_PER_RUN muss eine Zahl sein")
    return AiSettings(
        enabled=enabled,
        provider=provider,
        model=model or "claude-opus-5-5",
        max_per_run=int(raw_max),
        ollama_url=ollama_url,
    )


@dataclass(frozen=True, slots=True)
class FirewallSettings:
    url: str | None = None
    key: str | None = field(default=None, repr=False)
    secret: str | None = field(default=None, repr=False)
    cert_sha256: str | None = None
    ca_file: str | None = None
    alias: str = "aluco_quarantine"
    arp: bool = True

    @property
    def enabled(self) -> bool:
        return bool(self.url)


def firewall_settings_from_env(env: Mapping[str, str] | None = None) -> FirewallSettings:
    """OPNsense: nur aktiv mit OPNSENSE_URL, Schlüssel und TLS-Prüfung (Fingerprint oder CA)."""
    e = os.environ if env is None else env
    get = lambda k: (e.get(k, "") or "").strip() or None  # noqa: E731
    fw = FirewallSettings(
        url=get("OPNSENSE_URL"),
        key=get("OPNSENSE_API_KEY"),
        secret=get("OPNSENSE_API_SECRET"),
        cert_sha256=get("OPNSENSE_CERT_SHA256"),
        ca_file=get("OPNSENSE_CA_FILE"),
        alias=get("OPNSENSE_ALIAS") or "aluco_quarantine",
        arp=(get("OPNSENSE_ARP") or "true").lower() in {"1", "true", "yes"},
    )
    if fw.enabled:
        if not fw.url or not fw.url.startswith("https://"):
            raise ConfigError("OPNSENSE_URL muss mit https:// beginnen")
        if not (fw.key and fw.secret):
            raise ConfigError("OPNSENSE_URL gesetzt, aber OPNSENSE_API_KEY/SECRET fehlen")
        if not (fw.cert_sha256 or fw.ca_file):
            raise ConfigError("OPNsense: OPNSENSE_CERT_SHA256 oder OPNSENSE_CA_FILE angeben")
    return fw


def db_path_from_env(env: Mapping[str, str] | None = None) -> Path:
    """Nur der Datenbankpfad – für Befehle, die keine Datenquellen brauchen."""
    e = os.environ if env is None else env
    return Path(e.get("ALUCO_DB_PATH", "").strip() or DEFAULT_DB_PATH)


def _weekday(raw: str | None) -> int:
    from aluco.report import parse_weekday

    try:
        return 6 if raw is None else parse_weekday(raw)
    except ValueError as exc:
        raise ConfigError(f"ALUCO_REPORT_WEEKDAY: {exc}") from exc


def _timezone(raw: str | None) -> str:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    name = raw or "UTC"
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ConfigError(f"TZ: unbekannte Zeitzone {name!r}") from exc
    return name


@dataclass(frozen=True, slots=True)
class Config:
    db_path: Path = DEFAULT_DB_PATH
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS
    retention_days: int = DEFAULT_RETENTION_DAYS

    adguard_url: str | None = None
    adguard_user: str | None = None
    adguard_password: str | None = field(default=None, repr=False)

    netalertx_url: str | None = None
    netalertx_token: str | None = field(default=None, repr=False)

    ntfy_url: str | None = None  # komplette Topic-URL, z. B. https://ntfy.example/aluco-xyz
    ntfy_token: str | None = field(default=None, repr=False)
    notify_min_severity: Severity = Severity.MEDIUM
    notify_minimal: bool = False  # nur "neuer Vorfall" ohne Gerät/Domain im Text
    ai: AiSettings = field(default_factory=AiSettings)
    firewall: FirewallSettings = field(default_factory=FirewallSettings)
    threat_feeds: str | None = None  # None = Standardliste; "off" = aus
    nrd_feeds: str | None = None  # neu registrierte Domains; None = HaGeZi 14 Tage; "off" = aus
    nrd_allow: str | None = None  # eigene Domains, die nie als "neu registriert" gelten
    report_enabled: bool = True  # Wochenbericht über ntfy (nur mit NTFY_URL)
    report_weekday: int = 6  # Montag = 0 … Sonntag = 6
    report_hour: int = 18
    timezone: str = "UTC"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Config:
        e = os.environ if env is None else env

        def opt(name: str) -> str | None:
            value = e.get(name, "").strip()
            return value or None

        def integer(name: str, default: int, minimum: int) -> int:
            raw = opt(name)
            if raw is None:
                return default
            try:
                value = int(raw)
            except ValueError as exc:
                raise ConfigError(f"{name} muss eine Zahl sein, nicht {raw!r}") from exc
            if value < minimum:
                raise ConfigError(f"{name} muss mindestens {minimum} sein")
            return value

        severity_raw = (opt("ALUCO_NOTIFY_MIN_SEVERITY") or "medium").upper()
        try:
            severity = Severity[severity_raw]
        except KeyError as exc:
            names = ", ".join(s.name.lower() for s in Severity)
            raise ConfigError(f"ALUCO_NOTIFY_MIN_SEVERITY: eines von {names}") from exc

        cfg = cls(
            db_path=Path(opt("ALUCO_DB_PATH") or DEFAULT_DB_PATH),
            interval_seconds=integer("ALUCO_INTERVAL_SECONDS", DEFAULT_INTERVAL_SECONDS, 30),
            retention_days=integer("ALUCO_RETENTION_DAYS", DEFAULT_RETENTION_DAYS, 1),
            adguard_url=opt("ADGUARD_URL"),
            adguard_user=opt("ADGUARD_USER"),
            adguard_password=opt("ADGUARD_PASSWORD"),
            netalertx_url=opt("NETALERTX_URL"),
            netalertx_token=opt("NETALERTX_API_TOKEN"),
            ntfy_url=opt("NTFY_URL"),
            ntfy_token=opt("NTFY_TOKEN"),
            notify_min_severity=severity,
            notify_minimal=(opt("ALUCO_NOTIFY_MINIMAL") or "false").lower() in {"1", "true", "yes"},
            ai=ai_settings_from_env(e),
            firewall=firewall_settings_from_env(e),
            threat_feeds=opt("ALUCO_THREAT_FEEDS"),
            nrd_feeds=opt("ALUCO_NRD_FEEDS"),
            nrd_allow=opt("ALUCO_NRD_ALLOW"),
            report_enabled=(opt("ALUCO_REPORT") or "on").lower() not in {"off", "false", "0", "no"},
            report_weekday=_weekday(opt("ALUCO_REPORT_WEEKDAY")),
            report_hour=integer("ALUCO_REPORT_HOUR", 18, 0),
            timezone=_timezone(opt("TZ")),
        )
        if cfg.report_hour > 23:
            raise ConfigError("ALUCO_REPORT_HOUR muss zwischen 0 und 23 liegen")
        try:
            from aluco.threatintel import ThreatIntelError, parse_feeds

            parse_feeds(cfg.threat_feeds)
        except ThreatIntelError as exc:
            raise ConfigError(f"ALUCO_THREAT_FEEDS: {exc}") from exc
        try:
            from aluco.nrd import parse_allow, parse_nrd_feeds

            parse_nrd_feeds(cfg.nrd_feeds)
            parse_allow(cfg.nrd_allow)
        except ThreatIntelError as exc:
            raise ConfigError(f"ALUCO_NRD_FEEDS/ALUCO_NRD_ALLOW: {exc}") from exc
        if cfg.adguard_url and not (cfg.adguard_user and cfg.adguard_password):
            raise ConfigError("ADGUARD_URL gesetzt, aber ADGUARD_USER/ADGUARD_PASSWORD fehlen")
        if cfg.netalertx_url and not cfg.netalertx_token:
            raise ConfigError("NETALERTX_URL gesetzt, aber NETALERTX_API_TOKEN fehlt")
        if not (cfg.adguard_url or cfg.netalertx_url or cfg.firewall.enabled):
            raise ConfigError("Keine Datenquelle: ADGUARD_URL und/oder NETALERTX_URL setzen")
        return cfg
