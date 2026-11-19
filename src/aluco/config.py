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


def db_path_from_env(env: Mapping[str, str] | None = None) -> Path:
    """Nur der Datenbankpfad – für Befehle, die keine Datenquellen brauchen."""
    e = os.environ if env is None else env
    return Path(e.get("ALUCO_DB_PATH", "").strip() or DEFAULT_DB_PATH)


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
        )
        if cfg.adguard_url and not (cfg.adguard_user and cfg.adguard_password):
            raise ConfigError("ADGUARD_URL gesetzt, aber ADGUARD_USER/ADGUARD_PASSWORD fehlen")
        if cfg.netalertx_url and not cfg.netalertx_token:
            raise ConfigError("NETALERTX_URL gesetzt, aber NETALERTX_API_TOKEN fehlt")
        if not (cfg.adguard_url or cfg.netalertx_url):
            raise ConfigError("Keine Datenquelle: ADGUARD_URL und/oder NETALERTX_URL setzen")
        return cfg
