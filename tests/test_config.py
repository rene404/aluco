from __future__ import annotations

from pathlib import Path

import pytest

from aluco.config import Config, ConfigError
from aluco.model import Severity

BASE = {"NETALERTX_URL": "http://127.0.0.1:20212", "NETALERTX_API_TOKEN": "t"}


def test_defaults_and_values() -> None:
    cfg = Config.from_env(
        BASE
        | {
            "ADGUARD_URL": "http://127.0.0.1",
            "ADGUARD_USER": "admin",
            "ADGUARD_PASSWORD": "pw",
            "ALUCO_INTERVAL_SECONDS": "120",
            "ALUCO_NOTIFY_MIN_SEVERITY": "high",
            "ALUCO_NOTIFY_MINIMAL": "true",
            "ALUCO_DB_PATH": "/data/aluco.db",
        }
    )
    assert cfg.interval_seconds == 120
    assert cfg.retention_days == 30
    assert cfg.notify_min_severity is Severity.HIGH
    assert cfg.notify_minimal is True
    assert cfg.db_path == Path("/data/aluco.db")


def test_secrets_not_in_repr() -> None:
    cfg = Config.from_env(BASE | {"NETALERTX_API_TOKEN": "geheim", "NTFY_TOKEN": "auch-geheim"})
    assert "geheim" not in repr(cfg)


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({}, "Keine Datenquelle"),
        ({"NETALERTX_URL": "http://x"}, "NETALERTX_API_TOKEN"),
        ({"ADGUARD_URL": "http://x", "ADGUARD_USER": "a"}, "ADGUARD_PASSWORD"),
        (BASE | {"ALUCO_INTERVAL_SECONDS": "abc"}, "Zahl"),
        (BASE | {"ALUCO_INTERVAL_SECONDS": "5"}, "mindestens 30"),
        (BASE | {"ALUCO_NOTIFY_MIN_SEVERITY": "egal"}, "eines von"),
    ],
)
def test_invalid_config(env: dict[str, str], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        Config.from_env(env)


def test_blank_values_count_as_unset() -> None:
    cfg = Config.from_env(BASE | {"NTFY_URL": "  ", "ALUCO_RETENTION_DAYS": ""})
    assert cfg.ntfy_url is None
    assert cfg.retention_days == 30
