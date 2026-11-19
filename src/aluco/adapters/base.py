"""Schnittstellen der Adapter. Neue Systeme (UniFi, OpenWrt, MikroTik …) implementieren diese."""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from aluco.model import DeviceSighting, DnsQuery


class DnsSource(Protocol):
    name: str

    def fetch_queries(self, since: datetime | None) -> list[DnsQuery]:
        """DNS-Anfragen nach ``since`` (exklusiv), älteste zuerst."""
        ...


class DeviceSource(Protocol):
    name: str

    def fetch_sightings(self) -> list[DeviceSighting]:
        """Aktuell bzw. zuletzt gesehene Geräte."""
        ...


class AdapterError(RuntimeError):
    """Datenquelle nicht erreichbar oder unerwartete Antwort."""


# (Methode, Pfad, Query-Parameter) → geparstes JSON. Austauschbar für Tests.
JsonFetcher = Callable[[str, str, Mapping[str, str]], Any]


@dataclass(frozen=True, slots=True)
class HttpJsonClient:
    """Minimaler JSON-Client (Standardbibliothek) mit optionaler Basic-Auth."""

    base_url: str
    username: str | None = None
    password: str | None = None
    bearer_token: str | None = None
    timeout: float = 10.0

    def __repr__(self) -> str:  # Zugangsdaten nie in Logs/Tracebacks
        return f"HttpJsonClient(base_url={self.base_url!r})"

    def __call__(self, method: str, path: str, params: Mapping[str, str]) -> Any:
        if not self.base_url.startswith(("http://", "https://")):
            raise AdapterError(f"Ungültige URL: {self.base_url!r}")
        url = self.base_url.rstrip("/") + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, method=method)  # noqa: S310 – Schema oben geprüft
        req.add_header("Accept", "application/json")
        if self.bearer_token is not None:
            req.add_header("Authorization", f"Bearer {self.bearer_token}")
        elif self.username is not None:
            token = base64.b64encode(f"{self.username}:{self.password or ''}".encode()).decode()
            req.add_header("Authorization", f"Basic {token}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                return json.load(resp)
        except urllib.error.HTTPError as e:
            raise AdapterError(f"{method} {path}: HTTP {e.code}") from e
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            raise AdapterError(f"{method} {path}: {e}") from e
