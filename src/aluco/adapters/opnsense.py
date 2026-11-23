"""OPNsense: Geräte trennen (Firewall-Alias) und ARP-Tabelle als Geräte-Quelle.

Trennen = IP-Adresse in den Alias ``aluco_quarantine`` (Typ Host) eintragen. Eine
Firewall-Regel blockiert diesen Alias Richtung Internet (Einrichtung: docs/opnsense.md).
``alias_util/add`` und ``delete`` speichern bei Host-Aliasen dauerhaft in der Konfiguration.

Rechte des API-Schlüssels (an OPNsense 26.7 geprüft): „Diagnostics: PF Table IP addresses“
(alias_util), „Firewall: Aliases“ (Alias lesen) und optional „Diagnostics: ARP Table“.
TLS: OPNsense nutzt meist ein selbstsigniertes Zertifikat – geprüft wird entweder gegen
eine CA-Datei oder gegen den festgelegten SHA-256-Fingerprint des Zertifikats.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlsplit

from aluco.adapters.base import AdapterError
from aluco.model import DeviceSighting, normalize_mac

_ALIAS_RE = re.compile(r"^[A-Za-z0-9_]{1,31}$")
_PIN_RE = re.compile(r"^[0-9a-f]{64}$")


def normalize_pin(pin: str) -> str:
    """'AB:CD:…' oder 'abcd…' → 64 Hex-Zeichen klein."""
    cleaned = pin.replace(":", "").replace(" ", "").strip().lower()
    if not _PIN_RE.match(cleaned):
        raise AdapterError(
            "OPNSENSE_CERT_SHA256 muss ein SHA-256-Fingerprint sein (64 Hex-Zeichen)"
        )
    return cleaned


@dataclass(frozen=True)
class OPNsenseClient:
    """Minimaler JSON-Client mit Basic-Auth und strenger TLS-Prüfung (Standardbibliothek)."""

    url: str
    key: str = field(repr=False)
    secret: str = field(repr=False)
    ca_file: str | None = None
    cert_sha256: str | None = None
    timeout: float = 15.0

    def __post_init__(self) -> None:
        parts = urlsplit(self.url)
        if parts.scheme != "https" or not parts.hostname:
            raise AdapterError("OPNSENSE_URL muss eine https-Adresse sein")
        if not (self.ca_file or self.cert_sha256):
            raise AdapterError("OPNsense: OPNSENSE_CERT_SHA256 oder OPNSENSE_CA_FILE angeben")
        if self.cert_sha256:
            object.__setattr__(self, "cert_sha256", normalize_pin(self.cert_sha256))

    def _context(self) -> ssl.SSLContext:
        if self.cert_sha256:
            # Kette nicht prüfbar (selbstsigniert) → stattdessen exakt dieses Zertifikat erwarten.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return ssl.create_default_context(cafile=self.ca_file)

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        parts = urlsplit(self.url)
        conn = http.client.HTTPSConnection(
            parts.hostname or "", parts.port or 443, timeout=self.timeout, context=self._context()
        )
        try:
            conn.connect()
            if self.cert_sha256:
                der = conn.sock.getpeercert(binary_form=True) if conn.sock else None  # type: ignore[union-attr]
                actual = hashlib.sha256(der or b"").hexdigest()
                if not hmac.compare_digest(actual, self.cert_sha256):
                    raise AdapterError(
                        "OPNsense: Zertifikat passt nicht zum Fingerprint – abgebrochen"
                    )
            token = base64.b64encode(f"{self.key}:{self.secret}".encode()).decode()
            headers = {"Authorization": f"Basic {token}", "Accept": "application/json"}
            payload = None
            if body is not None:
                payload = json.dumps(body).encode()
                headers["Content-Type"] = "application/json"
            conn.request(method, parts.path.rstrip("/") + path, body=payload, headers=headers)
            resp = conn.getresponse()
            data = resp.read(5 * 1024 * 1024)
            if resp.status in (401, 403):
                raise AdapterError(
                    f"OPNsense: Zugriff verweigert (HTTP {resp.status}) – Schlüssel/Rechte prüfen"
                )
            if resp.status >= 400:
                raise AdapterError(f"OPNsense: HTTP {resp.status} für {path}")
            return json.loads(data or b"null")
        except (OSError, ssl.SSLError, json.JSONDecodeError, http.client.HTTPException) as e:
            raise AdapterError(f"OPNsense nicht erreichbar: {e}") from e
        finally:
            conn.close()


class OPNsense:
    """Trennen/Freigeben über einen Alias, ARP-Tabelle als Geräte-Quelle."""

    name = "opnsense"

    def __init__(self, client: Any, alias: str = "aluco_quarantine") -> None:
        if not _ALIAS_RE.match(alias):
            raise AdapterError(f"Ungültiger Alias-Name: {alias!r}")
        self._client = client
        self._alias = alias

    @staticmethod
    def _check_ip(ip: str) -> str:
        try:
            return str(ipaddress.ip_address(ip))
        except ValueError as e:
            raise AdapterError(f"Keine gültige IP-Adresse: {ip!r}") from e

    def _alias_call(self, action: str, ip: str) -> None:
        result = self._client.request(
            "POST", f"/api/firewall/alias_util/{action}/{quote(self._alias)}", {"address": ip}
        )
        status = (result or {}).get("status") if isinstance(result, dict) else None
        if status != "done":
            msg = (result or {}).get("status_msg", status) if isinstance(result, dict) else result
            raise AdapterError(f"OPNsense: {action} fehlgeschlagen ({msg})")

    def _configured(self) -> set[str]:
        """IP-Adressen, die dauerhaft in der Alias-Konfiguration stehen (nicht nur in pf)."""
        found = self._client.request(
            "GET", f"/api/firewall/alias/getAliasUUID/{quote(self._alias)}"
        )
        uuid = found.get("uuid") if isinstance(found, dict) else None
        if not uuid or not re.fullmatch(r"[0-9a-f-]{36}", str(uuid)):
            raise AdapterError(f"OPNsense: Alias {self._alias} nicht gefunden")
        item = self._client.request("GET", f"/api/firewall/alias/getItem/{uuid}")
        content = (item or {}).get("alias", {}).get("content", {}) if isinstance(item, dict) else {}
        out = set()
        for value, opt in content.items() if isinstance(content, dict) else []:
            if not (isinstance(opt, dict) and opt.get("selected")):
                continue
            try:
                out.add(str(ipaddress.ip_address(str(value).split("/")[0])))
            except ValueError:
                continue
        return out

    def block(self, ip: str) -> None:
        ip = self._check_ip(ip)
        # OPNsense hängt eine IP, die an erster Stelle des Alias steht, bei erneutem
        # alias_util/add ein zweites Mal an (array_search liefert 0). Darum nur hinzufügen,
        # wenn sie nicht schon wirksam gesperrt und gespeichert ist.
        if ip in self.blocked() and ip in self._configured():
            return
        self._alias_call("add", ip)

    def unblock(self, ip: str) -> None:
        ip = self._check_ip(ip)
        # delete entfernt je Aufruf nur ein Vorkommen aus der Konfiguration – so oft
        # wiederholen, bis die IP auch nach einem Neuladen der Firewall nicht mehr gesperrt wäre.
        for _ in range(10):
            self._alias_call("delete", ip)
            if ip not in self._configured():
                return
        raise AdapterError(f"OPNsense: {ip} bleibt in der Alias-Konfiguration stehen")

    def blocked(self) -> set[str]:
        result = self._client.request("GET", f"/api/firewall/alias_util/list/{quote(self._alias)}")
        rows = result.get("rows", []) if isinstance(result, dict) else []
        out = set()
        for r in rows:
            raw = str(r.get("ip", "")).split("/")[0]
            try:
                out.add(str(ipaddress.ip_address(raw)))
            except ValueError:
                continue
        return out

    def fetch_sightings(self) -> list[DeviceSighting]:
        """Aktuelle ARP-Einträge der Firewall (ohne abgelaufene)."""
        rows = self._client.request("GET", "/api/diagnostics/interface/get_arp")  # ACL: get_arp*
        if not isinstance(rows, list):
            raise AdapterError("OPNsense: unerwartete Antwort der ARP-Tabelle")
        now = datetime.now(UTC)
        out = []
        for r in rows:
            if not isinstance(r, dict) or r.get("expired") or r.get("permanent"):
                continue  # permanent = eigene Schnittstellen der Firewall
            try:
                mac = normalize_mac(str(r.get("mac", "")))
                ip = self._check_ip(str(r.get("ip", "")))
            except (ValueError, AdapterError):
                continue
            out.append(
                DeviceSighting(
                    mac=mac,
                    at=now,
                    ip=ip,
                    hostname=str(r.get("hostname") or "") or None,
                    vendor=str(r.get("manufacturer") or "") or None,
                    online=True,
                    source=self.name,
                )
            )
        return out
