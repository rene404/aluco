"""NetAlertX: Geräteinventar aus dem ARP-Scan (REST-API, Port 20212).

Achtung: Das NetAlertX-Token erlaubt auch Schreiben und Löschen. Dieser Adapter
nutzt ausschließlich lesende GET-Anfragen.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from aluco.adapters.base import AdapterError, JsonFetcher
from aluco.model import DeviceSighting, normalize_mac

# Platzhalter, die NetAlertX statt eines echten Namens einträgt.
_NO_NAME = frozenset({"", "(unknown)", "(name not found)"})


def parse_time(value: str) -> datetime:
    """NetAlertX speichert ``YYYY-MM-DD HH:MM:SS`` ohne Zone, laut Quellcode immer in UTC."""
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class NetAlertX:
    name = "netalertx"

    def __init__(self, fetch: JsonFetcher) -> None:
        self._fetch = fetch

    def fetch_sightings(self) -> list[DeviceSighting]:
        page = self._fetch("GET", "/devices", {})
        if not isinstance(page, dict) or not isinstance(page.get("devices"), list):
            raise AdapterError("NetAlertX: unerwartete Antwort von /devices")
        sightings = [_to_sighting(d) for d in page["devices"] if isinstance(d, dict)]
        return [s for s in sightings if s is not None]


def _to_sighting(dev: dict[str, Any]) -> DeviceSighting | None:
    try:
        mac = normalize_mac(str(dev.get("devMac") or ""))  # überspringt z. B. "Internet"
    except ValueError:
        return None
    raw_time = dev.get("devLastConnection") or dev.get("devFirstConnection")
    if not raw_time:
        return None
    try:
        at = parse_time(str(raw_time))
    except ValueError:
        return None
    name = str(dev.get("devName") or "").strip()
    return DeviceSighting(
        mac=mac,
        at=at,
        ip=dev.get("devPrimaryIPv4") or dev.get("devLastIP") or None,
        hostname=None if name in _NO_NAME else name,
        vendor=(str(dev.get("devVendor") or "").strip() or None),
        source=NetAlertX.name,
    )
