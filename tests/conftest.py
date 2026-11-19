from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from aluco.store import Store

# Dokumentationsbereiche: MAC 00:00:5e:00:53:xx (RFC 7042), IP 192.0.2.0/24 (RFC 5737).
MAC_A = "00:00:5e:00:53:01"
MAC_B = "00:00:5e:00:53:02"
MAC_RANDOM = "02:00:5e:00:53:03"  # lokal verwaltet (private WLAN-Adresse)
IP_A = "192.0.2.10"
IP_B = "192.0.2.11"

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def store() -> Iterator[Store]:
    s = Store()
    yield s
    s.close()
