from __future__ import annotations

import urllib.error
from datetime import timedelta
from pathlib import Path

import pytest

from aluco.ai import build_context
from aluco.config import Config, ConfigError
from aluco.devices import set_trust
from aluco.engine import Engine
from aluco.model import DeviceSighting, DnsQuery, TrustLevel
from aluco.rules import KnownBadDomainRule, default_dns_rules
from aluco.runner import Runner
from aluco.store import Store
from aluco.threatintel import (
    DEFAULT_FEEDS,
    Feed,
    ThreatIntel,
    ThreatIntelError,
    parse_feeds,
    parse_list,
)
from aluco.web import views
from tests.conftest import IP_A, MAC_A, T0

LIST = b"""# Title: Test
# Syntax: Domains
evil.example
c2.bad.example
||phish.example^
0.0.0.0 tracker-malware.example
not a domain line
*.wild.example
localhost
"""


def test_parse_list_formats() -> None:
    assert parse_list(LIST.decode().splitlines()) == {
        "evil.example",
        "c2.bad.example",
        "phish.example",
        "tracker-malware.example",
        "wild.example",
    }


def test_parse_feeds() -> None:
    [default] = parse_feeds(None)
    assert default.name == "hagezi-tif" and default.url.startswith("https://")
    assert parse_feeds("off") == []
    feeds = parse_feeds("a=https://x.example/a.txt, https://y.example/b.txt")
    assert [(f.name, f.url) for f in feeds] == [
        ("a", "https://x.example/a.txt"),
        ("liste2", "https://y.example/b.txt"),
    ]
    with pytest.raises(ThreatIntelError, match="https"):
        parse_feeds("x=http://insecure.example/list.txt")
    with pytest.raises(ThreatIntelError, match="https"):
        parse_feeds("x=file:///etc/passwd")
    assert DEFAULT_FEEDS.startswith("hagezi-tif=https://")


class FakeFetch:
    def __init__(self, data: bytes = LIST) -> None:
        self.data = data
        self.calls = 0
        self.fail = False

    def __call__(self, url: str) -> bytes:
        self.calls += 1
        if self.fail:
            raise urllib.error.URLError("offline")
        return self.data


def _intel(tmp_path: Path, fetch: FakeFetch) -> ThreatIntel:
    return ThreatIntel(
        [Feed("test", "https://lists.example/t.txt")],
        cache_dir=tmp_path / "ti",
        refresh_every=timedelta(hours=12),
        fetch=fetch,
    )


def test_refresh_caches_and_matches_subdomains(tmp_path: Path) -> None:
    fetch = FakeFetch()
    intel = _intel(tmp_path, fetch)
    assert intel.refresh(T0) == []
    assert intel.sizes() == {"test": 5}
    m = intel.match("cdn.EVIL.example.")
    assert m is not None and (m.feed, m.entry) == ("test", "evil.example")
    assert intel.match("x.c2.bad.example").entry == "c2.bad.example"  # type: ignore[union-attr]
    assert intel.match("bad.example") is None  # nur der Eintrag und seine Subdomains
    assert intel.match("example") is None

    intel.refresh(T0 + timedelta(hours=1))  # noch frisch: kein Download
    assert fetch.calls == 1
    intel.refresh(T0 + timedelta(hours=13))
    assert fetch.calls == 2


def test_failed_download_keeps_cached_list(tmp_path: Path) -> None:
    fetch = FakeFetch()
    intel = _intel(tmp_path, fetch)
    intel.refresh(T0)
    fetch.fail = True
    errors = intel.refresh(T0 + timedelta(days=1))
    assert errors == ["threatintel/test: <urlopen error offline>"]
    assert intel.match("evil.example") is not None

    fresh = _intel(tmp_path, fetch)  # Neustart: Liste kommt aus dem Zwischenspeicher
    fresh.refresh(T0 + timedelta(days=1))
    assert fresh.match("evil.example") is not None


def test_empty_list_is_rejected_and_old_one_kept(tmp_path: Path) -> None:
    fetch = FakeFetch()
    intel = _intel(tmp_path, fetch)
    intel.refresh(T0)
    fetch.data = b"<html>Fehlerseite</html>"
    errors = intel.refresh(T0 + timedelta(days=1))
    assert errors and "leer" in errors[0]
    assert intel.match("evil.example") is not None


def test_rule_creates_incident_with_blocked_flag(store: Store, tmp_path: Path) -> None:
    intel = _intel(tmp_path, FakeFetch())
    intel.refresh(T0)
    engine = Engine(store, dns_rules=[*default_dns_rules(), KnownBadDomainRule(intel)])
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A)], now=T0, learn_only=True)
    result = engine.process(
        queries=[
            DnsQuery(client_ip=IP_A, domain="login.phish.example", at=T0, blocked=True),
            DnsQuery(client_ip=IP_A, domain="www.harmless.example", at=T0),
            DnsQuery(
                client_ip=IP_A, domain="phish.example", at=T0, blocked=True
            ),  # gleicher Befund
        ],
        now=T0,
    )
    [incident] = result.alerts
    assert incident.rule == "bad_domain"
    assert incident.details == {
        "domain": "phish.example",
        "query": "login.phish.example",
        "list": "test",
        "blocked": "true",
    }
    assert store.incidents()[0].occurrences == 2
    facts = views.explain(incident)
    assert any("Bedrohungsliste" in f for f in facts)
    assert any("blockiert" in f for f in facts)
    ctx = build_context(incident, store.device(MAC_A), [])
    assert ctx["liste"] == "test" and ctx["von_adguard_blockiert"] is True


def test_company_devices_are_not_checked(store: Store, tmp_path: Path) -> None:
    intel = _intel(tmp_path, FakeFetch())
    intel.refresh(T0)
    engine = Engine(store, dns_rules=[KnownBadDomainRule(intel)])
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A)], now=T0, learn_only=True)
    set_trust(store, MAC_A, TrustLevel.COMPANY)
    result = engine.process(queries=[DnsQuery(client_ip=IP_A, domain="evil.example", at=T0)])
    assert result.alerts == []


def test_runner_refreshes_and_reports_errors(store: Store, tmp_path: Path) -> None:
    fetch = FakeFetch()
    fetch.fail = True
    intel = _intel(tmp_path, fetch)
    summary = Runner(store, [], [], threat_intel=intel).run_once(now=T0 + timedelta(hours=1))
    assert summary.errors == ["threatintel/test: <urlopen error offline>"]


def test_config_validates_feeds() -> None:
    base = {"NETALERTX_URL": "http://n", "NETALERTX_API_TOKEN": "t"}
    assert Config.from_env(base | {"ALUCO_THREAT_FEEDS": "off"}).threat_feeds == "off"
    with pytest.raises(ConfigError, match="ALUCO_THREAT_FEEDS"):
        Config.from_env(base | {"ALUCO_THREAT_FEEDS": "x=http://plain.example"})
