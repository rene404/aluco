"""Neu registrierte Domains (#25): Liste aufbereiten, Binärsuche, Regel, Konfiguration."""

from __future__ import annotations

import random
import urllib.error
from datetime import timedelta
from pathlib import Path

import pytest

from aluco.ai import RULE_TEXT, build_context
from aluco.config import Config, ConfigError
from aluco.engine import Engine
from aluco.model import DeviceSighting, DnsQuery
from aluco.nrd import (
    DEFAULT_FEEDS,
    NewlyRegistered,
    NrdError,
    SortedDomains,
    parse_allow,
    parse_nrd_feeds,
    prepare,
)
from aluco.rules import KnownBadDomainRule, NewlyRegisteredDomainRule, default_dns_rules
from aluco.runner import Runner
from aluco.store import Store
from aluco.threatintel import Feed, ThreatIntel
from aluco.web import views
from tests.conftest import IP_A, MAC_A, T0

LIST = b"""# Title: Newly Registered Domains (NRD)
# Number of entries: 6
0-1.net.cn
aaa-new.example
brand-new.example
evil-and-new.example
fresh.example
zz-last.example
"""


class FakeDownload:
    def __init__(self, data: bytes = LIST) -> None:
        self.data = data
        self.calls = 0
        self.fail = False

    def __call__(self, url: str, dest: Path) -> None:
        self.calls += 1
        if self.fail:
            raise urllib.error.URLError("offline")
        dest.write_bytes(self.data)


def _nrd(tmp_path: Path, download: FakeDownload, allow: str = "") -> NewlyRegistered:
    return NewlyRegistered(
        [Feed("nrd7", "https://x.example/nrd7.txt")],
        tmp_path / "nrd",
        allow=parse_allow(allow),
        download=download,
    )


# --- Liste und Suche -------------------------------------------------------------------


def test_prepare_validates_and_keeps_sorted(tmp_path: Path) -> None:
    src = tmp_path / "raw.txt"
    src.write_bytes(LIST + b"not a domain\nFRESH.example.\n\xff\xfe.example\n")
    dest = tmp_path / "clean.txt"
    assert prepare(src, dest) == 6
    lines = dest.read_bytes().splitlines()
    assert lines == sorted(lines) and b"fresh.example" in lines and len(set(lines)) == 6


def test_prepare_sorts_unsorted_lists(tmp_path: Path) -> None:
    src = tmp_path / "raw.txt"
    src.write_bytes(b"zeta.example\nalpha.example\nmid.example\nalpha.example\n")
    dest = tmp_path / "clean.txt"
    assert prepare(src, dest) == 3
    assert dest.read_bytes() == b"alpha.example\nmid.example\nzeta.example\n"


def test_prepare_rejects_empty_list_and_keeps_old(tmp_path: Path) -> None:
    dest = tmp_path / "clean.txt"
    dest.write_bytes(b"old.example\n")
    src = tmp_path / "raw.txt"
    src.write_bytes(b"<html>Fehlerseite</html>\n")
    with pytest.raises(NrdError, match="leer"):
        prepare(src, dest)
    assert dest.read_bytes() == b"old.example\n"


def test_binary_search_finds_every_entry_and_nothing_else(tmp_path: Path) -> None:
    rng = random.Random(25)  # noqa: S311 – nur Testdaten
    words = {
        "".join(
            rng.choice("abcdefghijklmnopqrstuvwxyz0123456789-") for _ in range(rng.randint(3, 20))
        ).strip("-")
        + rng.choice([".com", ".net", ".example", ".co.at"])
        for _ in range(3000)
    }
    words = {w for w in words if not w.startswith(".")}
    present = sorted(words)[::2]
    absent = sorted(words)[1::2]
    path = tmp_path / "l.txt"
    path.write_bytes(b"".join(w.encode() + b"\n" for w in sorted(present)))
    found = SortedDomains(path)
    assert all(w in found for w in present)
    assert not any(w in found for w in absent)
    assert "" not in found and "aaa" not in found and "zzzz.zz" not in found


def test_binary_search_on_edge_files(tmp_path: Path) -> None:
    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"")
    assert "a.example" not in SortedDomains(empty)
    one = tmp_path / "one.txt"
    one.write_bytes(b"only.example")  # ohne abschließenden Zeilenumbruch
    assert "only.example" in SortedDomains(one)
    assert "other.example" not in SortedDomains(one)


def test_match_uses_parent_domains_and_allowlist(tmp_path: Path) -> None:
    nrd = _nrd(tmp_path, FakeDownload(), allow="fresh.example, *.Brand-New.example.")
    assert nrd.refresh(T0) == []
    hit = nrd.match("cdn.login.aaa-new.example")
    assert hit is not None and (hit.feed, hit.entry) == ("nrd7", "aaa-new.example")
    assert nrd.match("x.0-1.net.cn") is not None  # zweiteilige Endung ohne Sonderbehandlung
    assert nrd.match("fresh.example") is None  # erlaubt
    assert nrd.match("www.brand-new.example") is None  # erlaubt inkl. Subdomains
    assert nrd.match("example") is None
    assert nrd.match("old.example") is None


def test_refresh_daily_and_keeps_list_on_errors(tmp_path: Path) -> None:
    download = FakeDownload()
    nrd = _nrd(tmp_path, download)
    nrd.refresh(T0)
    nrd.refresh(T0 + timedelta(hours=23))
    assert download.calls == 1
    download.fail = True
    errors = nrd.refresh(T0 + timedelta(hours=25))
    assert errors == ["nrd/nrd7: <urlopen error offline>"]
    assert nrd.match("fresh.example") is not None
    assert [p.name for p in (tmp_path / "nrd").iterdir()] == ["nrd7.txt"]  # kein Rest

    download.fail = False
    download.data = b"newer.example\n"
    assert nrd.refresh(T0 + timedelta(hours=26)) == []
    assert nrd.match("newer.example") is not None and nrd.match("fresh.example") is None

    restarted = _nrd(tmp_path, download)  # Neustart: Liste kommt aus dem Zwischenspeicher
    restarted.refresh(T0 + timedelta(hours=27))
    assert download.calls == 3 and restarted.match("newer.example") is not None


# --- Regel -----------------------------------------------------------------------------


def _engine(store: Store, tmp_path: Path, threats: bytes | None = None) -> Engine:
    nrd = _nrd(tmp_path, FakeDownload())
    nrd.refresh(T0)
    intel = None
    rules = [*default_dns_rules()]
    if threats is not None:
        intel = ThreatIntel(
            [Feed("tif", "https://x.example/tif.txt")], tmp_path / "ti", fetch=lambda u: threats
        )
        intel.refresh(T0)
        rules.append(KnownBadDomainRule(intel))
    rules.append(NewlyRegisteredDomainRule(nrd, threats=intel))
    engine = Engine(store, dns_rules=rules)
    engine.process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip=IP_A)], now=T0, learn_only=True)
    return engine


def test_rule_creates_one_incident_per_device_and_domain(store: Store, tmp_path: Path) -> None:
    engine = _engine(store, tmp_path)
    result = engine.process(
        queries=[
            DnsQuery(client_ip=IP_A, domain="login.brand-new.example", at=T0),
            DnsQuery(client_ip=IP_A, domain="brand-new.example", at=T0, blocked=True),
            DnsQuery(client_ip=IP_A, domain="www.old.example", at=T0),
        ],
        now=T0,
    )
    [incident] = result.alerts
    assert incident.rule == "newly_registered_domain"
    assert incident.severity.name == "MEDIUM"
    assert incident.details == {
        "domain": "brand-new.example",
        "query": "login.brand-new.example",
        "list": "nrd7",
        "blocked": "false",
    }
    assert store.incidents()[0].occurrences == 2
    facts = views.explain(incident)
    assert any("14 Tagen registriert" in f for f in facts)
    ctx = build_context(incident, store.device(MAC_A), [])
    assert ctx["neu_registrierte_domain"] == "brand-new.example"
    assert ctx["regel_beschreibung"] == RULE_TEXT["newly_registered_domain"]


def test_threat_list_wins_over_nrd(store: Store, tmp_path: Path) -> None:
    engine = _engine(store, tmp_path, threats=b"evil-and-new.example\n")
    result = engine.process(
        queries=[DnsQuery(client_ip=IP_A, domain="a.evil-and-new.example", at=T0)], now=T0
    )
    assert [i.rule for i in result.alerts] == ["bad_domain"]


def test_runner_refreshes_and_reports_errors(store: Store, tmp_path: Path) -> None:
    download = FakeDownload()
    download.fail = True
    nrd = _nrd(tmp_path, download)
    summary = Runner(store, [], [], nrd=nrd).run_once(now=T0)
    assert summary.errors == ["nrd/nrd7: <urlopen error offline>"]


# --- Konfiguration ---------------------------------------------------------------------


def test_feeds_and_allowlist_parsing() -> None:
    assert [f.name for f in parse_nrd_feeds(None)] == ["nrd7", "nrd14-8"]
    assert parse_nrd_feeds("off") == []
    assert all(
        f.url.startswith("https://cdn.jsdelivr.net/") for f in parse_nrd_feeds(DEFAULT_FEEDS)
    )
    assert parse_allow(" a.example,b.example  *.c.example ") == {
        "a.example",
        "b.example",
        "c.example",
    }
    assert parse_allow(None) == frozenset()
    with pytest.raises(NrdError, match="Erlaubnisliste"):
        parse_allow("nicht gültig!")


def test_config_validates_nrd_settings() -> None:
    base = {"NETALERTX_URL": "http://n", "NETALERTX_API_TOKEN": "t"}
    cfg = Config.from_env(base | {"ALUCO_NRD_FEEDS": "off", "ALUCO_NRD_ALLOW": "my.example"})
    assert (cfg.nrd_feeds, cfg.nrd_allow) == ("off", "my.example")
    with pytest.raises(ConfigError, match="ALUCO_NRD"):
        Config.from_env(base | {"ALUCO_NRD_FEEDS": "x=http://plain.example"})
    with pytest.raises(ConfigError, match="ALUCO_NRD"):
        Config.from_env(base | {"ALUCO_NRD_ALLOW": "kein domain"})
