"""Bedrohungslisten: bekannte Schad-Domains (Malware, Phishing, Command-and-Control).

Standard ist HaGeZi "Threat Intelligence Feeds" (mini, ~210 000 Domains, ohne Schlüssel,
auch von Quad9 genutzt). Weitere Listen lassen sich ergänzen, z. B. abuse.ch mit eigenem
Auth-Key. Unterstützte Formate: reine Domains, Hosts-Datei ("0.0.0.0 domain") und
Adblock ("||domain^"). Einträge gelten inklusive aller Subdomains.

Die Listen werden periodisch heruntergeladen, im Datenordner zwischengespeichert und
bei Download-Fehlern weiter aus dem Zwischenspeicher genutzt.
"""

from __future__ import annotations

import logging
import os
import re
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_FEEDS = (
    "hagezi-tif=https://raw.githubusercontent.com/hagezi/dns-blocklists/main/"
    "wildcard/tif.mini-onlydomains.txt"
)
MAX_BYTES = 50 * 1024 * 1024  # Schutz vor riesigen oder manipulierten Antworten
_DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$"
)
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")

# URL → Inhalt (bytes); austauschbar für Tests.
Fetcher = Callable[[str], bytes]


class ThreatIntelError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Feed:
    name: str
    url: str


@dataclass(frozen=True, slots=True)
class Match:
    feed: str
    entry: str  # der Listeneintrag, der getroffen hat (ggf. Elterndomain)


def parse_feeds(raw: str | None) -> list[Feed]:
    """``name=url, name2=url2`` (Komma oder Leerzeichen). ``off`` schaltet ab."""
    raw = DEFAULT_FEEDS if raw is None or not raw.strip() else raw.strip()
    if raw.lower() in {"off", "false", "0", "none"}:
        return []
    feeds = []
    for i, part in enumerate(p for p in re.split(r"[\s,]+", raw) if p):
        name, sep, url = part.partition("=")
        if not sep:
            name, url = f"liste{i + 1}", part
        name = name.strip().lower()
        if not _NAME_RE.match(name):
            raise ThreatIntelError(f"Ungültiger Listenname: {name!r}")
        if not url.startswith("https://"):
            raise ThreatIntelError(f"Liste {name}: nur https-URLs erlaubt")
        feeds.append(Feed(name, url))
    return feeds


def parse_list(lines: Iterable[str]) -> set[str]:
    """Domains aus Domain-, Hosts- oder Adblock-Format; ungültige Zeilen werden übersprungen."""
    out: set[str] = set()
    for line in lines:
        line = line.strip().lower()
        if not line or line[0] in "#!":
            continue
        if line.startswith("||"):  # Adblock: ||example.com^
            line = line[2:].split("^", 1)[0]
        else:
            parts = line.split()
            sinkholes = {"0.0.0.0", "127.0.0.1", "::", "::1"}  # noqa: S104 – Hosts-Präfix, kein Bind
            if len(parts) >= 2 and parts[0] in sinkholes:
                line = parts[1]  # Hosts-Format
            elif len(parts) != 1:
                continue
        line = line.removeprefix("*.").rstrip(".")
        if _DOMAIN_RE.match(line):
            out.add(line)
    return out


def _http_fetch(url: str) -> bytes:
    if not url.startswith("https://"):  # zusätzlich zu parse_feeds: nie file:// o. ä.
        raise ThreatIntelError("nur https-URLs erlaubt")
    req = urllib.request.Request(url, headers={"User-Agent": "aluco-threatintel"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 – Schema oben geprüft
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ThreatIntelError(f"Liste größer als {MAX_BYTES // 1024 // 1024} MB")
    return data


class ThreatIntel:
    def __init__(
        self,
        feeds: list[Feed],
        cache_dir: Path,
        refresh_every: timedelta = timedelta(hours=12),
        fetch: Fetcher = _http_fetch,
    ) -> None:
        self._feeds = feeds
        self._dir = cache_dir
        self._refresh_every = refresh_every
        self._fetch = fetch
        self._sets: dict[str, set[str]] = {}
        self._loaded_mtime: dict[str, float] = {}

    @property
    def enabled(self) -> bool:
        return bool(self._feeds)

    def sizes(self) -> dict[str, int]:
        return {name: len(s) for name, s in self._sets.items()}

    def _path(self, feed: Feed) -> Path:
        return self._dir / f"{feed.name}.txt"

    def refresh(self, now: datetime | None = None) -> list[str]:
        """Veraltete Listen neu laden. Liefert Fehlermeldungen (Lauf geht trotzdem weiter)."""
        now = now or datetime.now(UTC)
        errors: list[str] = []
        self._dir.mkdir(parents=True, exist_ok=True)
        for feed in self._feeds:
            path = self._path(feed)
            fresh = (
                path.exists()
                and now - datetime.fromtimestamp(path.stat().st_mtime, UTC) < self._refresh_every
            )
            if not fresh:
                try:
                    data = self._fetch(feed.url)
                    domains = parse_list(data.decode("utf-8", "replace").splitlines())
                    if not domains:
                        raise ThreatIntelError("Liste ist leer oder unlesbar")
                    _atomic_write(path, "\n".join(sorted(domains)) + "\n")
                    os.utime(path, (now.timestamp(), now.timestamp()))
                    log.info("Bedrohungsliste %s aktualisiert: %d Domains", feed.name, len(domains))
                except (ThreatIntelError, urllib.error.URLError, TimeoutError, OSError) as e:
                    errors.append(f"threatintel/{feed.name}: {e}")
            self._load(feed)
        return errors

    def _load(self, feed: Feed) -> None:
        path = self._path(feed)
        if not path.exists():
            return
        mtime = path.stat().st_mtime
        if self._loaded_mtime.get(feed.name) == mtime:
            return
        with path.open(encoding="utf-8") as f:
            self._sets[feed.name] = parse_list(f)
        self._loaded_mtime[feed.name] = mtime

    def match(self, domain: str) -> Match | None:
        """Trifft die Domain selbst oder eine ihrer Elterndomains einen Listeneintrag?"""
        labels = domain.rstrip(".").lower().split(".")
        candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)]
        for name, entries in self._sets.items():
            for c in candidates:
                if c in entries:
                    return Match(name, c)
        return None


def _atomic_write(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
