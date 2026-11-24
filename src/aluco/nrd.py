"""Neu registrierte Domains (NRD): Domains, die erst vor wenigen Tagen registriert wurden.

Standard sind die NRD-Listen von HaGeZi für die letzten 14 Tage (``nrd7`` + ``nrd14-8``,
zusammen ~5 Mio. Domains, ~90 MB, täglich neu). Als Python-Menge bräuchten sie rund
500 MB Arbeitsspeicher – zu viel für einen Raspberry Pi. Darum:

- Download direkt in eine Datei (nie komplett im Speicher), mit Größenbegrenzung.
- Beim Aufbereiten wird jede Zeile geprüft (gleiches Domain-Muster wie die Bedrohungsliste)
  und die Datei byteweise sortiert gespeichert. Die HaGeZi-Listen sind bereits sortiert;
  unsortierte Listen werden einmalig im Speicher sortiert.
- Nachschlagen per Binärsuche über ``mmap``: ~23 Vergleiche je Domain, kaum Speicher.

Fällt ein Download aus, gilt die zuletzt geladene Liste weiter.
"""

from __future__ import annotations

import logging
import mmap
import os
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from aluco.threatintel import _DOMAIN_RE, Feed, ThreatIntelError, parse_feeds

log = logging.getLogger(__name__)

_CDN = "https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/domains"
DEFAULT_FEEDS = f"nrd7={_CDN}/nrd7.txt nrd14-8={_CDN}/nrd14-8.txt"
MAX_BYTES = 200 * 1024 * 1024  # je Liste; nrd7 hat ~47 MB
_CHUNK = 1024 * 1024

# URL, Zieldatei → lädt die Liste in die Datei; austauschbar für Tests.
Downloader = Callable[[str, Path], None]


class NrdError(ThreatIntelError):
    pass


def parse_nrd_feeds(raw: str | None) -> list[Feed]:
    """Wie ``ALUCO_THREAT_FEEDS``: ``name=url …``, leer = HaGeZi 14 Tage, ``off`` = aus."""
    return parse_feeds(DEFAULT_FEEDS if raw is None or not raw.strip() else raw)


def parse_allow(raw: str | None) -> frozenset[str]:
    """Erlaubnisliste: Domains (inkl. Subdomains), getrennt durch Komma oder Leerzeichen."""
    out = set()
    for part in (raw or "").replace(",", " ").split():
        domain = part.strip().lower().removeprefix("*.").rstrip(".")
        if not _DOMAIN_RE.match(domain):
            raise NrdError(f"Ungültige Domain in der Erlaubnisliste: {part!r}")
        out.add(domain)
    return frozenset(out)


def _http_download(url: str, dest: Path) -> None:
    if not url.startswith("https://"):
        raise NrdError("nur https-URLs erlaubt")
    req = urllib.request.Request(url, headers={"User-Agent": "aluco-nrd"})  # noqa: S310
    total = 0
    with urllib.request.urlopen(req, timeout=120) as resp, dest.open("wb") as out:  # noqa: S310
        while chunk := resp.read(_CHUNK):
            total += len(chunk)
            if total > MAX_BYTES:
                raise NrdError(f"Liste größer als {MAX_BYTES // 1024 // 1024} MB")
            out.write(chunk)


def _domains(lines: Iterable[bytes]) -> Iterator[bytes]:
    """Gültige Domains aus einer reinen Domain-Liste (Kommentare und Müll werden übersprungen)."""
    for raw in lines:
        line = raw.strip().lower()
        if not line or line[:1] in (b"#", b"!"):
            continue
        line = line.removeprefix(b"*.").rstrip(b".")
        try:
            text = line.decode("ascii")
        except UnicodeDecodeError:
            continue
        if _DOMAIN_RE.match(text):
            yield line


def prepare(src: Path, dest: Path) -> int:
    """Rohliste → geprüfte, sortierte, eindeutige Datei (eine Domain je Zeile). Liefert Anzahl."""
    tmp = dest.with_name(f".{dest.name}.tmp")
    count = 0
    ordered = True
    prev = b""
    with src.open("rb") as f, tmp.open("wb") as out:
        for domain in _domains(f):
            if domain == prev:
                continue
            if domain < prev:
                ordered = False
            out.write(domain + b"\n")
            prev = domain
            count += 1
    if not ordered:  # Fallback für fremde Listen: einmal im Speicher sortieren
        with tmp.open("rb") as f:
            lines = sorted(set(f.read().splitlines()))
        tmp.write_bytes(b"".join(line + b"\n" for line in lines))
        count = len(lines)
    if count == 0:
        tmp.unlink(missing_ok=True)
        raise NrdError("Liste ist leer oder unlesbar")
    os.replace(tmp, dest)
    return count


class SortedDomains:
    """Sortierte Domain-Datei (eine je Zeile, byteweise sortiert) mit Binärsuche über mmap."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.mtime = path.stat().st_mtime
        size = path.stat().st_size
        self._mm: mmap.mmap | None = None
        if size:
            with path.open("rb") as f:
                self._mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    def close(self) -> None:
        if self._mm is not None:
            self._mm.close()
            self._mm = None

    def __contains__(self, domain: str) -> bool:
        mm = self._mm
        if mm is None:
            return False
        key = domain.encode("ascii", "replace")
        lo, hi = 0, len(mm)  # [lo, hi) besteht immer aus ganzen Zeilen
        while lo < hi:
            mid = (lo + hi) // 2
            start = mm.rfind(b"\n", 0, mid) + 1
            end = mm.find(b"\n", start)
            if end == -1:
                end = len(mm)
            line = mm[start:end]
            if line == key:
                return True
            if line < key:
                lo = end + 1
            else:
                hi = start
        return False


@dataclass(frozen=True, slots=True)
class NrdMatch:
    feed: str
    entry: str  # die registrierte Domain aus der Liste


class NewlyRegistered:
    def __init__(
        self,
        feeds: list[Feed],
        cache_dir: Path,
        allow: frozenset[str] = frozenset(),
        refresh_every: timedelta = timedelta(hours=24),
        download: Downloader = _http_download,
    ) -> None:
        self._feeds = feeds
        self._dir = cache_dir
        self._allow = allow
        self._refresh_every = refresh_every
        self._download = download
        self._files: dict[str, SortedDomains] = {}

    @property
    def enabled(self) -> bool:
        return bool(self._feeds)

    def sizes(self) -> dict[str, int]:
        return {name: f.path.stat().st_size for name, f in self._files.items()}

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
                fd, raw_name = tempfile.mkstemp(dir=self._dir, prefix=f".{feed.name}.raw.")
                os.close(fd)
                raw = Path(raw_name)
                try:
                    self._download(feed.url, raw)
                    count = prepare(raw, path)
                    os.utime(path, (now.timestamp(), now.timestamp()))
                    log.info("NRD-Liste %s aktualisiert: %d Domains", feed.name, count)
                except (ThreatIntelError, urllib.error.URLError, TimeoutError, OSError) as e:
                    errors.append(f"nrd/{feed.name}: {e}")
                finally:
                    raw.unlink(missing_ok=True)
            self._load(feed)
        return errors

    def _load(self, feed: Feed) -> None:
        path = self._path(feed)
        if not path.exists():
            return
        current = self._files.get(feed.name)
        if current is not None and current.mtime == path.stat().st_mtime:
            return
        self._files[feed.name] = SortedDomains(path)
        if current is not None:
            current.close()

    def allowed(self, domain: str) -> bool:
        labels = domain.rstrip(".").lower().split(".")
        return any(".".join(labels[i:]) in self._allow for i in range(len(labels)))

    def match(self, domain: str) -> NrdMatch | None:
        """Ist die Domain oder eine ihrer Elterndomains neu registriert (und nicht erlaubt)?"""
        if self.allowed(domain):
            return None
        labels = domain.rstrip(".").lower().split(".")
        candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)]
        for name, entries in self._files.items():
            for c in candidates:
                if c in entries:
                    return NrdMatch(name, c)
        return None
