"""Anmeldung fürs Dashboard: ein Passwort, Sitzungen im Speicher, Bremse gegen Raten."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable


def check_password(given: str, expected: str) -> bool:
    """Vergleich in konstanter Zeit (auch bei unterschiedlicher Länge)."""
    a = hashlib.sha256(given.encode()).digest()
    b = hashlib.sha256(expected.encode()).digest()
    return hmac.compare_digest(a, b)


class Sessions:
    """Sitzungs-Tokens im Speicher. Nach Neustart ist eine neue Anmeldung nötig."""

    def __init__(self, lifetime_seconds: int, clock: Callable[[], float] = time.monotonic) -> None:
        self._lifetime = lifetime_seconds
        self._clock = clock
        self._tokens: dict[str, float] = {}
        self._lock = threading.Lock()

    def create(self) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._purge()
            self._tokens[token] = self._clock() + self._lifetime
        return token

    def valid(self, token: str | None) -> bool:
        if not token:
            return False
        with self._lock:
            expires = self._tokens.get(token)
            if expires is None:
                return False
            if expires < self._clock():
                del self._tokens[token]
                return False
            return True

    def drop(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._tokens.pop(token, None)

    def _purge(self) -> None:
        now = self._clock()
        for t in [t for t, exp in self._tokens.items() if exp < now]:
            del self._tokens[t]


class LoginThrottle:
    """Höchstens ``max_failures`` Fehlversuche pro Client und ``max_global`` insgesamt
    in ``window_seconds`` – die globale Grenze greift auch, wenn ein Angreifer im LAN
    ständig neue IP-Adressen nutzt."""

    def __init__(
        self, max_failures: int = 5, window_seconds: int = 900, max_global: int = 20
    ) -> None:
        self._max = max_failures
        self._max_global = max_global
        self._window = window_seconds
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._all: deque[float] = deque()
        self._lock = threading.Lock()

    def blocked(self, client: str) -> bool:
        with self._lock:
            self._prune()
            return (
                len(self._failures.get(client, ())) >= self._max
                or len(self._all) >= self._max_global
            )

    def fail(self, client: str) -> None:
        with self._lock:
            now = time.monotonic()
            self._failures[client].append(now)
            self._all.append(now)
            self._prune()

    def reset(self, client: str) -> None:
        with self._lock:
            self._failures.pop(client, None)

    def _prune(self) -> None:
        cutoff = time.monotonic() - self._window
        while self._all and self._all[0] < cutoff:
            self._all.popleft()
        for client in list(self._failures):
            q = self._failures[client]
            while q and q[0] < cutoff:
                q.popleft()
            if not q:
                del self._failures[client]
