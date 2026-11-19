"""Kommandozeile: ``python -m aluco run`` (Dauerbetrieb) oder ``python -m aluco once``."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
from types import FrameType

from aluco import __version__
from aluco.config import Config, ConfigError
from aluco.runner import build_runner
from aluco.store import Store

log = logging.getLogger("aluco")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aluco", description="Aluco – Hausradar für dein Netz")
    parser.add_argument("command", choices=["run", "once"], help="Dauerbetrieb oder ein Lauf")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--version", action="version", version=f"aluco {__version__}")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        cfg = Config.from_env()
    except ConfigError as e:
        log.error("Konfiguration: %s", e)
        return 2

    cfg.db_path.parent.mkdir(parents=True, exist_ok=True)
    store = Store(cfg.db_path)
    runner = build_runner(cfg, store)

    if args.command == "once":
        summary = runner.run_once()
        store.close()
        return 1 if summary.errors else 0

    stop = threading.Event()

    def _stop(signum: int, _frame: FrameType | None) -> None:
        log.info("Signal %s – beende nach diesem Lauf", signal.Signals(signum).name)
        stop.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    log.info("Aluco %s gestartet, Intervall %ss", __version__, cfg.interval_seconds)
    while not stop.is_set():
        try:
            runner.run_once()
        except Exception:  # Dauerbetrieb: ein fehlerhafter Lauf darf den Dienst nicht beenden
            log.exception("Lauf fehlgeschlagen")
        stop.wait(cfg.interval_seconds)
    store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
