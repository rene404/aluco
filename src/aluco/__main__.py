"""Kommandozeile.

python -m aluco run                          Dauerbetrieb
python -m aluco once                         ein Lauf
python -m aluco device list                  Inventar anzeigen
python -m aluco device set-trust MAC STUFE   known | iot | guest | unknown | company
python -m aluco device protect MAC [--off]   Schutzliste (nie trennbar)
python -m aluco device name MAC [NAME]       Namen setzen (ohne NAME: entfernen)
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
from types import FrameType

from aluco import __version__
from aluco.config import Config, ConfigError, db_path_from_env
from aluco.devices import DeviceNotFoundError, set_name, set_protected, set_trust
from aluco.model import Device, TrustLevel, normalize_mac, utcnow
from aluco.runner import build_runner
from aluco.store import Store

log = logging.getLogger("aluco")

TRUST_DE = {
    TrustLevel.KNOWN: "bekannt",
    TrustLevel.IOT: "IoT",
    TrustLevel.GUEST: "Gast",
    TrustLevel.UNKNOWN: "unbekannt",
    TrustLevel.COMPANY: "Firma",
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aluco", description="Aluco – Hausradar für dein Netz")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--version", action="version", version=f"aluco {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="Dauerbetrieb")
    sub.add_parser("once", help="ein Lauf")
    sub.add_parser("web", help="Dashboard starten")
    sub.add_parser("mcp", help="MCP-Server über stdio (nur lesend)")
    ag = sub.add_parser("agent", help="Laptop-Agenten verwalten").add_subparsers(
        dest="action", required=True
    )
    for name, text in [("add", "Agent einrichten"), ("remove", "Agent entfernen")]:
        ap = ag.add_parser(name, help=text)
        ap.add_argument("device", help="MAC-Adresse oder Name")
    ag.add_parser("list", help="Agenten anzeigen")
    bk = sub.add_parser("backup-db", help="Datenbank konsistent sichern")
    bk.add_argument("target", help="Zieldatei, z. B. /data/backup-snapshot.db")

    dev = sub.add_parser("device", help="Geräte verwalten").add_subparsers(
        dest="action", required=True
    )
    dev.add_parser("list", help="Inventar anzeigen")
    st = dev.add_parser("set-trust", help="Vertrauensstufe setzen")
    st.add_argument("mac")
    st.add_argument("trust", choices=[t.value for t in TrustLevel])
    pr = dev.add_parser("protect", help="auf die Schutzliste setzen (nie trennbar)")
    pr.add_argument("mac")
    pr.add_argument("--off", action="store_true", help="von der Schutzliste nehmen")
    nm = dev.add_parser("name", help="Namen setzen")
    nm.add_argument("mac")
    nm.add_argument("name", nargs="?", default="")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if args.command == "device":
        return _device_command(args)
    if args.command == "web":
        return _web_command()
    if args.command == "mcp":
        return _mcp_command()
    if args.command == "agent":
        return _agent_command(args)
    if args.command == "backup-db":
        return _backup_command(args.target)
    return _run_command(args.command)


def _backup_command(target: str) -> int:
    from pathlib import Path

    path = db_path_from_env()
    if not path.exists():
        print(f"Keine Datenbank unter {path}", file=sys.stderr)
        return 2
    dest = Path(target)
    if dest.resolve() == path.resolve():
        print("Ziel darf nicht die Datenbank selbst sein", file=sys.stderr)
        return 2
    dest.unlink(missing_ok=True)
    store = Store(path)
    try:
        store.backup_to(dest)
    finally:
        store.close()
    print(f"Gesichert: {dest}")
    return 0


def _agent_command(args: argparse.Namespace) -> int:
    from aluco.agent import new_token

    path = db_path_from_env()
    if not path.exists():
        print(f"Keine Datenbank unter {path} – läuft der Aluco-Dienst schon?", file=sys.stderr)
        return 2
    store = Store(path)
    try:
        if args.action == "list":
            agents = store.agents()
            if not agents:
                print("Keine Agenten.")
            for mac, a in agents.items():
                d = store.device(mac)
                last = a["last_report_at"]
                print(
                    f"{mac}  {d.label if d else '?':<25}  letzter Bericht: {last or 'noch keiner'}"
                )
            return 0
        device = _find_device(store, args.device)
        if args.action == "remove":
            with store.transaction():
                n = store.delete_agent(device.mac)
            print(f"{device.label}: {'Agent entfernt' if n else 'hatte keinen Agenten'}")
            return 0
        if device.is_company:
            print("Fehler: Firmengeräte bekommen keinen Agenten.", file=sys.stderr)
            return 1
        token, token_hash = new_token()
        with store.transaction():
            store.add_agent(device.mac, token_hash, utcnow())
        print(f"Agent für {device.label} ({device.mac}) eingerichtet.")
        print("Token (wird nur jetzt angezeigt, wie ein Passwort behandeln):")
        print(token)
        return 0
    except (DeviceNotFoundError, ValueError) as e:
        print(f"Fehler: {e}", file=sys.stderr)
        return 1
    finally:
        store.close()


def _find_device(store: Store, needle: str) -> Device:
    try:
        d = store.device(normalize_mac(needle))
        if d:
            return d
    except ValueError:
        pass
    hits = [d for d in store.devices() if needle.lower() in d.label.lower()]
    if len(hits) != 1:
        raise DeviceNotFoundError(
            f"{len(hits)} Geräte passen zu {needle!r} – bitte MAC-Adresse angeben"
        )
    return hits[0]


def _mcp_command() -> int:
    """stdout gehört dem MCP-Protokoll – Logs gehen nur nach stderr (basicConfig-Standard)."""
    try:
        from aluco.mcp_server import build_server
    except ImportError:
        log.error("MCP-Server braucht das Extra 'mcp' (pip install 'aluco[mcp]')")
        return 2
    import os

    path = db_path_from_env()
    if not path.exists():
        log.error("Keine Datenbank unter %s – läuft der Aluco-Dienst schon?", path)
        return 2
    build_server(path, os.environ.get("TZ") or "UTC").run()
    return 0


def _web_command() -> int:
    import uvicorn

    from aluco.web import WebConfig, create_app

    try:
        cfg = WebConfig.from_env()
    except ConfigError as e:
        log.error("Konfiguration: %s", e)
        return 2
    cfg.db_path.parent.mkdir(parents=True, exist_ok=True)
    Store(cfg.db_path).close()  # Schema anlegen, falls der Runner noch nie lief
    log.info("Dashboard auf http://%s:%s", cfg.host, cfg.port)
    if cfg.trust_proxy and cfg.host not in {"127.0.0.1", "::1", "localhost"}:
        log.warning(
            "ALUCO_WEB_TRUST_PROXY=true, aber das Dashboard lauscht auf %s – dann ist es "
            "auch ohne HTTPS erreichbar. Für den Betrieb hinter Caddy ALUCO_WEB_HOST=127.0.0.1 "
            "setzen.",
            cfg.host,
        )
    if not cfg.secure_cookies:
        log.warning(
            "Dashboard läuft ohne HTTPS: Passwort und Sitzung gehen unverschlüsselt durchs "
            "Netz. Für den Dauerbetrieb einen Reverse-Proxy mit TLS davorschalten und "
            "ALUCO_WEB_SECURE_COOKIES=true setzen (docs/stage-0.md)."
        )
    if not cfg.allowed_hosts:
        log.info("Erreichbar nur über IP-Adresse oder localhost (ALUCO_WEB_ALLOWED_HOSTS)")
    uvicorn.run(
        create_app(cfg),
        host=cfg.host,
        port=cfg.port,
        server_header=False,
        # Nur hinter dem eigenen Proxy (Caddy auf demselben Host) Weiterleitungs-Header glauben.
        proxy_headers=cfg.trust_proxy,
        forwarded_allow_ips="127.0.0.1,::1" if cfg.trust_proxy else None,
        access_log=False,  # keine IPs/Pfade im Log
        log_level="info",
    )
    return 0


def _device_command(args: argparse.Namespace) -> int:
    path = db_path_from_env()
    if not path.exists():
        print(f"Keine Datenbank unter {path} – läuft der Aluco-Dienst schon?", file=sys.stderr)
        return 2
    store = Store(path)
    try:
        if args.action == "list":
            _print_devices(store)
        elif args.action == "set-trust":
            change = set_trust(store, args.mac, TrustLevel(args.trust))
            d = change.device
            print(f"{d.label}: {TRUST_DE[change.previous]} → {TRUST_DE[d.trust]}")
            if d.trust is TrustLevel.COMPANY:
                print(
                    f"Firmengerät: {change.domains_deleted} gespeicherte Domains und "
                    f"{change.incidents_deleted} Vorfälle zum Verhalten gelöscht. "
                    "Ab jetzt nur passiv beobachtet, nie trennbar."
                )
        elif args.action == "protect":
            d = set_protected(store, args.mac, not args.off)
            print(f"{d.label}: {'auf der Schutzliste' if d.protected else 'nicht geschützt'}")
        elif args.action == "name":
            d = set_name(store, args.mac, args.name)
            print(f"{d.mac}: Name {'= ' + d.name if d.name else 'entfernt'}")
    except (DeviceNotFoundError, ValueError) as e:
        print(f"Fehler: {e}", file=sys.stderr)
        return 1
    finally:
        store.close()
    return 0


def _print_devices(store: Store) -> None:
    devices = store.devices()
    if not devices:
        print("Inventar ist leer.")
        return
    print(f"{'MAC':<17}  {'Stufe':<9}  {'Schutz':<6}  {'IP':<15}  {'zuletzt (UTC)':<16}  Name")
    for d in devices:
        print(
            f"{d.mac:<17}  {TRUST_DE[d.trust]:<9}  {'ja' if d.protected else '':<6}  "
            f"{d.ip or '':<15}  {d.last_seen:%Y-%m-%d %H:%M}  {d.label}"
        )


def _run_command(command: str) -> int:
    try:
        cfg = Config.from_env()
    except ConfigError as e:
        log.error("Konfiguration: %s", e)
        return 2

    cfg.db_path.parent.mkdir(parents=True, exist_ok=True)
    store = Store(cfg.db_path)
    runner = build_runner(cfg, store)

    if command == "once":
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
