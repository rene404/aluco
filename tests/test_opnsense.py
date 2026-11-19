"""OPNsense: Adapter, TLS-Fingerprint (echter HTTPS-Server), Trennen/Freigeben, Dashboard."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from aluco.adapters.base import AdapterError
from aluco.adapters.opnsense import OPNsense, OPNsenseClient, normalize_pin
from aluco.config import ConfigError, firewall_settings_from_env
from aluco.engine import Engine
from aluco.incidents import TransitionError
from aluco.model import Device, DeviceSighting, IncidentStatus, TrustLevel
from aluco.quarantine import QuarantineError, disconnect, release, resync
from aluco.store import Store
from aluco.web import WebConfig, create_app
from tests.conftest import IP_A, MAC_A, MAC_B, T0


class FakeClient:
    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self.calls: list[tuple[str, str, Any]] = []
        self.responses = responses or {}

    def request(self, method: str, path: str, body: Any = None) -> Any:
        self.calls.append((method, path, body))
        for prefix, resp in self.responses.items():
            if path.startswith(prefix):
                if isinstance(resp, Exception):
                    raise resp
                return resp
        return {"status": "done"}


# --- Adapter -----------------------------------------------------------------------


def test_block_unblock_and_list() -> None:
    client = FakeClient(
        {"/api/firewall/alias_util/list/": {"rows": [{"ip": "192.0.2.10/32"}, {"ip": "kaputt"}]}}
    )
    fw = OPNsense(client)
    fw.block("192.0.2.10")
    fw.unblock("192.0.2.10")
    assert client.calls[0] == (
        "POST",
        "/api/firewall/alias_util/add/aluco_quarantine",
        {"address": "192.0.2.10"},
    )
    assert client.calls[1][1] == "/api/firewall/alias_util/delete/aluco_quarantine"
    assert fw.blocked() == {"192.0.2.10"}


def test_block_rejects_bad_input_and_failures() -> None:
    fw = OPNsense(
        FakeClient(
            {
                "/api/firewall/alias_util/add/": {
                    "status": "failed",
                    "status_msg": "nonexistent alias",
                }
            }
        )
    )
    with pytest.raises(AdapterError, match="nonexistent alias"):
        fw.block("192.0.2.10")
    with pytest.raises(AdapterError, match="IP-Adresse"):
        fw.block("192.0.2.10; rm -rf /")
    with pytest.raises(AdapterError, match="Alias"):
        OPNsense(FakeClient(), alias="evil/../x")


def test_arp_table_as_device_source() -> None:
    rows = [
        {
            "mac": "00:00:5e:00:53:01",
            "ip": "192.0.2.10",
            "hostname": "tv",
            "manufacturer": "Beispiel",
            "expired": False,
            "permanent": False,
        },
        {"mac": "00:00:5e:00:53:02", "ip": "192.0.2.1", "permanent": True},  # Firewall selbst
        {"mac": "00:00:5e:00:53:03", "ip": "192.0.2.12", "expired": True},
        {"mac": "kaputt", "ip": "192.0.2.13"},
    ]
    [s] = OPNsense(FakeClient({"/api/diagnostics/interface/getArp": rows})).fetch_sightings()
    assert (s.mac, s.ip, s.hostname, s.vendor, s.online, s.source) == (
        "00:00:5e:00:53:01", "192.0.2.10", "tv", "Beispiel", True, "opnsense",
    )  # fmt: skip


def test_client_requires_https_and_tls_check() -> None:
    with pytest.raises(AdapterError, match="https"):
        OPNsenseClient("http://192.0.2.1", "k", "s", cert_sha256="a" * 64)
    with pytest.raises(AdapterError, match="CERT_SHA256 oder"):
        OPNsenseClient("https://192.0.2.1", "k", "s")
    with pytest.raises(AdapterError, match="Fingerprint"):
        normalize_pin("zu-kurz")
    assert normalize_pin("AB:" * 31 + "AB") == "ab" * 32
    assert "s3cret" not in repr(
        OPNsenseClient("https://192.0.2.1", "key", "s3cret", cert_sha256="a" * 64)
    )


# --- TLS-Fingerprint gegen echten HTTPS-Server ------------------------------------


@pytest.fixture
def https_server(tmp_path: Path):
    cryptography = pytest.importorskip("cryptography")  # noqa: F841 – nur Testhilfe
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OPNsense.localdomain")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )  # fmt: skip
    cert_pem, key_pem = tmp_path / "c.pem", tmp_path / "k.pem"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pin = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    seen: list[str | None] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            seen.append(self.headers.get("Authorization"))
            body = json.dumps({"rows": [{"ip": "192.0.2.50"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_pem, key_pem)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"https://127.0.0.1:{server.server_address[1]}", pin, seen
    server.shutdown()


def test_pinned_certificate_is_accepted(https_server: Any) -> None:
    url, pin, seen = https_server
    fw = OPNsense(OPNsenseClient(url, "key", "secret", cert_sha256=pin))
    assert fw.blocked() == {"192.0.2.50"}
    assert seen and seen[0] and seen[0].startswith("Basic ")


def test_wrong_pin_aborts_before_sending_credentials(https_server: Any) -> None:
    url, _, seen = https_server
    fw = OPNsense(OPNsenseClient(url, "key", "secret", cert_sha256="0" * 64))
    with pytest.raises(AdapterError, match="Fingerprint"):
        fw.blocked()
    assert seen == []  # Server hat keine Anfrage (und kein Passwort) bekommen


# --- Trennen / Freigeben ------------------------------------------------------------


class FakeBlocker:
    def __init__(self, fail: bool = False) -> None:
        self.ips: set[str] = set()
        self.fail = fail

    def block(self, ip: str) -> None:
        if self.fail:
            raise AdapterError("Firewall nicht erreichbar")
        self.ips.add(ip)

    def unblock(self, ip: str) -> None:
        self.ips.discard(ip)

    def blocked(self) -> set[str]:
        return set(self.ips)


def _incident_for(store: Store, mac: str = MAC_A, **device: Any) -> int:
    Engine(store).process(
        sightings=[DeviceSighting(mac=mac, at=T0, ip=device.pop("ip", IP_A))], now=T0
    )
    d = store.device(mac)
    assert d is not None
    store.save_device(Device(**{**{f: getattr(d, f) for f in d.__slots__}, **device}))
    return next(i.id for i in store.incidents() if i.device_mac == mac) or 0


def test_disconnect_and_release(store: Store) -> None:
    blocker = FakeBlocker()
    iid = _incident_for(store)
    updated = disconnect(store, blocker, iid, note="unbekannt")
    assert updated.status is IncidentStatus.DISCONNECTED and blocker.ips == {IP_A}
    assert store.block(MAC_A)["ip"] == IP_A  # type: ignore[index]
    assert "über die Firewall getrennt" in store.events(limit=1)[0].title
    release(store, blocker, MAC_A)
    assert blocker.ips == set() and store.block(MAC_A) is None
    with pytest.raises(QuarantineError):
        release(store, blocker, MAC_A)


@pytest.mark.parametrize(
    ("extra", "error"),
    [({"protected": True}, "geschützt"), ({"trust": TrustLevel.COMPANY}, "geschützt")],
)
def test_protected_devices_are_never_blocked(
    store: Store, extra: dict[str, Any], error: str
) -> None:
    blocker = FakeBlocker()
    iid = _incident_for(store, **extra)
    with pytest.raises(TransitionError, match=error):
        disconnect(store, blocker, iid)
    assert blocker.ips == set()


def test_firewall_failure_changes_nothing(store: Store) -> None:
    iid = _incident_for(store)
    with pytest.raises(AdapterError):
        disconnect(store, FakeBlocker(fail=True), iid)
    assert store.incident_by_id(iid).status is IncidentStatus.NEW  # type: ignore[union-attr]
    assert store.block(MAC_A) is None


def test_no_ip_no_block(store: Store) -> None:
    iid = _incident_for(store, ip=None)
    with pytest.raises(QuarantineError, match="IP"):
        disconnect(store, FakeBlocker(), iid)


def test_resync_follows_dhcp_change(store: Store) -> None:
    blocker = FakeBlocker()
    disconnect(store, blocker, _incident_for(store))
    Engine(store).process(sightings=[DeviceSighting(mac=MAC_A, at=T0, ip="192.0.2.77")], now=T0)
    [change] = resync(store, blocker)
    assert change.endswith("192.0.2.10 → 192.0.2.77")
    assert resync(store, blocker) == []  # nichts mehr zu tun
    assert blocker.ips == {"192.0.2.77"} and store.block(MAC_A)["ip"] == "192.0.2.77"  # type: ignore[index]


# --- Konfiguration und Dashboard ------------------------------------------------------


def test_firewall_settings() -> None:
    assert firewall_settings_from_env({}).enabled is False
    base = {
        "OPNSENSE_URL": "https://192.0.2.1",
        "OPNSENSE_API_KEY": "k",
        "OPNSENSE_API_SECRET": "s",
    }
    with pytest.raises(ConfigError, match="CERT_SHA256 oder"):
        firewall_settings_from_env(base)
    with pytest.raises(ConfigError, match="https"):
        firewall_settings_from_env(
            base | {"OPNSENSE_URL": "http://192.0.2.1", "OPNSENSE_CERT_SHA256": "a" * 64}
        )
    fw = firewall_settings_from_env(
        base | {"OPNSENSE_API_SECRET": "geheim-123", "OPNSENSE_CERT_SHA256": "a" * 64}
    )
    assert fw.enabled and fw.alias == "aluco_quarantine"
    assert "geheim-123" not in repr(fw)


def _web(tmp_path: Path, blocker: Any) -> tuple[TestClient, int]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "a.db"
    s = Store(path)
    iid = _incident_for(s)
    s.close()
    client = TestClient(
        create_app(WebConfig(db_path=path, password="x" * 12), blocker=blocker),
        follow_redirects=False,
    )
    client.post("/login", data={"password": "x" * 12}, headers={"Origin": "http://testserver"})
    return client, iid


H = {"Origin": "http://testserver", "HX-Request": "true"}


def test_dashboard_disconnect_requires_firewall_and_confirmation(tmp_path: Path) -> None:
    client, iid = _web(tmp_path, None)
    assert "Braucht die Firewall" in client.get("/incidents").text
    assert (
        client.post(
            f"/incidents/{iid}/status", data={"status": "disconnected", "confirm": "ja"}, headers=H
        ).status_code
        == 400
    )

    blocker = FakeBlocker()
    client, iid = _web(tmp_path / "2", blocker)
    assert "hx-confirm" in client.get("/incidents").text
    r = client.post(f"/incidents/{iid}/status", data={"status": "disconnected"}, headers=H)
    assert r.status_code == 400 and blocker.ips == set()  # ohne Bestätigung nichts
    r = client.post(
        f"/incidents/{iid}/status", data={"status": "disconnected", "confirm": "ja"}, headers=H
    )
    assert r.status_code == 200 and "getrennt" in r.text and blocker.ips == {IP_A}

    page = client.get(f"/devices/{MAC_A}").text
    assert "Getrennt seit" in page and "Freigeben" in page and "style=" not in page
    assert "Getrennt – kein Internet" in client.get("/devices").text
    r = client.post(f"/devices/{MAC_A}/release", headers={"Origin": "http://testserver"})
    assert r.status_code == 303 and blocker.ips == set()


def test_dashboard_reports_firewall_errors(tmp_path: Path) -> None:
    client, iid = _web(tmp_path, FakeBlocker(fail=True))
    r = client.post(
        f"/incidents/{iid}/status", data={"status": "disconnected", "confirm": "ja"}, headers=H
    )
    assert r.status_code == 502 and "nicht erreichbar" in r.text


def test_unknown_mac_device_b_unaffected(store: Store) -> None:
    blocker = FakeBlocker()
    disconnect(store, blocker, _incident_for(store))
    _incident_for(store, mac=MAC_B, ip="192.0.2.20")
    assert blocker.ips == {IP_A}
