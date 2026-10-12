"""muon_bridge (KAN-527): sessions to a Bambu printer and a PrusaLink one,
through fake MQTT, FTPS, camera and HTTP servers on loopback."""
from __future__ import annotations

import asyncio
import base64
import gc
import json
import logging
import ssl
from typing import Any, Dict, Iterator, Optional, Tuple

import pytest

from moonraker import muon_access_policy as policy
from moonraker.common import RequestType, WebRequest
from moonraker.components.muon_bridge import MuonBridge, Session
from moonraker.muon_bridge_common import (
    BridgeError, RateLimit, Secret, check_filename, parse_target
)
from moonraker.muon_bridge_prusa import check_api_path
from moonraker.utils import redact
from moonraker.utils.exceptions import ServerError

from muon_access_fakes import caller
from muon_bridge_fakes import (
    ACCESS_CODE, JPEG, PRUSA_PASSWORD, PRUSA_USER, SERIAL, Authority,
    Config, Connection, FakeBroker, FakeCamera, FakeFtps, PrusaState,
    Server, have_openssl, start_prusa
)

pytestmark = pytest.mark.skipif(not have_openssl(),
                                reason="needs the openssl command")

BAMBU_IP = "192.168.1.20"
PRUSA_IP = "192.168.1.30"


def gateway(level: str = "admin", role: str = "operator",
            home: bool = True) -> Tuple[Any, Any]:
    _, ip, user = caller({"kind": "gateway", "principal": "jack",
                          "level": level, "role": role, "home": home})
    return ip, user


OWNER = gateway()


@pytest.fixture(autouse=True)
def access_state() -> Iterator[None]:
    policy.set_state(policy.AccessState(
        entry=policy.ENTRY_PROTECTED, owner=policy.OWNER_ACCOUNT))
    yield
    policy.set_state(None)


@pytest.fixture(scope="module")
def authorities(tmp_path_factory: Any) -> Dict[str, Authority]:
    root = str(tmp_path_factory.mktemp("bbl"))
    return {"bambu": Authority(root, "bambu"),
            "rogue": Authority(root, "rogue")}


def bridge(**options: Any) -> MuonBridge:
    values = {"enabled": True, "max_sessions": 2, "max_upload_mb": 4,
              "status_interval": 1.0, "prusalink_storage": "usb"}
    values.update(options)
    return MuonBridge(Config(Server(), **values))  # type: ignore[arg-type]


async def call(component: MuonBridge, method: str,
               args: Optional[Dict[str, Any]] = None,
               conn: Optional[Connection] = None,
               who: Tuple[Any, Any] = OWNER) -> Any:
    path = f"/server/muon_bridge/{method}"
    verbs, handler = component.server.handlers[path]  # type: ignore
    rtype = RequestType.GET if verbs == ["GET"] else RequestType.POST
    ip, user = who
    if conn is None:
        conn = Connection(ip, user)
    # What check_access decides for every transport, before the handler.
    policy.check_access(path, rtype, args or {}, conn, ip, user)
    request = WebRequest(path, args if args is not None else {}, rtype, conn,
                         ip, user)
    return await handler(request)


class Bambu:
    """A fake Bambu printer, and a bridge dialling it."""

    def __init__(self, authority: Authority, serial: str = SERIAL,
                 code: str = ACCESS_CODE) -> None:
        context = authority.server_context(serial)
        self.broker = FakeBroker(context, code)
        self.ftps = FakeFtps(context, code)
        self.camera = FakeCamera(context)
        self.ca = authority.ca

    async def __aenter__(self) -> "Bambu":
        await self.broker.start()
        await self.camera.start()
        ports = {8883: self.broker.port, 990: self.ftps.port,
                 6000: self.camera.port}
        self.bridge = bridge()
        self.bridge.ca_file = self.ca
        self.bridge.connect_timeout = 5.0
        self.bridge.dialer = lambda host, port: ("127.0.0.1", ports[port])
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.bridge.close()
        await self.broker.stop()
        await self.camera.stop()
        self.ftps.close()


def bambu_args(code: str = ACCESS_CODE, host: str = BAMBU_IP
               ) -> Dict[str, Any]:
    return {"kind": "bambu", "host": host, "serial": SERIAL,
            "credentials": {"access_code": code}}


async def settle(predicate: Any, timeout: float = 3.0) -> None:
    for _ in range(int(timeout / 0.02)):
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("timed out")


def notifications(conn: Connection) -> list:
    return [m for m in conn.messages
            if m.get("method") == "notify_muon_bridge_status"]


# -- off by default -------------------------------------------------------------


def test_off_by_default_registers_nothing() -> None:
    server = Server()
    MuonBridge(Config(server))  # type: ignore[arg-type]
    assert server.handlers == {} and server.events == {}


def test_enabled_registers_the_methods_and_no_broadcast() -> None:
    component = bridge()
    names = {p.rsplit("/", 1)[1] for p in component.server.handlers}
    assert {"open_session", "status", "upload", "start", "pause", "resume",
            "stop", "close_session"} <= names
    assert component.server.notifications == []  # type: ignore[attr-defined]


# -- a Bambu session, start to finish -------------------------------------------


def test_bambu_session_lifecycle(authorities: Dict[str, Authority]) -> None:
    async def run() -> None:
        async with Bambu(authorities["bambu"]) as printer:
            conn, other = Connection(*OWNER), Connection(*OWNER)
            opened = await call(printer.bridge, "open_session", bambu_args(),
                                conn)
            sid = opened["session_id"]
            assert opened["bridged"] is True and opened["kind"] == "bambu"
            assert opened["host"] == BAMBU_IP and opened["serial"] == SERIAL
            broker = printer.broker
            assert broker.connects[0]["user"] == "bblp"
            assert broker.subscriptions == [f"device/{SERIAL}/report"]
            await settle(lambda: broker.requests)
            assert broker.requests[0]["topic"] == f"device/{SERIAL}/request"
            assert broker.requests[0]["pushing"]["command"] == "pushall"

            # The report reaches the websocket that opened the session only
            await settle(lambda: notifications(conn))
            note = notifications(conn)[0]["params"][0]
            assert note["bridged"] is True and note["session_id"] == sid
            assert note["status"]["gcode_state"] == "IDLE"
            assert other.messages == []
            broker.report({"gcode_state": "RUNNING", "mc_percent": 12})
            await settle(lambda: len(notifications(conn)) == 2)
            status = await call(printer.bridge, "status",
                                {"session_id": sid}, conn)
            assert status["status"]["mc_percent"] == 12

            for command in ("pause", "resume", "stop"):
                sent = await call(printer.bridge, command,
                                  {"session_id": sid}, conn)
                await settle(lambda: broker.requests[-1].get("print", {}).get(
                    "sequence_id") == sent["sequence_id"])
                assert broker.requests[-1]["print"]["command"] == command

            data = b"PK\x03\x04" + b"3mf" * 1000
            up = await call(printer.bridge, "upload", {
                "session_id": sid, "filename": "benchy.3mf",
                "data": base64.b64encode(data).decode()}, conn)
            assert up["size"] == len(data)
            assert printer.ftps.files == {"benchy.3mf": data}
            # ftp.md: the data channel resumes the control's TLS session
            assert printer.ftps.reused == [True]

            await call(printer.bridge, "start", {
                "session_id": sid, "filename": "benchy.3mf",
                "options": {"plate": 2}}, conn)
            await settle(lambda: broker.requests[-1].get("print", {}).get(
                "command") == "project_file")
            job = broker.requests[-1]["print"]
            assert job["url"] == "ftp:///benchy.3mf"
            assert job["param"] == "Metadata/plate_2.gcode"

            frame = await call(printer.bridge, "camera", {"session_id": sid},
                               conn)
            assert base64.b64decode(frame["data"]) == JPEG
            assert printer.camera.auth == [("bblp", ACCESS_CODE)]

            closed = await call(printer.bridge, "close_session",
                                {"session_id": sid}, conn)
            assert closed["closed"] is True
            assert printer.bridge.sessions == {}
            await settle(lambda: broker.disconnects == 1)
            assert notifications(conn)[-1]["params"][0]["status"][
                "connected"] is False
            with pytest.raises(ServerError) as info:
                await call(printer.bridge, "status", {"session_id": sid},
                           conn)
            assert info.value.status_code == 404
    asyncio.run(run())


def test_disconnect_drops_the_session(
        authorities: Dict[str, Authority]) -> None:
    async def run() -> None:
        async with Bambu(authorities["bambu"]) as printer:
            conn = Connection(*OWNER)
            opened = await call(printer.bridge, "open_session", bambu_args(),
                                conn)
            session = printer.bridge.sessions[opened["session_id"]]
            assert session.printer is not None
            secret = session.printer.access_code  # type: ignore[union-attr]
            for callback in printer.bridge.server.events[  # type: ignore
                    "websockets:client_removed"]:
                callback(conn)
            await settle(lambda: not printer.bridge.sessions)
            await settle(lambda: printer.broker.disconnects == 1)
            assert secret.wiped
    asyncio.run(run())


def test_printer_going_away_closes_the_session(
        authorities: Dict[str, Authority]) -> None:
    async def run() -> None:
        async with Bambu(authorities["bambu"]) as printer:
            conn = Connection(*OWNER)
            await call(printer.bridge, "open_session", bambu_args(), conn)
            await printer.broker.stop()
            await settle(lambda: not printer.bridge.sessions)
            last = notifications(conn)[-1]["params"][0]["status"]
            assert last["connected"] is False
            assert "went away" in last["reason"]
    asyncio.run(run())


# -- targets --------------------------------------------------------------------


@pytest.mark.parametrize("host", [
    "8.8.8.8", "1.1.1.1", "100.64.0.1", "127.0.0.1", "169.254.1.1",
    "0.0.0.0", "224.0.0.1", "255.255.255.255", "2001:4860:4860::8888",
    "::1", "fe80::1", "::ffff:8.8.8.8", "printer.local", "", "192.168.1.10",
    "172.32.0.1", "11.0.0.1",
])
def test_refuses_anything_but_another_private_lan_address(host: str) -> None:
    with pytest.raises(BridgeError) as info:
        parse_target(host, ["192.168.1.10"])
    assert info.value.status_code in (400, 403)


@pytest.mark.parametrize("host", [
    "10.0.0.5", "172.16.4.4", "172.31.255.1", "192.168.1.20",
    "fd12:3456:789a::1", "[fdab::2]", "::ffff:192.168.1.20",
])
def test_accepts_rfc1918_and_ula(host: str) -> None:
    parse_target(host, ["192.168.1.10"])


def test_open_session_refuses_a_public_address(
        authorities: Dict[str, Authority]) -> None:
    async def run() -> None:
        async with Bambu(authorities["bambu"]) as printer:
            for host in ("8.8.8.8", "192.168.1.10", "localhost"):
                args = bambu_args(host=host)
                with pytest.raises(ServerError) as info:
                    await call(printer.bridge, "open_session", args)
                assert info.value.status_code in (400, 403)
                assert "credentials" not in args
            assert printer.broker.connects == []
    asyncio.run(run())


# -- credentials ----------------------------------------------------------------


def _reachable(root: Any) -> Iterator[Any]:
    """Every object reachable from root through attributes and containers,
    skipping modules, classes and functions (shared, not session state)."""
    seen = set()
    stack = [root]
    while stack:
        obj = stack.pop()
        if id(obj) in seen or isinstance(obj, (type, type(gc), type(_reachable))):
            continue
        seen.add(id(obj))
        yield obj
        if isinstance(obj, dict):
            stack.extend(obj.keys())
            stack.extend(obj.values())
        elif isinstance(obj, (list, tuple, set, frozenset)):
            stack.extend(obj)
        elif isinstance(obj, (str, bytes, bytearray, int, float)):
            continue
        else:
            stack.extend(getattr(obj, "__dict__", {}).values())
            for slot in getattr(type(obj), "__slots__", ()):
                if hasattr(obj, slot):
                    stack.append(getattr(obj, slot))


def _holds(root: Any, secret: str) -> bool:
    raw = secret.encode()
    for obj in _reachable(root):
        if isinstance(obj, str) and secret in obj:
            return True
        if isinstance(obj, (bytes, bytearray)) and raw in obj:
            return True
    return False


def test_credentials_are_never_logged_and_gone_after_close(
        authorities: Dict[str, Authority], caplog: Any) -> None:
    caplog.set_level(logging.DEBUG)

    async def run() -> None:
        async with Bambu(authorities["bambu"]) as printer:
            conn = Connection(*OWNER)
            args = bambu_args()
            # What Moonraker's request logging writes (common.py,
            # application.py) for these arguments.
            logging.debug(f"Received::{json.dumps(redact.redact(args))}")
            opened = await call(printer.bridge, "open_session", args, conn)
            assert "credentials" not in args
            sid = opened["session_id"]
            session = printer.bridge.sessions[sid]
            assert session.printer is not None
            secret = session.printer.access_code  # type: ignore[union-attr]
            assert "<redacted>" in repr(secret)
            assert ACCESS_CODE not in repr(session.printer.__dict__)
            await call(printer.bridge, "upload", {
                "session_id": sid, "filename": "a.gcode",
                "data": base64.b64encode(b"G28\n").decode()}, conn)
            await call(printer.bridge, "close_session", {"session_id": sid},
                       conn)
            assert secret.wiped
            with pytest.raises(BridgeError):
                secret.reveal()
            assert not _holds(printer.bridge, ACCESS_CODE)
            assert not _holds(session, ACCESS_CODE)
            assert not _holds(conn.messages, ACCESS_CODE)
    asyncio.run(run())
    assert caplog.records, "nothing was logged at all"
    assert ACCESS_CODE not in caplog.text
    assert "muon_bridge" in caplog.text


def test_prusalink_credentials_are_never_logged_and_gone_after_close(
        caplog: Any) -> None:
    caplog.set_level(logging.DEBUG)

    async def run() -> None:
        state = PrusaState(qop=True)
        server, port = start_prusa(state)
        component = bridge()
        component.dialer = lambda host, p: ("127.0.0.1", port)
        try:
            conn = Connection(*OWNER)
            args = prusa_args()
            logging.debug(f"Received::{json.dumps(redact.redact(args))}")
            opened = await call(component, "open_session", args, conn)
            session = component.sessions[opened["session_id"]]
            await call(component, "close_session",
                       {"session_id": session.id}, conn)
            assert not _holds(component, PRUSA_PASSWORD)
            assert not _holds(session, PRUSA_PASSWORD)
        finally:
            await component.close()
            server.stop()
    asyncio.run(run())
    assert PRUSA_PASSWORD not in caplog.text


def test_a_secret_wipes_in_place() -> None:
    secret = Secret("hunter22")
    buf = secret._buf
    secret.wipe()
    assert bytes(buf) == b"\0" * 8 and secret.wiped
    assert "hunter22" not in repr(secret) and "hunter22" not in str(secret)


def test_redaction_covers_the_bridge_fields() -> None:
    text = json.dumps(redact.redact({"params": {
        "credentials": {"access_code": "x1", "password": "x2"},
        "access_code": "x3"}}))
    assert "x1" not in text and "x2" not in text and "x3" not in text


def test_wrong_access_code_is_refused_and_dropped(
        authorities: Dict[str, Authority]) -> None:
    async def run() -> None:
        async with Bambu(authorities["bambu"]) as printer:
            with pytest.raises(ServerError) as info:
                await call(printer.bridge, "open_session",
                           bambu_args(code="wrong123"))
            assert info.value.status_code == 403
            assert printer.bridge.sessions == {}
    asyncio.run(run())


# -- certificates ---------------------------------------------------------------


@pytest.mark.parametrize("case", ["other_ca", "other_serial", "system_ca"])
def test_certificate_verification_failure(
        authorities: Dict[str, Authority], case: str) -> None:
    async def run() -> None:
        authority = authorities["rogue" if case == "other_ca" else "bambu"]
        serial = "01S00A999999999" if case == "other_serial" else SERIAL
        async with Bambu(authority, serial=serial) as printer:
            # The bridge trusts the Bambu CA only; for system_ca it trusts
            # its bundled roots, which never signed this fake.
            printer.bridge.ca_file = (
                authorities["bambu"].ca if case != "system_ca"
                else MuonBridge(Config(Server())).ca_file)  # type: ignore
            with pytest.raises(ServerError) as info:
                await call(printer.bridge, "open_session", bambu_args())
            assert info.value.status_code == 502
            assert "certificate did not verify" in str(info.value)
            assert printer.bridge.sessions == {}
            assert printer.broker.connects == []
    asyncio.run(run())


def test_bundled_bambu_ca_loads() -> None:
    component = MuonBridge(Config(Server()))  # type: ignore[arg-type]
    context = ssl.create_default_context(cafile=component.ca_file)
    names = [dict(x[0] for x in c["subject"])["commonName"]
             for c in context.get_ca_certs()]
    assert "BBL CA" in names
    assert len([n for n in names if n.startswith("BBL CA2")]) == 4


# -- PrusaLink ------------------------------------------------------------------


def prusa_args(password: str = PRUSA_PASSWORD) -> Dict[str, Any]:
    return {"kind": "prusalink", "host": PRUSA_IP,
            "credentials": {"username": PRUSA_USER, "password": password}}


@pytest.mark.parametrize("qop,algorithm", [
    (False, None), (True, None), (True, "SHA-256"),
])
def test_prusalink_digest_round_trip(qop: bool, algorithm: Optional[str]
                                     ) -> None:

    async def run() -> None:
        state = PrusaState(qop=qop, algorithm=algorithm)
        server, port = start_prusa(state)
        component = bridge()
        component.dialer = lambda host, p: ("127.0.0.1", port)
        try:
            conn = Connection(*OWNER)
            opened = await call(component, "open_session", prusa_args(), conn)
            sid = opened["session_id"]
            assert opened["status"]["state"] == "PRINTING"
            assert "serial" not in json.dumps(opened["status"])
            answer = await call(component, "prusalink", {
                "session_id": sid, "path": "/api/v1/job"}, conn)
            assert answer["response"]["status_code"] == 200
            assert answer["response"]["body"]["id"] == 7
            assert "WWW-Authenticate" not in answer["response"]["headers"]
            await call(component, "upload", {
                "session_id": sid, "filename": "part.gcode",
                "data": base64.b64encode(b"G28\nG1 X1\n").decode()}, conn)
            assert state.files == {"files/usb/part.gcode": b"G28\nG1 X1\n"}
            await call(component, "pause", {"session_id": sid}, conn)
            await call(component, "start", {"session_id": sid,
                                            "filename": "part.gcode"}, conn)
            await call(component, "stop", {"session_id": sid}, conn)
            assert state.actions == ["PUT job/7/pause",
                                     "POST files/usb/part.gcode",
                                     "DELETE job/7"]
            # One challenge, then every request answered without another
            assert state.unauthenticated == 1
            if qop:
                assert len(set(state.seen_nc)) == len(state.seen_nc) > 3
            assert all(PRUSA_PASSWORD not in a for a in state.authorizations)
            await call(component, "close_session", {"session_id": sid}, conn)
        finally:
            await component.close()
            server.stop()
    asyncio.run(run())


def test_prusalink_second_session_after_the_first() -> None:
    async def run() -> None:
        state = PrusaState(qop=True)
        server, port = start_prusa(state)
        component = bridge()
        component.dialer = lambda host, p: ("127.0.0.1", port)
        try:
            for _ in range(2):
                conn = Connection(*OWNER)
                opened = await call(component, "open_session", prusa_args(),
                                    conn)
                await call(component, "close_session",
                           {"session_id": opened["session_id"]}, conn)
            assert len(state.nonces) == 2
        finally:
            await component.close()
            server.stop()
    asyncio.run(run())


def test_prusalink_wrong_password() -> None:
    async def run() -> None:
        state = PrusaState(qop=False)
        server, port = start_prusa(state)
        component = bridge()
        component.dialer = lambda host, p: ("127.0.0.1", port)
        try:
            with pytest.raises(ServerError) as info:
                await call(component, "open_session", prusa_args("nope"))
            assert info.value.status_code == 403
            assert component.sessions == {}
        finally:
            server.stop()
    asyncio.run(run())


@pytest.mark.parametrize("path", [
    "/api/v1/../../etc", "/api/v2/status", "/admin", "/api/v1/./x",
    "/api/v1/%2e%2e/x", "/api/v1//x", "http://evil/api/v1/x",
    "/api/v1/x\r\nHost: evil", None,
])
def test_prusalink_proxy_stays_under_api_v1(path: Any) -> None:
    with pytest.raises(BridgeError):
        check_api_path(path)


# -- the owner-only gate --------------------------------------------------------


@pytest.mark.parametrize("who,allowed", [
    (OWNER, True),
    (gateway("member"), False),
    (gateway("signed_in_guest"), False),
    (gateway("admin", role="viewer"), False),
    (gateway("admin", home=False), False),
])
def test_owner_only(who: Tuple[Any, Any], allowed: bool) -> None:
    component = bridge()
    if allowed:
        listed = asyncio.run(call(component, "status", {}, None, who))
        assert listed == {"bridged": True, "sessions": []}
        with pytest.raises(ServerError) as info:
            asyncio.run(call(component, "open_session", {"kind": "x"},
                             None, who))
        assert info.value.status_code == 400
        return
    for method in ("status", "open_session", "stop", "close_session"):
        with pytest.raises(ServerError) as info:
            asyncio.run(call(component, method, {}, None, who))
        assert info.value.status_code == 403
        assert "access-denied:bridge" in str(info.value)


def test_the_component_gates_itself_too() -> None:
    """Not relying on check_access: the handler refuses a member alone."""
    component = bridge()
    ip, user = gateway("member")
    path = "/server/muon_bridge/status"
    _, handler = component.server.handlers[path]  # type: ignore
    request = WebRequest(path, {}, RequestType.GET, Connection(ip, user), ip,
                         user)
    with pytest.raises(ServerError) as info:
        asyncio.run(handler(request))
    assert info.value.status_code == 403


def test_without_muon_access_only_the_panel() -> None:
    policy.set_state(None)
    component = bridge()
    with pytest.raises(ServerError) as info:
        asyncio.run(call(component, "status", {}, None, OWNER))
    assert info.value.status_code == 403
    import ipaddress
    panel = (ipaddress.ip_address("127.0.0.1"), None)
    assert asyncio.run(call(component, "status", {}, None, panel)) == {
        "bridged": True, "sessions": []}


@pytest.mark.parametrize("owner", [policy.OWNER_NONE, policy.OWNER_UNKNOWN])
@pytest.mark.parametrize("entry", [policy.ENTRY_OPEN, policy.ENTRY_PROTECTED])
def test_with_no_owner_only_the_panel(owner: str, entry: str) -> None:
    """Bench finding: Open with no owner must not mean anyone at home."""
    import ipaddress
    state = policy.AccessState(entry=entry, owner=owner)
    policy.set_state(state)
    assert policy.required_level(policy.ACTIONS["bridge"], state) == \
        policy.PANEL
    component = bridge()
    for who in (OWNER, gateway("signed_out_guest"), gateway("member")):
        with pytest.raises(ServerError) as info:
            asyncio.run(call(component, "status", {}, None, who))
        assert info.value.status_code == 403
    panel = (ipaddress.ip_address("127.0.0.1"), None)
    assert asyncio.run(call(component, "status", {}, None, panel))[
        "bridged"] is True


def test_every_bridge_endpoint_is_the_bridge_row() -> None:
    for name in ("status", "open_session", "camera", "close_session"):
        for rtype in (RequestType.GET, RequestType.POST):
            actions = policy.classify(f"/server/muon_bridge/{name}", rtype)
            assert [a.name for a in actions] == ["bridge"]
    row = policy.ACTIONS["bridge"]
    assert row.fixed and row.home_only
    assert (row.relaxed, row.standard, row.strict) == (policy.ADMIN,) * 3


def test_a_session_belongs_to_whoever_opened_it(
        authorities: Dict[str, Authority]) -> None:
    async def run() -> None:
        async with Bambu(authorities["bambu"]) as printer:
            opened = await call(printer.bridge, "open_session", bambu_args())
            sid = opened["session_id"]
            _, _, other_user = caller({
                "kind": "gateway", "principal": "eve", "level": "admin",
                "role": "operator", "home": True})
            other = (OWNER[0], other_user)
            with pytest.raises(ServerError) as info:
                await call(printer.bridge, "stop", {"session_id": sid},
                           None, other)
            assert info.value.status_code == 403
            listed = await call(printer.bridge, "status", {}, None, other)
            assert listed["sessions"] == []
    asyncio.run(run())


# -- limits ---------------------------------------------------------------------


def test_session_and_rate_limits(authorities: Dict[str, Authority]) -> None:
    async def run() -> None:
        async with Bambu(authorities["bambu"]) as printer:
            printer.bridge.max_sessions = 1
            conn = Connection(*OWNER)
            opened = await call(printer.bridge, "open_session", bambu_args(),
                                conn)
            with pytest.raises(ServerError) as info:
                await call(printer.bridge, "open_session",
                           bambu_args(host="192.168.1.21"))
            assert info.value.status_code == 429
            with pytest.raises(ServerError) as info:
                await call(printer.bridge, "open_session", bambu_args())
            assert info.value.status_code == 409
            sid = opened["session_id"]
            codes = []
            for _ in range(15):
                try:
                    await call(printer.bridge, "pause", {"session_id": sid},
                               conn)
                    codes.append(200)
                except ServerError as exc:
                    codes.append(exc.status_code)
            assert codes[:10] == [200] * 10 and 429 in codes[10:]
    asyncio.run(run())


def test_rate_limit_refills() -> None:
    now = [0.0]
    limit = RateLimit(2, 1.0, clock=lambda: now[0])
    limit.take("x")
    limit.take("x")
    with pytest.raises(BridgeError):
        limit.take("x")
    now[0] = 1.0
    limit.take("x")


def test_upload_size_and_names() -> None:
    for bad in ("../x.3mf", "a/b.3mf", "x.exe", ".3mf", "a\r\n.3mf", None):
        with pytest.raises(BridgeError):
            check_filename(bad, (".3mf",))
    assert check_filename("Benchy (v2).3mf", (".3mf",))


def test_never_mistaken_for_this_printers_klipper() -> None:
    """Its own namespace; refuses this printer's own address; every answer
    says bridged."""
    component = bridge()
    assert all(p.startswith("/server/muon_bridge/")
               for p in component.server.handlers)
    with pytest.raises(BridgeError):
        parse_target("192.168.1.10", component._own_addresses())
    session = Session("mb-x", "bambu", parse_target(BAMBU_IP), SERIAL, "p",
                      Connection())
    described = session.describe()
    assert described["bridged"] is True and described["kind"] == "bambu"
    assert not {"klippy", "printer", "objects"} & set(described)
