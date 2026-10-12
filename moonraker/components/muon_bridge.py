# MUON, KAN-527 -- muon_bridge: drive another printer on this LAN, through
# this M1, from a browser that cannot reach it itself.
#
#   * Bambu Lab (LAN mode): MQTT over TLS on 8883, FTPS on 990 for uploads,
#     the A1/P1 camera on 6000 (muon_bridge_bambu.py).
#   * PrusaLink: /api/v1 with the Digest authentication done here, so the
#     browser never meets PrusaLink's missing CORS (muon_bridge_prusa.py).
#
# The rules:
#   * Off unless [muon_bridge] enabled: True. Off, it registers nothing.
#   * The owner's alone: the "bridge" row of muon_access_policy (admin, from
#     home, fixed). Checked by check_access for every transport and again
#     here; with no [muon_access] only the panel may use it.
#   * Targets are private LAN addresses (RFC 1918 or ULA), never this
#     printer, never a name.
#   * Credentials arrive in open_session's `credentials` field, live in RAM
#     (muon_bridge_common.Secret) and are overwritten on close_session, when
#     the websocket that opened the session goes, when the printer drops the
#     connection, and at shutdown. `credentials` and `access_code` are
#     redacted from every log (utils/redact.py); nothing here logs them.
#   * A few sessions at once; opening, commands, uploads and camera frames
#     are each rate limited.
#   * A bridged printer is never this M1's Klipper: its methods live only
#     under server.muon_bridge.*, its notifications are notify_muon_bridge_
#     status and go only to the websocket that opened the session, and every
#     answer says "bridged": true with the session, kind and address.

from __future__ import annotations

import asyncio
import base64
import binascii
import functools
import logging
import os
import secrets
import time
from typing import (
    TYPE_CHECKING, Any, Callable, Coroutine, Dict, List, Optional, Union
)

from .. import muon_access_policy as policy
from .. import muon_floor
from ..muon_bridge_bambu import BambuPrinter, check_serial
from ..muon_bridge_common import (
    BridgeError, Dialer, IPAddress, RateLimit, Secret, direct, optional_str,
    parse_target, take_secret
)
from ..muon_bridge_prusa import PrusaPrinter
from ..utils.exceptions import ServerError

if TYPE_CHECKING:
    from ..common import BaseRemoteConnection, WebRequest
    from ..confighelper import ConfigHelper

PREFIX = "/server/muon_bridge"
NOTIFICATION = "muon_bridge_status"
KINDS = ("bambu", "prusalink")
BAMBU_CA_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "assets", "muon_bridge_bambu_ca.pem")
#: A notification gathers what changed over this long before it is sent.
COALESCE = 0.5

Printer = Union[BambuPrinter, PrusaPrinter]


class Session:
    def __init__(self, session_id: str, kind: str, ip: IPAddress,
                 serial: Optional[str], principal: str,
                 connection: BaseRemoteConnection) -> None:
        self.id = session_id
        self.kind = kind
        self.ip = ip
        self.serial = serial
        self.principal = principal
        self.connection = connection
        self.printer: Optional[Printer] = None
        self.opened = time.time()
        self.connected = False
        self.commands = RateLimit(10, 1.0)
        self.uploads = RateLimit(2, 1 / 30)
        self.frames = RateLimit(4, 2.0)
        self.pending: Dict[str, Any] = {}
        self.flush: Optional[asyncio.TimerHandle] = None
        self.poller: Optional[asyncio.Task] = None
        self.closing = False

    def describe(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "bridged": True,
            "session_id": self.id,
            "kind": self.kind,
            "host": str(self.ip),
            "connected": self.connected,
            "opened": self.opened,
        }
        if self.serial is not None:
            out["serial"] = self.serial
        return out


Handler = Callable[..., Coroutine[Any, Any, Any]]


def _api(func: Handler) -> Handler:
    """A BridgeError reaches the caller as a ServerError with its status."""
    @functools.wraps(func)
    async def wrapper(self: MuonBridge, web_request: WebRequest) -> Any:
        try:
            return await func(self, web_request)
        except BridgeError as exc:
            raise ServerError(str(exc), exc.status_code) from None
    return wrapper


class MuonBridge:
    def __init__(self, config: ConfigHelper) -> None:
        self.server = config.get_server()
        self.enabled = config.getboolean("enabled", False)
        self.max_sessions = config.getint(
            "max_sessions", 2, minval=1, maxval=8)
        self.max_upload = config.getint(
            "max_upload_mb", 32, minval=1, maxval=36) * 1024 * 1024
        self.status_interval = config.getfloat(
            "status_interval", 5., minval=1., maxval=60.)
        self.prusa_storage = config.get("prusalink_storage", "usb")
        self.connect_timeout = 10.0
        self.ca_file = BAMBU_CA_FILE
        #: Where a target is dialled; tests point it at fake servers.
        self.dialer: Dialer = direct
        self.sessions: Dict[str, Session] = {}
        self.open_limit = RateLimit(4, 1 / 15)
        self._tasks: List[asyncio.Task] = []
        if not self.enabled:
            return
        routes = (
            ("open_session", "POST", self.open_session),
            ("status", "GET", self.status),
            ("upload", "POST", self.upload),
            ("start", "POST", self.start),
            ("pause", "POST", self.pause),
            ("resume", "POST", self.resume),
            ("stop", "POST", self.stop),
            ("close_session", "POST", self.close_session),
            ("camera", "GET", self.camera),
            ("prusalink", "POST", self.prusalink),
        )
        for name, verb, handler in routes:
            self.server.register_endpoint(f"{PREFIX}/{name}", [verb], handler)
        self.server.register_event_handler(
            "websockets:client_removed", self._client_removed)

    # -- who may ----------------------------------------------------------------

    def gate(self, web_request: WebRequest) -> str:
        """The caller's name, if muon_access says it is the owner (or the
        panel). check_access has decided this already for every transport;
        it is decided again here so that the bridge never depends on that."""
        transport = web_request.transport
        ip = web_request.get_ip_address()
        if muon_floor._is_internal(transport):
            return "internal"
        if muon_floor.local_address(ip):
            return "panel"
        state = policy.state()
        if state is None:
            raise BridgeError(
                "access-denied:bridge: muon_bridge is the owner's, and this "
                "printer has no [muon_access] to say who the owner is; only "
                "its panel may use it", 403)
        principal = policy.resolve_principal(
            transport, ip, web_request.get_current_user(), state.entry,
            state.home)
        decision = policy.decide_action(
            policy.ACTIONS["bridge"], principal, state)
        if not decision.allowed or principal is None:
            raise BridgeError(str(policy.refusal(decision)), 403)
        return f"{principal.kind}:{principal.name}"

    def _session(self, web_request: WebRequest) -> Session:
        principal = self.gate(web_request)
        session_id = web_request.get_args().get("session_id")
        session = self.sessions.get(session_id) if isinstance(
            session_id, str) else None
        if session is None or session.closing:
            raise BridgeError("no such muon_bridge session", 404)
        if session.principal != principal:
            raise BridgeError("this session belongs to someone else", 403)
        return session

    def _own_addresses(self) -> List[str]:
        machine = self.server.lookup_component("machine", None)
        if machine is None:
            return []
        try:
            network = machine.get_system_info().get("network", {})
        except Exception:
            return []
        return [
            addr.get("address", "") for intf in network.values()
            for addr in intf.get("ip_addresses", [])
        ]

    # -- sessions ---------------------------------------------------------------

    @_api
    async def open_session(self, web_request: WebRequest) -> Dict[str, Any]:
        principal = self.gate(web_request)
        args = web_request.get_args()
        # Out of the request's arguments first, whatever happens next.
        handed = args.pop("credentials", None)
        creds: Dict[str, Any] = handed if isinstance(handed, dict) else {}
        held: List[Secret] = []
        try:
            connection = web_request.get_client_connection()
            if connection is None:
                raise BridgeError(
                    "open a muon_bridge session over the websocket, so it "
                    "closes when the browser does", 400)
            kind = args.get("kind")
            if kind not in KINDS:
                raise BridgeError(f"'kind' must be one of {list(KINDS)}", 400)
            ip = parse_target(args.get("host"), self._own_addresses())
            serial = (check_serial(args.get("serial")) if kind == "bambu"
                      else None)
            if any(s.ip == ip for s in self.sessions.values()):
                raise BridgeError(
                    f"a muon_bridge session to {ip} is already open", 409)
            if len(self.sessions) >= self.max_sessions:
                raise BridgeError(
                    f"muon_bridge has its limit of {self.max_sessions} "
                    "sessions open", 429)
            if not isinstance(handed, dict):
                raise BridgeError("'credentials' is required", 400)
            self.open_limit.take("sessions opened")
            session = Session("mb-" + secrets.token_hex(16), kind, ip, serial,
                              principal, connection)
            printer: Printer
            if kind == "bambu":
                assert serial is not None
                code = take_secret(creds, "access_code", 32)
                held.append(code)
                printer = BambuPrinter(
                    ip, serial, code, self.ca_file,
                    functools.partial(self._changed, session),
                    functools.partial(self._dropped, session), self.dialer)
            else:
                if "username" not in creds:
                    creds["username"] = "maker"
                user = take_secret(creds, "username", 64)
                held.append(user)
                password = take_secret(creds, "password", 128)
                held.append(password)
                storage = optional_str(args.get("storage"), "storage", 16)
                printer = PrusaPrinter(
                    ip, user, password, storage or self.prusa_storage,
                    self.dialer)
            session.printer = printer
            self.sessions[session.id] = session
            try:
                await asyncio.wait_for(printer.open(), self.connect_timeout)
            except BaseException as exc:
                self.sessions.pop(session.id, None)
                await printer.close()
                if isinstance(exc, asyncio.TimeoutError):
                    raise BridgeError(f"{ip} did not answer in time", 504) \
                        from None
                raise
        except BaseException:
            for secret in held:
                secret.wipe()
            raise
        finally:
            creds.clear()
        session.connected = True
        if isinstance(printer, PrusaPrinter):
            session.poller = asyncio.get_running_loop().create_task(
                self._poll(session))
        logging.info(
            f"muon_bridge: {session.id} open to {kind} at {ip} for "
            f"{principal}")
        result = session.describe()
        result["status"] = printer.status()
        return result

    @_api
    async def close_session(self, web_request: WebRequest) -> Dict[str, Any]:
        session = self._session(web_request)
        await self._close(session, "closed")
        return {"bridged": True, "session_id": session.id, "closed": True}

    async def _close(self, session: Session, reason: str,
                     tell: bool = True) -> None:
        if session.closing:
            return
        session.closing = True
        session.connected = False
        self.sessions.pop(session.id, None)
        if session.flush is not None:
            session.flush.cancel()
        if session.poller is not None and \
                session.poller is not asyncio.current_task():
            session.poller.cancel()
        if session.printer is not None:
            try:
                await session.printer.close()
            except Exception:
                logging.exception(f"muon_bridge: closing {session.id}")
        logging.info(f"muon_bridge: {session.id} closed ({reason})")
        if tell:
            self._send(session, {"connected": False, "reason": reason})

    def _client_removed(self, connection: BaseRemoteConnection) -> None:
        for session in list(self.sessions.values()):
            if session.connection is connection:
                task = asyncio.get_running_loop().create_task(
                    self._close(session, "disconnected", tell=False))
                self._tasks.append(task)
                task.add_done_callback(self._tasks.remove)

    async def _dropped(self, session: Session, reason: str) -> None:
        await self._close(session, f"the printer went away: {reason}")

    # -- status -----------------------------------------------------------------

    def _send(self, session: Session, status: Dict[str, Any]) -> None:
        payload = session.describe()
        payload["status"] = status
        # Only to the websocket that opened the session. Not through
        # send_notification, which tells every other client, nor a
        # registered notification, which tells them all.
        try:
            session.connection.queue_message({
                "jsonrpc": "2.0", "method": f"notify_{NOTIFICATION}",
                "params": [payload]})
        except Exception:
            logging.exception(f"muon_bridge: notifying for {session.id}")

    def _changed(self, session: Session, changed: Dict[str, Any]) -> None:
        if session.closing:
            return
        session.pending.update(changed)
        if session.flush is None:
            session.flush = asyncio.get_running_loop().call_later(
                COALESCE, self._flush, session)

    def _flush(self, session: Session) -> None:
        session.flush = None
        pending, session.pending = session.pending, {}
        if pending and not session.closing:
            self._send(session, pending)

    async def _poll(self, session: Session) -> None:
        printer = session.printer
        assert isinstance(printer, PrusaPrinter)
        last = printer.status()
        failures = 0
        while not session.closing:
            await asyncio.sleep(self.status_interval)
            try:
                now = await printer.refresh()
            except BridgeError as exc:
                failures += 1
                if failures >= 3:
                    await self._close(
                        session, f"the printer went away: {exc}")
                    return
                continue
            failures = 0
            changed = {k: v for k, v in now.items() if last.get(k) != v}
            last = now
            if changed:
                self._changed(session, changed)

    @_api
    async def status(self, web_request: WebRequest) -> Dict[str, Any]:
        args = web_request.get_args()
        if args.get("session_id") is None:
            principal = self.gate(web_request)
            return {"bridged": True, "sessions": [
                s.describe() for s in self.sessions.values()
                if s.principal == principal]}
        session = self._session(web_request)
        assert session.printer is not None
        result = session.describe()
        result["status"] = session.printer.status()
        return result

    # -- commands ---------------------------------------------------------------

    async def _command(self, web_request: WebRequest, name: str
                       ) -> Dict[str, Any]:
        session = self._session(web_request)
        session.commands.take("commands")
        printer = session.printer
        assert printer is not None
        if name == "start":
            options = web_request.get_args().get("options") or {}
            if not isinstance(options, dict):
                raise BridgeError("'options' must be an object", 400)
            sent = await _maybe(printer.start(
                web_request.get_args().get("filename"), options))
        else:
            sent = await _maybe(getattr(printer, name)())
        result = session.describe()
        result["command"] = name
        if isinstance(sent, int):
            result["sequence_id"] = str(sent)
        return result

    @_api
    async def start(self, web_request: WebRequest) -> Dict[str, Any]:
        return await self._command(web_request, "start")

    @_api
    async def pause(self, web_request: WebRequest) -> Dict[str, Any]:
        return await self._command(web_request, "pause")

    @_api
    async def resume(self, web_request: WebRequest) -> Dict[str, Any]:
        return await self._command(web_request, "resume")

    @_api
    async def stop(self, web_request: WebRequest) -> Dict[str, Any]:
        return await self._command(web_request, "stop")

    @_api
    async def upload(self, web_request: WebRequest) -> Dict[str, Any]:
        session = self._session(web_request)
        args = web_request.get_args()
        filename = args.get("filename")
        encoded = args.get("data")
        if not isinstance(encoded, str):
            raise BridgeError("'data' must be the file, base64-encoded", 400)
        if len(encoded) > (self.max_upload * 4) // 3 + 4:
            raise BridgeError(
                f"the file is larger than {self.max_upload >> 20} MiB", 413)
        try:
            data = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise BridgeError("'data' is not valid base64", 400) from None
        session.uploads.take("uploads")
        assert session.printer is not None
        await session.printer.upload(filename, data)
        result = session.describe()
        result.update(filename=filename, size=len(data))
        return result

    @_api
    async def camera(self, web_request: WebRequest) -> Dict[str, Any]:
        session = self._session(web_request)
        if not isinstance(session.printer, BambuPrinter):
            raise BridgeError("only Bambu A1/P1 printers have a camera "
                              "stream here", 404)
        session.frames.take("camera frames")
        frame = await session.printer.snapshot()
        result = session.describe()
        result.update(content_type="image/jpeg",
                      data=base64.b64encode(frame).decode())
        return result

    @_api
    async def prusalink(self, web_request: WebRequest) -> Dict[str, Any]:
        """Any /api/v1 request to the session's PrusaLink printer."""
        session = self._session(web_request)
        if not isinstance(session.printer, PrusaPrinter):
            raise BridgeError("this is not a PrusaLink session", 400)
        session.commands.take("requests")
        args = web_request.get_args()
        method = optional_str(args.get("method", "GET"), "method", 8) or "GET"
        answer = await session.printer.proxy(
            method, args.get("path"), args.get("body"))
        result = session.describe()
        result["response"] = answer
        return result

    async def close(self) -> None:
        for session in list(self.sessions.values()):
            await self._close(session, "shutting down")


async def _maybe(value: Any) -> Any:
    if asyncio.iscoroutine(value):
        return await value
    return value


def load_component(config: ConfigHelper) -> MuonBridge:
    return MuonBridge(config)
