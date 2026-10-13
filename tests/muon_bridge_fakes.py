"""Fakes for muon_bridge: a certificate authority made with the openssl
command, and a Bambu printer's MQTT, FTPS and camera servers and a
PrusaLink's HTTP server, all on loopback. No real printer, no real secret."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import threading
from typing import Any, Dict, List, Optional, Tuple

from tornado.httpserver import HTTPServer
from tornado.web import Application, RequestHandler

from moonraker.common import BaseRemoteConnection
from moonraker.muon_bridge_mqtt import (
    CONNACK, CONNECT, DISCONNECT, PINGREQ, PINGRESP, PUBLISH, SUBACK,
    SUBSCRIBE, packet, read_packet
)

SERIAL = "01S00A123456789"
ACCESS_CODE = "c0dE5ecr"
PRUSA_USER = "maker"
PRUSA_PASSWORD = "pa55-w0rd-x"
JPEG = b"\xff\xd8\xff\xe0" + b"frame" * 20 + b"\xff\xd9"


def have_openssl() -> bool:
    return shutil.which("openssl") is not None


def _run(*args: str) -> None:
    subprocess.run(args, check=True, capture_output=True)


class Authority:
    """A CA and printer certificates (CN and SAN = serial), in `root`."""

    def __init__(self, root: str, name: str) -> None:
        self.root = root
        self.name = name
        self.ca = os.path.join(root, f"{name}-ca.pem")
        self.key = os.path.join(root, f"{name}-ca.key")
        _run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
             "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", self.key,
             "-out", self.ca, "-days", "2", "-subj", f"/CN={name} CA",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign")

    def issue(self, serial: str) -> Tuple[str, str]:
        base = os.path.join(self.root, f"{self.name}-{serial}")
        ext = base + ".ext"
        with open(ext, "w") as f:
            f.write(f"subjectAltName=DNS:{serial}\n")
        _run("openssl", "req", "-newkey", "ec", "-pkeyopt",
             "ec_paramgen_curve:prime256v1", "-nodes", "-keyout",
             base + ".key", "-out", base + ".csr", "-subj", f"/CN={serial}")
        _run("openssl", "x509", "-req", "-in", base + ".csr", "-CA", self.ca,
             "-CAkey", self.key, "-CAcreateserial", "-out", base + ".pem",
             "-days", "2", "-extfile", ext)
        return base + ".pem", base + ".key"

    def server_context(self, serial: str = SERIAL) -> ssl.SSLContext:
        cert, key = self.issue(serial)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        return context


# -- MQTT -----------------------------------------------------------------------


class FakeBroker:
    """A Bambu printer's MQTT server: checks bblp and the access code,
    answers pushall with a report, records every request."""

    def __init__(self, context: ssl.SSLContext,
                 access_code: str = ACCESS_CODE) -> None:
        self.context = context
        self.access_code = access_code
        self.connects: List[Dict[str, Any]] = []
        self.subscriptions: List[str] = []
        self.requests: List[Dict[str, Any]] = []
        self.disconnects = 0
        self.handshake_errors = 0
        self.writers: List[asyncio.StreamWriter] = []
        self.server: Optional[asyncio.AbstractServer] = None
        self.port = 0
        self.got_request = asyncio.Event()
        self.answer_pings = True

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._client, "127.0.0.1", 0, ssl=self.context)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        for writer in self.writers:
            writer.close()
        if self.server is not None:
            self.server.close()

    def report(self, fields: Dict[str, Any]) -> None:
        body = struct.pack("!H", len(self.topic)) + self.topic.encode()
        for writer in self.writers:
            writer.write(packet(PUBLISH, 0, body + json.dumps(
                {"print": fields}).encode()))

    topic = f"device/{SERIAL}/report"

    async def _client(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        try:
            kind, _, body = await read_packet(reader)
        except (OSError, asyncio.IncompleteReadError, ssl.SSLError):
            self.handshake_errors += 1
            return
        assert kind == CONNECT
        offset = 10
        fields = []
        for _ in range(3):
            (size,) = struct.unpack_from("!H", body, offset)
            fields.append(body[offset + 2:offset + 2 + size].decode())
            offset += 2 + size
        client_id, user, password = fields
        self.connects.append({"client_id": client_id, "user": user})
        if user != "bblp" or password != self.access_code:
            writer.write(packet(CONNACK, 0, b"\x00\x05"))
            writer.close()
            return
        writer.write(packet(CONNACK, 0, b"\x00\x00"))
        self.writers.append(writer)
        try:
            while True:
                kind, flags, body = await read_packet(reader)
                if kind == SUBSCRIBE:
                    (size,) = struct.unpack_from("!H", body, 2)
                    self.subscriptions.append(body[4:4 + size].decode())
                    writer.write(packet(SUBACK, 0, body[:2] + b"\x00"))
                elif kind == PUBLISH:
                    (size,) = struct.unpack_from("!H", body)
                    topic = body[2:2 + size].decode()
                    offset = 2 + size + (2 if flags & 6 else 0)
                    message = json.loads(body[offset:])
                    self.requests.append({"topic": topic, **message})
                    self.got_request.set()
                    inner = next(iter(message.values()))
                    if inner.get("command") == "pushall":
                        self.report({"gcode_state": "IDLE", "mc_percent": 0,
                                     "nozzle_temper": 24.5,
                                     "command": "push_status"})
                elif kind == PINGREQ:
                    if self.answer_pings:
                        writer.write(packet(PINGRESP, 0, b""))
                elif kind == DISCONNECT:
                    self.disconnects += 1
                    return
        except (OSError, asyncio.IncompleteReadError, ssl.SSLError):
            return


# -- FTPS -----------------------------------------------------------------------


class FakeFtps:
    """Implicit FTPS, one session at a time, in a thread. Records the files
    stored and whether each data channel resumed the control's session."""

    def __init__(self, context: ssl.SSLContext,
                 access_code: str = ACCESS_CODE) -> None:
        self.context = context
        self.access_code = access_code
        self.files: Dict[str, bytes] = {}
        self.reused: List[bool] = []
        self.logins: List[str] = []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.listener.close()

    def _serve(self) -> None:
        while True:
            try:
                raw, _ = self.listener.accept()
            except OSError:
                return
            try:
                self._session(raw)
            except (OSError, ssl.SSLError, ValueError):
                pass
            finally:
                raw.close()

    def _session(self, raw: socket.socket) -> None:
        conn = self.context.wrap_socket(raw, server_side=True)
        out = conn.makefile("rwb")

        def say(line: str) -> None:
            out.write(line.encode() + b"\r\n")
            out.flush()

        say("220 fake printer")
        data_listener: Optional[socket.socket] = None
        while True:
            line = out.readline().decode().strip()
            if not line:
                return
            verb, _, arg = line.partition(" ")
            verb = verb.upper()
            if verb == "USER":
                say("331 password")
            elif verb == "PASS":
                if arg != self.access_code:
                    say("530 login incorrect")
                    continue
                self.logins.append("bblp")
                say("230 in")
            elif verb in ("PBSZ", "PROT", "TYPE"):
                say("200 ok")
            elif verb == "PASV":
                data_listener = socket.socket()
                data_listener.bind(("127.0.0.1", 0))
                data_listener.listen(1)
                port = data_listener.getsockname()[1]
                # The address names a host the client must ignore.
                say(f"227 Entering Passive Mode (203,0,113,9,{port >> 8},"
                    f"{port & 255})")
            elif verb == "STOR" and data_listener is not None:
                say("150 go")
                raw_data, _ = data_listener.accept()
                data = self.context.wrap_socket(raw_data, server_side=True)
                self.reused.append(data.session_reused)
                chunks = []
                while True:
                    chunk = data.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                try:
                    data.unwrap()
                except (OSError, ssl.SSLError):
                    pass
                data.close()
                data_listener.close()
                data_listener = None
                self.files[arg] = b"".join(chunks)
                say("226 stored")
            elif verb == "QUIT":
                say("221 bye")
                return
            else:
                say("502 no")


# -- camera ---------------------------------------------------------------------


class FakeCamera:
    def __init__(self, context: ssl.SSLContext) -> None:
        self.context = context
        self.auth: List[Tuple[str, str]] = []
        self.port = 0
        self.server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._client, "127.0.0.1", 0, ssl=self.context)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()

    async def _client(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        try:
            auth = await reader.readexactly(80)
        except (OSError, asyncio.IncompleteReadError, ssl.SSLError):
            return
        self.auth.append((auth[16:48].rstrip(b"\0").decode(),
                          auth[48:80].rstrip(b"\0").decode()))
        writer.write(struct.pack("<IIII", len(JPEG), 0, 1, 0) + JPEG)
        await writer.drain()
        writer.close()


# -- PrusaLink ------------------------------------------------------------------


class PrusaState:
    def __init__(self, qop: bool, algorithm: Optional[str] = None) -> None:
        self.qop = qop
        self.algorithm = algorithm
        self.realm = "Printer API"
        #: A fresh nonce per challenge, as a server would, with the nonce
        #: counts seen under each.
        self.nonces: Dict[str, List[str]] = {}
        self.authorizations: List[str] = []
        self.files: Dict[str, bytes] = {}
        self.actions: List[str] = []
        self.seen_nc: List[Tuple[str, str]] = []
        self.unauthenticated = 0


def _hash(algorithm: Optional[str], data: str) -> str:
    fn = hashlib.sha256 if (algorithm or "MD5").startswith("SHA-256") \
        else hashlib.md5
    return fn(data.encode()).hexdigest()


class _Prusa(RequestHandler):
    def initialize(self, state: PrusaState) -> None:
        self.state = state

    def _challenge(self) -> None:
        s = self.state
        nonce = os.urandom(8).hex()
        s.nonces[nonce] = []
        header = f'Digest realm="{s.realm}", nonce="{nonce}"'
        if s.qop:
            header += ', qop="auth"'
        if s.algorithm:
            header += f", algorithm={s.algorithm}"
        self.set_status(401)
        self.set_header("WWW-Authenticate", header)
        self.finish({"error": "unauthorized"})

    def _authorized(self) -> bool:
        """Digest, checked independently of the bridge's code."""
        s = self.state
        header = self.request.headers.get("Authorization", "")
        if not header.startswith("Digest "):
            s.unauthenticated += 1
            return False
        s.authorizations.append(header)
        params: Dict[str, str] = {}
        for part in header[7:].split(", "):
            key, _, value = part.partition("=")
            params[key] = value.strip('"')
        if params.get("username") != PRUSA_USER or \
                params.get("nonce") not in s.nonces or \
                params.get("uri") != self.request.uri:
            return False
        ha1 = _hash(s.algorithm, f"{PRUSA_USER}:{s.realm}:{PRUSA_PASSWORD}")
        ha2 = _hash(s.algorithm, f"{self.request.method}:{self.request.uri}")
        if s.qop:
            nonce = params["nonce"]
            if params.get("qop") != "auth" or params["nc"] in s.nonces[nonce]:
                return False
            s.nonces[nonce].append(params["nc"])
            s.seen_nc.append((nonce, params["nc"]))
            want = _hash(s.algorithm, f"{ha1}:{nonce}:{params['nc']}:"
                         f"{params['cnonce']}:auth:{ha2}")
        else:
            want = _hash(s.algorithm, f"{ha1}:{params['nonce']}:{ha2}")
        return params.get("response") == want

    def prepare(self) -> None:
        if not self._authorized():
            self._challenge()

    def get(self, path: str) -> None:
        if path == "status":
            self.finish({"printer": {"state": "PRINTING", "temp_nozzle": 215.0,
                                     "temp_bed": 60.0, "serial": "SN-SECRET"},
                         "job": {"id": 7, "progress": 42}})
        elif path == "job":
            self.finish({"id": 7, "state": "PRINTING", "progress": 42})
        else:
            self.set_status(404)
            self.finish({"error": "nope"})

    def put(self, path: str) -> None:
        if path.startswith("files/"):
            self.state.files[path] = self.request.body
            self.set_status(201)
            self.finish()
            return
        self.state.actions.append(f"PUT {path}")
        self.set_status(204)
        self.finish()

    def post(self, path: str) -> None:
        self.state.actions.append(f"POST {path}")
        self.set_status(204)
        self.finish()

    def delete(self, path: str) -> None:
        self.state.actions.append(f"DELETE {path}")
        self.set_status(204)
        self.finish()


def start_prusa(state: PrusaState) -> Tuple[HTTPServer, int]:
    app = Application([(r"/api/v1/(.*)", _Prusa, {"state": state})])
    server = HTTPServer(app)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    sock.setblocking(False)
    server.add_sockets([sock])
    return server, sock.getsockname()[1]


# -- Moonraker ------------------------------------------------------------------


class Connection(BaseRemoteConnection):
    """A websocket: records what is queued to it."""

    def __init__(self, ip: Any = None, user: Any = None) -> None:
        self._uid = id(self)
        self._ip = ip
        self._user_info = user
        self.messages: List[Dict[str, Any]] = []
        self.is_closed = False

    @property
    def ip_addr(self) -> Any:
        return self._ip

    def queue_message(self, message: Any) -> None:
        self.messages.append(message)

    def screen_name(self) -> str:
        return "fake"


class Server:
    def __init__(self, own: str = "192.168.1.10") -> None:
        self.handlers: Dict[str, Tuple[List[str], Any]] = {}
        self.events: Dict[str, List[Any]] = {}
        self.notifications: List[str] = []
        self.own = own

    def register_endpoint(self, path: str, verbs: List[str], handler: Any
                          ) -> None:
        self.handlers[path] = (verbs, handler)

    def register_notification(self, name: str) -> None:
        self.notifications.append(name)

    def register_event_handler(self, event: str, callback: Any) -> None:
        self.events.setdefault(event, []).append(callback)

    def lookup_component(self, name: str, default: Any = None) -> Any:
        if name == "machine":
            own = self.own

            class Machine:
                def get_system_info(self) -> Dict[str, Any]:
                    return {"network": {"wlan0": {"ip_addresses": [
                        {"family": "ipv4", "address": own}]}}}
            return Machine()
        return default


class Config:
    def __init__(self, server: Server, **values: Any) -> None:
        self.server = server
        self.values = values

    def get_server(self) -> Server:
        return self.server

    def getboolean(self, name: str, default: bool) -> bool:
        return self.values.get(name, default)

    def getint(self, name: str, default: int, **_: Any) -> int:
        return self.values.get(name, default)

    def getfloat(self, name: str, default: float, **_: Any) -> float:
        return self.values.get(name, default)

    def get(self, name: str, default: Any) -> Any:
        return self.values.get(name, default)
