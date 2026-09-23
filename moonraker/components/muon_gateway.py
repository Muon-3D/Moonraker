# Moonraker component — muon_gateway.py
#
# GATE-2 / ADR 0002 option E: authenticate muon-link's gateway to Moonraker.
#
# Enable it in moonraker.conf:
#     [muon_gateway]
#     socket_path: /run/muon-gateway/gateway.sock
#
# THE PROBLEM THIS SOLVES
#
# muon-link terminates a paired client's Iroh session and forwards each request
# to 127.0.0.1:7125 with exactly one `X-Real-IP: 192.0.2.1`. That sentinel is
# deliberately NOT in `trusted_clients` (GATE-2(g)), so on its own Moonraker
# answers 401 to every request a paired client sends. Measured on the bench M1
# on 2026-09-23. Something has to tell Moonraker that the gateway admitted the
# caller, without making the sentinel itself a credential.
#
# WHAT THIS DOES
#
# muon-link asks this component for one token per request, over a Unix socket,
# and appends it to the request as `?token=`. The token is Moonraker's own
# one-shot token (`Authorization.get_oneshot_token`): single use, five seconds,
# and bound to the sentinel address, so `_check_oneshot_token` rejects it from
# any other address. It is checked in `authenticate_request` before
# `force_logins` and before `trusted_clients`. No upstream file is edited.
#
# WHAT STOPS ANOTHER LOCAL PROCESS MINTING A TOKEN
#
# `SO_PEERCRED`. The kernel reports the connecting process's uid, and only the
# uids in `allowed_uids` (default: 0, which is how muon-link runs) get a token.
# Every other local user — Klipper, nginx, a Moonraker extension, a shell as
# `pi` — is refused. A process that is already root owns the machine and gains
# nothing from a token. The socket file's mode is NOT the control and is left
# world-connectable on purpose: muon-link runs with an empty capability set, so
# it cannot rely on root's usual permission bypass to reach a moonraker-owned
# socket.
#
# The token authenticates the GATEWAY, not a role. muon-link's GATE-3 policy has
# already decided what the paired client may do before it asks for a token, and
# the user this token carries is an ordinary network user: `muon_floor` still
# classifies the sentinel as a network caller and still refuses the floor.

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import socket
import stat
import struct
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Set

from ..common import UserInfo

if TYPE_CHECKING:
    from ..confighelper import ConfigHelper

#: The address muon-link stamps on every forwarded request (GATE-2(b)).
SENTINEL = ipaddress.ip_address("192.0.2.1")

#: The longest request line accepted. `{"client":"<64 hex>"}` is 77 bytes.
MAX_REQUEST = 256

#: How long a connected peer may take to send its request.
READ_TIMEOUT = 2.0

_CLIENT_RE = re.compile(r"^[0-9a-f]{1,64}$")


def peer_uid(sock: socket.socket) -> int:
    """The uid of the process on the other end of a Unix socket."""
    creds = sock.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
    )
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid


def parse_request(line: bytes) -> str:
    """The client fingerprint from one request line, or ValueError."""
    if len(line) > MAX_REQUEST:
        raise ValueError("request too long")
    request = json.loads(line.decode("utf-8"))
    if not isinstance(request, dict):
        raise ValueError("request is not an object")
    client = request.get("client")
    if not isinstance(client, str) or not _CLIENT_RE.match(client):
        raise ValueError("client must be lower-case hex")
    return client


class MuonGateway:
    def __init__(self, config: ConfigHelper) -> None:
        self.server = config.get_server()
        self.socket_path = Path(config.get("socket_path"))
        uids = config.get("allowed_uids", "0")
        self.allowed_uids: Set[int] = {
            int(part) for part in uids.replace(",", " ").split() if part
        }
        if not self.allowed_uids:
            raise config.error("[muon_gateway] allowed_uids must name at least one uid")
        self._unix_server: Optional[asyncio.AbstractServer] = None
        self.minted = 0
        self.refused = 0

    async def component_init(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists() or self.socket_path.is_symlink():
            # Only ever remove a stale socket, never whatever else is there.
            if not stat.S_ISSOCK(os.lstat(self.socket_path).st_mode):
                raise self.server.error(
                    f"[muon_gateway] {self.socket_path} exists and is not a socket"
                )
            self.socket_path.unlink()
        self._unix_server = await asyncio.start_unix_server(
            self._handle, path=str(self.socket_path)
        )
        os.chmod(self.socket_path, 0o666)
        logging.info(
            "muon_gateway: minting gateway tokens on %s for uid(s) %s",
            self.socket_path,
            sorted(self.allowed_uids),
        )

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            sock = writer.get_extra_info("socket")
            uid = peer_uid(sock)
            if uid not in self.allowed_uids:
                self.refused += 1
                logging.warning(
                    "muon_gateway: refused a token request from uid %d", uid
                )
                await self._reply(writer, {"error": "refused"})
                return
            line = await asyncio.wait_for(
                reader.readline(), timeout=READ_TIMEOUT
            )
            try:
                client = parse_request(line.rstrip(b"\n"))
            except (ValueError, UnicodeDecodeError) as err:
                self.refused += 1
                logging.info("muon_gateway: malformed token request: %s", err)
                await self._reply(writer, {"error": "malformed"})
                return
            auth = self.server.lookup_component("authorization")
            user = UserInfo(
                username=f"muon-link:{client[:16]}",
                password="",
                source="muon_gateway",
            )
            token = auth.get_oneshot_token(SENTINEL, user)
            self.minted += 1
            await self._reply(writer, {"token": token})
        except asyncio.TimeoutError:
            self.refused += 1
        except Exception:
            logging.exception("muon_gateway: token request failed")
        finally:
            writer.close()

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, body: Any) -> None:
        writer.write(json.dumps(body).encode("utf-8") + b"\n")
        await writer.drain()

    async def close(self) -> None:
        if self._unix_server is not None:
            self._unix_server.close()
            await self._unix_server.wait_closed()
            self._unix_server = None
        try:
            if stat.S_ISSOCK(os.lstat(self.socket_path).st_mode):
                self.socket_path.unlink()
        except FileNotFoundError:
            pass


def load_component(config: ConfigHelper) -> MuonGateway:
    return MuonGateway(config)
