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
#
# THE PRINCIPAL (ACC-7, ACC-11; access-model section 5)
#
# muon-link may also say who the client is, for `muon_access`'s level table:
#
#     {"client": "<hex>", "principal": "<id>", "level": "member",
#      "role": "operator", "home": false}
#
# `level` is one of signed_out_guest, signed_in_guest, member or admin, and
# `role` is operator or viewer; the two come together or not at all.
# `principal` names the person or device (default: the client), and `home`
# says the session's path is on the printer's own network (default: false, so
# a home-only action is refused unless muon-link vouches for the path). The
# user the token carries holds them, and a request is decided on them. A
# request without them is the gateway as it was: muon-link's policy is the
# only limit, and `muon_access` treats it as admin with Operator.

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
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Optional, Set

from .. import muon_access_policy
from ..common import UserInfo

if TYPE_CHECKING:
    from ..confighelper import ConfigHelper

#: The address muon-link stamps on every forwarded request (GATE-2(b)).
SENTINEL = ipaddress.ip_address("192.0.2.1")

#: The longest request line accepted. The longest valid request -- a 64-hex
#: client, a 128-character principal, the longest level, a role and `home`,
#: written with json.dumps' default spacing -- is under 300 bytes; this
#: leaves room for a field or two more without accepting anything unbounded.
MAX_REQUEST = 512

#: How long a connected peer may take to send its request.
READ_TIMEOUT = 2.0

_CLIENT_RE = re.compile(r"^[0-9a-f]{1,64}$")
_PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9._:@+-]{1,128}$")


@dataclass
class GatewayUser(UserInfo):
    """The user a gateway token carries, with the principal muon-link named.
    None for the level and role is a muon-link that named none."""
    principal: str = ""
    access_level: Optional[str] = None
    access_role: Optional[str] = None
    access_home: bool = False


def peer_uid(sock: socket.socket) -> int:
    """The uid of the process on the other end of a Unix socket."""
    creds = sock.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
    )
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid


def _load_request(line: bytes) -> Dict[str, Any]:
    if len(line) > MAX_REQUEST:
        raise ValueError("request too long")
    request = json.loads(line.decode("utf-8"))
    if not isinstance(request, dict):
        raise ValueError("request is not an object")
    return request


def parse_request(line: bytes) -> str:
    """The client fingerprint from one request line, or ValueError."""
    client = _load_request(line).get("client")
    if not isinstance(client, str) or not _CLIENT_RE.match(client):
        raise ValueError("client must be lower-case hex")
    return client


def parse_principal(line: bytes) -> Dict[str, Any]:
    """The principal fields of one request line, checked, or ValueError.
    Empty when muon-link named no principal."""
    request = _load_request(line)
    level = request.get("level")
    role = request.get("role")
    principal = request.get("principal")
    home = request.get("home", False)
    if level is None and role is None:
        if principal is not None or "home" in request:
            raise ValueError("principal and home need a level and a role")
        return {}
    if level not in muon_access_policy.PRINCIPAL_LEVELS:
        raise ValueError(
            f"level must be one of {sorted(muon_access_policy.PRINCIPAL_LEVELS)}"
        )
    if role not in muon_access_policy.ROLES:
        raise ValueError(f"role must be one of {list(muon_access_policy.ROLES)}")
    if principal is not None and (
        not isinstance(principal, str) or not _PRINCIPAL_RE.match(principal)
    ):
        raise ValueError("principal must be 1-128 of [A-Za-z0-9._:@+-]")
    if not isinstance(home, bool):
        raise ValueError("home must be true or false")
    fields: Dict[str, Any] = {
        "access_level": level, "access_role": role, "access_home": home,
    }
    if principal is not None:
        fields["principal"] = principal
    return fields


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
                fields = parse_principal(line.rstrip(b"\n"))
            except (ValueError, UnicodeDecodeError) as err:
                self.refused += 1
                logging.info("muon_gateway: malformed token request: %s", err)
                await self._reply(writer, {"error": "malformed"})
                return
            auth = self.server.lookup_component("authorization")
            user = GatewayUser(
                username=f"muon-link:{client[:16]}",
                password="",
                source="muon_gateway",
                **fields,
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
