# Moonraker component — muon_link.py
#
# ADR 0018, route 3 of LINK-1: a client on the printer's own network may START
# an account link and read how it stands.
#
# Enable it in moonraker.conf:
#     [muon_link]
#     admin_address: 127.0.0.1:7131
#
# WHAT A LAN CLIENT CAN DO HERE
#
#   GET  /server/muon/link          where the link ceremony stands
#   POST /server/muon/link/start    ask muon-link for a link code
#   POST /server/muon/link/cancel   stop waiting
#
# That is the whole surface. It is what lets Fluidd on the same network show
# "link this printer" and fill the code in by itself: it starts the ceremony,
# reads the code back, and hands it to the account console.
#
# WHAT IT CAN NEVER DO
#
# Confirm. LINK-3's confirmation of the account happens at the panel, through
# muon-link's loopback admin endpoint, and there is no route here that reaches
# `/link/confirm` or `/link/unlink`. Starting a link grants nothing: a code is
# useless until the owner, standing at the printer, accepts the account the
# console names. A LAN caller at Level 0 already runs the printer outright, so
# letting it ask for a code adds no authority.
#
# The routes are not on the SEC-2 floor, and muon-link's gateway policy gives
# them to Owner only, so a remote grant cannot start a link either.

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING, Any, Dict, Tuple

if TYPE_CHECKING:
    from ..common import WebRequest
    from ..confighelper import ConfigHelper

# The only admin routes this component forwards to. Checked, not derived, so a
# future route on the admin endpoint is never exposed by accident.
ALLOWED = {
    ("GET", "/link"),
    ("POST", "/link/start"),
    ("POST", "/link/cancel"),
}
TIMEOUT = 3.0
MAX_BODY = 16 * 1024


def parse_address(value: str) -> Tuple[str, int]:
    host, _, port = value.strip().rpartition(":")
    if host not in ("127.0.0.1", "localhost", "::1", "[::1]"):
        raise ValueError(f"muon-link's admin endpoint must be loopback, not {host!r}")
    return host.strip("[]"), int(port)


class MuonLink:
    def __init__(self, config: ConfigHelper) -> None:
        self.server = config.get_server()
        self.host, self.port = parse_address(
            config.get("admin_address", "127.0.0.1:7131"))
        self.server.register_endpoint(
            "/server/muon/link", ["GET"], self._status)
        self.server.register_endpoint(
            "/server/muon/link/start", ["POST"], self._start)
        self.server.register_endpoint(
            "/server/muon/link/cancel", ["POST"], self._cancel)

    async def _status(self, web_request: WebRequest) -> Dict[str, Any]:
        return await self.call("GET", "/link")

    async def _start(self, web_request: WebRequest) -> Dict[str, Any]:
        return await self.call("POST", "/link/start")

    async def _cancel(self, web_request: WebRequest) -> Dict[str, Any]:
        return await self.call("POST", "/link/cancel")

    async def call(self, method: str, path: str) -> Dict[str, Any]:
        if (method, path) not in ALLOWED:
            raise self.server.error(f"{method} {path} is not forwarded", 403)
        try:
            status, body = await asyncio.wait_for(
                self._exchange(method, path), TIMEOUT)
        except (OSError, asyncio.TimeoutError, ValueError) as e:
            logging.info(f"muon_link: muon-link did not answer: {e}")
            raise self.server.error("muon-link is not answering", 503)
        try:
            payload = json.loads(body or b"{}")
        except ValueError:
            raise self.server.error("muon-link sent an unreadable answer", 502)
        if status >= 400:
            raise self.server.error(
                str(payload.get("error", "muon-link refused")), status)
        return payload

    async def _exchange(self, method: str, path: str) -> Tuple[int, bytes]:
        reader, writer = await asyncio.open_connection(self.host, self.port)
        try:
            writer.write(
                f"{method} {path} HTTP/1.1\r\nHost: {self.host}\r\n"
                "Content-Length: 0\r\nConnection: close\r\n\r\n".encode())
            await writer.drain()
            head = await reader.readuntil(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            status = int(lines[0].split(" ")[1])
            length = 0
            for line in lines[1:]:
                name, _, value = line.partition(":")
                if name.strip().lower() == "content-length":
                    length = int(value.strip())
            if length > MAX_BODY:
                raise ValueError("an over-long answer")
            body = await reader.readexactly(length)
            return status, body
        finally:
            writer.close()


def load_component(config: ConfigHelper) -> MuonLink:
    return MuonLink(config)
