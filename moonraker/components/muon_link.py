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
# muon-link refuses `start` with 409 while an offer waits for the owner, once
# the printer is linked, and when no orchestrator is configured. For the first
# two, `start` answers with the current phase and 200 instead, so a browser
# that asks late sees the offer (or the link) rather than an error. The third
# stays a 409. Other components call `status()`, `start()` and `cancel()`.
#
# WHAT IT CAN NEVER DO
#
# Confirm. LINK-3's confirmation of the account happens at the panel, through
# muon-link's loopback admin endpoint, and there is no route here that reaches
# `/link/confirm` or `/link/unlink`. Starting a link grants nothing on its own:
# a code is useless until the owner, standing at the printer, accepts the
# account the console names.
#
# WHO MAY CALL IT
#
# At Level 0 (Open) a LAN or hotspot caller already runs the printer outright,
# so letting it ask for a code adds no authority. At Level 1 (Protected),
# `start` is one of muon_floor.PROTECTED_PREFIXES: muon_floor.check_protection
# refuses it to a LAN or hotspot browser before this component sees the
# request, and only the panel, an in-process call (muon_setup) and a paired
# client through the gateway keep it. Reading the link and cancelling stay open
# at both levels. muon-link's gateway policy gives these routes to Owner only,
# so a paired client below Owner cannot start a link either.
#
# The two writes, `start` and `cancel`, follow the setup spec's write hygiene
# (02 §3), with muon_setup's own checks (muon_setup/caller.py):
#
#   * over plain HTTP, `Content-Type: application/json`, or 415;
#   * `Host` must name this printer, or 403;
#   * `Origin`, when present, must name this printer or be exactly one of
#     Muon3D's own consoles (CONSOLE_ORIGINS), or 403;
#   * a websocket call has its upgrade request's `Host` checked.
#
# Without them a web page a LAN browser visits could start a link and read the
# code back through DNS rebinding, or decline the owner's pending offer with a
# plain cross-site form. An in-process call has no headers and passes. The
# console origins are this component's alone: muon_setup's writes accept only
# the printer's own names.
#
# `start` is rate limited too: at most five a minute from one caller address,
# and the sixth is a 429. In-process calls are not counted.

from __future__ import annotations

import asyncio
import collections
import json
import logging
import time
from typing import TYPE_CHECKING, Any, Callable, Deque, Dict, Tuple

from ..common import TransportType
from ..utils.exceptions import ServerError
from .muon_setup import caller

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
#: The phases a refused `start` answers with instead of its 409.
STANDING_PHASES = ("offer", "linked")
#: Origins besides the printer's own that may start and cancel a link: Muon3D's
#: first-party account console, which a browser on the LAN uses to fetch the
#: printer directly. Starting grants nothing until the owner accepts the account
#: at the panel (LINK-3). Matched exactly as a browser serialises an Origin:
#: https, this host, the default port. Every other site is still refused, which
#: is the DNS-rebinding and cross-site defence. muon_setup does not accept these.
#: Jack's decision, 2026-09-28.
CONSOLE_ORIGINS = frozenset({
    "https://app.muon3d.com",
    "https://control.muon3d.com",
})
#: At most START_LIMIT `start` calls per START_WINDOW seconds per caller address.
START_LIMIT = 5
START_WINDOW = 60.0


def parse_address(value: str) -> Tuple[str, int]:
    host, _, port = value.strip().rpartition(":")
    if host not in ("127.0.0.1", "localhost", "::1", "[::1]"):
        raise ValueError(f"muon-link's admin endpoint must be loopback, not {host!r}")
    return host.strip("[]"), int(port)


class MuonLink:
    def __init__(
        self,
        config: ConfigHelper,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.server = config.get_server()
        self.host, self.port = parse_address(
            config.get("admin_address", "127.0.0.1:7131"))
        self._clock = clock
        self._starts: Dict[str, Deque[float]] = {}
        self.server.register_endpoint(
            "/server/muon/link", ["GET"], self._status)
        self.server.register_endpoint(
            "/server/muon/link/start", ["POST"], self._start)
        self.server.register_endpoint(
            "/server/muon/link/cancel", ["POST"], self._cancel)

    # ------------------------------------------------------------------
    # HTTP and websocket handlers. The Level 1 check on `start` has already
    # run in muon_floor.check_protection by the time these are called.
    # ------------------------------------------------------------------

    async def _status(self, web_request: WebRequest) -> Dict[str, Any]:
        return await self.status()

    async def _start(self, web_request: WebRequest) -> Dict[str, Any]:
        self._check_write(web_request)
        self._count_start(web_request)
        return await self.start()

    async def _cancel(self, web_request: WebRequest) -> Dict[str, Any]:
        self._check_write(web_request)
        return await self.cancel()

    def _check_write(self, web_request: WebRequest) -> None:
        caller.check_hygiene(
            web_request, caller.printer_hosts(self.server), "muon_link",
            CONSOLE_ORIGINS)

    def _count_start(self, web_request: WebRequest) -> None:
        transport = web_request.get_subscribable()
        if getattr(transport, "transport_type", None) == TransportType.INTERNAL:
            return
        now = self._clock()
        for key in list(self._starts):
            recent = self._starts[key]
            while recent and now - recent[0] >= START_WINDOW:
                recent.popleft()
            if not recent:
                del self._starts[key]
        key = str(web_request.get_ip_address())
        recent = self._starts.setdefault(key, collections.deque())
        if len(recent) >= START_LIMIT:
            raise ServerError(
                "muon_link: too many link starts, try again in a minute", 429)
        recent.append(now)

    # ------------------------------------------------------------------
    # The Python API, for other components (muon_setup).
    # ------------------------------------------------------------------

    async def status(self) -> Dict[str, Any]:
        """Where the link ceremony stands: muon-link's `GET /link`."""
        return await self.call("GET", "/link")

    async def start(self) -> Dict[str, Any]:
        """Ask for a link code. A 409 while an offer waits, or once linked,
        answers with that phase instead."""
        try:
            return await self.call("POST", "/link/start")
        except ServerError as refused:
            if refused.status_code != 409:
                raise
            try:
                current = await self.status()
            except ServerError:
                raise refused
            if current.get("phase") in STANDING_PHASES:
                return current
            raise refused

    async def cancel(self) -> Dict[str, Any]:
        """Stop waiting: muon-link's `POST /link/cancel`."""
        return await self.call("POST", "/link/cancel")

    async def call(self, method: str, path: str) -> Dict[str, Any]:
        # muon_setup._linked looks for this method by name, so keep it.
        if (method, path) not in ALLOWED:
            raise ServerError(f"{method} {path} is not forwarded", 403)
        try:
            status, body = await asyncio.wait_for(
                self._exchange(method, path), TIMEOUT)
        except (OSError, asyncio.TimeoutError, ValueError) as e:
            logging.info(f"muon_link: muon-link did not answer: {e}")
            raise ServerError("muon-link is not answering", 503)
        try:
            payload = json.loads(body or b"{}")
        except ValueError:
            raise ServerError("muon-link sent an unreadable answer", 502)
        if not isinstance(payload, dict):
            raise ServerError("muon-link sent an answer that is not an object", 502)
        if status >= 400:
            raise ServerError(
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
