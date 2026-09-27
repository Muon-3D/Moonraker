"""The account-link component: what the LAN can reach, and what it cannot."""
from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import unittest
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, Tuple

import pytest

from moonraker.components.muon_link import (
    ALLOWED,
    START_LIMIT,
    START_WINDOW,
    MuonLink,
    parse_address,
)
from moonraker.common import WebRequest
from moonraker.utils.exceptions import ServerError

from muon_setup_fakes import GOOD_HEADERS, request

Route = Tuple[str, str]
START = ("POST", "/link/start")
STATUS = ("GET", "/link")
CANCEL = ("POST", "/link/cancel")
START_EP = "/server/muon/link/start"
CANCEL_EP = "/server/muon/link/cancel"
#: One of the printer's own addresses, as the machine component reports it.
PRINTER_IP = "192.168.1.37"


class _Machine:
    def get_system_info(self) -> Dict[str, Any]:
        addresses = [{"family": "ipv4", "address": PRINTER_IP}]
        return {"network": {"wlan0": {"ip_addresses": addresses}}}


class _Server:
    def __init__(self) -> None:
        self.endpoints: Dict[str, List[str]] = {}
        self.handlers: Dict[str, Any] = {}
        self.components: Dict[str, Any] = {"machine": _Machine()}

    def register_endpoint(self, path: str, methods: List[str], handler: Any) -> None:
        self.endpoints[path] = methods
        self.handlers[path] = handler

    def lookup_component(self, name: str, default: Any = None) -> Any:
        return self.components.get(name, default)


class _Config:
    def __init__(self, values: Dict[str, str]) -> None:
        self.values = values
        self.server = _Server()

    def get_server(self) -> _Server:
        return self.server

    def get(self, name: str, default: str) -> str:
        return self.values.get(name, default)


class _FakeAdmin:
    """An HTTP server standing in for muon-link's admin endpoint.

    Answers each (method, path) from `routes`: a status and a body, which is
    sent as JSON unless it is already bytes. A route it was not given is a 404.
    """

    def __init__(self, routes: Dict[Route, Tuple[int, Any]]) -> None:
        self.routes = routes
        self.seen: List[Route] = []

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        method, path, _ = head.decode().split("\r\n")[0].split(" ")
        self.seen.append((method, path))
        status, body = self.routes.get((method, path), (404, {"error": "no"}))
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        writer.write(
            f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(raw)}\r\n\r\n".encode() + raw)
        await writer.drain()
        writer.close()


CONNECTING: Dict[Route, Tuple[int, Any]] = {
    START: (200, {"phase": "connecting"}),
    STATUS: (200, {"phase": "connecting"}),
    CANCEL: (200, {"phase": "idle"}),
}


@contextlib.asynccontextmanager
async def _linked_to(
    routes: Dict[Route, Tuple[int, Any]],
    clock: Optional[Callable[[], float]] = None,
) -> AsyncIterator[Tuple[MuonLink, _FakeAdmin]]:
    admin = _FakeAdmin(routes)
    server = await asyncio.start_server(admin.handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    config: Any = _Config({"admin_address": f"127.0.0.1:{port}"})
    link = MuonLink(config) if clock is None else MuonLink(config, clock)
    try:
        yield link, admin
    finally:
        server.close()


def _call(
    routes: Dict[Route, Tuple[int, Any]],
    use: Callable[[MuonLink], Any],
) -> Tuple[Any, _FakeAdmin]:
    """Run `use(link)` against a fake admin: its answer (or the ServerError it
    raised) and the admin, so a test can see what was forwarded."""
    async def go() -> Tuple[Any, _FakeAdmin]:
        async with _linked_to(routes) as (link, admin):
            try:
                return await use(link), admin
            except ServerError as e:
                return e, admin
    return asyncio.run(go())


def _handle(link: MuonLink, web: WebRequest) -> Any:
    return link.server.handlers[web.get_endpoint()](web)


class TestMuonLink(unittest.TestCase):
    def test_only_status_start_and_cancel_are_registered(self) -> None:
        link = MuonLink(_Config({}))  # type: ignore[arg-type]
        self.assertEqual(
            sorted(link.server.endpoints),
            ["/server/muon/link", CANCEL_EP, START_EP],
        )
        # LINK-3's confirmation and the unlink stay at the panel.
        self.assertNotIn(("POST", "/link/confirm"), ALLOWED)
        self.assertNotIn(("POST", "/link/unlink"), ALLOWED)

    def test_the_admin_address_must_be_loopback(self) -> None:
        self.assertEqual(parse_address("127.0.0.1:7131"), ("127.0.0.1", 7131))
        with self.assertRaises(ValueError):
            parse_address("192.168.1.5:7131")

    def test_a_route_outside_the_list_is_refused_without_a_connection(self) -> None:
        link = MuonLink(_Config({}))  # type: ignore[arg-type]
        with self.assertRaises(ServerError) as refused:
            asyncio.run(link.call("POST", "/link/confirm"))
        self.assertEqual(refused.exception.status_code, 403)

    def test_status_and_refusals_are_forwarded_with_their_status(self) -> None:
        ok, admin = _call(CONNECTING, lambda link: link.call(*START))
        self.assertEqual(ok, {"phase": "connecting"})
        self.assertEqual(admin.seen, [START])

        linked = {START: (409, {"error": "this printer is already linked"})}
        refused, _ = _call(linked, lambda link: link.call(*START))
        self.assertIsInstance(refused, ServerError)
        self.assertEqual(refused.status_code, 409)
        self.assertIn("already linked", str(refused))

    def test_a_silent_muon_link_is_a_503(self) -> None:
        link = MuonLink(_Config({"admin_address": "127.0.0.1:1"}))  # type: ignore
        with self.assertRaises(ServerError) as down:
            asyncio.run(link.call("GET", "/link"))
        self.assertEqual(down.exception.status_code, 503)


class TestThePythonMethods:
    """muon_setup and other components call these rather than the routes."""

    @pytest.mark.parametrize("name,route", [
        ("status", STATUS), ("start", START), ("cancel", CANCEL),
    ])
    def test_each_forwards_its_route(self, name: str, route: Route) -> None:
        answer, admin = _call(CONNECTING, lambda link: getattr(link, name)())
        assert answer == CONNECTING[route][1]
        assert admin.seen == [route]

    def test_call_is_kept_for_muon_setup(self) -> None:
        """muon_setup._linked checks `hasattr(link, "call")`."""
        answer, _ = _call(CONNECTING, lambda link: link.call(*STATUS))
        assert answer == {"phase": "connecting"}

    @pytest.mark.parametrize("body", [[1, 2], "linked", 3, None])
    def test_an_answer_that_is_not_an_object_is_a_502(self, body: Any) -> None:
        for status in (200, 409):
            answer, _ = _call({STATUS: (status, body)}, lambda link: link.status())
            assert isinstance(answer, ServerError)
            assert answer.status_code == 502

    def test_an_unreadable_answer_is_a_502(self) -> None:
        answer, _ = _call({STATUS: (200, b"<html>")}, lambda link: link.status())
        assert isinstance(answer, ServerError)
        assert answer.status_code == 502


class TestARefusedStart:
    """02 §9: muon-link answers `start` with 409 while an offer waits, once the
    printer is linked, and with no orchestrator configured. A browser that
    asks late should see where the ceremony stands, not an error."""

    @pytest.mark.parametrize("phase", ["offer", "linked"])
    def test_answers_with_the_phase_when_past_start(self, phase: str) -> None:
        current = {"phase": phase, "account": "Jack's workshop"}
        routes = {
            START: (409, {"error": "an offer is waiting"}),
            STATUS: (200, current),
        }
        answer, admin = _call(routes, lambda link: link.start())
        assert answer == current
        assert admin.seen == [START, STATUS]

    def test_the_route_answers_the_same_way(self) -> None:
        routes = {
            START: (409, {"error": "an offer is waiting"}),
            STATUS: (200, {"phase": "offer"}),
        }
        answer, _ = _call(
            routes, lambda link: _handle(link, request("lan", START_EP)))
        assert answer == {"phase": "offer"}

    @pytest.mark.parametrize("status_answer", [
        (200, {"phase": "idle"}),
        (200, {"phase": "code", "code": "ABCD-1234"}),
        (200, {}),
        (500, {"error": "muon-link is unwell"}),
    ])
    def test_otherwise_stays_the_409(self, status_answer: Tuple[int, Any]) -> None:
        routes = {
            START: (409, {"error": "no orchestrator is configured"}),
            STATUS: status_answer,
        }
        answer, admin = _call(routes, lambda link: link.start())
        assert isinstance(answer, ServerError)
        assert answer.status_code == 409
        assert "no orchestrator" in str(answer)
        assert admin.seen == [START, STATUS]

    def test_a_refusal_that_is_not_a_409_does_not_read_the_phase(self) -> None:
        routes = {START: (400, {"error": "bad"}), STATUS: (200, {"phase": "offer"})}
        answer, admin = _call(routes, lambda link: link.start())
        assert isinstance(answer, ServerError)
        assert answer.status_code == 400
        assert admin.seen == [START]


class TestWriteHygiene:
    """02 §3 on the two writes: a JSON content type over plain HTTP, and a Host
    (and Origin, when present) that names this printer. Checked before
    anything is forwarded."""

    @pytest.fixture(params=[START_EP, CANCEL_EP])
    def endpoint(self, request: Any) -> str:
        return request.param

    def _refused(self, web: WebRequest) -> Tuple[ServerError, _FakeAdmin]:
        answer, admin = _call(CONNECTING, lambda link: _handle(link, web))
        assert isinstance(answer, ServerError), answer
        assert admin.seen == [], "a refused write must not reach muon-link"
        assert str(answer).startswith("muon_link: ")
        return answer, admin

    def _allowed(self, web: WebRequest) -> None:
        answer, admin = _call(CONNECTING, lambda link: _handle(link, web))
        assert not isinstance(answer, ServerError), answer
        assert len(admin.seen) == 1

    @pytest.mark.parametrize("ctype", [
        None, "text/plain", "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=x",
    ])
    def test_a_write_without_a_json_content_type_is_a_415(
        self, endpoint: str, ctype: Optional[str]
    ) -> None:
        headers = {"Host": "10.42.0.1"}
        if ctype is not None:
            headers["Content-Type"] = ctype
        refused, _ = self._refused(request("lan", endpoint, headers=headers))
        assert refused.status_code == 415

    @pytest.mark.parametrize("host", ["evil.example", "nas.local", "10.0.0.9"])
    def test_a_foreign_host_is_a_403(self, endpoint: str, host: str) -> None:
        headers = {"Host": host, "Content-Type": "application/json"}
        refused, _ = self._refused(request("lan", endpoint, headers=headers))
        assert refused.status_code == 403
        assert "Host" in str(refused)

    @pytest.mark.parametrize("origin", ["http://evil.example", "null"])
    def test_a_foreign_origin_is_a_403(self, endpoint: str, origin: str) -> None:
        headers = dict(GOOD_HEADERS, Origin=origin)
        refused, _ = self._refused(request("lan", endpoint, headers=headers))
        assert refused.status_code == 403
        assert "Origin" in str(refused)

    @pytest.mark.parametrize("host,origin", [
        ("10.42.0.1", None),
        ("10.42.0.1:80", "http://10.42.0.1"),
        ("muon3d.local", "http://muon3d.local"),
        (f"{PRINTER_IP}:80", f"http://{PRINTER_IP}"),
    ])
    def test_the_printers_own_names_pass(
        self, endpoint: str, host: str, origin: Optional[str]
    ) -> None:
        headers = {"Host": host, "Content-Type": "application/json"}
        if origin is not None:
            headers["Origin"] = origin
        self._allowed(request("lan", endpoint, headers=headers))

    def test_the_hostname_passes(
        self, endpoint: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(socket, "gethostname", lambda: "Muon-walnut-8987")
        headers = {"Host": "muon-walnut-8987.local",
                   "Content-Type": "application/json"}
        self._allowed(request("lan", endpoint, headers=headers))

    def test_a_websocket_write_checks_the_upgrade_host(self, endpoint: str) -> None:
        bad = {"Host": "evil.example", "Origin": "http://evil.example"}
        refused, _ = self._refused(
            request("lan", endpoint, headers=bad, websocket=True))
        assert refused.status_code == 403
        self._allowed(request(
            "lan", endpoint, headers={"Host": "10.42.0.1"}, websocket=True))

    def test_an_internal_call_has_no_headers_and_passes(self, endpoint: str) -> None:
        self._allowed(request("internal", endpoint))

    def test_reading_the_link_is_not_a_write(self) -> None:
        answer, _ = _call(CONNECTING, lambda link: _handle(
            link, request("lan", "/server/muon/link", method="GET")))
        assert answer == {"phase": "connecting"}


class TestTheStartRateLimit:
    """At most START_LIMIT starts a minute from one caller address."""

    def test_the_sixth_start_in_a_minute_is_a_429(self) -> None:
        assert (START_LIMIT, START_WINDOW) == (5, 60.0)
        now = [1000.0]

        async def go() -> None:
            async with _linked_to(CONNECTING, lambda: now[0]) as (link, admin):
                for _ in range(START_LIMIT):
                    await _handle(link, request("lan", START_EP))
                with pytest.raises(ServerError) as info:
                    await _handle(link, request("lan", START_EP))
                assert info.value.status_code == 429
                assert admin.seen == [START] * START_LIMIT
                # Another caller has its own allowance.
                await _handle(link, request("hotspot", START_EP))
                # Still limited just inside the minute, clear after it.
                now[0] += START_WINDOW - 1
                with pytest.raises(ServerError):
                    await _handle(link, request("lan", START_EP))
                now[0] += 1
                await _handle(link, request("lan", START_EP))
        asyncio.run(go())

    def test_in_process_starts_are_not_limited(self) -> None:
        async def go() -> None:
            async with _linked_to(CONNECTING, lambda: 0.0) as (link, admin):
                for _ in range(START_LIMIT * 2):
                    await _handle(link, request("internal", START_EP))
                assert len(admin.seen) == START_LIMIT * 2
        asyncio.run(go())

    def test_cancel_is_not_limited(self) -> None:
        async def go() -> None:
            async with _linked_to(CONNECTING, lambda: 0.0) as (link, admin):
                for _ in range(START_LIMIT * 2):
                    await _handle(link, request("lan", CANCEL_EP))
                assert len(admin.seen) == START_LIMIT * 2
        asyncio.run(go())

    def test_a_start_refused_by_hygiene_is_not_counted(self) -> None:
        bad = {"Host": "evil.example", "Content-Type": "application/json"}

        async def go() -> None:
            async with _linked_to(CONNECTING, lambda: 0.0) as (link, admin):
                for _ in range(START_LIMIT):
                    with pytest.raises(ServerError):
                        await _handle(link, request("lan", START_EP, headers=bad))
                for _ in range(START_LIMIT):
                    await _handle(link, request("lan", START_EP))
                assert len(admin.seen) == START_LIMIT
        asyncio.run(go())


if __name__ == "__main__":
    unittest.main()
