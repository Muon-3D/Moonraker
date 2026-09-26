"""The account-link component: what the LAN can reach, and what it cannot."""
from __future__ import annotations

import asyncio
import json
import unittest
from typing import Any, Dict, List, Tuple

from moonraker.components.muon_link import ALLOWED, MuonLink, parse_address


class _Server:
    class error(Exception):
        def __init__(self, message: str, status: int = 400) -> None:
            super().__init__(message)
            self.status_code = status

    def __init__(self) -> None:
        self.endpoints: Dict[str, List[str]] = {}

    def register_endpoint(self, path: str, methods: List[str], handler: Any) -> None:
        self.endpoints[path] = methods


class _Config:
    def __init__(self, values: Dict[str, str]) -> None:
        self.values = values
        self.server = _Server()

    def get_server(self) -> _Server:
        return self.server

    def get(self, name: str, default: str) -> str:
        return self.values.get(name, default)


class _FakeAdmin:
    """A one-shot HTTP server standing in for muon-link's admin endpoint."""

    def __init__(self, status: int, body: Dict[str, Any]) -> None:
        self.status = status
        self.body = json.dumps(body).encode()
        self.seen: List[Tuple[str, str]] = []

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        method, path, _ = head.decode().split("\r\n")[0].split(" ")
        self.seen.append((method, path))
        writer.write(
            f"HTTP/1.1 {self.status} X\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(self.body)}\r\n\r\n".encode() + self.body)
        await writer.drain()
        writer.close()


class TestMuonLink(unittest.TestCase):
    def test_only_status_start_and_cancel_are_registered(self) -> None:
        link = MuonLink(_Config({}))
        self.assertEqual(
            sorted(link.server.endpoints),
            ["/server/muon/link", "/server/muon/link/cancel", "/server/muon/link/start"],
        )
        # LINK-3's confirmation and the unlink stay at the panel.
        self.assertNotIn(("POST", "/link/confirm"), ALLOWED)
        self.assertNotIn(("POST", "/link/unlink"), ALLOWED)

    def test_the_admin_address_must_be_loopback(self) -> None:
        self.assertEqual(parse_address("127.0.0.1:7131"), ("127.0.0.1", 7131))
        with self.assertRaises(ValueError):
            parse_address("192.168.1.5:7131")

    def test_a_route_outside_the_list_is_refused_without_a_connection(self) -> None:
        link = MuonLink(_Config({}))
        with self.assertRaises(_Server.error) as refused:
            asyncio.run(link.call("POST", "/link/confirm"))
        self.assertEqual(refused.exception.status_code, 403)

    def test_status_and_refusals_are_forwarded_with_their_status(self) -> None:
        async def run(status: int, body: Dict[str, Any]) -> Tuple[Any, _FakeAdmin]:
            admin = _FakeAdmin(status, body)
            server = await asyncio.start_server(admin.handle, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            link = MuonLink(_Config({"admin_address": f"127.0.0.1:{port}"}))
            try:
                return await link.call("POST", "/link/start"), admin
            except _Server.error as e:
                return e, admin
            finally:
                server.close()

        ok, admin = asyncio.run(run(200, {"phase": "connecting"}))
        self.assertEqual(ok, {"phase": "connecting"})
        self.assertEqual(admin.seen, [("POST", "/link/start")])

        refused, _ = asyncio.run(run(409, {"error": "this printer is already linked"}))
        self.assertIsInstance(refused, _Server.error)
        self.assertEqual(refused.status_code, 409)
        self.assertIn("already linked", str(refused))

    def test_a_silent_muon_link_is_a_503(self) -> None:
        link = MuonLink(_Config({"admin_address": "127.0.0.1:1"}))
        with self.assertRaises(_Server.error) as down:
            asyncio.run(link.call("GET", "/link"))
        self.assertEqual(down.exception.status_code, 503)


if __name__ == "__main__":
    unittest.main()
