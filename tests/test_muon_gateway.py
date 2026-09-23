"""The GATE-2 token component: who gets a token, and what the token is."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, List, Tuple

from moonraker.components import muon_gateway
from moonraker.components.muon_gateway import MuonGateway, parse_request

UNIX = sys.platform != "win32" and hasattr(__import__("socket"), "SO_PEERCRED")


class _Authorization:
    def __init__(self) -> None:
        self.issued: List[Tuple[Any, Any]] = []

    def get_oneshot_token(self, ip_addr: Any, user: Any) -> str:
        self.issued.append((ip_addr, user))
        return "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


class _Server:
    error = RuntimeError

    def __init__(self) -> None:
        self.authorization = _Authorization()

    def lookup_component(self, name: str, default: Any = None) -> Any:
        return self.authorization if name == "authorization" else default


class _Config:
    error = RuntimeError

    def __init__(self, server: _Server, values: dict) -> None:
        self.server = server
        self.values = values

    def get_server(self) -> _Server:
        return self.server

    def get(self, name: str, default: Any = None) -> Any:
        return self.values.get(name, default)


class ParseRequestTests(unittest.TestCase):
    def test_a_hex_client_is_accepted(self) -> None:
        self.assertEqual(parse_request(b'{"client":"ab12"}'), "ab12")

    def test_anything_else_is_refused(self) -> None:
        for bad in (
            b'{"client":"AB12"}',
            b'{"client":"ab12&x"}',
            b'{"client":""}',
            b'{"client":1}',
            b"[]",
            b"not json",
            b'{"client":"' + b"a" * 300 + b'"}',
        ):
            with self.assertRaises(ValueError, msg=bad):
                parse_request(bad)


@unittest.skipUnless(UNIX, "needs Unix sockets and SO_PEERCRED")
class TokenSocketTests(unittest.IsolatedAsyncioTestCase):
    async def _component(self, uids: str) -> Tuple[MuonGateway, _Server, Path]:
        tmp = tempfile.mkdtemp()
        path = Path(tmp) / "gateway.sock"
        server = _Server()
        component = MuonGateway(
            _Config(server, {"socket_path": str(path), "allowed_uids": uids})
        )
        await component.component_init()
        self.addAsyncCleanup(component.close)
        return component, server, path

    async def _ask(self, path: Path, line: bytes) -> dict:
        reader, writer = await asyncio.open_unix_connection(str(path))
        writer.write(line)
        await writer.drain()
        answer = await reader.readline()
        writer.close()
        return json.loads(answer)

    async def test_an_allowed_uid_gets_a_token_bound_to_the_sentinel(self) -> None:
        component, server, path = await self._component(str(os.getuid()))
        answer = await self._ask(path, b'{"client":"ab12"}\n')
        self.assertEqual(answer, {"token": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"})
        ((ip, user),) = server.authorization.issued
        self.assertEqual(ip, ipaddress.ip_address("192.0.2.1"))
        self.assertEqual(user.username, "muon-link:ab12")
        # An ordinary network user: the floor still refuses it.
        self.assertEqual(user.groups, ["network"])

    async def test_any_other_uid_is_refused_and_nothing_is_minted(self) -> None:
        component, server, path = await self._component(str(os.getuid() + 1))
        answer = await self._ask(path, b'{"client":"ab12"}\n')
        self.assertEqual(answer, {"error": "refused"})
        self.assertEqual(server.authorization.issued, [])
        self.assertEqual(component.refused, 1)

    async def test_a_malformed_request_mints_nothing(self) -> None:
        component, server, path = await self._component(str(os.getuid()))
        answer = await self._ask(path, b'{"client":"AB&x"}\n')
        self.assertEqual(answer, {"error": "malformed"})
        self.assertEqual(server.authorization.issued, [])

    async def test_a_non_socket_at_the_path_is_never_removed(self) -> None:
        tmp = tempfile.mkdtemp()
        path = Path(tmp) / "gateway.sock"
        path.write_text("keep me")
        component = MuonGateway(
            _Config(_Server(), {"socket_path": str(path), "allowed_uids": "0"})
        )
        with self.assertRaises(RuntimeError):
            await component.component_init()
        self.assertEqual(path.read_text(), "keep me")


class SentinelTests(unittest.TestCase):
    def test_the_sentinel_matches_the_gateway(self) -> None:
        # muon-link's hygiene.rs stamps exactly this address (GATE-2(b)).
        self.assertEqual(str(muon_gateway.SENTINEL), "192.0.2.1")


if __name__ == "__main__":
    unittest.main()
