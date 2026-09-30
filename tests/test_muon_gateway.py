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
from moonraker.components.muon_gateway import (
    MuonGateway, parse_request, parse_token_request,
)

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

    async def test_a_bluetooth_request_gets_a_token_bound_to_192_0_2_2(
        self,
    ) -> None:
        component, server, path = await self._component(str(os.getuid()))
        answer = await self._ask(
            path, b'{"client":"ab12","transport":"bluetooth"}\n')
        self.assertEqual(answer, {"token": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"})
        ((ip, _user),) = server.authorization.issued
        self.assertEqual(ip, ipaddress.ip_address("192.0.2.2"))

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


# ---------------------------------------------------------------------------
# KAN-436, ADR 0032 D4: a token for a Bluetooth connection is bound to
# 192.0.2.2, and only when muon-link asks for one by name.
# ---------------------------------------------------------------------------

SENTINEL = ipaddress.ip_address("192.0.2.1")
BLUETOOTH = ipaddress.ip_address("192.0.2.2")


class ParseTokenRequestTests(unittest.TestCase):
    def test_no_transport_binds_to_the_sentinel_as_before(self) -> None:
        self.assertEqual(
            parse_token_request(b'{"client":"ab12"}'), ("ab12", SENTINEL))

    def test_bluetooth_binds_to_the_bluetooth_address(self) -> None:
        self.assertEqual(
            parse_token_request(b'{"client":"ab12","transport":"bluetooth"}'),
            ("ab12", BLUETOOTH))

    def test_an_unknown_transport_is_refused_not_defaulted(self) -> None:
        """A request that names a transport this component does not know must
        not get a token for one it does."""
        for bad in (
            b'{"client":"ab12","transport":"wifi"}',
            b'{"client":"ab12","transport":"Bluetooth"}',
            b'{"client":"ab12","transport":""}',
            b'{"client":"ab12","transport":null}',
            b'{"client":"ab12","transport":["bluetooth"]}',
        ):
            with self.assertRaises(ValueError, msg=bad) as info:
                parse_token_request(bad)
            self.assertEqual(str(info.exception), "unknown transport", msg=bad)

    def test_a_bad_client_is_refused_whatever_the_transport(self) -> None:
        with self.assertRaises(ValueError) as info:
            parse_token_request(b'{"client":"AB12","transport":"bluetooth"}')
        self.assertEqual(str(info.exception), "client must be lower-case hex")

    def test_the_longest_bluetooth_request_fits(self) -> None:
        line = json.dumps(
            {"client": "a" * 64, "transport": "bluetooth"},
            separators=(",", ":")).encode()
        self.assertLessEqual(len(line), muon_gateway.MAX_REQUEST)
        self.assertEqual(parse_token_request(line)[1], BLUETOOTH)


class _Writer:
    def __init__(self) -> None:
        self.data = b""
        self.closed = False

    def get_extra_info(self, name: str) -> Any:
        return object()

    def write(self, data: bytes) -> None:
        self.data += data

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class TokenHandlerTests(unittest.IsolatedAsyncioTestCase):
    """`_handle` without a Unix socket, so it runs on every platform: only
    the uid lookup is replaced. TokenSocketTests covers the socket on Linux."""

    async def _ask(self, line: bytes, uid: int = 0) -> Tuple[dict, _Server]:
        server = _Server()
        component = MuonGateway(_Config(server, {"socket_path": "/unused"}))
        original = muon_gateway.peer_uid
        muon_gateway.peer_uid = lambda sock: uid  # type: ignore[assignment]
        try:
            reader = asyncio.StreamReader()
            reader.feed_data(line)
            reader.feed_eof()
            writer = _Writer()
            await component._handle(reader, writer)  # type: ignore[arg-type]
        finally:
            muon_gateway.peer_uid = original  # type: ignore[assignment]
        self.assertTrue(writer.closed)
        return json.loads(writer.data), server

    async def test_a_bluetooth_request_gets_a_token_bound_to_192_0_2_2(self) -> None:
        answer, server = await self._ask(
            b'{"client":"ab12","transport":"bluetooth"}\n')
        self.assertEqual(answer, {"token": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"})
        ((ip, user),) = server.authorization.issued
        self.assertEqual(ip, BLUETOOTH)
        self.assertEqual(user.source, "muon_gateway")
        self.assertEqual(user.username, "muon-link:ab12")

    async def test_a_plain_request_still_gets_the_sentinel(self) -> None:
        answer, server = await self._ask(b'{"client":"ab12"}\n')
        self.assertIn("token", answer)
        ((ip, _user),) = server.authorization.issued
        self.assertEqual(ip, SENTINEL)

    async def test_an_unknown_transport_mints_nothing(self) -> None:
        answer, server = await self._ask(
            b'{"client":"ab12","transport":"wifi"}\n')
        self.assertEqual(answer, {"error": "malformed"})
        self.assertEqual(server.authorization.issued, [])

    async def test_another_uid_gets_no_bluetooth_token_either(self) -> None:
        answer, server = await self._ask(
            b'{"client":"ab12","transport":"bluetooth"}\n', uid=1000)
        self.assertEqual(answer, {"error": "refused"})
        self.assertEqual(server.authorization.issued, [])


class BluetoothSentinelTests(unittest.TestCase):
    def test_the_bluetooth_address_matches_adr_0032(self) -> None:
        # ADR 0032 D4 rule 3: muon-link stamps exactly this address on a
        # connection that started on its Bluetooth transport.
        self.assertEqual(str(muon_gateway.BLUETOOTH_SENTINEL), "192.0.2.2")
        self.assertNotEqual(muon_gateway.BLUETOOTH_SENTINEL, muon_gateway.SENTINEL)


if __name__ == "__main__":
    unittest.main()
