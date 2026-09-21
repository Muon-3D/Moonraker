from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from typing import Any, Optional

from tornado.httputil import HTTPHeaders
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application, HTTPError

from moonraker.components.application import (
    AuthorizedFileHandler,
    AuthorizedRequestHandler,
)
from moonraker.components.websockets import BridgeSocket, WebSocket
from moonraker.utils.real_ip import validate_real_ip_header


class _Authorization:
    def __init__(self) -> None:
        self.authentication_count = 0

    async def check_cors(self, origin: Optional[str]) -> bool:
        return False

    async def authenticate_request(self, request: Any, auth_required: bool = True):
        self.authentication_count += 1
        return None


class _Server:
    def __init__(self) -> None:
        self.authorization = _Authorization()

    def lookup_component(self, name: str, default: Any = None) -> Any:
        if name == "authorization":
            return self.authorization
        return default


def _headers(*values: str) -> HTTPHeaders:
    headers = HTTPHeaders()
    for value in values:
        headers.add("X-Real-IP", value)
    return headers


class _UnreachableDependencies:
    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"prepare accessed {name} before validating headers")

    def __getitem__(self, name: str) -> Any:
        raise AssertionError(f"prepare accessed {name} before validating headers")


class RealIPHeaderPolicyTests(unittest.TestCase):
    def _assert_allowed(self, *values: str) -> None:
        self.assertIsNone(validate_real_ip_header(_headers(*values)))

    def _assert_denied(self, *values: str) -> None:
        with self.assertRaises(HTTPError) as raised:
            validate_real_ip_header(_headers(*values))
        self.assertEqual(raised.exception.status_code, 403)

    def test_absent_header_is_allowed(self) -> None:
        self._assert_allowed()

    def test_gateway_sentinel_ipv4_is_allowed(self) -> None:
        self._assert_allowed("192.0.2.1")

    def test_ordinary_ipv4_is_allowed(self) -> None:
        self._assert_allowed("198.51.100.12")

    def test_ordinary_ipv6_is_allowed(self) -> None:
        self._assert_allowed("2001:db8::12")

    def test_malformed_single_value_is_denied(self) -> None:
        self._assert_denied("not-an-ip")

    def test_duplicate_valid_values_are_denied(self) -> None:
        self._assert_denied("198.51.100.12", "203.0.113.8")

    def test_duplicate_value_with_garbage_is_denied(self) -> None:
        self._assert_denied("198.51.100.12", "garbage")

    def test_comma_joined_value_is_denied(self) -> None:
        self._assert_denied("198.51.100.12, 203.0.113.8")

    def test_ipv4_mapped_loopback_is_shape_allowed(self) -> None:
        self._assert_allowed("::ffff:127.0.0.1")

    def test_every_reader_entry_point_denies_before_auth_or_trust(self) -> None:
        handlers = (
            AuthorizedRequestHandler,
            AuthorizedFileHandler,
            WebSocket,
            BridgeSocket,
        )
        for handler_type in handlers:
            with self.subTest(handler=handler_type.__name__):
                unreachable = _UnreachableDependencies()
                handler = SimpleNamespace(
                    request=SimpleNamespace(headers=_headers("not-an-ip")),
                    server=unreachable,
                    settings=unreachable,
                )
                with self.assertRaises(HTTPError) as raised:
                    asyncio.run(handler_type.prepare(handler))
                self.assertEqual(raised.exception.status_code, 403)


class _ProbeHandler(AuthorizedRequestHandler):
    def get(self) -> None:
        self.write("authenticated")


class RealIPHeaderHTTPOrderingTests(AsyncHTTPTestCase):
    def get_app(self) -> Application:
        self.server_stub = _Server()
        return Application([(r"/", _ProbeHandler)], server=self.server_stub)

    def test_malformed_header_returns_403_before_authentication(self) -> None:
        response = self.fetch("/", headers=_headers("not-an-ip"))
        self.assertEqual(response.code, 403)
        self.assertEqual(self.server_stub.authorization.authentication_count, 0)


if __name__ == "__main__":
    unittest.main()
