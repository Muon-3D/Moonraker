"""SEC-8: the protection-level component -- who can change the level, and what
happens to it when the stored value is missing, wrong or unreadable.

Pure unit tests with a stub server and database, in the shape of
test_muon_gateway.py, so they need none of conftest's heavyweight fixtures.
The enforcement itself is `muon_floor.check_protection`, tested in
test_muon_floor.py; the last class here drives the two together, because the
property that matters is end to end: the panel sets Level 1 and a LAN browser
is refused.
"""
from __future__ import annotations

import asyncio
import ipaddress
from typing import Any, Dict, List, Optional, Tuple

import pytest

from moonraker import muon_floor
from moonraker.common import RequestType, UserInfo, WebRequest
from moonraker.components import muon_protection
from moonraker.components.muon_protection import MuonProtection
from moonraker.utils.exceptions import ServerError

LOOPBACK = ipaddress.ip_address("127.0.0.1")
LAN = ipaddress.ip_address("192.168.1.50")
HOTSPOT = ipaddress.ip_address("10.42.0.23")
SENTINEL = ipaddress.ip_address("192.0.2.1")

WIFI = "/server/aux/wifi/connect"
check_protection = muon_floor.check_protection

TRUSTED_USER = UserInfo("_TRUSTED_USER_", "")
GATEWAY_USER = UserInfo("muon-link:0123456789abcdef", "", source="muon_gateway")


class _Transport:
    def __init__(self, name: str) -> None:
        self.transport_type = type("_T", (), {"name": name})()


HTTP = _Transport("HTTP")
INTERNAL = _Transport("INTERNAL")


class _Namespace:
    def __init__(self) -> None:
        self.values: Dict[str, Any] = {}
        self.fail_get = False
        self.fail_insert = False
        self.inserts: List[Tuple[str, Any]] = []

    async def get(self, key: str, default: Any = None) -> Any:
        if self.fail_get:
            raise RuntimeError("database unreadable")
        return self.values.get(key, default)

    async def insert(self, key: str, value: Any) -> None:
        if self.fail_insert:
            raise RuntimeError("database read-only")
        self.inserts.append((key, value))
        self.values[key] = value


class _Database:
    def __init__(self) -> None:
        self.namespace = _Namespace()
        self.registered: List[Tuple[str, bool]] = []

    def register_local_namespace(
        self, namespace: str, forbidden: bool = False, parse_keys: bool = False
    ) -> _Namespace:
        self.registered.append((namespace, forbidden))
        return self.namespace


class _Server:
    error = ServerError

    def __init__(self) -> None:
        self.database = _Database()
        self.endpoints: List[Tuple[str, Any]] = []
        self.notifications: List[Tuple[str, Optional[str]]] = []
        self.events: List[Tuple[str, Tuple[Any, ...]]] = []

    def lookup_component(self, name: str, default: Any = None) -> Any:
        return self.database if name == "database" else default

    def register_endpoint(self, uri: str, request_types: Any, callback: Any) -> None:
        self.endpoints.append((uri, request_types))

    def register_notification(
        self, event: str, notify_name: Optional[str] = None
    ) -> None:
        self.notifications.append((event, notify_name))

    def send_event(self, event: str, *args: Any) -> None:
        self.events.append((event, args))


class _Config:
    def __init__(self, server: _Server) -> None:
        self.server = server

    def get_server(self) -> _Server:
        return self.server


@pytest.fixture(autouse=True)
def _level_is_reset_after_every_test():
    yield
    muon_floor.set_protection_level(muon_floor.LEVEL_OPEN)


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _component(stored: Any = None) -> Tuple[MuonProtection, _Server]:
    server = _Server()
    if stored is not None:
        server.database.namespace.values[muon_protection.LEVEL_KEY] = stored
    return MuonProtection(_Config(server)), server


def _request(
    request_type: RequestType,
    ip_addr: Any,
    user: Any = TRUSTED_USER,
    transport: Any = HTTP,
    args: Optional[Dict[str, Any]] = None,
) -> WebRequest:
    return WebRequest(
        muon_protection.ENDPOINT, args or {}, request_type, transport, ip_addr, user
    )


def _post(component: MuonProtection, ip_addr: Any, level: Any, **kw: Any) -> Any:
    return _run(
        component._handle(
            _request(RequestType.POST, ip_addr, args={"level": level}, **kw)
        )
    )


class TestLoading:
    def test_the_namespace_is_forbidden_to_clients(self):
        """If a client could write this namespace through /server/database, it
        could lower the level without going near the panel."""
        _component_, server = _component()
        assert server.database.registered == [(muon_protection.NAMESPACE, True)]

    def test_the_endpoint_and_notification_are_registered(self):
        _component_, server = _component()
        assert server.endpoints == [(muon_protection.ENDPOINT, ["GET", "POST"])]
        assert server.notifications == [
            (muon_protection.EVENT, muon_protection.NOTIFY_NAME)
        ]

    def test_the_level_is_protected_until_the_stored_value_is_read(self):
        """Between load and component_init the printer cannot say which level
        it is at, so it enforces the stricter one."""
        _component()
        assert muon_floor.protection_level() == muon_floor.LEVEL_PROTECTED

    def test_nothing_stored_means_the_shipped_default(self):
        """A new or factory-reset printer is Open (SEC-1)."""
        component, _server = _component()
        _run(component.component_init())
        assert muon_floor.protection_level() == muon_floor.LEVEL_OPEN

    @pytest.mark.parametrize(
        "stored", [muon_floor.LEVEL_OPEN, muon_floor.LEVEL_PROTECTED]
    )
    def test_a_stored_level_survives_a_restart(self, stored):
        component, _server = _component(stored)
        _run(component.component_init())
        assert muon_floor.protection_level() == stored

    @pytest.mark.parametrize("stored", [2, -1, "1", "open", True, 1.0, [], {}])
    def test_a_stored_value_that_is_not_a_level_fails_closed(self, stored):
        """Fail closed, because the panel is exempt and can always set it
        back; failing open would silently undo an owner's choice."""
        component, _server = _component(stored)
        _run(component.component_init())
        assert muon_floor.protection_level() == muon_floor.LEVEL_PROTECTED

    def test_an_unreadable_database_fails_closed(self):
        component, server = _component()
        server.database.namespace.fail_get = True
        _run(component.component_init())
        assert muon_floor.protection_level() == muon_floor.LEVEL_PROTECTED


class TestWhoMayChangeIt:
    def test_the_panel_can(self):
        component, server = _component()
        _run(component.component_init())
        result = _post(component, LOOPBACK, 1)
        assert result["level"] == muon_floor.LEVEL_PROTECTED
        assert muon_floor.protection_level() == muon_floor.LEVEL_PROTECTED
        assert server.database.namespace.values[muon_protection.LEVEL_KEY] == 1

    @pytest.mark.parametrize("ip_addr", [LAN, HOTSPOT, None])
    @pytest.mark.parametrize("level", [0, 1])
    def test_a_network_caller_cannot_move_it_either_way(self, ip_addr, level):
        """SEC-8: a network caller must not lower the level -- and must not
        raise it either. Nothing is stored, and the level does not move."""
        component, server = _component(1 - level)
        _run(component.component_init())
        with pytest.raises(ServerError) as excinfo:
            _post(component, ip_addr, level)
        assert excinfo.value.status_code == 403
        assert muon_floor.protection_level() == 1 - level
        assert server.database.namespace.inserts == []

    def test_a_paired_client_cannot_change_it(self):
        """SEC-5 keeps Owner at the panel. A paired client has an identity,
        which is enough to reach a protected surface, and not enough to
        change the level that protects it."""
        component, server = _component(1)
        _run(component.component_init())
        with pytest.raises(ServerError) as excinfo:
            _post(component, SENTINEL, 0, user=GATEWAY_USER)
        assert excinfo.value.status_code == 403
        assert muon_floor.protection_level() == muon_floor.LEVEL_PROTECTED
        assert server.database.namespace.inserts == []

    @pytest.mark.parametrize("level", [2, -1])
    def test_an_unknown_level_is_refused(self, level):
        component, server = _component()
        _run(component.component_init())
        with pytest.raises(ServerError) as excinfo:
            _post(component, LOOPBACK, level)
        assert excinfo.value.status_code == 400
        assert muon_floor.protection_level() == muon_floor.LEVEL_OPEN
        assert server.database.namespace.inserts == []

    def test_a_level_the_database_did_not_take_is_not_enforced(self):
        """It would last until the next restart and then silently revert, so
        the change is refused rather than half-made."""
        component, server = _component()
        _run(component.component_init())
        server.database.namespace.fail_insert = True
        with pytest.raises(RuntimeError):
            _post(component, LOOPBACK, 1)
        assert muon_floor.protection_level() == muon_floor.LEVEL_OPEN

    def test_a_change_is_announced_once(self):
        component, server = _component()
        _run(component.component_init())
        _post(component, LOOPBACK, 1)
        _post(component, LOOPBACK, 1)
        assert server.events == [
            (muon_protection.EVENT, ({"level": 1, "name": "protected"},))
        ]


class TestWhatAClientIsTold:
    def test_a_lan_browser_learns_the_level_and_why_it_is_refused(self):
        component, _server = _component(1)
        _run(component.component_init())
        status = _run(component._handle(_request(RequestType.GET, LAN)))
        assert status["level"] == 1
        assert status["name"] == "protected"
        assert status["caller_has_identity"] is False
        assert status["changeable_by_caller"] is False
        assert status["protected_surfaces"] == ["/server/aux", "/machine/update"]

    def test_the_panel_is_told_it_can_change_it(self):
        component, _server = _component()
        _run(component.component_init())
        status = _run(component._handle(_request(RequestType.GET, LOOPBACK)))
        assert status["caller_has_identity"] is True
        assert status["changeable_by_caller"] is True

    def test_a_paired_client_has_an_identity_and_cannot_change_it(self):
        component, _server = _component()
        _run(component.component_init())
        status = _run(
            component._handle(_request(RequestType.GET, SENTINEL, user=GATEWAY_USER))
        )
        assert status["caller_has_identity"] is True
        assert status["changeable_by_caller"] is False


class TestEndToEnd:
    def test_the_panel_protects_the_printer_and_a_lan_browser_is_refused(self):
        component, _server = _component()
        _run(component.component_init())
        # Level 0: Fluidd on the LAN joins a network.
        check_protection(WIFI, HTTP, LAN, TRUSTED_USER)

        _post(component, LOOPBACK, 1)
        with pytest.raises(ServerError) as excinfo:
            muon_floor.check_protection(
                "/server/aux/wifi/connect", HTTP, LAN, TRUSTED_USER
            )
        assert excinfo.value.status_code == 403
        # The panel and a paired client keep it.
        check_protection(WIFI, HTTP, LOOPBACK, TRUSTED_USER)
        check_protection(WIFI, HTTP, SENTINEL, GATEWAY_USER)

        _post(component, LOOPBACK, 0)
        check_protection(WIFI, HTTP, LAN, TRUSTED_USER)


class TestTheCheckIsWiredIn:
    """`check_protection` is only a check if every request reaches it. The one
    place every transport converges is `APIDefinition.request` (see
    muon_floor.py), so drive a request through it. Without this, deleting the
    call in common.py leaves every other test here green."""

    @staticmethod
    def _api(endpoint: str) -> Any:
        from moonraker.common import APIDefinition

        async def callback(web_request: WebRequest) -> Dict[str, Any]:
            return {"reached": web_request.get_endpoint()}

        return APIDefinition.create(endpoint, ["POST"], callback)

    def test_a_lan_browser_is_refused_through_the_request_path(self):
        muon_floor.set_protection_level(muon_floor.LEVEL_PROTECTED)
        api = self._api("/server/aux/wifi/connect")
        with pytest.raises(ServerError) as excinfo:
            api.request({}, RequestType.POST, HTTP, LAN, TRUSTED_USER)
        assert excinfo.value.status_code == 403

    def test_the_panel_and_a_paired_client_reach_the_handler(self):
        muon_floor.set_protection_level(muon_floor.LEVEL_PROTECTED)
        api = self._api("/server/aux/wifi/connect")
        for ip_addr, user in ((LOOPBACK, TRUSTED_USER), (SENTINEL, GATEWAY_USER)):
            result = _run(api.request({}, RequestType.POST, HTTP, ip_addr, user))
            assert result == {"reached": "/server/aux/wifi/connect"}

    def test_level_zero_passes_a_lan_browser_through(self):
        api = self._api("/server/aux/wifi/connect")
        result = _run(api.request({}, RequestType.POST, HTTP, LAN, TRUSTED_USER))
        assert result == {"reached": "/server/aux/wifi/connect"}
