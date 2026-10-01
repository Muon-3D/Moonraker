"""SEC-8: the connection password the panel sets.

The property that matters is end to end, so these drive the real
`Authorization.authenticate_request` and `set_panel_login` on an instance built
without a server: with the password set, a LAN or hotspot browser must sign in,
the panel must not have to (MuonOS #87), and a paired client is unaffected. Then
`muon_protection` must let only the panel set or clear it.

Pure unit tests with stubs, in the shape of test_muon_protection.py, so they
need none of conftest's fixtures.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
from typing import Any, Dict, List, Optional, Tuple

import pytest
from tornado.web import HTTPError

from moonraker import muon_floor
from moonraker.common import RequestType, UserInfo, WebRequest
from moonraker.components import authorization as auth_mod
from moonraker.components import muon_protection
from moonraker.components.authorization import Authorization
from moonraker.components.muon_protection import MuonProtection
from moonraker.utils.exceptions import ServerError

LOOPBACK = "127.0.0.1"
MAPPED_LOOPBACK = "::ffff:127.0.0.1"
LAN = "192.168.1.50"
HOTSPOT = "10.42.0.23"
SENTINEL = "192.0.2.1"
LOGIN = muon_floor.PANEL_LOGIN_USER


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


class _Tx:
    def __init__(self, log: List[Tuple[str, Any]]) -> None:
        self.log = log

    async def __aenter__(self) -> "_Tx":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    async def execute(self, sql: str, params: Any = None) -> None:
        self.log.append((sql.split()[0], params))


class _Loop:
    def __init__(self) -> None:
        self.events: List[Tuple[str, Dict[str, Any]]] = []

    def delay_callback(self, _delay: float, _fn: Any, event: str, data: Any) -> None:
        self.events.append((event, data))


class _AuthServer:
    error = ServerError

    def __init__(self) -> None:
        self.loop = _Loop()

    def get_event_loop(self) -> _Loop:
        return self.loop

    def send_event(self, *_a: Any) -> None:
        pass


def _authorization(force_logins: bool = True) -> Authorization:
    """An Authorization holding what the M1 config gives it, no more."""
    auth = Authorization.__new__(Authorization)
    auth.server = _AuthServer()  # type: ignore[assignment]
    auth.force_logins = force_logins
    auth.enable_api_key = False
    auth.api_key = "k"
    auth.users = {auth_mod.API_USER: UserInfo(auth_mod.API_USER, "k")}
    auth.public_jwks = {}
    auth.trusted_users = {}
    auth.oneshot_tokens = {}
    auth.trusted_ips = []
    auth.trusted_ranges = [
        ipaddress.ip_network(n)
        for n in ("127.0.0.0/8", "::1/128", "10.0.0.0/8", "192.168.0.0/16")
    ]
    auth.trusted_domains = []
    auth.onlink_prefixes = None
    auth.sql_log = []  # type: ignore[attr-defined]
    auth.user_table = _Tx(auth.sql_log)  # type: ignore
    return auth


class _Request:
    def __init__(self, ip: str, headers: Optional[Dict[str, str]] = None) -> None:
        self.method = "GET"
        self.remote_ip = ip
        self.headers = headers or {}
        self.query_arguments: Dict[str, Any] = {}
        self.arguments: Dict[str, Any] = {}


def _authenticate(auth: Authorization, ip: str) -> Any:
    return _run(auth.authenticate_request(_Request(ip)))  # type: ignore[arg-type]


class TestLoginRequired:
    @pytest.mark.parametrize("ip", [LAN, HOTSPOT, SENTINEL, None])
    def test_a_network_caller_must_sign_in_once_a_login_exists(self, ip):
        addr = None if ip is None else ipaddress.ip_address(ip)
        assert muon_floor.login_required(True, 2, addr) is True

    @pytest.mark.parametrize("ip", [LOOPBACK, MAPPED_LOOPBACK, "::1"])
    def test_the_panel_never_has_to(self, ip):
        assert muon_floor.login_required(True, 2, ipaddress.ip_address(ip)) is False

    def test_the_api_key_user_alone_switches_nothing_on(self):
        assert muon_floor.login_required(True, 1, ipaddress.ip_address(LAN)) is False

    def test_without_force_logins_nobody_has_to(self):
        assert muon_floor.login_required(False, 2, ipaddress.ip_address(LAN)) is False


class TestAuthenticateRequest:
    def test_with_no_password_the_lan_is_trusted_as_today(self):
        auth = _authorization()
        assert _authenticate(auth, LAN).username == auth_mod.TRUSTED_USER

    def test_with_a_password_a_lan_or_hotspot_browser_gets_401(self):
        auth = _authorization()
        _run(auth.set_panel_login("correct horse"))
        for ip in (LAN, HOTSPOT):
            with pytest.raises(HTTPError) as excinfo:
                _authenticate(auth, ip)
            assert excinfo.value.status_code == 401

    def test_the_password_works_where_force_logins_is_off(self):
        auth = _authorization(force_logins=False)
        _run(auth.set_panel_login("correct horse"))
        with pytest.raises(HTTPError) as excinfo:
            _authenticate(auth, LAN)
        assert excinfo.value.status_code == 401
        assert _authenticate(auth, LOOPBACK).username == auth_mod.TRUSTED_USER

    def test_with_a_password_the_panel_is_still_trusted(self):
        """MuonOS #87: before this, the second user 401'd the panel on
        everything, and the panel has no way to sign in."""
        auth = _authorization()
        _run(auth.set_panel_login("correct horse"))
        for ip in (LOOPBACK, "::1"):
            assert _authenticate(auth, ip).username == auth_mod.TRUSTED_USER

    def test_a_paired_client_still_gets_in_with_its_gateway_token(self):
        auth = _authorization()
        _run(auth.set_panel_login("correct horse"))
        gateway_user = UserInfo("muon-link:ab", "", source="muon_gateway")
        hdl = type("_H", (), {"cancel": lambda self: None})()
        auth.oneshot_tokens["tok"] = (  # type: ignore[assignment]
            ipaddress.ip_address(SENTINEL), gateway_user, hdl)
        request = _Request(SENTINEL)
        request.arguments = {"token": [b"tok"]}
        assert _run(auth.authenticate_request(request)) is gateway_user  # type: ignore

    def test_clearing_the_password_reopens_the_lan(self):
        auth = _authorization()
        _run(auth.set_panel_login("correct horse"))
        _run(auth.set_panel_login(None))
        assert _authenticate(auth, LAN).username == auth_mod.TRUSTED_USER


class TestSetPanelLogin:
    @staticmethod
    def _hash(user: UserInfo, password: str) -> str:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(user.salt), auth_mod.HASH_ITER
        ).hex()

    def test_it_creates_the_one_login_fluidd_signs_in_with(self):
        auth = _authorization()
        _run(auth.set_panel_login("correct horse"))
        user = auth.users[LOGIN]
        assert user.source == "moonraker"
        assert user.password == self._hash(user, "correct horse")
        assert auth.panel_login_set() is True

    def test_a_new_password_logs_out_every_old_session(self):
        auth = _authorization()
        _run(auth.set_panel_login("correct horse"))
        auth.users[LOGIN].jwk_id = "old-key"
        auth.public_jwks["old-key"] = {}
        _run(auth.set_panel_login("battery staple"))
        user = auth.users[LOGIN]
        assert user.password == self._hash(user, "battery staple")
        assert user.jwk_id is None and "old-key" not in auth.public_jwks
        assert auth.server.loop.events[-1] == (  # type: ignore[attr-defined]
            "authorization:user_logged_out", {"username": LOGIN})

    def test_clearing_it_deletes_the_user_and_its_sessions(self):
        auth = _authorization()
        _run(auth.set_panel_login("correct horse"))
        auth.users[LOGIN].jwk_id = "key"
        auth.public_jwks["key"] = {}
        _run(auth.set_panel_login(None))
        assert LOGIN not in auth.users and auth.public_jwks == {}
        assert auth.panel_login_set() is False
        assert auth.server.loop.events[-1] == (  # type: ignore[attr-defined]
            "authorization:user_deleted", {"username": LOGIN})

    def test_clearing_when_there_is_none_does_nothing(self):
        auth = _authorization()
        _run(auth.set_panel_login(None))
        assert auth.sql_log == []  # type: ignore[attr-defined]


class TestTheNetworkCannotChangeIt:
    """SEC-6: the network routes that would reset or delete the login refuse
    it, or a LAN caller could take the password away."""

    def _web_request(self, user: UserInfo, args: Dict[str, Any]) -> WebRequest:
        transport = type("_T", (), {"transport_type": None})()
        return WebRequest(
            "/access/user", args, RequestType.POST, transport,  # type: ignore
            ipaddress.ip_address(LAN), user)

    def test_a_password_reset_is_refused(self):
        auth = _authorization()
        _run(auth.set_panel_login("correct horse"))
        request = self._web_request(
            auth.users[LOGIN],
            {"password": "correct horse", "new_password": "mine now"})
        with pytest.raises(ServerError) as excinfo:
            _run(auth._handle_password_reset(request))
        assert excinfo.value.status_code == 403

    def test_deleting_it_is_refused(self):
        auth = _authorization()
        _run(auth.set_panel_login("correct horse"))
        other = UserInfo("someone", "")
        with pytest.raises(ServerError) as excinfo:
            _run(auth._delete_jwt_user(self._web_request(other, {"username": LOGIN})))
        assert excinfo.value.status_code == 403
        assert LOGIN in auth.users


class TestIdentityAtLevelOne:
    WIFI = "/server/aux/wifi/connect"
    HTTP = type("_T", (), {"transport_type": type("_N", (), {"name": "HTTP"})()})()

    @pytest.fixture(autouse=True)
    def _protected(self):
        muon_floor.set_protection_level(muon_floor.LEVEL_PROTECTED)
        yield
        muon_floor.set_protection_level(muon_floor.LEVEL_OPEN)

    def test_a_browser_signed_in_with_the_password_has_an_identity(self):
        signed_in = UserInfo(LOGIN, "", source="moonraker")
        muon_floor.check_protection(
            self.WIFI, self.HTTP, ipaddress.ip_address(LAN), signed_in)

    @pytest.mark.parametrize("user", [
        UserInfo("_TRUSTED_USER_", ""),
        UserInfo(LOGIN, "", source="ldap"),
        UserInfo("someone", ""),
    ])
    def test_nothing_else_from_the_lan_does(self, user):
        with pytest.raises(ServerError) as excinfo:
            muon_floor.check_protection(
                self.WIFI, self.HTTP, ipaddress.ip_address(LAN), user)
        assert excinfo.value.status_code == 403


# --- muon_protection: who may set it -----------------------------------------


class _FakeAuth:
    def __init__(self) -> None:
        self.calls: List[Optional[str]] = []
        self.set = False

    def panel_login_set(self) -> bool:
        return self.set

    async def set_panel_login(self, password: Optional[str]) -> None:
        self.calls.append(password)
        self.set = password is not None


class _Namespace:
    def __init__(self) -> None:
        self.values: Dict[str, Any] = {}

    async def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    async def insert(self, key: str, value: Any) -> None:
        self.values[key] = value


class _Server:
    error = ServerError

    def __init__(self, auth: Optional[_FakeAuth]) -> None:
        self.auth = auth
        self.namespace = _Namespace()

    def lookup_component(self, name: str, default: Any = None) -> Any:
        if name == "database":
            return self
        if name == "authorization":
            return self.auth if self.auth is not None else default
        return default

    def register_local_namespace(self, *_a: Any, **_k: Any) -> _Namespace:
        return self.namespace

    def register_endpoint(self, *_a: Any) -> None:
        pass

    def register_notification(self, *_a: Any) -> None:
        pass

    def send_event(self, *_a: Any) -> None:
        pass


class _Config:
    def __init__(self, server: _Server) -> None:
        self.server = server

    def get_server(self) -> _Server:
        return self.server


@pytest.fixture(autouse=True)
def _level_is_reset_after_every_test():
    yield
    muon_floor.set_protection_level(muon_floor.LEVEL_OPEN)


def _protection(auth: Optional[_FakeAuth]) -> MuonProtection:
    component = MuonProtection(_Config(_Server(auth)))  # type: ignore[arg-type]
    _run(component.component_init())
    return component


def _post(component: MuonProtection, ip: str, args: Dict[str, Any],
          user: Any = None) -> Any:
    transport = type("_T", (), {"transport_type": type("_N", (), {"name": "HTTP"})()})()
    request = WebRequest(
        muon_protection.ENDPOINT, args, RequestType.POST, transport,  # type: ignore
        ipaddress.ip_address(ip), user or UserInfo("_TRUSTED_USER_", ""))
    return _run(component._handle(request))


class TestTheEndpoint:
    def test_the_panel_sets_and_clears_it(self):
        auth = _FakeAuth()
        component = _protection(auth)
        status = _post(component, LOOPBACK, {"password": "correct horse"})
        assert status["password_set"] is True
        assert status["login_user"] == LOGIN
        status = _post(component, LOOPBACK, {"password": ""})
        assert status["password_set"] is False
        assert auth.calls == ["correct horse", None]

    def test_setting_it_leaves_the_level_alone(self):
        component = _protection(_FakeAuth())
        _post(component, LOOPBACK, {"password": "correct horse"})
        assert muon_floor.protection_level() == muon_floor.LEVEL_OPEN

    @pytest.mark.parametrize("ip", [LAN, HOTSPOT])
    def test_a_network_caller_cannot(self, ip):
        auth = _FakeAuth()
        component = _protection(auth)
        with pytest.raises(ServerError) as excinfo:
            _post(component, ip, {"password": ""})
        assert excinfo.value.status_code == 403
        assert auth.calls == []

    def test_a_paired_client_cannot(self):
        auth = _FakeAuth()
        component = _protection(auth)
        with pytest.raises(ServerError) as excinfo:
            _post(component, SENTINEL, {"password": "x"},
                  user=UserInfo("muon-link:ab", "", source="muon_gateway"))
        assert excinfo.value.status_code == 403
        assert auth.calls == []

    def test_a_password_that_is_not_a_string_is_refused(self):
        auth = _FakeAuth()
        component = _protection(auth)
        with pytest.raises(ServerError) as excinfo:
            _post(component, LOOPBACK, {"password": 12345678})
        assert excinfo.value.status_code == 400
        assert auth.calls == []

    def test_without_authorization_there_is_nothing_to_set(self):
        component = _protection(None)
        status = _run(component._handle(WebRequest(
            muon_protection.ENDPOINT, {}, RequestType.GET,
            type("_T", (), {"transport_type": None})(),  # type: ignore
            ipaddress.ip_address(LOOPBACK), None)))
        assert status["password_set"] is None
        with pytest.raises(ServerError) as excinfo:
            _post(component, LOOPBACK, {"password": "correct horse"})
        assert excinfo.value.status_code == 400

def test_panel_password_requires_login_without_force_logins():
    auth = _authorization()
    auth.force_logins = False
    _run(auth.set_panel_login('correct horse'))
    with pytest.raises(HTTPError):
        _authenticate(auth, LAN)
    assert _authenticate(auth, LOOPBACK).username == auth_mod.TRUSTED_USER
