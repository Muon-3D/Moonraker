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
import json
import sqlite3
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

import pytest
from tornado.web import HTTPError

from moonraker import muon_floor
from moonraker.common import RequestType, UserInfo, WebRequest
from moonraker.components import authorization as auth_mod
from moonraker.components import muon_protection
from moonraker.components.database import SqliteProvider, SqlTableWrapper
from moonraker.components.authorization import Authorization
from moonraker.components.muon_protection import MuonProtection
from moonraker.components.websockets import WebsocketManager, WebSocket, BridgeSocket
from moonraker.components.klippy_connection import KlippyConnection
from moonraker import muon_access_policy
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

    async def rollback(self) -> None:
        pass


class _Loop:
    def __init__(self) -> None:
        self.events: List[Tuple[str, Dict[str, Any]]] = []

    def delay_callback(self, _delay: float, _fn: Any, event: str, data: Any) -> None:
        self.events.append((event, data))


class _AuthServer:
    error = ServerError

    def __init__(self) -> None:
        self.loop = _Loop()
        self.auth = None
        self.wsm = WebsocketManager.__new__(WebsocketManager)
        self.wsm.server = self
        self.wsm.clients = {}
        self.wsm.bridge_connections = {}
        self.kconn = KlippyConnection.__new__(KlippyConnection)
        self.kconn.subscriptions = {}

    def lookup_component(self, name, default=None):
        return {"authorization": self.auth, "websockets": self.wsm,
                "klippy_connection": self.kconn}.get(name, default)

    def get_event_loop(self) -> _Loop:
        return self.loop

    def send_event(self, *_a: Any) -> None:
        pass


def _authorization(force_logins: bool = True) -> Authorization:
    """An Authorization holding what the M1 config gives it, no more."""
    auth = Authorization.__new__(Authorization)
    auth._credential_lock = asyncio.Lock()
    auth.server = _AuthServer()  # type: ignore[assignment]
    auth.server.auth = auth
    auth.force_logins = force_logins
    auth.default_source = "moonraker"
    auth.issuer = "http://moonraker.test"
    auth.login_timeout = 90
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


class _FailingTx(_Tx):
    def __init__(self, log: List[Tuple[str, Any]], phase: str) -> None:
        super().__init__(log)
        self.phase = phase

    async def __aenter__(self) -> "_FailingTx":
        if self.phase == "begin":
            raise OSError("password storage unavailable")
        return self

    async def execute(self, sql: str, params: Any = None) -> None:
        if self.phase == "write":
            raise OSError("password storage unavailable")
        await super().execute(sql, params)

    async def __aexit__(self, *exc: Any) -> None:
        if self.phase == "commit":
            raise OSError("password storage unavailable")


class TestPasswordPersistence:
    @staticmethod
    def _original(operation: str) -> Authorization:
        auth = _authorization()
        if operation != "create":
            _run(auth.set_panel_login("original password"))
            auth.users[LOGIN].jwk_id = "old-key"
            auth.public_jwks["old-key"] = {}  # type: ignore[assignment]
        return auth

    @staticmethod
    def _assert_original(auth: Authorization, original: Any, keys: Any) -> None:
        assert auth.users.get(LOGIN) is original
        assert auth.public_jwks == keys
        assert auth.server.loop.events == []  # type: ignore[attr-defined]
        if original is None:
            assert _authenticate(auth, LAN).username == auth_mod.TRUSTED_USER
        else:
            with pytest.raises(HTTPError) as excinfo:
                _authenticate(auth, LAN)
            assert excinfo.value.status_code == 401

    @pytest.mark.parametrize("operation", ["create", "rekey", "clear"])
    @pytest.mark.parametrize("phase", ["begin", "write", "commit"])
    def test_storage_failure_preserves_credentials_and_sessions(self, operation, phase):
        auth = self._original(operation)
        original, keys = auth.users.get(LOGIN), dict(auth.public_jwks)
        auth.user_table = _FailingTx(auth.sql_log, phase)  # type: ignore
        password = None if operation == "clear" else "new password"
        with pytest.raises(OSError, match="password storage unavailable"):
            _run(auth.set_panel_login(password))
        self._assert_original(auth, original, keys)

    @pytest.mark.parametrize("operation", ["create", "rekey", "clear"])
    def test_failed_sqlite_commit_cannot_apply_on_a_later_write(
        self, operation, monkeypatch
    ):
        auth = self._original(operation)
        original, keys = auth.users.get(LOGIN), dict(auth.public_jwks)
        connection = sqlite3.connect(":memory:")
        monkeypatch.setitem(
            sqlite3.adapters, (list, sqlite3.PrepareProtocol), json.dumps
        )
        connection.execute("CREATE TABLE " + auth_mod.UserSqlDefinition.prototype)
        connection.execute("CREATE TABLE unrelated(value TEXT)")
        if original is not None:
            connection.execute(
                "INSERT INTO authorized_users VALUES(?,?,?,?,?,?,?,?)",
                original.as_tuple(),
            )
        connection.commit()
        before = connection.execute("SELECT * FROM authorized_users").fetchall()

        # Only the queue/thread boundary is synchronous. The table context,
        # SQL execution, commit and rollback use the actual production code.
        provider = SqliteProvider.__new__(SqliteProvider)

        async def dispatch(callback, *args):
            return callback(connection, *args)

        provider.execute_db_function = dispatch  # type: ignore[method-assign]
        auth.user_table = SqlTableWrapper(
            SimpleNamespace(db_provider=provider),  # type: ignore
            auth_mod.UserSqlDefinition(),
        )

        def deny_commit(action, argument, *_args):
            if action == sqlite3.SQLITE_TRANSACTION and argument == "COMMIT":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        try:
            connection.set_authorizer(deny_commit)
            password = None if operation == "clear" else "new password"
            with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
                _run(auth.set_panel_login(password))
            self._assert_original(auth, original, keys)
            connection.set_authorizer(None)
            connection.execute("INSERT INTO unrelated VALUES('later write')")
            connection.commit()
            actual = connection.execute("SELECT * FROM authorized_users").fetchall()
            assert actual == before
        finally:
            connection.close()

    @pytest.mark.parametrize("operation", ["login", "logout"])
    def test_session_during_rekey_cannot_restore_old_password(self, operation):
        auth = self._original("rekey")
        auth.default_source = "moonraker"
        auth.ldap = None
        auth.login_timeout = 90
        # Exercise login's normal first-session write against real SQLite.
        auth.users[LOGIN].jwk_id = None
        auth.public_jwks.clear()

        async def exercise():
            started, release = asyncio.Event(), asyncio.Event()
            connection = sqlite3.connect(":memory:")
            connection.execute("CREATE TABLE " + auth_mod.UserSqlDefinition.prototype)

            class PausedCommit:
                owner = None

                async def __aenter__(self):
                    if self.owner is None:
                        self.owner = asyncio.current_task()
                    return self

                async def execute(self, sql, params):
                    values = tuple(
                        json.dumps(v) if isinstance(v, list) else v for v in params
                    )
                    connection.execute(sql, values)

                async def __aexit__(self, *exc):
                    if asyncio.current_task() is self.owner:
                        started.set()
                        await release.wait()
                    connection.commit()

            auth.user_table = PausedCommit()  # type: ignore[assignment]
            changing = asyncio.create_task(auth.set_panel_login("new password"))
            await started.wait()
            request = WebRequest(
                "/access/login", {"username": LOGIN, "password": "original password"},
                RequestType.POST,
                type("_T", (), {"transport_type": None})(),  # type: ignore
                ipaddress.ip_address(LAN), None,
            )
            if operation == "logout":
                request = WebRequest(
                    "/access/logout", {}, RequestType.POST, request.transport,
                    ipaddress.ip_address(LAN), auth.users[LOGIN],
                )
            session = asyncio.create_task(
                auth._login_jwt_user(request) if operation == "login"
                else auth._handle_logout(request)
            )
            await asyncio.sleep(0)
            release.set()
            outcomes = await asyncio.gather(changing, session, return_exceptions=True)
            assert outcomes[0] is None
            if operation == "login":
                assert isinstance(outcomes[1], ServerError)
                assert "Invalid Password" in str(outcomes[1])
            else:
                assert outcomes[1] == {"username": LOGIN, "action": "user_logged_out"}
            stored = connection.execute(
                "SELECT password FROM authorized_users WHERE username = ?", (LOGIN,)
            ).fetchone()[0]
            connection.close()
            assert stored == auth.users[LOGIN].password
            assert stored == TestSetPanelLogin._hash(auth.users[LOGIN], "new password")

        _run(exercise())


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
        auth = _authorization()
        _run(auth.set_panel_login("correct horse"))
        signed_in = auth.users[LOGIN]
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

    async def get_batch(self, _namespace, keys):
        return {key: self.namespace.values[key] for key in keys
                if key in self.namespace.values}

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

class TestPanelCredentialBoundary:
    @staticmethod
    def _login_request(username=LOGIN, source="moonraker"):
        return WebRequest(
            "/access/user",
            {"username": username, "password": "correct horse", "source": source},
            RequestType.POST, SimpleNamespace(transport_type=None),
            ipaddress.ip_address(LAN), None)

    @pytest.mark.parametrize(
        "source,create", [("moonraker", True), ("ldap", True), ("ldap", False)])
    def test_normal_user_creation_cannot_claim_the_panel_name(self, source, create):
        auth = _authorization()

        class Ldap:
            async def authenticate_ldap_user(self, *_args):
                pass
        auth.ldap = Ldap()
        with pytest.raises(ServerError):
            _run(auth._login_jwt_user(
                self._login_request(source=source), create=create))
        assert LOGIN not in auth.users
        assert auth.sql_log == []

    def test_an_unmarked_admin_is_not_a_panel_identity(self):
        user = UserInfo(LOGIN, "", source="moonraker")
        assert not muon_floor.has_identity(None, ipaddress.ip_address(LAN), user)
        assert not muon_access_policy._is_password_user(user)
        auth = _authorization()
        auth.users[LOGIN] = user
        assert auth.panel_login_set()  # fail closed until a panel reset

    def test_preexisting_admin_jwt_cannot_supply_panel_provenance(self):
        auth = _authorization()
        auth.issuer = "http://moonraker.test"
        _run(auth.set_panel_login("correct horse"))
        token = _run(auth._login_jwt_user(self._login_request()))["token"]
        assert auth.decode_jwt(token) is auth.users[LOGIN]
        auth.users[LOGIN].groups = []
        with pytest.raises(ServerError):
            auth.decode_jwt(token)

    def test_an_unmarked_legacy_password_keeps_the_network_closed(self):
        auth = _authorization(force_logins=False)
        auth.users[LOGIN] = UserInfo(LOGIN, "old-password", source="moonraker")
        with pytest.raises(HTTPError):
            _authenticate(auth, LAN)
        assert _authenticate(auth, LOOPBACK).username == auth_mod.TRUSTED_USER

    @staticmethod
    def _socket(ip, user):
        sc = WebSocket.__new__(WebSocket)
        sc._ip_addr = ipaddress.ip_address(ip)
        sc._user_info = user
        sc._need_auth = False
        sc._uid = id(sc)
        sc.closed = []
        sc.close_socket = lambda code, reason: sc.closed.append((code, reason))
        return sc

    @staticmethod
    def _bridge(ip, user):
        sc = BridgeSocket.__new__(BridgeSocket)
        sc._ip_addr = ipaddress.ip_address(ip)
        sc.current_user = user
        sc.uid = id(sc)
        sc.klippy_write_buf = []
        sc.klippy_writer = None
        sc.closed = []
        sc.close_socket = lambda code, reason: sc.closed.append((code, reason))
        return sc

    def test_first_password_revokes_network_sockets_bridges_and_oneshots(self):
        auth = _authorization()
        trusted = UserInfo(auth_mod.TRUSTED_USER, "")
        gateway = UserInfo("muon-link:ab", "", source="muon_gateway")
        sockets = [self._socket(ip, user) for ip, user in
                   [(LAN, trusted), (HOTSPOT, trusted), (LOOPBACK, trusted),
                    (MAPPED_LOOPBACK, trusted), (SENTINEL, gateway)]]
        bridges = [self._bridge(ip, user) for ip, user in
                   [(LAN, trusted), (LOOPBACK, trusted), (SENTINEL, gateway)]]
        auth.server.wsm.clients = {id(sc): sc for sc in sockets}
        auth.server.kconn.subscriptions = {sc: {} for sc in sockets}
        auth.server.wsm.bridge_connections = {id(sc): sc for sc in bridges}
        cancelled = []
        for ip, user, token in [(LAN, trusted, "lan"), (LOOPBACK, trusted, "panel"),
                                (SENTINEL, gateway, "gateway")]:
            handle = SimpleNamespace(cancel=lambda token=token: cancelled.append(token))
            auth.oneshot_tokens[token] = (ipaddress.ip_address(ip), user, handle)
        _run(auth.set_panel_login("correct horse"))
        assert [sc.need_auth for sc in sockets] == [True, True, False, False, False]
        assert [bool(sc.closed) for sc in sockets] == [True, True, False, False, False]
        assert set(auth.server.kconn.subscriptions) == set(sockets[2:])
        assert [bool(sc.closed) for sc in bridges] == [True, False, False]
        assert set(auth.oneshot_tokens) == {"panel", "gateway"}
        assert cancelled == ["lan"]

    @pytest.mark.parametrize("password", ["new password", None])
    def test_rekey_or_clear_revokes_old_admin_oneshots_and_bridges(self, password):
        auth = _authorization()
        _run(auth.set_panel_login("correct horse"))
        user = auth.users[LOGIN]
        bridge = self._bridge(LAN, user)
        auth.server.wsm.bridge_connections = {id(bridge): bridge}
        cancelled = []
        auth.oneshot_tokens["old"] = (
            ipaddress.ip_address(LAN), user,
            SimpleNamespace(cancel=lambda: cancelled.append(True)))
        _run(auth.set_panel_login(password))
        assert bridge.closed
        assert auth.oneshot_tokens == {}
        assert cancelled == [True]

    def test_a_socket_prepared_before_the_password_cannot_register_after_it(self):
        auth = _authorization()
        trusted = UserInfo(auth_mod.TRUSTED_USER, "")
        socket = self._socket(LAN, trusted)
        bridge = self._bridge(LAN, trusted)
        _run(auth.set_panel_login("correct horse"))
        auth.server.wsm.add_client(socket)
        auth.server.wsm.add_bridge_connection(bridge)
        assert socket.need_auth
        assert bridge.closed

    def test_a_trusted_lookup_finishing_after_password_creation_is_refused(self):
        async def exercise():
            auth = _authorization()
            started, release = asyncio.Event(), asyncio.Event()

            async def lookup(_ip):
                started.set()
                await release.wait()
                return UserInfo(auth_mod.TRUSTED_USER, "")
            auth._check_trusted_connection = lookup
            authenticating = asyncio.create_task(
                auth.authenticate_request(_Request(LAN)))
            await started.wait()
            await auth.set_panel_login("correct horse")
            release.set()
            with pytest.raises(HTTPError):
                await authenticating
        _run(exercise())

class TestPanelApiKeyAndSetupRole:
    def test_stalled_ldap_cannot_delay_password_activation_or_create_a_late_user(
        self
    ):
        async def exercise():
            auth = _authorization(force_logins=False)
            entered, release = asyncio.Event(), asyncio.Event()

            class Ldap:
                async def authenticate_ldap_user(self, *_args):
                    entered.set()
                    await release.wait()
            auth.ldap = Ldap()
            request = TestPanelCredentialBoundary._login_request(
                username="late-friend", source="ldap")
            login = asyncio.create_task(auth._login_jwt_user(request))
            try:
                await entered.wait()
                await asyncio.wait_for(auth.set_panel_login("correct horse"), 1)
                release.set()
                with pytest.raises(ServerError):
                    await login
                assert "late-friend" not in auth.users
                assert auth.users[LOGIN].username == LOGIN
            finally:
                release.set()
                await asyncio.gather(login, return_exceptions=True)
        _run(exercise())

    @pytest.mark.parametrize("ip", [LAN, None])
    @pytest.mark.parametrize("operation", ["login", "refresh"])
    def test_http_associated_local_socket_cannot_replace_the_request_address(
        self, ip, operation
    ):
        auth = _authorization(force_logins=False)
        credentials = TestPanelCredentialBoundary._login_request(username="friend")
        login = _run(auth._login_jwt_user(credentials, create=True))
        _run(auth.set_panel_login("correct horse"))
        local = TestPanelCredentialBoundary._socket(LOOPBACK, None)
        args = (credentials.args if operation == "login" else
                {"refresh_token": login["refresh_token"]})
        request = WebRequest(
            "/access/" + operation, args, RequestType.POST, local,
            None if ip is None else ipaddress.ip_address(ip),
            http_headers={})
        with pytest.raises(ServerError):
            _run(auth._login_jwt_user(request) if operation == "login"
                 else auth._handle_refresh_jwt(request))
        assert local.user_info is None

    @pytest.mark.parametrize("source", ["moonraker", "ldap"])
    def test_existing_ordinary_credentials_cannot_bypass_the_panel_password(
        self, source
    ):
        auth = _authorization(force_logins=False)
        request = TestPanelCredentialBoundary._login_request(username="friend")
        if source == "ldap":
            class Ldap:
                async def authenticate_ldap_user(self, *_args):
                    pass
            auth.ldap = Ldap()
            request.args["source"] = source
        login = _run(auth._login_jwt_user(request, create=source == "moonraker"))
        user = auth.users["friend"]
        headers = {"Authorization": "Bearer " + login["token"]}
        assert _run(auth.authenticate_request(_Request(LAN, headers))) is user
        socket = TestPanelCredentialBoundary._socket(LAN, user)
        socket.server = auth.server
        auth.server.wsm.clients = {socket.uid: socket}
        _run(auth.set_panel_login("correct horse"))
        assert socket.closed
        for ip in (LAN, HOTSPOT):
            with pytest.raises(HTTPError):
                _run(auth.authenticate_request(_Request(ip, headers)))
        with pytest.raises(ServerError):
            socket.authenticate(token=login["token"])
        with pytest.raises(ServerError):
            _run(auth._login_jwt_user(request))
        with pytest.raises(ServerError):
            _run(auth._handle_refresh_jwt(WebRequest(
                "/access/refresh_jwt", {"refresh_token": login["refresh_token"]},
                RequestType.POST, SimpleNamespace(transport_type=None),
                ipaddress.ip_address(LAN))))
        assert _run(auth.authenticate_request(_Request(LOOPBACK, headers))) is user
        _run(auth.set_panel_login(None))
        assert _run(auth.authenticate_request(_Request(LAN, headers))) is user

    def test_stale_api_identity_cannot_mint_or_redeem_a_network_oneshot(self):
        auth = _authorization()
        user = auth.users[auth_mod.API_USER]
        addr = ipaddress.ip_address(LAN)
        _run(auth.set_panel_login("correct horse"))
        auth.server.loop.delay_callback = lambda *_args: SimpleNamespace(
            cancel=lambda: None)
        with pytest.raises(ServerError):
            auth.get_oneshot_token(addr, user)
        cancelled = []
        auth.oneshot_tokens["stale"] = (
            addr, user, SimpleNamespace(cancel=lambda: cancelled.append(True)))
        assert auth._check_oneshot_token("stale", addr) is None
        assert cancelled == [True]

    def test_password_preserves_explicit_unix_api_identification(self):
        from moonraker.components.extensions import UnixSocketClient
        auth = _authorization()
        auth.enable_api_key = True
        _run(auth.set_panel_login("correct horse"))
        client = UnixSocketClient.__new__(UnixSocketClient)
        client.server = auth.server
        client._user_info = None
        client._need_auth = False
        client.authenticate(api_key="k")
        assert client.user_info is auth.users[auth_mod.API_USER]
        assert client.ip_addr is None  # no change to floor authority

    def test_http_batch_rechecks_cached_api_identity_between_requests(self):
        from moonraker.common import APIDefinition, JsonRPC, TransportType
        from moonraker.components.application import RPCHandler

        async def exercise():
            auth = _authorization()
            auth.enable_api_key = True
            handler = RPCHandler.__new__(RPCHandler)
            handler.server = auth.server
            handler.request = _Request(LAN)
            handler.current_user = auth.users[auth_mod.API_USER]
            rpc = JsonRPC(SimpleNamespace(is_verbose_enabled=lambda: False))
            entered, release = asyncio.Event(), asyncio.Event()
            calls = []

            async def first(_request):
                entered.set()
                await release.wait()
                return "first"

            async def second(_request):
                calls.append("second")
                return "second"

            for name, callback in (("first", first), ("second", second)):
                definition = APIDefinition(
                    "/server/" + name, "/server/" + name, [name],
                    RequestType.GET, TransportType.HTTP, callback, True)
                rpc.register_method(name, RequestType.GET, definition)
            batch = json.dumps([
                {"jsonrpc": "2.0", "method": name, "id": index}
                for index, name in enumerate(("first", "second"))])
            pending = asyncio.create_task(rpc.dispatch(batch, handler))
            await entered.wait()
            await auth.set_panel_login("correct horse")
            release.set()
            responses = json.loads(await pending)
            assert responses[0]["result"] == "first"
            assert responses[1]["error"]["code"] == -32602
            assert calls == []
        _run(exercise())

    def test_enabling_password_rejects_network_api_headers_but_keeps_loopback(self):
        auth = _authorization()
        auth.enable_api_key = True
        headers = {"X-Api-Key": "k"}
        user = auth.users[auth_mod.API_USER]
        assert _run(auth.authenticate_request(_Request(LAN, headers))) is user
        _run(auth.set_panel_login("correct horse"))
        for ip in (LAN, HOTSPOT):
            with pytest.raises(HTTPError):
                _run(auth.authenticate_request(_Request(ip, headers)))
        for ip in (LOOPBACK, MAPPED_LOOPBACK):
            assert _run(auth.authenticate_request(_Request(ip, headers))) is user

    def test_api_key_connections_and_tokens_are_revoked_after_first_password(self):
        auth = _authorization()
        auth.enable_api_key = True
        user = auth.users[auth_mod.API_USER]
        socket = TestPanelCredentialBoundary._socket(LAN, user)
        bridge = TestPanelCredentialBoundary._bridge(HOTSPOT, user)
        local = TestPanelCredentialBoundary._socket(LOOPBACK, user)
        auth.server.wsm.clients = {id(sc): sc for sc in (socket, local)}
        auth.server.wsm.bridge_connections = {id(bridge): bridge}
        cancelled = []
        auth.oneshot_tokens["api"] = (
            ipaddress.ip_address(LAN), user,
            SimpleNamespace(cancel=lambda: cancelled.append(True)))
        _run(auth.set_panel_login("correct horse"))
        assert socket.closed and bridge.closed
        assert not local.closed
        assert auth.oneshot_tokens == {} and cancelled == [True]

    def test_socket_cannot_reauthenticate_with_the_api_key_after_password(self):
        auth = _authorization()
        auth.enable_api_key = True
        _run(auth.set_panel_login("correct horse"))
        socket = TestPanelCredentialBoundary._socket(LAN, None)
        socket.server = auth.server
        socket._need_auth = True
        with pytest.raises(ServerError):
            socket.authenticate(api_key="k")
        local = TestPanelCredentialBoundary._socket(LOOPBACK, None)
        local.server = auth.server
        local.authenticate(api_key="k")
        assert local.user_info is auth.users[auth_mod.API_USER]

    def test_password_user_remains_a_lan_setup_caller(self):
        from moonraker.components.muon_setup import caller
        auth = _authorization()
        _run(auth.set_panel_login("correct horse"))
        request = WebRequest(
            "/server/muon/setup", {}, RequestType.GET,
            SimpleNamespace(transport_type=None), ipaddress.ip_address(LAN),
            auth.users[LOGIN])
        assert caller.caller_kind(request) == caller.LAN
        caller.require(caller.caller_kind(request), caller.READ_STATE)
