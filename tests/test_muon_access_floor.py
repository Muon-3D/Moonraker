"""The floor holds Moonraker's account administration (MuonOS #87, for the LAN).

The defect these pin: with the shipped M1 config, one unauthenticated
``POST /access/user`` from any device on the printer's LAN or hotspot created a
Moonraker user. The first human user arms ``force_logins``, whose gate in
``authenticate_request`` runs before the trusted-client check, so from then on
the panel -- which signs in by loopback address and nothing else -- got 401 on
everything, including every control that could undo it.

These drive the real ``Authorization`` component, built by its own
``__init__`` from the ``[authorization]`` section of the shipped
``core/M1/moonraker.core.conf.template``, and send each request through the
real ``APIDefinition.request`` -- the point every transport converges on, and
where the floor is checked. The server, the database and the event loop are
stubs; the authentication, the floor and the handlers are not.

Pure unit tests, so they need none of conftest's fixtures:
``pytest --noconftest tests/test_muon_access_floor.py``.
"""
from __future__ import annotations

import asyncio
import configparser
import ipaddress
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest
from tornado.web import HTTPError

from moonraker import muon_floor
from moonraker.common import APIDefinition, RequestType, TransportType
from moonraker.components import authorization as auth_mod
from moonraker.components.authorization import Authorization
from moonraker.utils.exceptions import ServerError

TEMPLATE = (
    Path(__file__).resolve().parents[1] / "core" / "M1" / "moonraker.core.conf.template"
)

LOOPBACK = "127.0.0.1"
LAN = "192.168.1.50"
HOTSPOT = "10.42.0.23"
LINK_LOCAL = "fe80::1c2d:3e4f"
ULA = "fd12:3456:789a::50"
NETWORK_CALLERS = [LAN, HOTSPOT, LINK_LOCAL, ULA]

FLOOR_REFUSAL = "is not available over the network"

# Written out rather than read from muon_floor, so that dropping an entry there
# fails here instead of quietly shrinking what is tested.
ACCOUNT_WRITES = [
    ("/access/user", "POST"),
    ("/access/user", "DELETE"),
    ("/access/user/password", "POST"),
    ("/access/api_key", "POST"),
]


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Stubs for what Authorization.__init__ reaches outside itself.
# ---------------------------------------------------------------------------


class _Table:
    """The user table. Records writes; Authorization keeps its users in memory."""

    def __init__(self) -> None:
        self.writes: List[Tuple[str, Any]] = []

    async def __aenter__(self) -> "_Table":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    async def execute(self, sql: str, params: Any = None) -> None:
        self.writes.append((sql.split()[0], params))

    async def executemany(self, sql: str, params: Any = None) -> None:
        self.writes.append((sql.split()[0], params))

    async def rollback(self) -> None:
        pass


class _Database:
    def __init__(self) -> None:
        self.table = _Table()

    def register_table(self, _definition: Any) -> _Table:
        return self.table


class _Websockets:
    def register_notification(self, *_a: Any, **_kw: Any) -> None:
        pass


class _Timer:
    def start(self, delay: float = 0.0) -> None:
        pass

    def stop(self) -> None:
        pass


class _Loop:
    def register_timer(self, _callback: Any) -> _Timer:
        return _Timer()

    def delay_callback(self, *_a: Any) -> None:
        pass


class _Server:
    error = ServerError

    def __init__(self) -> None:
        self.database = _Database()
        self.loop = _Loop()
        self.endpoints: Dict[str, APIDefinition] = {}
        self.warnings: List[str] = []

    def get_host_info(self) -> Dict[str, Any]:
        return {"hostname": "m1", "port": 7125}

    def get_event_loop(self) -> _Loop:
        return self.loop

    def add_warning(self, msg: str, *_a: Any, **_kw: Any) -> None:
        self.warnings.append(msg)

    def send_event(self, *_a: Any) -> None:
        pass

    def lookup_component(self, name: str, default: Any = None) -> Any:
        return {"database": self.database, "websockets": _Websockets()}.get(
            name, default)

    def register_endpoint(
        self,
        endpoint: str,
        request_types: RequestType,
        callback: Any,
        transports: TransportType = TransportType.all(),
        wrap_result: bool = True,
        content_type: Optional[str] = None,
        auth_required: bool = True,
        is_remote: bool = False,
    ) -> None:
        # What MoonrakerApp.register_endpoint does first. The definition cache
        # is class-wide, so drop any entry an earlier test bound to another
        # Authorization instance.
        APIDefinition.pop_cached_def(endpoint)
        self.endpoints[endpoint] = APIDefinition.create(
            endpoint, request_types, callback, transports, auth_required,
            is_remote,
        )


class _Config:
    """The [authorization] section of the shipped M1 config."""

    def __init__(self, server: _Server, section: Dict[str, str]) -> None:
        self.server = server
        self.section = section

    def get_server(self) -> _Server:
        return self.server

    def has_section(self, _name: str) -> bool:
        return False

    def get(self, name: str, default: Any = None) -> Any:
        return self.section.get(name, default)

    def getint(self, name: str, default: Any = None, **_kw: Any) -> Any:
        val = self.section.get(name)
        return default if val is None else int(val)

    def getboolean(self, name: str, default: Any = None) -> Any:
        val = self.section.get(name)
        if val is None:
            return default
        return val.strip().lower() in ("true", "yes", "on", "1")

    def getlist(self, name: str, default: Any = None) -> Any:
        val = self.section.get(name)
        if val is None:
            return default
        entries = [line.split("#", 1)[0].strip() for line in val.splitlines()]
        return [e for e in entries if e]


def _shipped_authorization_section() -> Dict[str, str]:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(TEMPLATE, encoding="utf-8")
    section = dict(parser.items("authorization"))
    # Read from the kernel every 30 s on a device. Off here so the test does
    # not depend on this machine's routes; none of the callers below needs it.
    section["trust_onlink_ipv6"] = "false"
    return section


def _printer() -> Tuple[Authorization, _Server]:
    server = _Server()
    auth = Authorization(_Config(server, _shipped_authorization_section()))
    # component_init's work, minus reading an empty table back.
    auth._initialize_users()
    return auth, server


class _Request:
    """The parts of a tornado request authenticate_request reads."""

    def __init__(self, ip: str) -> None:
        self.method = "GET"
        self.remote_ip = ip
        self.headers: Dict[str, str] = {}
        self.query_arguments: Dict[str, Any] = {}
        self.arguments: Dict[str, Any] = {}


class _Websocket:
    """Duck-typed like muon_floor reads it: transport_type.name only."""

    transport_type = type("_T", (), {"name": "WEBSOCKET"})()


def _authenticate(auth: Authorization, ip: str) -> Any:
    return _run(auth.authenticate_request(_Request(ip)))  # type: ignore[arg-type]


def _call(
    server: _Server,
    endpoint: str,
    request_type: RequestType,
    args: Dict[str, Any],
    ip: str,
    user: Any,
    transport: Any = None,
) -> Any:
    async def go() -> Any:
        return await server.endpoints[endpoint].request(
            args, request_type, transport, ipaddress.ip_address(ip), user
        )
    return _run(go())


def _as(auth: Authorization, server: _Server, ip: str, endpoint: str,
        request_type: RequestType, args: Dict[str, Any]) -> Any:
    """A request from `ip`, authenticated the way Moonraker would."""
    user = _authenticate(auth, ip)
    return _call(server, endpoint, request_type, args, ip, user)


CREATE = {"username": "mallory", "password": "hunter22"}


# ---------------------------------------------------------------------------


class TestThePreconditions:
    """What made one request enough. If one of these stops holding, the tests
    below may pass for that reason instead of because of the floor, so they
    fail here first rather than going quietly vacuous."""

    def test_the_shipped_config_forces_logins_once_a_user_exists(self):
        auth, _ = _printer()
        assert auth.force_logins is True
        # _API_KEY_USER_ is always there, so the next user is the one that arms it.
        assert list(auth.users) == [auth_mod.API_USER]

    @pytest.mark.parametrize("ip", NETWORK_CALLERS + [LOOPBACK])
    def test_the_lan_the_hotspot_and_the_panel_are_trusted(self, ip):
        auth, _ = _printer()
        assert _authenticate(auth, ip).username == auth_mod.TRUSTED_USER

    def test_the_account_routes_are_registered_where_the_floor_expects(self):
        _, server = _printer()
        for endpoint, rtype in ACCOUNT_WRITES:
            api_def = server.endpoints[endpoint]
            assert RequestType.from_string(rtype) in api_def.request_types, (
                endpoint, rtype)


class TestTheLockout:
    @pytest.mark.parametrize("ip", NETWORK_CALLERS)
    def test_a_network_caller_cannot_lock_the_panel_out(self, ip):
        """The defect, end to end. Before the fix the request succeeded, and the
        panel's next request raised 401 "Force Logins Enabled"."""
        auth, server = _printer()
        try:
            _as(auth, server, ip, "/access/user", RequestType.POST, CREATE)
        except ServerError:
            pass
        assert _authenticate(auth, LOOPBACK).username == auth_mod.TRUSTED_USER
        assert _authenticate(auth, ip).username == auth_mod.TRUSTED_USER

    @pytest.mark.parametrize("ip", NETWORK_CALLERS)
    def test_creating_a_user_from_the_network_is_refused_by_the_floor(self, ip):
        auth, server = _printer()
        with pytest.raises(ServerError) as excinfo:
            _as(auth, server, ip, "/access/user", RequestType.POST, CREATE)
        assert excinfo.value.status_code == 403
        assert FLOOR_REFUSAL in str(excinfo.value)
        assert list(auth.users) == [auth_mod.API_USER]
        assert server.database.table.writes == []

    def test_the_websocket_method_is_refused_too(self):
        """``access.post_user`` over an open socket is the same endpoint with
        the same request type, so the floor sees it at the same place."""
        auth, server = _printer()
        api_def = server.endpoints["/access/user"]
        rpc = dict((name, rtype) for rtype, name in api_def.rpc_items())
        assert rpc["access.post_user"] == RequestType.POST
        user = _authenticate(auth, LAN)
        with pytest.raises(ServerError) as excinfo:
            _call(server, "/access/user", rpc["access.post_user"], CREATE, LAN,
                  user, transport=_Websocket())
        assert excinfo.value.status_code == 403
        assert FLOOR_REFUSAL in str(excinfo.value)
        assert list(auth.users) == [auth_mod.API_USER]

    def test_the_api_key_does_not_get_round_the_floor(self):
        """GET /access/api_key stays open to the LAN (Fluidd's init needs it),
        and the key authenticates ahead of the force_logins gate. The floor
        reads the address, not the credential, so the key opens nothing."""
        auth, server = _printer()
        key = _as(auth, server, LAN, "/access/api_key", RequestType.GET, {})
        request = _Request(LAN)
        request.headers = {"X-Api-Key": key}
        api_user = _run(auth.authenticate_request(request))  # type: ignore[arg-type]
        assert api_user.username == auth_mod.API_USER
        with pytest.raises(ServerError) as excinfo:
            _call(server, "/access/user", RequestType.POST, CREATE, LAN, api_user)
        assert FLOOR_REFUSAL in str(excinfo.value)
        assert list(auth.users) == [auth_mod.API_USER]


class TestTheOtherAccountWrites:
    @pytest.mark.parametrize("ip", NETWORK_CALLERS)
    def test_deleting_a_user_is_refused(self, ip):
        auth, server = _printer()
        with pytest.raises(ServerError) as excinfo:
            _as(auth, server, ip, "/access/user", RequestType.DELETE,
                {"username": "owner"})
        assert excinfo.value.status_code == 403
        assert FLOOR_REFUSAL in str(excinfo.value)

    @pytest.mark.parametrize("ip", NETWORK_CALLERS)
    def test_changing_a_password_is_refused(self, ip):
        auth, server = _printer()
        with pytest.raises(ServerError) as excinfo:
            _as(auth, server, ip, "/access/user/password", RequestType.POST,
                {"password": "a", "new_password": "b"})
        assert excinfo.value.status_code == 403
        assert FLOOR_REFUSAL in str(excinfo.value)

    @pytest.mark.parametrize("ip", NETWORK_CALLERS)
    def test_rotating_the_api_key_is_refused(self, ip):
        auth, server = _printer()
        before = auth.api_key
        with pytest.raises(ServerError) as excinfo:
            _as(auth, server, ip, "/access/api_key", RequestType.POST, {})
        assert excinfo.value.status_code == 403
        assert FLOOR_REFUSAL in str(excinfo.value)
        assert auth.api_key == before
        assert server.database.table.writes == []


class TestWhatStaysOpen:
    """Fluidd's auth/init awaits these three in sequence, uncaught, so refusing
    any one of them breaks Fluidd on the LAN."""

    @pytest.mark.parametrize("ip", NETWORK_CALLERS)
    def test_fluidds_init_reads_still_answer(self, ip):
        auth, server = _printer()
        me = _as(auth, server, ip, "/access/user", RequestType.GET, {})
        assert me["username"] == auth_mod.TRUSTED_USER
        listed = _as(auth, server, ip, "/access/users/list", RequestType.GET, {})
        assert listed == {"users": []}
        key = _as(auth, server, ip, "/access/api_key", RequestType.GET, {})
        assert key == auth.api_key

    @pytest.mark.parametrize("endpoint,rtype", [
        ("/access/info", RequestType.GET),
        ("/access/oneshot_token", RequestType.GET),
        ("/access/login", RequestType.POST),
        ("/access/logout", RequestType.POST),
        ("/access/refresh_jwt", RequestType.POST),
    ])
    def test_signing_in_and_out_is_not_floored(self, endpoint, rtype):
        assert not muon_floor.is_floor_request(endpoint, rtype)
        muon_floor.check_floor(endpoint, None, ipaddress.ip_address(LAN), rtype)

    @pytest.mark.parametrize("endpoint,rtype", ACCOUNT_WRITES)
    def test_the_panel_and_a_component_still_reach_them(self, endpoint, rtype):
        """The floor's usual exemptions. Whether the panel should ever create a
        user is a separate question (see muon_protection); the floor's answer
        for an on-device caller is the same as for every other entry."""
        req = RequestType.from_string(rtype)
        muon_floor.check_floor(endpoint, None, ipaddress.ip_address(LOOPBACK), req)
        internal = type("_I", (), {
            "transport_type": type("_T", (), {"name": "INTERNAL"})()})()
        muon_floor.check_floor(endpoint, internal, None, req)


class TestTheRule:
    def test_the_floored_account_writes_are_exactly_these(self):
        assert list(muon_floor.FLOOR_REQUESTS) == ACCOUNT_WRITES

    def test_an_entry_matches_its_endpoint_exactly(self):
        """Not a prefix: /access/user/password is its own entry, and nothing
        else under /access/user is floored by the /access/user ones."""
        assert not muon_floor.is_floor_request("/access/users/list", RequestType.GET)
        assert not muon_floor.is_floor_request("/access/user", RequestType.GET)
        assert muon_floor.is_floor_request("/access/user/password", RequestType.POST)

    @pytest.mark.parametrize("endpoint", sorted({e for e, _ in ACCOUNT_WRITES}))
    def test_no_request_type_is_floored_rather_than_waved_through(self, endpoint):
        assert muon_floor.is_floor_request(endpoint, None)
        with pytest.raises(ServerError) as excinfo:
            muon_floor.check_floor(endpoint, None, ipaddress.ip_address(LAN))
        assert FLOOR_REFUSAL in str(excinfo.value)

    def test_the_prefix_floor_is_untouched(self):
        """The account writes are a separate tuple, so the prefix list MuonOS
        mirrors into its nginx vhost (and pins) does not change."""
        for endpoint, _ in ACCOUNT_WRITES:
            assert not muon_floor.is_floor_endpoint(endpoint)

    def test_one_user_row_is_enough_to_switch_trust_off(self):
        """The mechanism the floor guards, through the real gate: with one user
        present and the shipped config, a trusted LAN address gets 401. At this
        commit the panel gets the same 401 (asserted end to end above, by its
        absence); exempting the panel from the gate is MuonOS #87's other half
        and does not make this floor unnecessary, because the LAN half stays."""
        auth, _ = _printer()
        auth.users["someone"] = auth_mod.UserInfo("someone", "x")
        with pytest.raises(HTTPError) as excinfo:
            _authenticate(auth, LAN)
        assert excinfo.value.status_code == 401
