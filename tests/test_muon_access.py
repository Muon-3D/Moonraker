"""ACC-7 to ACC-11, ACC-23, ACC-24: the level table, and the component that
holds its settings.

Pure unit tests with stub servers, in the shape of test_muon_protection.py.
The table is written out here as literals rather than imported, so a change
to the table in muon_access_policy.py fails a test instead of moving the
expectation with it. The matrix tests drive real requests through
APIDefinition.request, so endpoint classification, the decision and the call
in common.py are all under test together.
"""
from __future__ import annotations

import asyncio
import inspect
import ipaddress
from typing import Any, Dict, List, Optional, Tuple

import pytest

from moonraker import muon_access_policy as policy
from moonraker import muon_floor
from moonraker.common import APIDefinition, RequestType, UserInfo, WebRequest
from moonraker.components import application, muon_gateway
from moonraker.components.muon_access import MuonAccess
from moonraker.components.muon_gateway import GatewayUser, parse_principal
from moonraker.components.muon_protection import MuonProtection
from moonraker.utils.exceptions import ServerError

LOOPBACK = ipaddress.ip_address("127.0.0.1")
LAN = ipaddress.ip_address("192.168.1.50")
SENTINEL = ipaddress.ip_address("192.0.2.1")

TRUSTED_USER = UserInfo("_TRUSTED_USER_", "")
PASSWORD_USER = UserInfo("admin", "", source="moonraker")
LEGACY_GATEWAY_USER = GatewayUser(
    "muon-link:0123456789abcdef", "", source="muon_gateway"
)

LEVELS = ("signed_out_guest", "signed_in_guest", "member", "admin")
RANK = {name: rank for rank, name in enumerate(LEVELS, start=1)}

# Section 3 of access-model.md, row by row. Written out on purpose.
STANDARD = {
    "read": "signed_out_guest",
    "emergency_stop": "signed_out_guest",
    "print": "signed_in_guest",
    "files": "signed_in_guest",
    "motion": "member",
    "files_others": "admin",
    "console": "admin",
    "wifi": "member",
    "hotspot": "admin",
    "updates": "admin",
    "rename": "admin",
    "config": "admin",
    "protection": "admin",
}
RELAXED = dict(
    STANDARD, print="signed_out_guest", files="signed_out_guest",
    motion="signed_out_guest", files_others="member", console="member",
    wifi="signed_out_guest", rename="signed_in_guest",
)
STRICT = dict(
    STANDARD, read="signed_in_guest", print="member", files="member",
    wifi="admin",
)
READ_ROWS = {"read"}
VIEWER_ROWS = {"read", "emergency_stop"}
HOME_ONLY = {"wifi", "hotspot", "updates", "config"}
ADMIN_FROM_AWAY = {"wifi", "hotspot", "updates"}

# One request for each row, as a client would send it.
SAMPLES: Dict[str, Tuple[str, RequestType, Dict[str, Any]]] = {
    "read": ("/server/files/list", RequestType.GET, {}),
    "emergency_stop": ("emergency_stop", RequestType.POST, {}),
    "print": ("/printer/print/start", RequestType.POST, {"filename": "a.gcode"}),
    "files": ("/server/files/copy", RequestType.POST,
              {"source": "gcodes/a.gcode", "dest": "gcodes/b.gcode"}),
    "motion": ("gcode/script", RequestType.POST, {"script": "G28\nG1 X10 F600"}),
    "files_others": ("/server/files/delete_file", RequestType.DELETE,
                     {"path": "gcodes/a.gcode"}),
    "console": ("gcode/script", RequestType.POST,
                {"script": "SET_KINEMATIC_POSITION Z=0"}),
    "wifi": ("/server/aux/wifi/connect", RequestType.POST, {}),
    "hotspot": ("/server/aux/wifi/ap/up", RequestType.POST, {}),
    "updates": ("/machine/update/full", RequestType.POST, {}),
    "rename": ("/server/muon/identity/name", RequestType.POST, {"name": "m1"}),
    "config": ("/server/files/copy", RequestType.POST,
               {"source": "config/printer.cfg", "dest": "config/old.cfg"}),
    "protection": ("/server/muon/access", RequestType.POST, {"entry": "open"}),
}


class _Transport:
    def __init__(self, name: str) -> None:
        self.transport_type = type("_T", (), {"name": name})()


HTTP = _Transport("HTTP")
INTERNAL = _Transport("INTERNAL")


def gateway(level: str, role: str, home: bool = True) -> GatewayUser:
    return GatewayUser(
        "muon-link:0123456789abcdef", "", source="muon_gateway",
        principal="device:abcd", access_level=level, access_role=role,
        access_home=home,
    )


def state(**kwargs: Any) -> policy.AccessState:
    kwargs.setdefault("entry", policy.ENTRY_PROTECTED)
    kwargs.setdefault("owner", policy.OWNER_ORGANISATION)
    return policy.AccessState(**kwargs)


@pytest.fixture(autouse=True)
def _reset():
    yield
    policy.set_state(None)
    muon_floor.set_protection_level(muon_floor.LEVEL_OPEN)


def _api(endpoint: str) -> APIDefinition:
    async def callback(web_request: WebRequest) -> Dict[str, Any]:
        return {"reached": web_request.get_endpoint()}

    # Klippy's own endpoints are registered by bare name, as remote
    return APIDefinition.create(
        endpoint, ["GET", "POST", "DELETE"], callback,
        is_remote=not endpoint.startswith("/"),
    )


def send(row: str, ip_addr: Any, user: Any, transport: Any = HTTP) -> Any:
    endpoint, request_type, args = SAMPLES[row]
    api = _api(endpoint)
    return asyncio.run(
        api.request(dict(args), request_type, transport, ip_addr, user)
    )


def refused(row: str, ip_addr: Any, user: Any) -> Optional[str]:
    """The 403 message, or None when the handler was reached."""
    try:
        send(row, ip_addr, user)
    except ServerError as err:
        assert err.status_code == 403
        return str(err)
    return None


class TestTheTableIsTheDesign:
    def test_each_preset_matches_section_3(self):
        for name, table in (("relaxed", RELAXED), ("standard", STANDARD),
                            ("strict", STRICT)):
            for row, level in table.items():
                action = policy.ACTIONS[row]
                got = policy.LEVEL_NAMES[action.level_for(name)]
                assert got == level, (name, row)

    def test_flags_match_section_3(self):
        assert {n for n, a in policy.ACTIONS.items() if a.home_only} == HOME_ONLY
        assert {n for n, a in policy.ACTIONS.items()
                if a.admin_from_away} == ADMIN_FROM_AWAY
        assert {n for n, a in policy.ACTIONS.items()
                if a.read or a.viewer_allowed} == VIEWER_ROWS | {"read"}

    def test_the_fixed_rows(self):
        # ACC-24, plus emergency stop's "never above this"
        fixed = {n for n, a in policy.ACTIONS.items() if a.fixed}
        assert fixed == {"emergency_stop", "protection", "owner", "dev_mode",
                         "setup"}

    def test_each_sample_is_classified_as_its_row(self):
        for row, (endpoint, rtype, args) in SAMPLES.items():
            names = {a.name for a in policy.classify(endpoint, rtype, args)}
            assert names == {row}, (row, names)


class TestStandardForEveryLevelAndRole:
    """The acceptance matrix: an organisation's printer at Standard, every
    row, every level, both roles, through APIDefinition.request."""

    @pytest.mark.parametrize("entry", ["open", "protected"])
    @pytest.mark.parametrize("role", ["operator", "viewer"])
    @pytest.mark.parametrize("level", LEVELS)
    def test_matrix(self, level: str, role: str, entry: str):
        policy.set_state(state(entry=entry, preset="standard"))
        for row, needed in STANDARD.items():
            message = refused(row, SENTINEL, gateway(level, role))
            may = RANK[level] >= RANK[needed]
            if role == "viewer":
                may = may and row in VIEWER_ROWS
            if may:
                assert message is None, (level, role, row, message)
            else:
                assert message is not None, (level, role, row)
                assert message.startswith(f"access-denied:{row}:"), message

    def test_a_viewer_is_refused_every_write(self):
        policy.set_state(state(preset="standard"))
        for row in STANDARD:
            message = refused(row, SENTINEL, gateway("admin", "viewer"))
            if row in VIEWER_ROWS:
                assert message is None, row
            else:
                assert message is not None and "Viewer" in message, row

    def test_an_estop_line_in_a_script_is_allowed_to_a_viewer(self):
        policy.set_state(state(preset="standard"))
        api = _api("gcode/script")
        asyncio.run(api.request({"script": "M112"}, RequestType.POST, HTTP,
                                SENTINEL, gateway("signed_out_guest", "viewer")))

    def test_a_script_is_judged_line_by_line(self):
        policy.set_state(state(preset="standard"))
        api = _api("gcode/script")
        # a member may move, not use the console: the console line refuses
        with pytest.raises(ServerError) as err:
            asyncio.run(api.request(
                {"script": "G28\nSET_KINEMATIC_POSITION Z=0\nG1 Z5"},
                RequestType.POST, HTTP, SENTINEL, gateway("member", "operator"),
            ))
        assert str(err.value).startswith("access-denied:console:")


class TestTheFloorAndThePanel:
    def test_the_floor_still_refuses_an_admin(self):
        policy.set_state(state(preset="relaxed"))
        api = _api("/server/aux/bms/ship")
        with pytest.raises(ServerError) as err:
            asyncio.run(api.request({}, RequestType.POST, HTTP, SENTINEL,
                                    gateway("admin", "operator")))
        assert err.value.status_code == 403
        # The floor's own refusal, not the table's
        assert "not available over the network" in str(err.value)

    @pytest.mark.parametrize("owner", policy.OWNERS)
    @pytest.mark.parametrize("entry", ["open", "protected"])
    def test_the_panel_is_allowed_everything_outside_the_floor(
        self, owner: str, entry: str
    ):
        policy.set_state(state(entry=entry, owner=owner, preset="strict",
                               overrides={"read": policy.ADMIN}))
        for row in STANDARD:
            assert send(row, LOOPBACK, TRUSTED_USER)["reached"]
            assert send(row, None, None, INTERNAL)["reached"]

    def test_the_floor_still_holds_for_the_panel_too(self):
        # The floor admits the panel; the table must not refuse it either
        policy.set_state(state())
        api = _api("/server/aux/bms/ship")
        assert asyncio.run(api.request({}, RequestType.POST, HTTP, LOOPBACK,
                                       TRUSTED_USER))["reached"]


class TestPrincipals:
    def test_anyone_at_home_under_open_is_a_signed_out_guest_operator(self):
        p = policy.resolve_principal(HTTP, LAN, TRUSTED_USER, "open")
        assert p is not None
        assert (p.kind, p.level, p.role, p.home, p.identified) == (
            "home", policy.SIGNED_OUT_GUEST, "operator", True, False)

    def test_anyone_at_home_under_protected_is_not_admitted(self):
        policy.set_state(state(entry="protected", preset="relaxed"))
        message = refused("read", LAN, TRUSTED_USER)
        assert message is not None and "Protected" in message

    def test_the_password_is_a_signed_out_guest_at_home(self):
        p = policy.resolve_principal(HTTP, LAN, PASSWORD_USER, "protected")
        assert p is not None
        assert (p.kind, p.level, p.role, p.identified) == (
            "password", policy.SIGNED_OUT_GUEST, "operator", True)
        policy.set_state(state(entry="protected", owner="account"))
        assert refused("read", LAN, PASSWORD_USER) is None

    def test_the_password_does_not_work_from_away(self):
        # ACC-16: the same login through the gateway is not admitted
        assert policy.resolve_principal(
            HTTP, SENTINEL, PASSWORD_USER, "open") is None

    def test_the_gateway_address_without_its_token_is_nobody(self):
        assert policy.resolve_principal(
            HTTP, SENTINEL, TRUSTED_USER, "open") is None
        assert policy.resolve_principal(HTTP, SENTINEL, None, "open") is None

    def test_no_address_is_nobody(self):
        assert policy.resolve_principal(None, None, TRUSTED_USER, "open") is None

    def test_a_token_naming_no_principal_is_the_gateway_as_it_was(self):
        p = policy.resolve_principal(HTTP, SENTINEL, LEGACY_GATEWAY_USER, "open")
        assert p is not None
        assert (p.level, p.role) == (policy.ADMIN, "operator")

    def test_a_token_carries_level_role_and_home(self):
        p = policy.resolve_principal(
            HTTP, SENTINEL, gateway("member", "viewer", home=False), "open")
        assert p is not None
        assert (p.name, p.level, p.role, p.home) == (
            "device:abcd", policy.MEMBER, "viewer", False)

    def test_the_password_login_name_agrees_with_moonraker_32(self):
        panel_login = getattr(muon_floor, "PANEL_LOGIN_USER", None)
        if panel_login is None:
            pytest.skip("Moonraker#32 (the password) is not merged here")
        assert policy.PASSWORD_LOGIN_USER == panel_login


class TestOwnerReadings:
    def test_one_owner_reads_member_as_owner(self):
        s = state(owner="account", entry="protected")
        assert policy.effective_preset(s) == "standard"
        assert policy.effective_table(s)["motion"] == "admin"
        assert policy.effective_table(s)["wifi"] == "admin"

    def test_one_owner_uses_relaxed_while_open(self):
        s = state(owner="account", entry="open")
        assert policy.effective_preset(s) == "relaxed"
        policy.set_state(s)
        # Jack's single-owner Open case: a guest at home may print, Wi-Fi
        assert refused("print", LAN, TRUSTED_USER) is None
        assert refused("wifi", LAN, TRUSTED_USER) is None
        assert refused("hotspot", LAN, TRUSTED_USER) is not None
        assert refused("updates", LAN, TRUSTED_USER) is not None
        assert refused("protection", LAN, TRUSTED_USER) is not None

    @pytest.mark.parametrize("owner", ["none", "unknown"])
    def test_no_owner_open_is_todays_printer(self, owner: str):
        policy.set_state(state(owner=owner, entry="open", preset="strict"))
        for row in STANDARD:
            message = refused(row, LAN, TRUSTED_USER)
            if row == "protection":
                assert message is not None and "panel" in message
            else:
                assert message is None, (row, message)

    @pytest.mark.parametrize("owner", ["none", "unknown"])
    def test_no_owner_protected_needs_an_approved_device(self, owner: str):
        policy.set_state(state(owner=owner, entry="protected"))
        # the password: signed-out guest rows only
        assert refused("read", LAN, PASSWORD_USER) is None
        assert refused("emergency_stop", LAN, PASSWORD_USER) is None
        assert refused("print", LAN, PASSWORD_USER) is not None
        # a gateway principal below admin is not an approved device: it
        # keeps the signed-out guest rows and nothing above them
        guest = gateway("signed_in_guest", "operator")
        assert refused("read", SENTINEL, guest) is None
        message = refused("print", SENTINEL, guest)
        assert message is not None and "needs admin" in message
        # an approved device acts at the admin level...
        for row in STANDARD:
            message = refused(row, SENTINEL, gateway("admin", "operator"))
            if row == "protection":
                # ...except Protection, which is the panel's
                assert message is not None and "panel" in message
            else:
                assert message is None, (row, message)


class TestHomeOnly:
    def test_a_home_only_row_is_refused_from_away(self):
        policy.set_state(state(preset="relaxed"))
        message = refused("wifi", SENTINEL,
                          gateway("member", "operator", home=False))
        assert message is not None and "home network" in message
        assert refused("wifi", SENTINEL,
                       gateway("member", "operator", home=True)) is None

    def test_a_trusted_device_may_change_wifi_hotspot_updates_from_away(self):
        policy.set_state(state(preset="standard"))
        admin_away = gateway("admin", "operator", home=False)
        for row in ("wifi", "hotspot", "updates"):
            assert refused(row, SENTINEL, admin_away) is None, row
        # printer.cfg stays home only (parity table)
        assert refused("config", SENTINEL, admin_away) is not None


class TestClassification:
    def test_unrecognised_writes_fail_closed_to_admin(self):
        actions = policy.classify("/server/something/new", RequestType.POST, {})
        assert [a.name for a in actions] == ["system"]
        actions = policy.classify("some/klippy_thing", RequestType.POST, {})
        assert [a.name for a in actions] == ["console"]

    def test_an_unknown_macro_is_the_console(self):
        assert [a.name for a in policy.gcode_actions("MY_MACRO")] == ["console"]
        assert [a.name for a in policy.gcode_actions("LOAD_FILAMENT")] == [
            "motion"]

    def test_gcode_parsing(self):
        assert policy.gcode_commands(
            "N10 G1X10 ; move\n\nset_fan_speed FAN=a\n; c\nM112") == [
            "G1", "SET_FAN_SPEED", "M112"]

    def test_the_aux_proxy_is_classified_by_its_path(self):
        names = lambda path, method: [a.name for a in policy.classify(  # noqa
            "/server/aux/proxy", RequestType.POST,
            {"path": path, "method": method})]
        assert names("/wifi/ap/up", "POST") == ["hotspot"]
        assert names("/wifi/scan", "GET") == ["read"]
        assert names("/update/../wifi/ap/up", "POST") == ["hotspot"]
        assert names("/brand/new", "POST") == ["system"]

    def test_an_upload_that_prints_is_a_print_too(self):
        names = [a.name for a in policy.classify(
            "/server/files/upload", RequestType.POST,
            {"root": "gcodes", "print": "true"})]
        assert names == ["files", "print"]
        names = [a.name for a in policy.classify(
            "/server/files/upload", RequestType.POST, {"root": "config"})]
        assert names == ["config"]

    def test_delegated_rows_are_left_to_their_own_checks(self):
        policy.set_state(state(entry="open", owner="account", preset="strict"))
        api = _api("/server/muon/setup/name")
        assert asyncio.run(api.request({}, RequestType.POST, HTTP, LAN,
                                       TRUSTED_USER))["reached"]
        # but a Viewer still may not write them
        with pytest.raises(ServerError):
            asyncio.run(api.request({}, RequestType.POST, HTTP, SENTINEL,
                                    gateway("admin", "viewer")))

    def test_without_the_component_nothing_is_refused(self):
        policy.set_state(None)
        assert refused("protection", SENTINEL, gateway("signed_out_guest",
                                                       "viewer")) is None


class TestTheFileHandlers:
    """Uploads and the file DELETE do not pass APIDefinition.request."""

    class _Request:
        def __init__(self, ip: str) -> None:
            self.remote_ip = ip

    def test_the_helper_refuses_with_a_403(self):
        import tornado.web
        policy.set_state(state(owner="account", entry="protected"))
        with pytest.raises(tornado.web.HTTPError) as err:
            application._check_file_access(
                self._Request("192.168.1.50"), PASSWORD_USER,
                "/server/files/upload", RequestType.POST, {"root": "gcodes"})
        assert err.value.status_code == 403
        assert "access-denied:files:" in str(err.value.reason)
        application._check_file_access(
            self._Request("127.0.0.1"), TRUSTED_USER,
            "/server/files/upload", RequestType.POST, {"root": "config"})

    def test_the_handlers_call_it(self):
        delete = inspect.getsource(application.FileRequestHandler.delete)
        prepare = inspect.getsource(application.FileUploadHandler.prepare)
        post = inspect.getsource(application.FileUploadHandler.post)
        assert "_check_file_access" in delete
        assert "_check_file_access" in prepare
        assert "_check_file_access" in post


class TestTheGatewayRequest:
    def test_a_full_principal(self):
        fields = parse_principal(
            b'{"client":"ab","principal":"acct:sam","level":"member",'
            b'"role":"viewer","home":true}')
        assert fields == {"access_level": "member", "access_role": "viewer",
                          "access_home": True, "principal": "acct:sam"}

    def test_none_is_the_gateway_as_it_was(self):
        assert parse_principal(b'{"client":"ab"}') == {}

    @pytest.mark.parametrize("body", [
        b'{"client":"ab","level":"member"}',
        b'{"client":"ab","role":"operator"}',
        b'{"client":"ab","principal":"x"}',
        b'{"client":"ab","level":"owner","role":"operator"}',
        b'{"client":"ab","level":"panel","role":"operator"}',
        b'{"client":"ab","level":"member","role":"admin"}',
        b'{"client":"ab","level":"member","role":"viewer","home":"yes"}',
        b'{"client":"ab","level":"member","role":"viewer","principal":"a b"}',
    ])
    def test_a_partial_or_wrong_principal_is_refused(self, body: bytes):
        with pytest.raises(ValueError):
            parse_principal(body)

    def test_the_user_is_still_a_gateway_user(self):
        user = gateway("member", "operator")
        assert isinstance(user, UserInfo)
        assert user.source == muon_floor.GATEWAY_USER_SOURCE
        assert muon_gateway.SENTINEL == muon_floor.GATEWAY_SENTINEL


# ---------------------------------------------------------------------------
# The component: storage, migration, the dual write
# ---------------------------------------------------------------------------


class _Namespace:
    def __init__(self) -> None:
        self.values: Dict[str, Any] = {}
        self.fail_get = False
        self.fail_insert = False

    async def get(self, key: str, default: Any = None) -> Any:
        if self.fail_get:
            raise RuntimeError("database unreadable")
        return self.values.get(key, default)

    async def insert(self, key: str, value: Any) -> None:
        if self.fail_insert:
            raise RuntimeError("database read-only")
        self.values[key] = value


class _Database:
    def __init__(self) -> None:
        self.namespaces: Dict[str, _Namespace] = {}

    def register_local_namespace(
        self, namespace: str, forbidden: bool = False, parse_keys: bool = False
    ) -> _Namespace:
        assert forbidden, namespace
        return self.namespaces.setdefault(namespace, _Namespace())


class _Link:
    def __init__(self, phase: str) -> None:
        self.phase = phase

    async def status(self) -> Dict[str, Any]:
        return {"phase": self.phase}


class _Server:
    error = ServerError

    def __init__(self) -> None:
        self.components: Dict[str, Any] = {"database": _Database()}
        self.events: List[Tuple[str, Tuple[Any, ...]]] = []

    def lookup_component(self, name: str, default: Any = None) -> Any:
        return self.components.get(name, default)

    def load_component(self, config: Any, name: str, default: Any = None) -> Any:
        return self.components.get(name, default)

    def register_endpoint(self, *args: Any) -> None:
        pass

    def register_notification(self, *args: Any) -> None:
        pass

    def send_event(self, event: str, *args: Any) -> None:
        self.events.append((event, args))


class _Config:
    error = ValueError

    def __init__(self, server: _Server, dual_write: bool = True) -> None:
        self.server = server
        self.dual_write = dual_write

    def get_server(self) -> _Server:
        return self.server

    def getboolean(self, name: str, default: bool) -> bool:
        assert name == "dual_write_protection_level"
        return self.dual_write


def _db(server: _Server, name: str) -> _Namespace:
    return server.components["database"].register_local_namespace(
        name, forbidden=True)


def _printer(
    old_level: Any = None, record: Any = None, link: Optional[str] = None
) -> Tuple[MuonAccess, MuonProtection, _Server]:
    server = _Server()
    if old_level is not None:
        _db(server, "muon_protection").values["level"] = old_level
    if record is not None:
        _db(server, "muon_access").values["record"] = record
    if link is not None:
        server.components["muon_link"] = _Link(link)
    protection = MuonProtection(_Config(server))
    server.components["muon_protection"] = protection
    access = MuonAccess(_Config(server))
    server.components["muon_access"] = access

    async def start() -> None:
        await protection.component_init()
        await access.component_init()
        await access.close()   # stop the owner poll; state stays published
        policy.set_state(access.access_state())

    asyncio.run(start())
    return access, protection, server


def _post(component: Any, ip_addr: Any, args: Dict[str, Any],
          user: Any = TRUSTED_USER) -> Dict[str, Any]:
    request = WebRequest("/x", args, RequestType.POST, HTTP, ip_addr, user)
    return asyncio.run(component._handle(request))


class TestMigrationAndRollback:
    def test_a_protected_printer_migrates_to_protected(self):
        access, _p, server = _printer(old_level=1)
        assert access.record["entry"] == "protected"
        assert _db(server, "muon_access").values["record"]["entry"] == "protected"

    def test_an_open_or_new_printer_migrates_to_open(self):
        for old in (0, None):
            access, _p, _s = _printer(old_level=old)
            assert access.record["entry"] == "open"

    def test_a_garbled_old_level_migrates_to_protected(self):
        access, _p, _s = _printer(old_level="1")
        assert access.record["entry"] == "protected"

    def test_the_old_key_wins_after_a_rollback_changed_it(self):
        # This release wrote Protected (1); the release before it, booted by a
        # rollback, was set to Open at its panel; then this one came back.
        record = {"version": 1, "entry": "protected", "preset": None,
                  "overrides": {}, "written_level": 1}
        access, _p, _s = _printer(old_level=0, record=record)
        assert access.record["entry"] == "open"

    def test_an_unreadable_record_enforces_protected(self):
        server = _Server()
        _db(server, "muon_access").fail_get = True
        protection = MuonProtection(_Config(server))
        server.components["muon_protection"] = protection
        access = MuonAccess(_Config(server))
        asyncio.run(access.component_init())
        assert policy.state() is not None
        assert policy.state().entry == "protected"

    def test_dual_write_needs_muon_protection(self):
        server = _Server()
        with pytest.raises(ValueError):
            MuonAccess(_Config(server))


class TestTheDualWrite:
    def test_protected_writes_level_1_and_open_writes_level_0(self):
        access, protection, server = _printer(old_level=0, link="linked")
        old = _db(server, "muon_protection")
        policy.set_state(access.access_state())
        _post(access, LOOPBACK, {"entry": "protected"})
        assert old.values["level"] == 1
        assert muon_floor.protection_level() == muon_floor.LEVEL_PROTECTED
        assert access.record["written_level"] == 1
        _post(access, LOOPBACK, {"entry": "open"})
        assert old.values["level"] == 0
        assert muon_floor.protection_level() == muon_floor.LEVEL_OPEN

    def test_a_failed_old_write_refuses_the_change_and_keeps_both(self):
        access, protection, server = _printer(old_level=1)
        _db(server, "muon_protection").fail_insert = True
        with pytest.raises(ServerError) as err:
            _post(access, LOOPBACK, {"entry": "open"})
        assert err.value.status_code == 500
        assert access.record["entry"] == "protected"
        assert _db(server, "muon_access").values["record"]["entry"] == "protected"
        assert policy.state().entry == "protected"
        assert muon_floor.protection_level() == muon_floor.LEVEL_PROTECTED

    def test_a_failed_new_write_changes_nothing(self):
        access, protection, server = _printer(old_level=1)
        _db(server, "muon_access").fail_insert = True
        with pytest.raises(RuntimeError):
            _post(access, LOOPBACK, {"entry": "open"})
        assert _db(server, "muon_protection").values["level"] == 1
        assert policy.state().entry == "protected"

    def test_the_panels_protection_post_moves_the_entry_too(self):
        access, protection, server = _printer(old_level=0)
        request = WebRequest("/server/muon/protection", {"level": 1},
                             RequestType.POST, HTTP, LOOPBACK, TRUSTED_USER)
        asyncio.run(protection._handle(request))
        assert access.record["entry"] == "protected"
        assert _db(server, "muon_access").values["record"]["written_level"] == 1
        assert _db(server, "muon_protection").values["level"] == 1

    def test_without_dual_write_the_old_key_is_left_alone(self):
        server = _Server()
        _db(server, "muon_protection").values["level"] = 0
        protection = MuonProtection(_Config(server))
        server.components["muon_protection"] = protection
        access = MuonAccess(_Config(server, dual_write=False))
        asyncio.run(protection.component_init())
        asyncio.run(access.component_init())
        asyncio.run(access.close())
        _post(access, LOOPBACK, {"entry": "protected"})
        assert _db(server, "muon_protection").values["level"] == 0


class TestTheSettings:
    def test_the_owner_follows_the_link(self):
        access, _p, _s = _printer(old_level=0, link="linked")
        assert access.owner == "account"
        access, _p, _s = _printer(old_level=0, link="unlinked")
        assert access.owner == "none"
        access, _p, _s = _printer(old_level=0)
        assert access.owner == "none"

    def test_overrides_change_a_row_and_can_be_cleared(self):
        access, _p, _s = _printer(old_level=0, link="linked")
        result = _post(access, LOOPBACK, {"overrides": {"print": "admin"}})
        assert result["overrides"] == {"print": "admin"}
        assert result["table"]["print"] == "admin"
        result = _post(access, LOOPBACK, {"overrides": {"print": None}})
        assert result["overrides"] == {}

    @pytest.mark.parametrize("overrides", [
        {"protection": "member"},
        {"emergency_stop": "admin"},
        {"dev_mode": "admin"},
        {"print": "panel"},
        {"print": "owner"},
        {"nonsense": "admin"},
    ])
    def test_fixed_rows_and_unknown_levels_are_refused(self, overrides):
        access, _p, _s = _printer(old_level=0, link="linked")
        with pytest.raises(ServerError) as err:
            _post(access, LOOPBACK, {"overrides": overrides})
        assert err.value.status_code == 400

    def test_the_preset_can_follow_the_owner_again(self):
        access, _p, _s = _printer(old_level=0, link="linked")
        assert _post(access, LOOPBACK, {"preset": "strict"})[
            "effective_preset"] == "strict"
        assert _post(access, LOOPBACK, {"preset": "auto"})[
            "effective_preset"] == "relaxed"

    def test_a_caller_is_told_what_it_may_do(self):
        access, _p, _s = _printer(old_level=0, link="linked")
        request = WebRequest("/server/muon/access", {}, RequestType.GET, HTTP,
                             LAN, TRUSTED_USER)
        result = asyncio.run(access._handle(request))
        assert result["caller"]["kind"] == "home"
        assert "print" in result["caller_allowed"]
        assert "protection" not in result["caller_allowed"]

    def test_a_lan_caller_cannot_change_the_settings(self):
        access, _p, _s = _printer(old_level=0, link="linked")
        api = _api("/server/muon/access")
        with pytest.raises(ServerError) as err:
            asyncio.run(api.request({"entry": "protected"}, RequestType.POST,
                                    HTTP, LAN, TRUSTED_USER))
        assert str(err.value).startswith("access-denied:protection:")
