"""KAN-436 x ACC-23: a phone setting the printer up over Bluetooth, in the
floor and in the level table.

muon-link forwards a connection that started on its Bluetooth transport as
``192.0.2.2`` with a ``muon_gateway`` token (ADR 0032 D4, D7). While setup is
not complete it may be a stranger in radio range that muon-link admitted
without pairing (D4 rule 2), and muon-link's gateway holds it to
``/server/muon/setup`` and ``/server/muon/link``. These pin the same rule on
Moonraker's side, so that muon-link alone is never the only wall:

* ``muon_floor.check_bluetooth``, always on: until muon_setup says setup is
  complete, ``192.0.2.2`` reaches the setup routes and nothing else, through
  ``APIDefinition.request``, the file handlers and both websockets;
* ``muon_access_policy``, when ``[muon_access]`` is loaded: the principal
  ``bluetooth`` -- a signed-out guest, a Viewer, never on the home network,
  never identified, never trusted, whatever its token names -- allowed the
  setup routes by endpoint and refused every row of the table besides, under
  every owner, entry, preset and override;
* once setup is complete, ``192.0.2.2`` is a paired client that started on
  Bluetooth: decided as the gateway principal its token names, except that it
  is never on the home network.

The routes and rows are written out here, not read from the modules, so that
a change there fails a test instead of moving the expectation with it.

Pure unit tests: ``pytest --noconftest tests/test_muon_access_bluetooth.py``.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

import pytest
from tornado.httputil import HTTPHeaders
from tornado.web import HTTPError

from moonraker import muon_access_policy as policy
from moonraker import muon_floor
from moonraker.common import APIDefinition, RequestType, UserInfo, WebRequest
from moonraker.components import application, muon_gateway, websockets
from moonraker.components.muon_access_api import AccessApi
from moonraker.components.muon_gateway import GatewayUser
from moonraker.utils.exceptions import ServerError

from muon_setup_fakes import Harness, run, state_with

BLUETOOTH = ipaddress.ip_address("192.0.2.2")
SENTINEL = ipaddress.ip_address("192.0.2.1")
LOOPBACK = ipaddress.ip_address("127.0.0.1")
LAN = ipaddress.ip_address("192.168.1.50")
HOTSPOT = ipaddress.ip_address("10.42.0.23")

FLOOR_REFUSAL = "is not available over Bluetooth while this printer is being set up"
TABLE_REFUSAL = (
    "a phone setting this printer up over Bluetooth reaches the setup routes "
    "only"
)

# The printer's interfaces in these tests: a /24 LAN.
HOME = policy.HomeNetwork.from_interface_addresses(
    [("192.168.1.10", 24), ("fe80::1", 64)])

#: What muon-link sends today: a token with no principal fields.
LEGACY_TOKEN = GatewayUser("muon-link:0123456789abcdef", "", source="muon_gateway")
TRUSTED_USER = UserInfo("_TRUSTED_USER_", "")


def token(level: str, role: str, home: bool) -> GatewayUser:
    return GatewayUser(
        "muon-link:0123456789abcdef", "", source="muon_gateway",
        principal="device:abcd", access_level=level, access_role=role,
        access_home=home,
    )


#: Every token a Bluetooth request might carry, the most generous included.
TOKENS = [
    LEGACY_TOKEN,
    token("admin", "operator", True),
    token("signed_out_guest", "viewer", False),
]

# muon-link's BLUETOOTH_SETUP_RULES, written out: what a phone being set up
# over Bluetooth reaches.
SETUP_ROUTES: List[Tuple[str, RequestType, Dict[str, Any]]] = [
    ("/server/muon/setup", RequestType.GET, {}),
    ("/server/muon/setup/options", RequestType.GET, {}),
    ("/server/muon/setup/driver", RequestType.POST, {"kind": "phone"}),
    ("/server/muon/setup/wifi", RequestType.POST, {"ssid": "home"}),
    ("/server/muon/setup/finish", RequestType.POST, {}),
    ("/server/muon/link", RequestType.GET, {}),
    ("/server/muon/link/start", RequestType.POST, {}),
    ("/server/muon/link/cancel", RequestType.POST, {}),
]

# One request per row of the table, and the surfaces the table names by
# endpoint. Each must be refused to a phone being set up over Bluetooth.
OUTSIDE: List[Tuple[str, RequestType, Dict[str, Any]]] = [
    ("/server/files/list", RequestType.GET, {}),
    ("/printer/objects/query", RequestType.GET, {}),
    ("/server/info", RequestType.GET, {}),
    ("objects/query", RequestType.POST, {}),
    ("emergency_stop", RequestType.POST, {}),
    ("/printer/print/start", RequestType.POST, {"filename": "a.gcode"}),
    ("/server/files/copy", RequestType.POST,
     {"source": "gcodes/a.gcode", "dest": "gcodes/b.gcode"}),
    ("gcode/script", RequestType.POST, {"script": "G28"}),
    ("gcode/script", RequestType.POST, {"script": "M112"}),
    ("/server/files/delete_file", RequestType.DELETE, {"path": "gcodes/a.gcode"}),
    ("/server/aux/wifi/connect", RequestType.POST, {}),
    ("/server/aux/wifi/ap/up", RequestType.POST, {}),
    ("/server/aux/proxy", RequestType.POST, {"path": "/wifi/connect"}),
    ("/machine/update/full", RequestType.POST, {}),
    ("/server/muon/identity/name", RequestType.POST, {"name": "m1"}),
    ("/server/muon/protection", RequestType.POST, {"level": 0}),
    ("/server/muon/access", RequestType.GET, {}),
    ("/server/muon/access", RequestType.POST, {"entry": "open"}),
    ("/server/muon/access/request", RequestType.POST, {"action": "print"}),
    ("/server/muon/access/request_status", RequestType.GET, {}),
    ("/server/database/item", RequestType.POST, {"namespace": "x"}),
    ("/machine/reboot", RequestType.POST, {}),
    ("/access/user", RequestType.POST, {}),
    # On a segment boundary: neither of these is a setup route.
    ("/server/muon/setupx", RequestType.GET, {}),
    ("/server/muon/linked", RequestType.GET, {}),
]


@pytest.fixture(autouse=True)
def _reset():
    # A MuonSetup built by another test file registers itself and is never
    # closed: start every test from "muon_setup has not said".
    muon_floor.set_setup_complete_source(None)
    yield
    muon_floor.set_setup_complete_source(None)
    policy.set_state(None)
    muon_floor.set_protection_level(muon_floor.LEVEL_OPEN)


def setup_is_complete() -> None:
    muon_floor.set_setup_complete_source(lambda: True)


class _Transport:
    def __init__(self, name: str) -> None:
        self.transport_type = type("_T", (), {"name": name})()


HTTP = _Transport("HTTP")
INTERNAL = _Transport("INTERNAL")


def send(endpoint: str, request_type: RequestType, args: Dict[str, Any],
         ip_addr: Any, user: Any, transport: Any = HTTP) -> Any:
    async def callback(web_request: WebRequest) -> Dict[str, Any]:
        return {"reached": web_request.get_endpoint()}

    APIDefinition._cache.pop(endpoint, None)
    api = APIDefinition.create(
        endpoint, ["GET", "POST", "DELETE"], callback,
        is_remote=not endpoint.startswith("/"),
    )
    try:
        return asyncio.run(
            api.request(dict(args), request_type, transport, ip_addr, user))
    finally:
        APIDefinition._cache.pop(endpoint, None)


def refusal(endpoint: str, request_type: RequestType, args: Dict[str, Any],
            ip_addr: Any, user: Any) -> Optional[str]:
    """The 403's message, or None when the handler was reached."""
    try:
        result = send(endpoint, request_type, args, ip_addr, user)
    except ServerError as err:
        assert err.status_code == 403, err
        return str(err)
    assert result == {"reached": endpoint}
    return None


def access_states() -> List[policy.AccessState]:
    """Every owner and entry, every preset, and every row overridden to the
    lowest level there is: the most open table a printer can have."""
    lowest = {
        name: policy.SIGNED_OUT_GUEST
        for name, action in policy.ACTIONS.items() if not action.fixed
    }
    states = []
    for owner in policy.OWNERS:
        for entry in policy.ENTRIES:
            for preset in (None,) + policy.PRESETS:
                states.append(policy.AccessState(
                    entry=entry, preset=preset, owner=owner, home=HOME))
            states.append(policy.AccessState(
                entry=entry, preset="relaxed", overrides=lowest, owner=owner,
                home=HOME))
    return states


# ---------------------------------------------------------------------------
# The floor: always on, [muon_access] or not
# ---------------------------------------------------------------------------


class TestTheFloorHoldsBluetoothToSetup:
    @pytest.mark.parametrize("user", TOKENS + [None, TRUSTED_USER])
    @pytest.mark.parametrize("endpoint,rtype,args", OUTSIDE)
    def test_everything_but_setup_is_refused(self, endpoint, rtype, args, user):
        for level in (muon_floor.LEVEL_OPEN, muon_floor.LEVEL_PROTECTED):
            muon_floor.set_protection_level(level)
            message = refusal(endpoint, rtype, args, BLUETOOTH, user)
            assert message is not None, (endpoint, level)
            # The floor's own surfaces keep the floor's reason (SEC-2 first)
            if not muon_floor.is_floor_request(endpoint, rtype):
                assert FLOOR_REFUSAL in message, (endpoint, message)

    @pytest.mark.parametrize("endpoint,rtype,args", SETUP_ROUTES)
    def test_the_setup_routes_are_reached(self, endpoint, rtype, args):
        for level in (muon_floor.LEVEL_OPEN, muon_floor.LEVEL_PROTECTED):
            muon_floor.set_protection_level(level)
            assert refusal(endpoint, rtype, args, BLUETOOTH, LEGACY_TOKEN) is None

    def test_other_callers_are_untouched_while_setup_is_open(self):
        for ip_addr, user in ((SENTINEL, LEGACY_TOKEN), (LAN, TRUSTED_USER),
                              (HOTSPOT, TRUSTED_USER), (LOOPBACK, None)):
            assert refusal("/server/files/list", RequestType.GET, {},
                           ip_addr, user) is None, ip_addr
        # An in-process call carries no address and is never held
        muon_floor.check_bluetooth("/server/files/list", INTERNAL, BLUETOOTH)

    def test_once_setup_is_complete_the_floor_lets_it_through(self):
        setup_is_complete()
        assert refusal("/server/files/list", RequestType.GET, {},
                       BLUETOOTH, LEGACY_TOKEN) is None
        muon_floor.check_bluetooth("/websocket", None, BLUETOOTH)

    def test_not_known_is_not_complete(self):
        assert not muon_floor.setup_complete()

        def broken() -> bool:
            raise RuntimeError("muon_setup cannot say")
        for source in (broken, lambda: 1, lambda: "complete", lambda: None):
            muon_floor.set_setup_complete_source(source)  # type: ignore[arg-type]
            assert not muon_floor.setup_complete()
            with pytest.raises(ServerError) as info:
                muon_floor.check_bluetooth("/server/files/list", None, BLUETOOTH)
            assert info.value.status_code == 403

    def test_the_file_handlers_hold_it_too(self):
        # FileRequestHandler and FileUploadHandler never reach APIDefinition
        request = SimpleNamespace(remote_ip=str(BLUETOOTH))
        for endpoint, rtype in (("/server/files/gcodes/a.gcode", RequestType.GET),
                                ("/server/files/upload", RequestType.POST),
                                ("/server/files/gcodes/a.gcode",
                                 RequestType.DELETE)):
            with pytest.raises(HTTPError) as info:
                application._check_file_access(
                    request, LEGACY_TOKEN, endpoint, rtype, {})
            assert info.value.status_code == 403
            assert FLOOR_REFUSAL in str(info.value.reason)
        # Nothing changes for a LAN caller without [muon_access]
        application._check_file_access(
            SimpleNamespace(remote_ip=str(LAN)), TRUSTED_USER,
            "/server/files/gcodes/a.gcode", RequestType.GET, {})

    @pytest.mark.parametrize("handler", [websockets.WebSocket,
                                         websockets.BridgeSocket])
    def test_no_websocket_and_no_klippy_socket(self, handler):
        class Stub:
            connection_count = 0

            def __init__(self, remote_ip: str) -> None:
                self.request = SimpleNamespace(headers=HTTPHeaders(),
                                               remote_ip=remote_ip)
                self.settings = {"max_websocket_connections": -1}
                self.server = SimpleNamespace(error=ServerError)

        def stub(remote_ip: str) -> Any:
            return Stub(remote_ip)
        with pytest.raises(ServerError) as info:
            asyncio.run(handler.prepare(stub(str(BLUETOOTH))))
        assert info.value.status_code == 403
        assert FLOOR_REFUSAL in str(info.value)
        # Anyone else gets past it to the next check (here, a full house)
        for remote_ip in (str(LAN), str(SENTINEL)):
            with pytest.raises(ServerError) as info:
                asyncio.run(handler.prepare(stub(remote_ip)))
            assert "Maximum Number of" in str(info.value)
        setup_is_complete()
        with pytest.raises(ServerError) as info:
            asyncio.run(handler.prepare(stub(str(BLUETOOTH))))
        assert "Maximum Number of" in str(info.value)


class TestMuonSetupSaysWhenSetupIsComplete:
    def test_it_registers_and_answers_from_the_state(self):
        harness = Harness(stored=state_with(
            language={"status": "done", "value": "en"}))
        assert muon_floor._setup_complete_source == harness.setup.complete_for_floor
        # Before the migration check has decided: not complete here
        assert harness.setup.doc is None
        assert not muon_floor.setup_complete()
        run(harness.start())
        assert harness.setup.doc is not None
        assert harness.setup.doc["state"] != "complete"
        assert not muon_floor.setup_complete()
        harness.setup.doc["state"] = "complete"
        assert muon_floor.setup_complete()
        harness.setup.doc["state"] = "new"
        assert not muon_floor.setup_complete()

    def test_close_hands_back_not_complete(self):
        harness = Harness(stored=state_with(
            language={"status": "done", "value": "en"}))
        run(harness.start())
        harness.setup.doc["state"] = "complete"
        assert muon_floor.setup_complete()
        run(harness.setup.close())
        assert muon_floor._setup_complete_source is None
        assert not muon_floor.setup_complete()

    def test_close_of_an_old_instance_leaves_the_new_one(self):
        old = Harness()
        new = Harness()
        run(old.setup.close())
        assert muon_floor._setup_complete_source == new.setup.complete_for_floor


# ---------------------------------------------------------------------------
# The level table: with [muon_access]
# ---------------------------------------------------------------------------


class TestTheBluetoothPrincipal:
    @pytest.mark.parametrize("user", TOKENS)
    def test_the_least_there_is_whatever_the_token_says(self, user):
        p = policy.resolve_principal(HTTP, BLUETOOTH, user, "open", HOME)
        assert p is not None
        assert (p.kind, p.level, p.role, p.home, p.identified) == (
            "bluetooth", policy.SIGNED_OUT_GUEST, "viewer", False, False)
        assert p.describe() == {
            "kind": "bluetooth", "level": "signed_out_guest", "role": "viewer",
            "home": False, "identified": False,
        }
        assert not AccessApi.trusted(p)

    def test_the_address_without_the_token_is_nobody(self):
        for user in (None, TRUSTED_USER, UserInfo("admin", "", source="moonraker")):
            assert policy.resolve_principal(
                HTTP, BLUETOOTH, user, "open", HOME) is None

    def test_it_is_never_at_home_even_if_home_held_its_address(self):
        odd_home = policy.HomeNetwork.from_interface_addresses(
            [("192.0.2.10", 24)])
        assert odd_home.contains(BLUETOOTH)
        p = policy.resolve_principal(HTTP, BLUETOOTH, LEGACY_TOKEN, "open",
                                     odd_home)
        assert p is not None and not p.home
        state = policy.AccessState(entry="open", owner="none", home=odd_home)
        # Not "a caller at home asking to be let in" (ACC-6) either
        assert not policy.at_home_unadmitted(
            [policy.ACTIONS["access_request"]], BLUETOOTH, state)

    def test_it_may_do_setup_and_the_link_and_no_other_row(self):
        p = policy.resolve_principal(HTTP, BLUETOOTH, LEGACY_TOKEN, "open", HOME)
        for state in access_states():
            assert sorted(policy.allowed_actions(p, state)) == ["owner", "setup"]


class TestTheTableHoldsBluetoothToSetup:
    """policy.check_access alone, without the floor in front of it."""

    @pytest.mark.parametrize("endpoint,rtype,args", OUTSIDE)
    def test_everything_but_setup_is_refused(self, endpoint, rtype, args):
        for state in access_states():
            policy.set_state(state)
            for user in TOKENS:
                with pytest.raises(ServerError) as info:
                    policy.check_access(endpoint, rtype, args, HTTP,
                                        BLUETOOTH, user)
                assert info.value.status_code == 403
                message = str(info.value)
                assert message.startswith("access-denied:"), message
                assert TABLE_REFUSAL in message, message

    @pytest.mark.parametrize("endpoint,rtype,args", SETUP_ROUTES)
    def test_the_setup_routes_pass_under_every_setting(self, endpoint, rtype,
                                                       args):
        # A strict preset puts "read" above a signed-out guest; the state
        # read is a setup route all the same.
        for state in access_states():
            policy.set_state(state)
            policy.check_access(endpoint, rtype, args, HTTP, BLUETOOTH,
                                LEGACY_TOKEN)

    def test_through_the_real_request_path_as_well(self):
        for state in access_states():
            policy.set_state(state)
            assert refusal("/server/muon/setup", RequestType.GET, {},
                           BLUETOOTH, LEGACY_TOKEN) is None
            assert refusal("/printer/print/start", RequestType.POST,
                           {"filename": "a.gcode"}, BLUETOOTH,
                           LEGACY_TOKEN) is not None

    def test_it_hears_muon_setup_and_nothing_else(self):
        policy.set_state(policy.AccessState(entry="open", owner="none",
                                            home=HOME))
        socket = SimpleNamespace(ip_addr=BLUETOOTH, user_info=LEGACY_TOKEN,
                                 transport_type=None)
        for name in ("gcode_response", "status_update", "klippy_ready",
                     "muon_access_changed", "filelist_changed"):
            assert policy.filter_notification(name, [{"x": 1}], socket) is None
        assert policy.filter_notification(
            "muon_setup_changed", [{"rev": 1}], socket) == [{"rev": 1}]
        setup_is_complete()
        assert policy.filter_notification(
            "gcode_response", ["ok"], socket) == ["ok"]


class TestAfterSetupIsComplete:
    """muon-link closes setup connections and admits only paired clients over
    Bluetooth. 192.0.2.2 is then such a client: its token decides, and it is
    never on the home network."""

    def test_a_paired_client_over_bluetooth_is_the_gateway_principal(self):
        setup_is_complete()
        p = policy.resolve_principal(HTTP, BLUETOOTH, LEGACY_TOKEN, "open", HOME)
        assert p is not None
        assert (p.kind, p.level, p.role, p.home) == (
            "gateway", policy.ADMIN, "operator", False)
        p = policy.resolve_principal(
            HTTP, BLUETOOTH, token("member", "viewer", True), "open", HOME)
        assert p is not None
        assert (p.kind, p.level, p.role, p.home) == (
            "gateway", policy.MEMBER, "viewer", False)

    def test_home_only_rows_are_refused_although_the_token_says_home(self):
        setup_is_complete()
        policy.set_state(policy.AccessState(
            entry="protected", owner="organisation", preset="relaxed",
            home=HOME))
        at_home = token("member", "operator", True)
        # The same token through 192.0.2.1 is at home ...
        assert refusal("/server/aux/wifi/connect", RequestType.POST, {},
                       SENTINEL, at_home) is None
        # ... and over Bluetooth it is not.
        message = refusal("/server/aux/wifi/connect", RequestType.POST, {},
                          BLUETOOTH, at_home)
        assert message is not None and "home network" in message
        # A trusted device keeps what it may do from away, and no more
        admin = token("admin", "operator", True)
        assert refusal("/server/aux/wifi/connect", RequestType.POST, {},
                       BLUETOOTH, admin) is None
        message = refusal("/server/files/copy", RequestType.POST,
                          {"source": "config/printer.cfg",
                           "dest": "config/old.cfg"}, BLUETOOTH, admin)
        assert message is not None and "home network" in message

    def test_setup_starting_again_holds_it_again(self):
        # A reset at the panel: muon_setup's state is "new" again
        harness = Harness(stored=state_with(
            language={"status": "done", "value": "en"}))
        run(harness.start())
        harness.setup.doc["state"] = "complete"
        p = policy.resolve_principal(HTTP, BLUETOOTH, LEGACY_TOKEN, "open", HOME)
        assert p is not None and p.kind == "gateway"
        harness.setup.doc["state"] = "new"
        p = policy.resolve_principal(HTTP, BLUETOOTH, LEGACY_TOKEN, "open", HOME)
        assert p is not None and p.kind == "bluetooth"


class TestTheTokenRequest:
    def test_a_bluetooth_token_may_name_a_principal_and_fits(self):
        line = json.dumps({
            "client": "a" * 64, "principal": "x" * 128,
            "level": "signed_out_guest", "role": "operator", "home": False,
            "transport": "bluetooth",
        }).encode()
        # muon_gateway's comment: the longest valid request is under 350
        assert len(line) < 350 <= muon_gateway.MAX_REQUEST
        client, address = muon_gateway.parse_token_request(line)
        assert (client, address) == ("a" * 64, muon_gateway.BLUETOOTH_SENTINEL)
        assert muon_gateway.parse_principal(line)["access_level"] == (
            "signed_out_guest")

    def test_the_floor_and_the_gateway_agree_on_the_address(self):
        assert muon_gateway.BLUETOOTH_SENTINEL == muon_floor.BLUETOOTH_SENTINEL
        assert muon_floor.is_bluetooth_address(BLUETOOTH)
        assert not muon_floor.is_bluetooth_address(SENTINEL)
        assert not muon_floor.is_bluetooth_address(None)
        assert not muon_floor.is_bluetooth_address("not an address")
