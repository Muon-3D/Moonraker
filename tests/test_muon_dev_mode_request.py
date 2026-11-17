"""KAN-3604: POST /server/muon/dev_mode/request.

Jack, 17 Nov 2026: an open printer lets Control do everything over any route;
only the first developer-mode warranty release is confirmed at the panel
(Aux decides that). Who may ASK is this side's rule: anyone on an open printer
with no owner, the owning account on a linked one, Protected respected.
"""
from __future__ import annotations

import asyncio
import ipaddress
from typing import Any, Optional

import pytest

from moonraker import muon_access_policy as policy
from moonraker import muon_floor
from moonraker.common import RequestType
from moonraker.utils.exceptions import ServerError

from test_aux_api_proxy import (
    FakeHttpClient, FakeResponse, FakeWebRequest, make_proxy,
)
from test_muon_access import (  # noqa: F401  (the autouse reset is reused)
    HOTSPOT, HTTP, LAN, LOOPBACK, PASSWORD_USER, PUBLIC, SENTINEL,
    TRUSTED_USER, _api, _reset, gateway, state,
)

ENDPOINT = "/server/muon/dev_mode/request"
BLUETOOTH = ipaddress.ip_address("192.0.2.2")


def ask(ip_addr: Any, user: Any, endpoint: str = ENDPOINT) -> Optional[str]:
    """The 403 message, or None when the handler was reached."""
    api = _api(endpoint)
    try:
        asyncio.run(api.request({"enabled": True}, RequestType.POST, HTTP,
                                ip_addr, user))
    except ServerError as err:
        assert err.status_code == 403
        return str(err)
    return None


def printer(entry: str, owner: str, **kw: Any) -> None:
    policy.set_state(state(entry=entry, owner=owner, **kw))


OPEN, PROTECTED = policy.ENTRY_OPEN, policy.ENTRY_PROTECTED
NOBODY, LINKED = policy.OWNER_NONE, policy.OWNER_ACCOUNT


class TestWhoMayAsk:
    def test_the_route_is_its_own_row(self):
        names = {a.name for a in policy.classify(ENDPOINT, RequestType.POST, {})}
        assert names == {"dev_mode_request"}

    @pytest.mark.parametrize("who", ["anyone", "password", "guest", "hotspot"])
    def test_an_open_printer_lets_any_client(self, who):
        printer(OPEN, NOBODY)
        ip, user = {
            "anyone": (LAN, None),
            "hotspot": (HOTSPOT, None),
            "password": (LAN, PASSWORD_USER),
            "guest": (SENTINEL, gateway("signed_out_guest", "operator")),
        }[who]
        assert ask(ip, user) is None

    def test_the_panel_always_may(self):
        printer(PROTECTED, LINKED)
        assert ask(LOOPBACK, TRUSTED_USER) is None

    def test_a_linked_printer_lets_the_owning_account_only(self):
        printer(OPEN, LINKED)
        assert ask(SENTINEL, gateway("admin", "operator")) is None
        # a stranger at home, a guest, a member, and the printer password
        assert "dev_mode_request" in ask(LAN, None)
        assert "dev_mode_request" in ask(LAN, PASSWORD_USER)
        assert "dev_mode_request" in ask(
            SENTINEL, gateway("signed_out_guest", "operator"))
        assert "dev_mode_request" in ask(
            SENTINEL, gateway("member", "operator"))

    def test_a_viewer_cannot_ask_even_as_the_owner(self):
        printer(OPEN, LINKED)
        assert ask(SENTINEL, gateway("admin", "viewer")) is not None

    @pytest.mark.parametrize("owner", [NOBODY, LINKED])
    def test_protected_admits_no_unidentified_caller(self, owner):
        printer(PROTECTED, owner)
        assert ask(LAN, None) is not None
        assert ask(HOTSPOT, None) is not None
        assert ask(PUBLIC, None) is not None

    def test_protected_with_an_owner_lets_the_owner_not_the_password(self):
        printer(PROTECTED, LINKED)
        assert ask(SENTINEL, gateway("admin", "operator")) is None
        assert ask(LAN, PASSWORD_USER) is not None

    @pytest.mark.parametrize("preset", ["relaxed", "standard", "strict"])
    def test_no_preset_opens_a_linked_printer(self, preset):
        printer(OPEN, LINKED, preset=preset)
        assert ask(LAN, None) is not None
        assert ask(SENTINEL, gateway("member", "operator")) is not None
        assert ask(SENTINEL, gateway("admin", "operator")) is None

    def test_an_override_cannot_open_it(self):
        # the row is fixed: a stored override of it is ignored
        printer(OPEN, LINKED,
                overrides={"dev_mode_request": policy.SIGNED_OUT_GUEST})
        assert ask(LAN, None) is not None

    def test_a_phone_still_in_bluetooth_setup_is_refused(self):
        printer(OPEN, NOBODY)
        user = gateway("admin", "operator")
        with pytest.raises(ServerError):
            muon_floor.check_bluetooth(ENDPOINT, HTTP, BLUETOOTH, user)

    def test_an_unknown_owner_is_panel_only_not_open(self):
        printer(OPEN, policy.OWNER_UNKNOWN)
        assert ask(LAN, None) is not None


class TestNoRawAuxPassThrough:
    def test_the_aux_route_is_not_mirrored_under_server_aux(self):
        """Aux publishes /dev_mode/request. The `dev_mode` access row is
        delegated to Aux, so a mirror at /server/aux/dev_mode/request would
        skip the owner rule: it must not exist, and its sibling still does."""
        proxy, server, _client = make_proxy()
        proxy._register_from_spec({"paths": {
            "/dev_mode": {"post": {}},
            "/dev_mode/request": {"post": {"requestBody": {}}},
        }})
        assert "/server/aux/dev_mode/request" not in server.paths()
        assert "/server/aux/dev_mode" in server.paths()
        assert ENDPOINT in server.paths()

    def test_the_handler_only_ever_calls_aux_dev_mode_request(self):
        proxy, server, client = make_proxy(
            FakeHttpClient(FakeResponse({"enabled": True})))
        handler = server.handler_for(ENDPOINT)
        asyncio.run(handler(FakeWebRequest("POST", {"enabled": True})))
        kind, call = client.calls[-1]
        assert kind == "post"
        assert call["url"] == "http://127.0.0.1:6789/dev_mode/request"
        assert call["body"] == '{"enabled": true}'

    def test_it_forwards_nothing_but_the_flag(self):
        proxy, server, client = make_proxy(
            FakeHttpClient(FakeResponse({"enabled": False})))
        handler = server.handler_for(ENDPOINT)
        asyncio.run(handler(FakeWebRequest(
            "POST", {"enabled": False, "path": "/bms/ship", "challenge_id": "x",
                     "waiver_acknowledged": True})))
        assert client.last["body"] == '{"enabled": false}'


class TestOffTheFloor:
    def test_it_is_not_on_the_sec2_floor_like_the_get(self):
        assert not muon_floor.is_floor_endpoint(ENDPOINT)
        assert not muon_floor.is_floor_endpoint("/server/muon/dev_mode")
        assert not muon_floor.is_protected_endpoint(ENDPOINT)


class _Refused(FakeResponse):
    def raise_for_status(self, message: Optional[str] = None) -> None:
        raise ServerError(message or "Forbidden", 403)


class TestTheHandler:
    def _call(self, response, args=None):
        proxy, server, client = make_proxy(FakeHttpClient(response))
        handler = server.handler_for(ENDPOINT)
        return asyncio.run(handler(FakeWebRequest(
            "POST", {"enabled": True} if args is None else args)))

    def test_the_route_is_post_only(self):
        _p, server, _c = make_proxy()
        assert server.verbs_for(ENDPOINT) == ["POST"]

    def test_a_challenge_is_returned_as_challenge_id(self):
        out = self._call(FakeResponse({
            "enabled": None, "challenge_id": "c-1", "expires_at": 9.0,
            "expires_in_seconds": 60.0, "instruction": "x"}))
        assert out == {"challenge_id": "c-1"}

    def test_an_applied_change_is_returned_as_enabled(self):
        assert self._call(FakeResponse({"enabled": True})) == {"enabled": True}
        assert self._call(FakeResponse({"enabled": False}),
                          {"enabled": False}) == {"enabled": False}

    def test_panel_only_is_a_plain_403_code(self):
        resp = _Refused({"detail": {"code": "panel_only", "message": "long"}},
                        status_code=403)
        with pytest.raises(Exception) as err:
            self._call(resp)
        assert err.value.status_code == 403
        assert str(err.value) == "panel_only"

    @pytest.mark.parametrize("bad", [None, "true", 1, "", [True]])
    def test_enabled_must_be_a_real_boolean(self, bad):
        with pytest.raises(Exception) as err:
            self._call(FakeResponse({"enabled": True}), {"enabled": bad})
        assert err.value.status_code == 400
