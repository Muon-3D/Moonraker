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
            "POST", {"enabled": False, "path": "/bms/ship",
                     "waiver_acknowledged": True, "signer_name": "x",
                     "reentry_token": "t"})))
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

    def test_the_route_is_get_and_post_only(self):
        _p, server, _c = make_proxy()
        assert server.verbs_for(ENDPOINT) == ["GET", "POST"]

    def test_a_challenge_is_returned_with_what_control_reads(self):
        out = self._call(FakeResponse({
            "enabled": None, "challenge_id": "c-1", "expires_at": 9.0,
            "expires_in_seconds": 60.0, "instruction": "x"}))
        assert out["challenge_id"] == "c-1"
        assert out["enabled"] is True
        assert out["expires_in_seconds"] == 60.0
        assert out["instruction"] == "x"
        assert "expires_at" not in out

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
        assert str(err.value) == "dev-mode:panel_only: long"

    @pytest.mark.parametrize("bad", [None, "true", 1, "", [True]])
    def test_enabled_must_be_a_real_boolean(self, bad):
        with pytest.raises(Exception) as err:
            self._call(FakeResponse({"enabled": True}), {"enabled": bad})
        assert err.value.status_code == 400


# --------------------------------------------------------------------------
# KAN-4351: GET, and the whole flow on the one route
# --------------------------------------------------------------------------

CHALLENGE = "abcdefghij0123456789"
WAIVER = {"version": "2026-11-v1", "text": "Turning this on ends the warranty."}


class _Answered(FakeResponse):
    """An Aux answer with a status: raise_for_status raises like http_client."""

    def raise_for_status(self, message: Optional[str] = None) -> None:
        if self.status_code >= 400:
            raise ServerError(message or "refused", self.status_code)


class AuxStub(FakeHttpClient):
    """An Aux API that answers by path, so one handler call may make two."""

    def __init__(self, routes: dict) -> None:
        super().__init__()
        self.routes = routes

    async def _record(self, kind: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((kind, kwargs))
        path = kwargs["url"].replace("http://127.0.0.1:6789", "")
        reply = self.routes.get(path, _Answered({"detail": "nope"}, status_code=404))
        return reply

    def paths(self, kind: Optional[str] = None) -> list:
        return [c["url"].replace("http://127.0.0.1:6789", "")
                for k, c in self.calls if kind in (None, k)]


class _GatewayRequest(FakeWebRequest):
    """A request as Moonraker's WebRequest carries who is asking."""

    def __init__(self, action, args=None, ip=None, user=None, transport=HTTP):
        super().__init__(action, args, ip=None)
        self._ip = ip
        self._user = user
        self.transport = transport

    def get_current_user(self):
        return self._user


def call(routes, request):
    proxy, server, client = make_proxy(AuxStub(routes))
    proxy.server.components["muon_access"] = type(
        "_A", (), {"owner_email": "owner@example.com"})()
    handler = server.handler_for(ENDPOINT)
    return asyncio.run(handler(request)), client


class TestGetWhoMayAsk:
    ROUTES = {"/dev_mode/waiver": _Answered(WAIVER)}

    def ask_as(self, ip, user):
        out, client = call(self.ROUTES, _GatewayRequest("GET", ip=ip, user=user))
        assert client.paths() == ["/dev_mode/waiver"]
        return out

    def test_the_owner_of_a_linked_printer(self):
        printer(OPEN, LINKED)
        out = self.ask_as(SENTINEL, gateway("admin", "operator"))
        assert out == {
            "as_owner": True, "may_ask": True,
            "owner": {"linked": True, "account": "owner@example.com"},
            "waiver": WAIVER,
        }

    def test_a_stranger_is_told_who_may_instead_of_being_refused(self):
        printer(OPEN, LINKED)
        out = self.ask_as(LAN, None)
        assert out["as_owner"] is False
        assert out["may_ask"] is False
        assert out["owner"] == {"linked": True, "account": "owner@example.com"}

    def test_a_member_is_not_the_owner(self):
        printer(OPEN, LINKED)
        out = self.ask_as(SENTINEL, gateway("member", "operator"))
        assert (out["as_owner"], out["may_ask"]) == (False, False)

    def test_an_open_printer_with_no_owner_lets_anyone_at_home_ask(self):
        printer(OPEN, NOBODY)
        out = self.ask_as(LAN, None)
        assert (out["as_owner"], out["may_ask"]) == (False, True)
        assert out["owner"] == {"linked": False, "account": None}

    def test_the_panel_counts_as_the_owner(self):
        printer(PROTECTED, LINKED)
        out = self.ask_as(LOOPBACK, TRUSTED_USER)
        assert (out["as_owner"], out["may_ask"]) == (True, True)

    def test_protected_admits_no_unidentified_caller(self):
        printer(PROTECTED, NOBODY)
        out = self.ask_as(LAN, None)
        assert (out["as_owner"], out["may_ask"]) == (False, False)

    def test_an_owner_not_yet_known_is_null_not_false(self):
        printer(OPEN, policy.OWNER_UNKNOWN)
        out = self.ask_as(LAN, None)
        assert out["owner"] == {"linked": None, "account": None}
        assert out["may_ask"] is False

    def test_no_policy_loaded_asks_nothing_of_anyone(self):
        policy.set_state(None)
        out = self.ask_as(LAN, None)
        assert out["may_ask"] is False
        assert out["owner"]["linked"] is None

    def test_the_waiver_is_null_when_aux_has_none_to_show(self):
        printer(OPEN, NOBODY)
        out, _c = call({}, _GatewayRequest("GET", ip=LAN))
        assert out["waiver"] is None

    def test_a_get_is_a_read_so_the_table_lets_a_stranger_reach_it(self):
        printer(OPEN, LINKED)
        api = _api(ENDPOINT)
        out = asyncio.run(api.request({}, RequestType.GET, HTTP, LAN, None))
        assert out == {"reached": ENDPOINT}


class TestGetPoll:
    def poll(self, reply, challenge=CHALLENGE):
        routes = {f"/dev_mode/consent/{CHALLENGE}": reply}
        return call(routes, _GatewayRequest(
            "GET", {"challenge_id": challenge}, ip=SENTINEL))

    def test_not_yet_answered(self):
        out, client = self.poll(_Answered({
            "challenge_id": CHALLENGE, "confirmed": False, "expires_at": 9.0,
            "refused": False}))
        assert out == {"confirmed": False, "refused": False}
        assert client.paths("get") == [f"/dev_mode/consent/{CHALLENGE}"]
        assert [k for k, _c in client.calls] == ["get"]

    def test_confirmed(self):
        out, _c = self.poll(_Answered({"confirmed": True, "expires_at": 9.0}))
        assert out == {"confirmed": True, "refused": False}

    def test_refused_at_the_printer(self):
        out, _c = self.poll(_Answered({"confirmed": False, "refused": True}))
        assert out == {"confirmed": False, "refused": True}

    def test_an_expired_challenge_is_a_coded_404(self):
        with pytest.raises(Exception) as err:
            self.poll(_Answered({"detail": "gone"}, status_code=404))
        assert err.value.status_code == 404
        assert str(err.value).startswith("dev-mode:unknown_challenge: ")

    @pytest.mark.parametrize("bad", ["../../wifi", "short", "a/b" * 8, "", "x" * 200])
    def test_a_challenge_id_that_is_not_one_never_reaches_aux(self, bad):
        proxy, server, client = make_proxy(AuxStub({}))
        handler = server.handler_for(ENDPOINT)
        with pytest.raises(Exception) as err:
            asyncio.run(handler(FakeWebRequest("GET", {"challenge_id": bad})))
        assert err.value.status_code == 400
        assert client.calls == []

    def test_an_unreadable_answer_is_a_502(self):
        with pytest.raises(Exception) as err:
            self.poll(_Answered({"nothing": 1}))
        assert err.value.status_code == 502


class TestPostRequestThenComplete:
    def test_a_first_release_opens_a_challenge_with_its_waiver(self):
        out, client = call({
            "/dev_mode/request": _Answered({
                "challenge_id": CHALLENGE, "expires_at": 9.0,
                "expires_in_seconds": 120.0, "instruction": "Press Confirm"}),
            "/dev_mode/waiver": _Answered(WAIVER),
        }, FakeWebRequest("POST", {"enabled": True}))
        assert out == {
            "challenge_id": CHALLENGE, "enabled": True,
            "expires_in_seconds": 120.0, "instruction": "Press Confirm",
            "waiver": WAIVER,
        }

    def test_a_change_applied_directly_is_passed_through(self):
        # KAN-4352: an admin build answers {enabled} with no challenge.
        out, client = call({
            "/dev_mode/request": _Answered({"enabled": True}),
        }, FakeWebRequest("POST", {"enabled": True}))
        assert out == {"enabled": True}
        assert client.paths() == ["/dev_mode/request"]

    def test_leaving_opens_no_waiver_lookup(self):
        out, client = call({
            "/dev_mode/request": _Answered({
                "challenge_id": CHALLENGE, "enabled": False,
                "expires_in_seconds": 60.0, "instruction": "Press"}),
        }, FakeWebRequest("POST", {"enabled": False}))
        assert out["enabled"] is False
        assert "waiver" not in out
        assert client.paths() == ["/dev_mode/request"]

    def test_the_confirmed_change_is_made_through_aux(self):
        out, client = call({
            "/dev_mode": _Answered({"enabled": True, "core_cfg": "/x/core.cfg"}),
        }, FakeWebRequest("POST", {
            "enabled": True, "challenge_id": CHALLENGE,
            "waiver_acknowledged": True, "waiver_version": WAIVER["version"],
            "signer_name": "x", "reentry_token": "t", "path": "/bms/ship"}))
        assert out == {"enabled": True}
        assert client.paths() == ["/dev_mode"]
        kind, sent = client.calls[-1]
        assert kind == "post"
        import json
        assert json.loads(sent["body"]) == {
            "enabled": True, "challenge_id": CHALLENGE,
            "waiver_acknowledged": True, "waiver_version": WAIVER["version"]}

    def test_a_completion_that_leaves_sends_no_waiver(self):
        out, client = call({
            "/dev_mode": _Answered({"enabled": False}),
        }, FakeWebRequest("POST", {
            "enabled": False, "challenge_id": CHALLENGE,
            "waiver_acknowledged": True, "waiver_version": "v"}))
        assert out == {"enabled": False}
        import json
        assert json.loads(client.calls[-1][1]["body"]) == {
            "enabled": False, "challenge_id": CHALLENGE}

    def test_a_waiver_not_acknowledged_is_sent_as_not_acknowledged(self):
        _o, client = call({
            "/dev_mode": _Answered({"enabled": True}),
        }, FakeWebRequest("POST", {
            "enabled": True, "challenge_id": CHALLENGE,
            "waiver_acknowledged": "yes"}))
        import json
        assert json.loads(client.calls[-1][1]["body"])[
            "waiver_acknowledged"] is False

    def test_a_malformed_challenge_id_is_a_400_and_reaches_nothing(self):
        proxy, server, client = make_proxy(AuxStub({}))
        handler = server.handler_for(ENDPOINT)
        with pytest.raises(Exception) as err:
            asyncio.run(handler(FakeWebRequest(
                "POST", {"enabled": True, "challenge_id": "x"})))
        assert err.value.status_code == 400
        assert client.calls == []

    @pytest.mark.parametrize("status,detail,code", [
        (428, "Needs a confirmation at the printer", "consent_required"),
        (429, "Too many", "throttled"),
        (403, {"error": "waiver_required", "message": "Show it"},
         "waiver_required"),
        (409, {"error": "waiver_out_of_date", "message": "Old"},
         "waiver_out_of_date"),
        (403, {"code": "panel_only", "message": "At the screen"}, "panel_only"),
    ])
    def test_aux_refusals_reach_control_as_coded_messages(
            self, status, detail, code):
        with pytest.raises(Exception) as err:
            call({"/dev_mode": _Answered({"detail": detail},
                                         status_code=status)},
                 FakeWebRequest("POST", {
                     "enabled": True, "challenge_id": CHALLENGE,
                     "waiver_acknowledged": True, "waiver_version": "v"}))
        assert err.value.status_code == status
        assert str(err.value).startswith(f"dev-mode:{code}: ")

    def test_an_aux_that_is_not_answering_is_a_503(self):
        class Down(FakeResponse):
            def raise_for_status(self, message=None):
                raise ServerError("HTTP Request Error", 599)
        with pytest.raises(Exception) as err:
            call({"/dev_mode": Down()}, FakeWebRequest("POST", {
                "enabled": True, "challenge_id": CHALLENGE}))
        assert err.value.status_code == 503


class TestOtherMethods:
    @pytest.mark.parametrize("verb", ["PUT", "DELETE", "PATCH"])
    def test_the_route_is_registered_for_get_and_post_only(self, verb):
        _p, server, _c = make_proxy()
        assert verb not in server.verbs_for(ENDPOINT)
        assert set(server.verbs_for(ENDPOINT)) == {"GET", "POST"}

    def test_moonraker_serves_only_those_two_verbs_on_it(self):
        """Tornado answers any verb the route was not registered for with 405."""
        from moonraker.common import APIDefinition
        _p, server, _c = make_proxy()

        async def callback(web_request):
            return {}

        api = APIDefinition.create(
            ENDPOINT, server.verbs_for(ENDPOINT), callback)
        assert api.request_types == RequestType.GET | RequestType.POST
        assert RequestType.DELETE not in api.request_types
