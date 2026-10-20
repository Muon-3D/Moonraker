"""KAN-547: the owner's developer-mode request route.

`POST /server/muon/dev_mode/request` opens a developer-mode challenge at the
printer's panel, `GET` follows it, and `POST` with the challenge id completes
it. The Aux API decides who may ask (MuonOS #378, dev_mode_owner): on a linked
printer only the owner. This route is the one place that can tell Aux a
request IS the owner's, by setting `X-Muon-Access-Level: admin`.

What these tests pin:

* the header is set for a gateway session whose token names the admin level
  and the Operator role, and for nobody else: not a member, not a console
  Operator session, not a guest, not a Viewer, not the panel, not a LAN
  browser with the printer password;
* the trap: a gateway token that names no level is NOT the owner here,
  although muon_access_policy reads that token as admin;
* Aux's refusal reaches the caller with its code first, so a client can say
  who may ask;
* nothing the caller sends is forwarded beyond the fields Aux takes.

Unit tests: no server, no sockets, no Aux API. The fake Aux below applies
#378's rule itself (a linked printer refuses a request without the owner
header), so "refused" here is the same answer a real printer gives.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
from typing import Any, Dict, List, Optional, Tuple

import pytest

from moonraker import muon_access_policy as policy
from moonraker import muon_floor
from moonraker.common import RequestType, UserInfo, WebRequest
from moonraker.components import aux_api_proxy
from moonraker.components.aux_api_proxy import AuxAutoProxy
from moonraker.components.muon_gateway import (
    SENTINEL, GatewayUser, parse_principal, parse_request,
)
from moonraker.utils import ServerError

ENDPOINT = "/server/muon/dev_mode/request"
LOOPBACK = ipaddress.ip_address("127.0.0.1")
LAN = ipaddress.ip_address("192.168.1.50")
OWNER_ACCOUNT = "jack@example.com"
CHALLENGE = "Zb3s0VJpXkq2c1yN8dRtLw4mPa7oQe6F"  # token_urlsafe(24)'s shape
WAIVER = {"version": "2026-08-1-norecord", "text": "Developer mode unlocks..."}


# --------------------------------------------------------------------------
# Who is asking
# --------------------------------------------------------------------------

def minted(fields: Dict[str, Any]) -> GatewayUser:
    """The user a token carries, built the way muon_gateway._handle builds it
    from muon-link's request line, so the field names cannot drift."""
    line = json.dumps(dict({"client": "ab12cd34"}, **fields)).encode()
    client = parse_request(line)
    return GatewayUser(
        username=f"muon-link:{client[:16]}", password="",
        source="muon_gateway", **parse_principal(line),
    )


OWNER_AWAY = minted({"principal": "device:owner-phone", "level": "admin",
                     "role": "operator", "home": False})
OWNER_AT_HOME = minted({"principal": "device:owner-laptop", "level": "admin",
                        "role": "operator", "home": True})
MEMBER = minted({"principal": "acct:member", "level": "member",
                 "role": "operator", "home": False})
# app.muon3d.com: a console grant, Operator, never the admin level (NET-11)
CONSOLE_OPERATOR = minted({"principal": "acct:jack", "level": "signed_in_guest",
                           "role": "operator", "home": False})
OPEN_GUEST = minted({"level": "signed_out_guest", "role": "operator",
                     "home": True})
ADMIN_VIEWER = minted({"principal": "device:owner-tv", "level": "admin",
                       "role": "viewer", "home": True})
# The muon-link MuonOS main pins: it sends {"client": ...} and nothing else.
NO_PRINCIPAL = minted({})
PASSWORD_USER = UserInfo("admin", "", source="moonraker",
                         groups=[muon_floor.PANEL_LOGIN_GROUP])
TRUSTED_USER = UserInfo("_TRUSTED_USER_", "")


def request(
    action: str, args: Dict[str, Any], ip: Any = SENTINEL,
    user: Optional[UserInfo] = OWNER_AWAY,
) -> WebRequest:
    rtype = RequestType.GET if action == "GET" else RequestType.POST
    return WebRequest(ENDPOINT, args, rtype, ip_addr=ip, user=user)


# --------------------------------------------------------------------------
# A fake Aux API that applies #378's rule
# --------------------------------------------------------------------------

class Response:
    def __init__(self, status: int, payload: Any = None) -> None:
        self.status_code = status
        self._payload = payload
        self.headers: Dict[str, str] = {}
        self.content = b""

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no body")
        return self._payload

    def raise_for_status(self, message: Optional[str] = None) -> None:
        if self.status_code >= 400:
            raise ServerError(message or "error", self.status_code)


class FakeAux:
    """Answers the four developer-mode calls the route makes, and records
    each one. `linked` is muon-link's answer; `dev_mode` the current state."""

    def __init__(self, linked: bool = True, dev_mode: bool = True) -> None:
        self.linked = linked
        self.dev_mode = dev_mode
        self.calls: List[Dict[str, Any]] = []
        self.answer: Optional[Response] = None
        self.confirmed = False

    def paths(self) -> List[Tuple[str, str]]:
        return [(c["method"], c["path"]) for c in self.calls]

    def owner_header(self, call: Dict[str, Any]) -> Optional[str]:
        return call["headers"].get("X-Muon-Access-Level")

    def refusal(self, headers: Dict[str, Any]) -> Optional[Response]:
        if not self.linked:
            return None
        if headers.get("X-Muon-Access-Level") == "admin":
            return None
        return Response(403, {"detail": {
            "error": "owner_required",
            "message": f"Only {OWNER_ACCOUNT} can change developer mode on "
                       "this printer.",
            "account": OWNER_ACCOUNT,
        }})

    async def request(self, **kwargs: Any) -> Response:
        url = kwargs["url"]
        assert url.startswith(aux_api_proxy.FASTAPI_ROOT)
        path = url[len(aux_api_proxy.FASTAPI_ROOT):]
        body = json.loads(kwargs["body"]) if kwargs.get("body") else None
        call = dict(method=kwargs["method"], path=path, body=body,
                    headers=dict(kwargs.get("headers") or {}),
                    timeout=kwargs.get("request_timeout"))
        self.calls.append(call)
        if self.answer is not None:
            return self.answer
        method = kwargs["method"]
        if (method, path) == ("GET", "/dev_mode/waiver"):
            return Response(200, dict(WAIVER))
        if (method, path) == ("POST", "/dev_mode/consent"):
            refused = self.refusal(call["headers"])
            if refused is not None:
                return refused
            enabled = body["enabled"] if body else True
            if enabled == self.dev_mode:
                return Response(409, {"detail": {
                    "error": "no_change",
                    "message": "Developer mode is already on."}})
            return Response(200, {
                "challenge_id": CHALLENGE, "expires_at": 1000.0,
                "expires_in_seconds": 120.0, "enabled": enabled,
                "instruction": "Press the knob on the printer.",
            })
        if (method, path) == ("GET", f"/dev_mode/consent/{CHALLENGE}"):
            return Response(200, {
                "challenge_id": CHALLENGE, "confirmed": self.confirmed,
                "refused": False, "expires_at": 1000.0, "enabled": False,
            })
        if (method, path) == ("POST", "/dev_mode"):
            refused = self.refusal(call["headers"])
            if refused is not None:
                return refused
            if not self.confirmed:
                return Response(428, {"detail": (
                    "Confirm this on the printer's panel first.")})
            self.dev_mode = body["enabled"]
            answer = {"enabled": self.dev_mode, "core_cfg": "/opt/core.cfg",
                      "guard_armed": True, "released": True}
            if self.dev_mode:
                answer["reentry_token"] = "rt-secret"
            return Response(200, answer)
        return Response(404, {"detail": "Not Found"})


class FakeLink:
    """Moonraker's muon_link: muon-link's GET /link, as status()."""

    def __init__(self, answer: Any) -> None:
        self.answer = answer

    async def status(self) -> Any:
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


LINKED = {"phase": "linked", "account": OWNER_ACCOUNT, "connected": True}
UNLINKED = {"phase": "unlinked"}


class FakeServer:
    def __init__(self, http_client: Any, link: Any = None) -> None:
        self.endpoints: Dict[str, Tuple[List[str], Any]] = {}
        self.components: Dict[str, Any] = {
            "http_client": http_client, "database": FakeDatabase(),
        }
        if link is not None:
            self.components["muon_link"] = link

    def lookup_component(self, name: str, default: Any = None) -> Any:
        return self.components.get(name, default)

    def register_endpoint(self, path: str, verbs: List[str], handler: Any
                          ) -> None:
        self.endpoints[path] = (verbs, handler)

    def error(self, message: str, status_code: int = 500) -> ServerError:
        return ServerError(message, status_code)


class FakeDatabase:
    def register_local_namespace(self, namespace: str, forbidden: bool = False
                                 ) -> None:
        pass


class FakeConfig:
    def __init__(self, server: FakeServer) -> None:
        self.server = server

    def get_server(self) -> FakeServer:
        return self.server


@pytest.fixture(autouse=True)
def _token(monkeypatch, tmp_path):
    token = tmp_path / "token"
    token.write_text("boot-token\n")
    monkeypatch.setattr(aux_api_proxy, "AUX_TOKEN_FILE", token)


def make(
    aux: Optional[FakeAux] = None, link: Any = None,
) -> Tuple[AuxAutoProxy, FakeAux, Any]:
    aux = aux or FakeAux()
    server = FakeServer(aux, link)
    proxy = AuxAutoProxy(FakeConfig(server))
    verbs, handler = server.endpoints[ENDPOINT]
    assert sorted(verbs) == ["GET", "POST"]
    return proxy, aux, handler


def call(handler: Any, web_request: WebRequest) -> Any:
    return asyncio.run(handler(web_request))


def refused(handler: Any, web_request: WebRequest) -> ServerError:
    with pytest.raises(ServerError) as info:
        call(handler, web_request)
    return info.value


# --------------------------------------------------------------------------
# Who the route vouches for
# --------------------------------------------------------------------------

def test_the_owner_through_the_gateway_is_vouched_for():
    _proxy, aux, handler = make()

    answer = call(handler, request("POST", {"enabled": False}))

    opened = aux.calls[-1]
    assert (opened["method"], opened["path"]) == ("POST", "/dev_mode/consent")
    assert opened["body"] == {"enabled": False}
    assert opened["headers"]["X-Muon-Access-Level"] == "admin"
    assert opened["headers"]["X-Muon-Principal"] == "device:owner-phone"
    assert opened["headers"]["X-Aux-Api-Key"] == "boot-token"
    assert answer["challenge_id"] == CHALLENGE
    assert answer["enabled"] is False
    assert answer["as_owner"] is True
    assert "waiver" not in answer  # turning off needs no waiver (DEV-5)


def test_a_lan_session_signed_in_as_the_owner_is_the_owner():
    """A page at home that reached the printer through muon-link as one of the
    owner's devices: the same level, home true."""
    _proxy, aux, handler = make()

    answer = call(handler, request("POST", {"enabled": False},
                                   user=OWNER_AT_HOME))

    assert aux.owner_header(aux.calls[-1]) == "admin"
    assert answer["as_owner"] is True


@pytest.mark.parametrize("who, ip, user", [
    ("a member", SENTINEL, MEMBER),
    ("app.muon3d.com's Operator session", SENTINEL, CONSOLE_OPERATOR),
    ("an Open guest", SENTINEL, OPEN_GUEST),
    ("an admin device with the Viewer role", SENTINEL, ADMIN_VIEWER),
    ("the panel, on loopback", LOOPBACK, None),
    ("a LAN browser with the printer password", LAN, PASSWORD_USER),
    ("anyone at home", LAN, TRUSTED_USER),
    ("an admin token from anywhere but the sentinel", LAN, OWNER_AWAY),
], ids=lambda value: value if isinstance(value, str) else "")
def test_everyone_else_is_refused_on_a_linked_printer(who, ip, user):
    _proxy, aux, handler = make(FakeAux(linked=True))

    error = refused(handler, request("POST", {"enabled": False}, ip, user))

    sent = aux.calls[-1]
    assert not any(h.startswith("X-Muon-") for h in sent["headers"]), who
    assert error.status_code == 403
    assert str(error).startswith("dev-mode:owner_required: "), str(error)
    assert OWNER_ACCOUNT in str(error)


def test_a_gateway_that_names_no_principal_is_not_the_owner():
    """The trap. muon-link before it names a principal sends {"client": ...}
    only, and muon_access_policy reads that token as admin with Operator, so
    that such a muon-link keeps working. This route must not: every remote
    session, app.muon3d.com's included, would be the owner."""
    assert policy._gateway_principal(NO_PRINCIPAL).level == policy.ADMIN
    _proxy, aux, handler = make(FakeAux(linked=True))

    error = refused(handler, request("POST", {"enabled": True},
                                     user=NO_PRINCIPAL))

    assert aux.owner_header(aux.calls[-1]) is None
    assert error.status_code == 403
    assert str(error).startswith("dev-mode:owner_required: ")


def test_a_gateway_user_carrying_a_bogus_principal_names_no_principal():
    user = GatewayUser("muon-link:ab12", "", source="muon_gateway",
                       principal="bad\r\nX-Injected: 1",
                       access_level="admin", access_role="operator")

    headers = aux_api_proxy.owner_headers(SENTINEL, user)

    assert headers == {"X-Muon-Access-Level": "admin"}


def test_only_the_gateways_own_users_count():
    impostor = GatewayUser("muon-link:ab12", "", source="moonraker",
                           access_level="admin", access_role="operator")

    assert aux_api_proxy.owner_headers(SENTINEL, impostor) == {}
    assert aux_api_proxy.owner_headers(SENTINEL, None) == {}
    assert aux_api_proxy.owner_headers(None, OWNER_AWAY) == {}


def test_on_a_printer_nobody_owns_anyone_may_ask():
    """Aux takes the request; the route adds no owner claim for a guest."""
    _proxy, aux, handler = make(FakeAux(linked=False))

    answer = call(handler, request("POST", {"enabled": False}, LAN,
                                   TRUSTED_USER))

    assert aux.owner_header(aux.calls[-1]) is None
    assert answer["challenge_id"] == CHALLENGE
    assert answer["as_owner"] is False


# --------------------------------------------------------------------------
# Turning on: the waiver comes with the request
# --------------------------------------------------------------------------

def test_turning_on_reads_the_waiver_before_the_panel_is_asked():
    _proxy, aux, handler = make(FakeAux(dev_mode=False))

    answer = call(handler, request("POST", {"enabled": True}))

    assert aux.paths() == [("GET", "/dev_mode/waiver"),
                           ("POST", "/dev_mode/consent")]
    # The read carries no owner claim: it asks nothing of anyone.
    assert aux.owner_header(aux.calls[0]) is None
    assert answer["waiver"] == WAIVER
    assert answer["enabled"] is True


def test_no_waiver_no_prompt():
    aux = FakeAux(dev_mode=False)
    aux.answer = Response(500)  # Aux not answering: no body at all
    _proxy, aux, handler = make(aux)

    error = refused(handler, request("POST", {"enabled": True}))

    assert aux.paths() == [("GET", "/dev_mode/waiver")]
    assert error.status_code == 503
    assert str(error).startswith("dev-mode:unavailable: ")


def test_asking_for_the_state_it_is_already_in_is_no_change():
    _proxy, _aux, handler = make(FakeAux(dev_mode=True))

    error = refused(handler, request("POST", {"enabled": True}))

    assert error.status_code == 409
    assert str(error).startswith("dev-mode:no_change: ")


# --------------------------------------------------------------------------
# Following the answer, and completing it
# --------------------------------------------------------------------------

def test_the_poll_reads_the_challenge_and_claims_nothing():
    aux = FakeAux()
    aux.confirmed = True
    _proxy, aux, handler = make(aux)

    answer = call(handler, request("GET", {"challenge_id": CHALLENGE},
                                   user=CONSOLE_OPERATOR))

    assert aux.paths() == [("GET", f"/dev_mode/consent/{CHALLENGE}")]
    assert aux.owner_header(aux.calls[0]) is None
    assert answer == {"challenge_id": CHALLENGE, "confirmed": True,
                      "refused": False, "expires_at": 1000.0,
                      "enabled": False}


@pytest.mark.parametrize("bad", [
    "../update/install", "a/b", "short", "x" * 129, "id?x=1", "id#x",
    "%2e%2e%2fupdate", 12345,
])
def test_a_challenge_id_is_one_safe_segment(bad):
    _proxy, aux, handler = make()

    for web_request in (
        request("GET", {"challenge_id": bad}),
        request("POST", {"enabled": False, "challenge_id": bad}),
    ):
        error = refused(handler, web_request)
        assert error.status_code == 400
    assert aux.calls == []


def test_the_owner_completes_it_once_the_panel_confirmed():
    aux = FakeAux(dev_mode=False)
    aux.confirmed = True
    _proxy, aux, handler = make(aux)

    answer = call(handler, request("POST", {
        "enabled": True, "challenge_id": CHALLENGE,
        "waiver_acknowledged": True, "waiver_version": WAIVER["version"],
        "signer_name": "Jack",
    }))

    redeem = aux.calls[-1]
    assert (redeem["method"], redeem["path"]) == ("POST", "/dev_mode")
    assert redeem["headers"]["X-Muon-Access-Level"] == "admin"
    assert redeem["body"] == {
        "enabled": True, "challenge_id": CHALLENGE,
        "waiver_acknowledged": True, "waiver_version": WAIVER["version"],
        "signer_name": "Jack",
    }
    # Long enough for the clone and Klipper's restart (Aux waits 60 s).
    assert redeem["timeout"] >= 90
    # core_cfg is a filesystem path and stays on the printer.
    assert answer == {"enabled": True, "released": True,
                      "reentry_token": "rt-secret"}


def test_only_the_fields_aux_takes_are_forwarded():
    aux = FakeAux(dev_mode=True)
    aux.confirmed = True
    _proxy, aux, handler = make(aux)

    call(handler, request("POST", {
        "enabled": "false", "challenge_id": CHALLENGE,
        "core_cfg": "/etc/shadow", "path": "/update/install",
        "X-Muon-Access-Level": "admin", "reentry_token": "rt-1",
    }, user=OWNER_AT_HOME))

    assert aux.calls[-1]["body"] == {
        "enabled": False, "challenge_id": CHALLENGE, "reentry_token": "rt-1"}


def test_a_non_owner_cannot_complete_a_request_on_a_linked_printer():
    """Aux checks again when a challenge is redeemed (#378), so a challenge
    the owner opened is no use to anyone else."""
    aux = FakeAux(dev_mode=True)
    aux.confirmed = True
    _proxy, aux, handler = make(aux)

    error = refused(handler, request(
        "POST", {"enabled": False, "challenge_id": CHALLENGE},
        user=CONSOLE_OPERATOR))

    assert aux.owner_header(aux.calls[-1]) is None
    assert error.status_code == 403
    assert str(error).startswith("dev-mode:owner_required: ")
    assert aux.dev_mode is True


def test_completing_before_the_press_says_so():
    _proxy, _aux, handler = make(FakeAux(dev_mode=True))

    error = refused(handler, request(
        "POST", {"enabled": False, "challenge_id": CHALLENGE}))

    assert error.status_code == 428
    assert str(error).startswith("dev-mode:confirmation_required: ")


@pytest.mark.parametrize("args, message", [
    ({}, "'enabled' is required"),
    ({"enabled": "maybe"}, "'enabled' must be true or false"),
    ({"enabled": True, "challenge_id": CHALLENGE, "waiver_version": 3},
     "'waiver_version' must be a string"),
    ({"enabled": True, "challenge_id": CHALLENGE,
      "waiver_acknowledged": "yes"}, "'waiver_acknowledged' must be true"),
])
def test_a_malformed_request_is_refused_before_aux_is_asked(args, message):
    _proxy, aux, handler = make()

    error = refused(handler, request("POST", args))

    assert error.status_code == 400
    assert message in str(error)
    assert aux.calls == []


# --------------------------------------------------------------------------
# Who may ask: what a client reads before it offers the switch
# --------------------------------------------------------------------------

def test_the_owner_is_told_it_may_ask_and_what_turning_on_agrees_to():
    _proxy, aux, handler = make(FakeAux(linked=True), FakeLink(LINKED))

    answer = call(handler, request("GET", {}))

    assert answer == {
        "as_owner": True,
        "owner": {"linked": True, "account": OWNER_ACCOUNT},
        "may_ask": True,
        "waiver": WAIVER,
    }
    # Reading it asks nothing of the panel.
    assert aux.paths() == [("GET", "/dev_mode/waiver")]


@pytest.mark.parametrize("ip, user", [
    (SENTINEL, CONSOLE_OPERATOR), (SENTINEL, NO_PRINCIPAL), (SENTINEL, MEMBER),
    (LAN, TRUSTED_USER), (LOOPBACK, None),
])
def test_on_a_linked_printer_nobody_else_may_ask(ip, user):
    _proxy, _aux, handler = make(FakeAux(linked=True), FakeLink(LINKED))

    answer = call(handler, request("GET", {}, ip, user))

    assert answer["as_owner"] is False
    assert answer["may_ask"] is False
    assert answer["owner"] == {"linked": True, "account": OWNER_ACCOUNT}


def test_on_a_printer_nobody_owns_anyone_may_ask_and_no_code_is_shown():
    """The `code` phase carries the link code, which only the panel shows
    (APP-38): a printer waiting to be linked is not owned yet."""
    code = {"phase": "code", "code": "493-117", "expires_at": 9,
            "url": "https://muon3d.com/link?c=493-117"}
    _proxy, _aux, handler = make(FakeAux(linked=False), FakeLink(code))

    answer = call(handler, request("GET", {}, LAN, TRUSTED_USER))

    assert answer["may_ask"] is True
    assert answer["owner"] == {"linked": False, "account": None}
    assert "493-117" not in json.dumps(answer)


@pytest.mark.parametrize("link", [
    None, FakeLink(RuntimeError("muon-link down")),
    FakeLink({"phase": "a_phase_from_later"}), FakeLink("not an object"),
])
def test_a_link_nobody_can_read_is_the_owners_alone(link):
    for user, may in ((CONSOLE_OPERATOR, False), (OWNER_AWAY, True)):
        _proxy, _aux, handler = make(FakeAux(linked=True), link)

        answer = call(handler, request("GET", {}, SENTINEL, user))

        assert answer["owner"] == {"linked": None, "account": None}
        assert answer["may_ask"] is may


def test_the_answer_stands_without_the_waiver():
    aux = FakeAux()
    aux.answer = Response(500)
    _proxy, _aux, handler = make(aux, FakeLink(LINKED))

    answer = call(handler, request("GET", {}))

    assert answer["waiver"] is None
    assert answer["may_ask"] is True


def test_a_real_aux_500_keeps_its_status_and_its_words():
    aux = FakeAux(dev_mode=True)
    aux.answer = Response(500, {"detail": "Failed to update env file: disk"})
    _proxy, aux, handler = make(aux)

    error = refused(handler, request(
        "POST", {"enabled": False, "challenge_id": CHALLENGE}))

    assert error.status_code == 500
    assert str(error) == "dev-mode:refused: Failed to update env file: disk"


# --------------------------------------------------------------------------
# Nothing else in the component can carry the claim
# --------------------------------------------------------------------------

def test_the_mirrored_aux_routes_never_forward_an_owner_claim():
    """The static handlers and /server/aux/proxy build their own headers, so
    an owner reaching them (from the LAN; muon-link closes /server/aux/ to
    every remote session) is still just a network caller to Aux."""
    proxy, aux, _handler = make(FakeAux(linked=False))
    proxy._register_from_spec({"paths": {
        "/dev_mode/consent": {"post": {"requestBody": {"content": {}}}},
        "/dev_mode/consent/{challenge_id}": {"get": {}},
    }})
    static = proxy._make_static_handler("/dev_mode/consent")

    asyncio.run(static(WebRequest(
        "/server/aux/dev_mode/consent", {"enabled": False},
        RequestType.POST, ip_addr=SENTINEL, user=OWNER_AWAY)))
    asyncio.run(proxy._handle_dynamic_proxy(WebRequest(
        "/server/aux/proxy",
        {"path": f"/dev_mode/consent/{CHALLENGE}", "method": "GET"},
        RequestType.POST, ip_addr=SENTINEL, user=OWNER_AWAY)))

    for sent in aux.calls:
        assert not any(h.startswith("X-Muon-") for h in sent["headers"])


# --------------------------------------------------------------------------
# muon_access, where it is loaded
# --------------------------------------------------------------------------

@pytest.fixture
def access_open():
    home = policy.HomeNetwork.from_interface_addresses(
        [("192.168.1.10", 24)])
    policy.set_state(policy.AccessState(
        entry=policy.ENTRY_OPEN, owner=policy.OWNER_ACCOUNT, home=home))
    yield
    policy.set_state(None)


def test_asking_is_the_delegated_dev_mode_row_not_system():
    """Classified as "system" (admin), a request from a guest on a printer
    nobody owns would be refused before Aux could take it."""
    names = [a.name for a in policy.classify(ENDPOINT, RequestType.POST,
                                             {"enabled": True})]
    assert names == ["dev_mode"]
    assert [a.name for a in policy.classify(ENDPOINT, RequestType.GET,
                                            {"challenge_id": CHALLENGE})] \
        == ["read"]


def test_muon_access_admits_the_request_and_leaves_the_decision_to_aux(
        access_open):
    for ip, user in ((LAN, TRUSTED_USER), (SENTINEL, CONSOLE_OPERATOR),
                     (SENTINEL, OWNER_AWAY), (SENTINEL, MEMBER)):
        policy.check_access(ENDPOINT, RequestType.POST, {"enabled": True},
                            None, ip, user)


def test_muon_access_refuses_a_viewer(access_open):
    with pytest.raises(ServerError) as info:
        policy.check_access(ENDPOINT, RequestType.POST, {"enabled": True},
                            None, SENTINEL, ADMIN_VIEWER)
    assert info.value.status_code == 403
    assert "access-denied:dev_mode" in str(info.value)
