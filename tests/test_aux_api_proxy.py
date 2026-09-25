"""Cover the Aux API proxy component (KAN-85).

`aux_api_proxy.py` is how every Muon-specific route reaches the printer: it
reads the Aux API's OpenAPI document at startup and mirrors each route under
Moonraker's `/server/aux` namespace, so the touchscreen talks to Moonraker and
Moonraker talks to the Aux API. It had no tests.

Two properties matter enough to pin down.

The route table is derived from the spec, not hand-written, so the set of
things reachable through Moonraker is exactly the set the Aux API published.
Routes with path parameters cannot be mirrored that way and fall through to a
single generic `/server/aux/proxy` endpoint, which takes the verb from the
caller -- so that verb is checked against an allowlist before anything is
forwarded.

And every call out to the Aux API is bounded. Moonraker serves the UI; if a
request to a wedged Aux API could hang, a stuck backend would take the
printer's interface with it.

Unit tests: no server, no sockets, no Aux API. Coroutines run under
asyncio.run rather than pytest-asyncio, because tests/conftest.py defines a
class-scoped `event_loop` fixture that newer releases no longer support.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import pytest

from moonraker.components import aux_api_proxy
from moonraker.components.aux_api_proxy import AuxAutoProxy


# --------------------------------------------------------------------------
# Fakes
# --------------------------------------------------------------------------

class FakeServerError(Exception):
    def __init__(self, message: str, status_code: int = 500) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class FakeResponse:
    def __init__(
        self,
        payload: Any = None,
        *,
        json_raises: bool = False,
        status_code: int = 200,
        content: bytes = b"",
    ) -> None:
        self._payload = payload
        self._json_raises = json_raises
        self.status_code = status_code
        self.content = content
        self.headers: Dict[str, str] = {}
        self.raised_for_status = False

    def json(self) -> Any:
        if self._json_raises:
            raise ValueError("not JSON")
        return self._payload

    def raise_for_status(self, message: Optional[str] = None) -> None:
        # The real HttpResponse.raise_for_status takes the message to raise
        # with (KAN-216 passes the Aux API's own), so the fake must accept it.
        self.raised_for_status = True
        self.raise_message = message


class UnreachableResponse(FakeResponse):
    """What http_client hands back when the connection is refused: its
    raise_for_status raises ServerError with status 500."""

    def raise_for_status(self, message: Optional[str] = None) -> None:
        from moonraker.utils import ServerError
        raise ServerError("HTTP Request Error: http://127.0.0.1:6789/", 500)


class FakeDatabase:
    """The slice of Moonraker's database the proxy uses: the `muon`
    namespace, for the owner's rename (ID-3)."""

    def __init__(self) -> None:
        self.namespaces: Dict[str, Dict[str, Any]] = {}

    def register_local_namespace(self, namespace: str, forbidden: bool = False
                                 ) -> None:
        self.namespaces.setdefault(namespace, {})

    async def get_item(self, namespace: str, key: str, default: Any = None) -> Any:
        return self.namespaces.get(namespace, {}).get(key, default)

    async def insert_item(self, namespace: str, key: str, value: Any) -> None:
        self.namespaces.setdefault(namespace, {})[key] = value

    async def delete_item(self, namespace: str, key: str) -> Any:
        return self.namespaces[namespace].pop(key)


class FakeHttpClient:
    """Records every outbound call so the tests can assert on them."""

    def __init__(self, response: Optional[FakeResponse] = None) -> None:
        self.response = response if response is not None else FakeResponse({"ok": True})
        self.calls: List[Tuple[str, Dict[str, Any]]] = []
        self.raise_with: Optional[Exception] = None

    async def _record(self, kind: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((kind, kwargs))
        if self.raise_with is not None:
            raise self.raise_with
        return self.response

    async def request(self, **kwargs: Any) -> FakeResponse:
        return await self._record("request", **kwargs)

    async def get(self, url: str, **kwargs: Any) -> FakeResponse:
        return await self._record("get", url=url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> FakeResponse:
        return await self._record("post", url=url, **kwargs)

    @property
    def last(self) -> Dict[str, Any]:
        return self.calls[-1][1]


class FakeServer:
    def __init__(self, http_client: FakeHttpClient) -> None:
        self.http_client = http_client
        self.endpoints: List[Tuple[str, List[str], Any]] = []
        # Without these, AuxAutoProxy.__init__ raised on the database lookup
        # and every test that built a proxy failed (42 of them, KAN-203 MR-9).
        self.components: Dict[str, Any] = {
            "http_client": http_client,
            "database": FakeDatabase(),
        }

    def lookup_component(self, name: str, default: Any = None) -> Any:
        return self.components.get(name, default)

    def register_endpoint(self, path: str, verbs: List[str], handler: Any) -> None:
        self.endpoints.append((path, verbs, handler))

    def error(self, message: str, status_code: int = 500) -> FakeServerError:
        return FakeServerError(message, status_code)

    # -- helpers for the tests -------------------------------------------
    def paths(self) -> List[str]:
        return [path for path, _verbs, _handler in self.endpoints]

    def verbs_for(self, path: str) -> List[str]:
        for registered, verbs, _handler in self.endpoints:
            if registered == path:
                return verbs
        raise AssertionError(f"{path} was never registered: {self.paths()}")

    def handler_for(self, path: str) -> Any:
        for registered, _verbs, handler in self.endpoints:
            if registered == path:
                return handler
        raise AssertionError(f"{path} was never registered: {self.paths()}")


class FakeConfig:
    def __init__(self, server: FakeServer) -> None:
        self._server = server

    def get_server(self) -> FakeServer:
        return self._server


class FakeWebRequest:
    """Stands in for Moonraker's WebRequest."""

    def __init__(
        self,
        action: str = "GET",
        args: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._action = action
        self._args = args or {}
        self.raw_responses: List[Tuple[Any, int, Dict[str, str]]] = []

    def get_action(self) -> str:
        return self._action

    def get_args(self) -> Dict[str, Any]:
        return dict(self._args)

    def get_str(self, name: str, default: Any = None) -> str:
        if name in self._args:
            return str(self._args[name])
        if default is None:
            raise KeyError(name)
        return str(default)

    def get(self, name: str, default: Any = None) -> Any:
        return self._args.get(name, default)

    def create_raw_response(
        self, content: Any, code: int = 200, headers: Optional[Dict[str, str]] = None
    ) -> str:
        self.raw_responses.append((content, code, headers or {}))
        return "raw-response"


SPEC: Dict[str, Any] = {
    "paths": {
        "/wifi/scan": {"get": {}},
        "/wifi/connect": {"post": {"requestBody": {"content": {}}}},
        "/update/status": {"get": {}},
        "/dev-mode": {"get": {}, "post": {"requestBody": {"content": {}}}},
    }
}

SPEC_WITH_PARAMS: Dict[str, Any] = {
    "paths": dict(SPEC["paths"], **{
        "/wifi/show/{ssid}": {"get": {}},
        # Published for three verbs, so the per-route verb set KAN-83 records
        # can be told apart from a blanket "any verb" allowance.
        "/wifi/profile/{name}": {"get": {}, "put": {}, "delete": {}},
    }),
}


def make_proxy(
    http_client: Optional[FakeHttpClient] = None,
) -> Tuple[AuxAutoProxy, FakeServer, FakeHttpClient]:
    client = http_client or FakeHttpClient()
    server = FakeServer(client)
    proxy = AuxAutoProxy(FakeConfig(server))
    return proxy, server, client


# --------------------------------------------------------------------------
# Building the route table from the spec
# --------------------------------------------------------------------------

def test_every_concrete_path_is_mirrored_under_the_moonraker_prefix():
    proxy, server, _client = make_proxy()

    proxy._register_from_spec(SPEC)

    for fast_path in SPEC["paths"]:
        assert f"/server/aux{fast_path}" in server.paths()


def test_the_verbs_come_from_the_spec_not_from_a_default():
    proxy, server, _client = make_proxy()

    proxy._register_from_spec(SPEC)

    assert server.verbs_for("/server/aux/wifi/scan") == ["GET"]
    assert server.verbs_for("/server/aux/wifi/connect") == ["POST"]
    assert sorted(server.verbs_for("/server/aux/dev-mode")) == ["GET", "POST"]


def test_the_raw_openapi_document_is_served():
    """The client fetches this to discover what the printer supports."""
    proxy, server, _client = make_proxy()
    proxy._register_from_spec(SPEC)

    handler = server.handler_for("/server/aux/openapi.json")
    assert asyncio.run(handler(FakeWebRequest())) is SPEC


def test_non_verb_keys_in_a_path_item_are_ignored():
    """`parameters`, `summary` and friends sit alongside the verbs."""
    proxy, server, _client = make_proxy()

    proxy._register_from_spec({
        "paths": {
            "/thing": {"get": {}, "parameters": [], "summary": "a thing"},
        }
    })

    assert server.verbs_for("/server/aux/thing") == ["GET"]


def test_a_path_with_no_verbs_at_all_is_skipped():
    proxy, server, _client = make_proxy()

    proxy._register_from_spec({"paths": {"/thing": {"summary": "no verbs"}}})

    assert "/server/aux/thing" not in server.paths()


def test_an_empty_spec_still_registers_only_the_openapi_route():
    proxy, server, _client = make_proxy()

    proxy._register_from_spec({"paths": {}})

    # The /server/muon endpoints are registered unconditionally, in __init__,
    # not from the spec (see test_the_muon_endpoints_exist_before_any_spec).
    # /server/muon/dev_mode is there because SEC-2 took every /server/aux/*
    # path off the network including the dev-mode status read, and DEV-4
    # still requires developer mode to be visible in the interface, so it is
    # published off the floor. It is GET only and forwards no body, which is
    # what stops it becoming a way to *change* the mode.
    assert server.paths() == [
        "/server/muon/dev_mode",
        "/server/muon/identity",
        "/server/muon/identity/name",
        "/server/aux/openapi.json",
    ]


# --------------------------------------------------------------------------
# The printer's name and developer mode: the endpoints the proxy serves itself
# (KAN-203 MR-9, spec 02 §7)
# --------------------------------------------------------------------------

AUX_IDENTITY = {
    "serial": "10000000abcd8987", "name": "walnut", "suffix": "8987",
    "ssid": "Muon-walnut-8987", "display": "Walnut · 8987",
    "fingerprint": "SHA256:placeholder",
}


def test_the_muon_endpoints_exist_before_any_spec():
    """They are served by the helpers, not mirrored, so a late Aux API must
    not leave the printer unable to say its name."""
    _proxy, server, _client = make_proxy()

    assert server.paths() == [
        "/server/muon/dev_mode",
        "/server/muon/identity",
        "/server/muon/identity/name",
    ]
    assert server.verbs_for("/server/muon/identity") == ["GET"]
    assert server.verbs_for("/server/muon/identity/name") == ["POST"]


def test_a_late_aux_api_still_fails_init_but_the_identity_answers_503():
    """component_init still raises -- the /server/aux routes do need the
    spec, and Moonraker's warning about that is worth keeping -- but the
    identity endpoint is registered and says "not yet", not "no such route"."""
    client = FakeHttpClient(UnreachableResponse())
    proxy, server, _client = make_proxy(client)

    with pytest.raises(Exception):
        asyncio.run(proxy.component_init())

    handler = server.handler_for("/server/muon/identity")
    with pytest.raises(FakeServerError) as excinfo:
        asyncio.run(handler(FakeWebRequest("GET")))
    assert excinfo.value.status_code == 503

    dev_mode = server.handler_for("/server/muon/dev_mode")
    with pytest.raises(FakeServerError) as excinfo:
        asyncio.run(dev_mode(FakeWebRequest("GET")))
    assert excinfo.value.status_code == 503


def test_an_aux_refusal_is_not_turned_into_503():
    """Only "not answering" is 503. An answer Aux chose to give -- its own
    503 when the serial cannot be read, say -- keeps its status."""
    class Refused(FakeResponse):
        def raise_for_status(self, message: Optional[str] = None) -> None:
            from moonraker.utils import ServerError
            raise ServerError("could not derive this printer's identity", 404)

    _proxy, server, _client = make_proxy(FakeHttpClient(Refused()))
    handler = server.handler_for("/server/muon/identity")
    from moonraker.utils import ServerError
    with pytest.raises(ServerError) as excinfo:
        asyncio.run(handler(FakeWebRequest("GET")))
    assert excinfo.value.status_code == 404


def test_the_identity_is_the_derived_name_until_the_owner_renames_it():
    """What the endpoint said before MR-9, pinned: the owner's rename wins,
    the derived half is always reported, and the display form follows the
    rename."""
    _proxy, server, _client = make_proxy(
        FakeHttpClient(FakeResponse(dict(AUX_IDENTITY))))
    get = server.handler_for("/server/muon/identity")
    rename = server.handler_for("/server/muon/identity/name")

    assert asyncio.run(get(FakeWebRequest("GET"))) == {
        "name": "walnut", "source": "derived", "derived_name": "walnut",
        "suffix": "8987", "display": "Walnut · 8987",
        "ssid": "Muon-walnut-8987", "fingerprint": "SHA256:placeholder",
        # KAN-403 (#27): null until Aux reports an EndpointId.
        "endpoint_id": None,
        "setup": None,
    }

    renamed = asyncio.run(rename(FakeWebRequest("POST", {"name": "  Workshop "})))
    assert renamed["name"] == "Workshop"
    assert renamed["source"] == "owner"
    assert renamed["derived_name"] == "walnut"
    assert renamed["display"] == "Workshop · 8987"

    cleared = asyncio.run(rename(FakeWebRequest("POST", {"name": ""})))
    assert cleared["name"] == "walnut"
    assert cleared["source"] == "derived"


def test_a_rename_is_bounded_and_must_be_a_string():
    _proxy, server, _client = make_proxy(
        FakeHttpClient(FakeResponse(dict(AUX_IDENTITY))))
    rename = server.handler_for("/server/muon/identity/name")
    for args in ({}, {"name": 7}, {"name": "x" * 33}):
        with pytest.raises(FakeServerError) as excinfo:
            asyncio.run(rename(FakeWebRequest("POST", args)))
        assert excinfo.value.status_code == 400


@pytest.mark.parametrize("state", ["new", "in_progress", "complete"])
def test_the_identity_says_whether_setup_is_done(state: str):
    """02 §7: apps route a printer they found by this (06 §1)."""
    class Setup:
        def public_state(self) -> Dict[str, Any]:
            return {"state": state}

    _proxy, server, _client = make_proxy(
        FakeHttpClient(FakeResponse(dict(AUX_IDENTITY))))
    server.components["muon_setup"] = Setup()
    get = server.handler_for("/server/muon/identity")
    assert asyncio.run(get(FakeWebRequest("GET")))["setup"] == state


# --------------------------------------------------------------------------
# Parameterised paths go through the generic proxy
# --------------------------------------------------------------------------

def test_parameterised_paths_are_not_mirrored_directly():
    """`/wifi/show/{ssid}` is not a route; it is a template."""
    proxy, server, _client = make_proxy()

    proxy._register_from_spec(SPEC_WITH_PARAMS)

    assert "/server/aux/wifi/show/{ssid}" not in server.paths()


def test_a_spec_with_parameterised_paths_registers_the_generic_proxy():
    proxy, server, _client = make_proxy()

    proxy._register_from_spec(SPEC_WITH_PARAMS)

    assert "/server/aux/proxy" in server.paths()
    assert server.verbs_for("/server/aux/proxy") == ["POST"]


def test_a_spec_without_them_does_not_register_the_generic_proxy():
    """No template routes means no reason to expose a pass-through."""
    proxy, server, _client = make_proxy()

    proxy._register_from_spec(SPEC)

    assert "/server/aux/proxy" not in server.paths()


# --------------------------------------------------------------------------
# The generic proxy's verb allowlist
# --------------------------------------------------------------------------

@pytest.mark.parametrize("verb", ["GET", "PUT", "DELETE"])
def test_the_generic_proxy_forwards_verbs_the_route_publishes(verb: str):
    proxy, _server, client = make_proxy()
    proxy._register_from_spec(SPEC_WITH_PARAMS)

    webreq = FakeWebRequest(
        args={"path": "/wifi/profile/home", "method": verb}
    )
    result = asyncio.run(proxy._handle_dynamic_proxy(webreq))

    assert result == {"ok": True}
    assert client.last["method"] == verb
    assert client.last["url"] == "http://127.0.0.1:6789/wifi/profile/home"
    # This endpoint takes its path and verb from the caller, so it is the one
    # most worth proving bounded -- and the only one whose timeouts used to be
    # inherited from http_client's defaults rather than passed.
    assert 0 < client.last["request_timeout"] <= 30
    assert client.last["connect_timeout"] > 0


@pytest.mark.parametrize("verb", ["TRACE", "CONNECT", "OPTIONS", "HEAD", "nonsense"])
def test_the_generic_proxy_refuses_everything_else(verb: str):
    """And refuses it *before* anything leaves the box.

    This endpoint takes both the verb and the path from whoever called it, so
    the allowlist is the only thing standing between a caller and an arbitrary
    request against the Aux API.
    """
    proxy, _server, client = make_proxy()
    proxy._register_from_spec(SPEC_WITH_PARAMS)

    webreq = FakeWebRequest(args={"path": "/wifi/show/home", "method": verb})

    with pytest.raises(FakeServerError) as excinfo:
        asyncio.run(proxy._handle_dynamic_proxy(webreq))

    assert excinfo.value.status_code == 400
    assert client.calls == [], "a rejected verb still reached the Aux API"


def test_the_generic_proxy_defaults_to_get():
    proxy, _server, client = make_proxy()
    proxy._register_from_spec(SPEC_WITH_PARAMS)

    asyncio.run(proxy._handle_dynamic_proxy(
        FakeWebRequest(args={"path": "/wifi/show/home"})
    ))

    assert client.last["method"] == "GET"


def test_a_query_string_is_only_appended_for_verbs_that_take_one():
    proxy, _server, client = make_proxy()
    proxy._register_from_spec(SPEC_WITH_PARAMS)

    asyncio.run(proxy._handle_dynamic_proxy(FakeWebRequest(
        args={"path": "/wifi/profile/home", "method": "GET",
              "query": "rescan=1"}
    )))
    assert client.last["url"].endswith("/wifi/profile/home?rescan=1")

    asyncio.run(proxy._handle_dynamic_proxy(FakeWebRequest(
        args={"path": "/wifi/profile/home", "method": "PUT",
              "query": "rescan=1"}
    )))
    assert client.last["url"].endswith("/wifi/profile/home")


# --------------------------------------------------------------------------
# The static handlers
# --------------------------------------------------------------------------

def test_an_operation_with_a_request_body_gets_a_json_body():
    proxy, server, client = make_proxy()
    proxy._register_from_spec(SPEC)

    handler = server.handler_for("/server/aux/wifi/connect")
    args = {"ssid": "home", "password": "hunter2"}
    asyncio.run(handler(FakeWebRequest("POST", args)))

    assert client.last["headers"] == {"Content-Type": "application/json"}
    assert json.loads(client.last["body"]) == args
    assert "?" not in client.last["url"]


def test_an_operation_without_one_gets_a_query_string_instead():
    proxy, server, client = make_proxy()
    proxy._register_from_spec(SPEC)

    handler = server.handler_for("/server/aux/wifi/scan")
    asyncio.run(handler(FakeWebRequest("GET", {"rescan": "1"})))

    assert client.last["url"] == "http://127.0.0.1:6789/wifi/scan?rescan=1"
    assert client.last["body"] is None


def test_a_bodyless_post_still_sends_an_empty_body():
    """Tornado rejects a POST with a body of None."""
    proxy, server, client = make_proxy()
    proxy._register_from_spec({"paths": {"/ping": {"post": {}}}})

    handler = server.handler_for("/server/aux/ping")
    asyncio.run(handler(FakeWebRequest("POST", {})))

    assert client.last["body"] == ""


def test_a_non_json_response_falls_back_to_a_raw_response():
    client = FakeHttpClient(FakeResponse(json_raises=True, content=b"binary"))
    proxy, server, _client = make_proxy(client)
    proxy._register_from_spec(SPEC)

    handler = server.handler_for("/server/aux/wifi/scan")
    webreq = FakeWebRequest("GET", {})
    result = asyncio.run(handler(webreq))

    assert result == "raw-response"
    assert webreq.raw_responses[0][0] == b"binary"


def test_a_failing_upstream_status_is_raised_not_swallowed():
    class Failing(FakeResponse):
        def raise_for_status(self, message: Optional[str] = None) -> None:
            raise FakeServerError("500 from the Aux API", 500)

    proxy, server, _client = make_proxy(FakeHttpClient(Failing()))
    proxy._register_from_spec(SPEC)

    handler = server.handler_for("/server/aux/wifi/scan")
    with pytest.raises(FakeServerError):
        asyncio.run(handler(FakeWebRequest("GET", {})))


# --------------------------------------------------------------------------
# The OTA wrappers other components call
# --------------------------------------------------------------------------

def test_the_ota_wrappers_target_the_canonical_update_routes():
    """These are the paths ota_deploy drives the update UI through.

    The Aux API renamed them -- /update/check_server became /update/check,
    /update/start became /update/install -- and still answers on the old ones
    with routes hidden from the OpenAPI document. Hidden means the generated
    clients cannot see them, so pinning the canonical spelling here keeps this
    component from being the last caller of a deprecated alias.
    """
    proxy, _server, client = make_proxy()

    asyncio.run(proxy.ota_status())
    assert client.last["url"] == "http://127.0.0.1:6789/update/status"

    asyncio.run(proxy.ota_check_server())
    assert client.last["url"] == "http://127.0.0.1:6789/update/check"
    assert json.loads(client.last["body"]) == {"wait": False}

    asyncio.run(proxy.ota_start())
    assert client.last["url"] == "http://127.0.0.1:6789/update/install"
    assert json.loads(client.last["body"]) == {}

    asyncio.run(proxy.ota_commit())
    assert client.last["url"] == "http://127.0.0.1:6789/update/commit"


def test_ota_start_passes_a_bundle_url_when_it_is_given_one():
    proxy, _server, client = make_proxy()

    asyncio.run(proxy.ota_start("https://example.invalid/system.rugixb"))

    assert json.loads(client.last["body"]) == {
        "url": "https://example.invalid/system.rugixb"
    }


def test_a_post_body_that_is_already_a_string_is_sent_unchanged():
    proxy, _server, client = make_proxy()

    asyncio.run(proxy.post("/thing", "raw text"))

    assert client.last["body"] == "raw text"
    # KAN-25: every call out is wrapped by _auth_headers, so this is always a
    # dict. `is None` would mean the wrapper had been bypassed -- which is the
    # regression worth catching here. What the dict *contains* when a token
    # exists is pinned by test_every_call_out_carries_this_boots_aux_api_token.
    assert isinstance(client.last["headers"], dict)


# --------------------------------------------------------------------------
# A slow Aux API must not take Moonraker with it
# --------------------------------------------------------------------------

def test_every_helper_call_carries_a_bounded_timeout():
    """Moonraker serves the UI from this process.

    An unbounded request against a wedged Aux API would hold the connection
    open for as long as the backend stayed wedged.
    """
    proxy, _server, client = make_proxy()

    asyncio.run(proxy.get("/update/status"))
    asyncio.run(proxy.post("/update/check", {"wait": False}))
    asyncio.run(proxy.delete("/setup/complete"))

    assert len(client.calls) == 3
    for _kind, call in client.calls:
        assert call["connect_timeout"] > 0
        assert call["request_timeout"] > 0
        assert call["request_timeout"] <= 30, (
            f"a timeout long enough to look like a hang: {call['request_timeout']}"
        )


def test_static_handlers_are_bounded_too():
    proxy, server, client = make_proxy()
    proxy._register_from_spec(SPEC)

    handler = server.handler_for("/server/aux/wifi/scan")
    asyncio.run(handler(FakeWebRequest("GET", {})))

    assert client.last["connect_timeout"] > 0
    assert client.last["request_timeout"] > 0


def test_a_timed_out_aux_api_surfaces_as_an_error():
    """Rather than being suppressed into a success with no data."""
    client = FakeHttpClient()
    client.raise_with = asyncio.TimeoutError("timed out")
    proxy, _server, _client = make_proxy(client)

    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(proxy.ota_status())


# --------------------------------------------------------------------------
# Wiring
# --------------------------------------------------------------------------

def test_load_component_returns_the_proxy():
    client = FakeHttpClient()
    component = aux_api_proxy.load_component(FakeConfig(FakeServer(client)))

    assert isinstance(component, AuxAutoProxy)


def test_the_backend_address_never_leaves_the_box():
    """Not the literal, the property.

    Every request this component makes is built by concatenating
    FASTAPI_ROOT with a path the caller supplies, so if that root ever
    pointed off-box the generic proxy would become an open relay reachable
    through Moonraker.
    """
    from urllib.parse import urlparse

    host = urlparse(aux_api_proxy.FASTAPI_ROOT).hostname
    assert host in {"localhost", "127.0.0.1", "::1"}, aux_api_proxy.FASTAPI_ROOT
    assert aux_api_proxy.MOON_PREFIX.startswith("/")


# --------------------------------------------------------------------------
# Requirements this component inherits from elsewhere
# --------------------------------------------------------------------------

def test_the_aux_api_is_reached_over_loopback_by_address_not_by_name():
    """KAN-68 binds the Aux API to loopback; this pins that we reach it there.

    Asserted as the requirement rather than as whatever FASTAPI_ROOT happens
    to say today. The host must be a loopback *address*: a name is
    resolver-dependent -- it can answer ::1, and a search domain or an edited
    hosts file can move it off the loopback interface entirely -- so a
    hostname would not be the bind KAN-68 asks for even on a day it works.
    """
    host = urlsplit(aux_api_proxy.FASTAPI_ROOT).hostname
    assert host is not None, "FASTAPI_ROOT must carry a host"
    # A hostname raises ValueError here, which is the point: names are not
    # addresses, and only an address can be checked for being loopback.
    assert ipaddress.ip_address(host).is_loopback, (
        f"Aux API must be reached over loopback by address, got {host!r}"
    )


def test_every_call_out_carries_this_boots_aux_api_token(tmp_path, monkeypatch):
    """KAN-25: the Aux API authenticates, so an outgoing call must be signed.

    Asserted as the requirement -- the token header is actually present on the
    way out -- not merely that a headers dict is tolerated. Covers the static
    handler, the generic proxy and the internal get/post helpers, because a
    single unsigned path is a way round the authentication.
    """
    token_file = tmp_path / "aux_token"
    token_file.write_text("s3cret" + chr(10))
    monkeypatch.setattr(aux_api_proxy, "AUX_TOKEN_FILE", token_file)

    proxy, server, client = make_proxy()
    proxy._register_from_spec(SPEC_WITH_PARAMS)

    asyncio.run(server.handler_for("/server/aux/wifi/scan")(FakeWebRequest()))
    assert client.last["headers"][aux_api_proxy.AUX_TOKEN_HEADER] == "s3cret"

    asyncio.run(proxy._handle_dynamic_proxy(FakeWebRequest(
        args={"path": "/wifi/show/home", "method": "GET"}
    )))
    assert client.last["headers"][aux_api_proxy.AUX_TOKEN_HEADER] == "s3cret"

    asyncio.run(proxy.get("/update/status"))
    assert client.last["headers"][aux_api_proxy.AUX_TOKEN_HEADER] == "s3cret"

    asyncio.run(proxy.post("/update/commit", {}))
    assert client.last["headers"][aux_api_proxy.AUX_TOKEN_HEADER] == "s3cret"


# --------------------------------------------------------------------------
# KAN-83: what the generic proxy will and will not reach
# --------------------------------------------------------------------------

@pytest.mark.parametrize("verb", ["POST", "PATCH"])
def test_a_verb_the_route_does_not_publish_is_refused(verb: str):
    """405, and nothing leaves the process.

    The allowlist records a verb set per route, not just a shape. Before
    KAN-83 the verb was only checked against the generic
    {GET,POST,PUT,PATCH,DELETE} set, so a route published for GET alone could
    be driven as DELETE or PUT.
    """
    proxy, _server, client = make_proxy()
    proxy._register_from_spec(SPEC_WITH_PARAMS)

    webreq = FakeWebRequest(args={"path": "/wifi/show/home", "method": verb})
    with pytest.raises(FakeServerError) as excinfo:
        asyncio.run(proxy._handle_dynamic_proxy(webreq))

    assert excinfo.value.status_code == 405
    assert client.calls == [], "a refused verb still reached the Aux API"


@pytest.mark.parametrize("path", [
    "/update/install",              # privileged, and never parameterised
    "/bms/ship_mode/enable",        # not in the spec at all
    "/wifi/scan",                   # concrete: it has its own static handler
    "@evil.example/wifi/scan",      # host pivot via userinfo
    "//evil.example/wifi/scan",     # host pivot via protocol-relative path
    "/wifi/show/..%2f..%2fupdate%2finstall",   # encoded separators
    "/wifi/show/%2e%2e%2fupdate",              # encoded dot-segments
])
def test_a_path_outside_the_published_parameterised_routes_is_refused(path):
    """400, and nothing leaves the process.

    `path` used to be concatenated onto FASTAPI_ROOT unchecked, so any Aux
    route was reachable and a userinfo or protocol-relative value re-pointed
    the request at an arbitrary host -- an SSRF pivot speaking from inside the
    printer's network.
    """
    proxy, _server, client = make_proxy()
    proxy._register_from_spec(SPEC_WITH_PARAMS)

    webreq = FakeWebRequest(args={"path": path, "method": "GET"})
    with pytest.raises(FakeServerError) as excinfo:
        asyncio.run(proxy._handle_dynamic_proxy(webreq))

    assert excinfo.value.status_code == 400
    assert client.calls == [], f"{path!r} reached the Aux API"


def test_a_percent_encoded_value_that_is_not_a_separator_still_works():
    """This is not a ban on '%'. An SSID with a space is legitimate."""
    proxy, _server, client = make_proxy()
    proxy._register_from_spec(SPEC_WITH_PARAMS)

    asyncio.run(proxy._handle_dynamic_proxy(FakeWebRequest(
        args={"path": "/wifi/show/my%20network", "method": "GET"}
    )))

    assert client.last["url"].endswith("/wifi/show/my%20network")



# --------------------------------------------------------------------------
# KAN-216: the Aux API's explanation survives the proxy
# --------------------------------------------------------------------------
#
# These drive the module-level `_aux_error_message` directly. That is not a
# convenience: the rest of this file builds an AuxAutoProxy, and its
# constructor has needed a `database` component since ID-3 landed, which the
# fake server here does not provide -- so 42 of the 44 tests in this file
# error in __init__ before reaching their subject, on `master` as much as on
# this branch. Testing a free function keeps this coverage out of that hole.

class FakeJsonResponse:
    """Only the part of HttpResponse that _aux_error_message touches.

    `json()` raising is the realistic failure: Moonraker's HttpResponse parses
    `self._result` on demand, and an error page that is not JSON -- nginx's
    502, say -- raises rather than returning None.
    """

    def __init__(self, payload: Any = None, raises: bool = False) -> None:
        self._payload = payload
        self._raises = raises

    def json(self) -> Any:
        if self._raises:
            raise ValueError("not JSON")
        return self._payload


def test_the_aux_apis_own_message_is_recovered():
    """The shape every OTA route uses: update_routes._http_error."""
    resp = FakeJsonResponse({
        "detail": {
            "code": "invalid_state",
            "message": "refusing to install while the running system requires commit",
        }
    })

    assert aux_api_proxy._aux_error_message(resp) == (
        "refusing to install while the running system requires commit"
    )


def test_a_plain_string_detail_is_recovered():
    """HTTPException(detail="...") -- FastAPI's own default shape."""
    resp = FakeJsonResponse({"detail": "printer is busy"})

    assert aux_api_proxy._aux_error_message(resp) == "printer is busy"


def test_a_validation_error_list_is_recovered():
    """FastAPI answers a 422 with a LIST of detail objects, not a dict."""
    resp = FakeJsonResponse({
        "detail": [
            {"loc": ["body", "url"], "msg": "field required", "type": "value_error"}
        ]
    })

    assert aux_api_proxy._aux_error_message(resp) == "field required"


@pytest.mark.parametrize("payload", [
    None,                                   # no body at all
    {},                                     # JSON, no detail
    {"detail": {}},                         # detail, no message
    {"detail": {"message": "   "}},         # message, but only whitespace
    {"detail": {"message": 42}},            # message, wrong type
    {"detail": []},                         # empty validation list
    {"detail": [{"loc": ["body"]}]},        # validation entry with no msg
    {"detail": ""},                         # empty string detail
    ["not", "an", "object"],                # JSON, but not a document
])
def test_nothing_better_to_say_leaves_the_default_message_alone(payload):
    """None means "do not override", not "the message is None".

    raise_for_status(None) keeps Tornado's own reason phrase, so every shape
    this cannot read degrades to exactly the behaviour before this change --
    never to a blank or a crash on an already-failing request.
    """
    assert aux_api_proxy._aux_error_message(FakeJsonResponse(payload)) is None


def test_a_body_that_is_not_json_is_not_an_error():
    """An error page from something in front of the Aux API.

    This function only ever runs on a request that has already failed, so
    raising here would replace a useful failure with a confusing one.
    """
    assert aux_api_proxy._aux_error_message(
        FakeJsonResponse(raises=True)
    ) is None


# The wiring, not just the helper. `get` and `post` are driven UNBOUND against
# a stub self, which was how they could be tested while AuxAutoProxy.__init__
# still broke the rest of this file (fixed in KAN-203 MR-9). The response is a
# REAL HttpResponse carrying a REAL tornado HTTPError, so this pins the
# integration with Moonraker's own raise_for_status rather than a fake of it.

class _StubProxySelf:
    """Only what get()/post() touch on self."""

    def __init__(self, response: Any) -> None:
        self.http_client = _StubHttpClient(response)

    def _auth_headers(self, headers: Optional[Dict[str, Any]] = None
                      ) -> Dict[str, Any]:
        return dict(headers or {})


class _StubHttpClient:
    def __init__(self, response: Any) -> None:
        self._response = response

    async def get(self, *args: Any, **kwargs: Any) -> Any:
        return self._response

    async def post(self, *args: Any, **kwargs: Any) -> Any:
        return self._response


def _refused_response() -> Any:
    from tornado.httpclient import HTTPError as TornadoHTTPError
    from tornado.httputil import HTTPHeaders

    from moonraker.components.http_client import HttpResponse

    body = json.dumps({
        "detail": {
            "code": "invalid_state",
            "message": "refusing to install while the running system requires commit",
        }
    }).encode()
    # message=None is the real shape: tornado fills in the reason phrase, which
    # is where the bare word "Conflict" came from.
    error = TornadoHTTPError(409)
    return HttpResponse(
        "http://127.0.0.1:6789/update/install",
        "http://127.0.0.1:6789/update/install",
        409, body, HTTPHeaders(), error,
    )


def test_post_raises_with_the_aux_apis_message_not_the_reason_phrase():
    """The defect, end to end through the real method.

    Before this change the assertion below held the string "Conflict": the
    body was dropped by raise_for_status() and no client could recover it.
    """
    from moonraker.utils import ServerError

    stub = _StubProxySelf(_refused_response())

    with pytest.raises(ServerError) as excinfo:
        asyncio.run(AuxAutoProxy.post(stub, "/update/install", {}))

    assert "requires commit" in str(excinfo.value)
    # The status code still has to be the Aux API's, not a flattened 500 --
    # update_manager and the clients branch on it.
    assert excinfo.value.status_code == 409


def test_get_raises_with_the_aux_apis_message_too():
    """Same path, the other verb: /update/status is a GET."""
    from moonraker.utils import ServerError

    stub = _StubProxySelf(_refused_response())

    with pytest.raises(ServerError) as excinfo:
        asyncio.run(AuxAutoProxy.get(stub, "/update/status"))

    assert "requires commit" in str(excinfo.value)


def test_a_successful_response_is_returned_and_not_raised():
    """The negative control: nothing above may turn a 200 into an error."""
    from tornado.httputil import HTTPHeaders

    from moonraker.components.http_client import HttpResponse

    ok = HttpResponse(
        "http://127.0.0.1:6789/update/status",
        "http://127.0.0.1:6789/update/status",
        200, json.dumps({"state": "idle"}).encode(), HTTPHeaders(), None,
    )

    assert asyncio.run(AuxAutoProxy.get(_StubProxySelf(ok), "/update/status")) == {
        "state": "idle"
    }


def test_delete_goes_to_the_aux_api_with_the_token_and_raises_on_refusal():
    """muon_setup's reset clears OS-7's marker with DELETE /setup/complete."""
    client = FakeHttpClient(FakeResponse({"complete": False}))
    proxy, _server, _client = make_proxy(client)
    proxy._token = "t0k"

    assert asyncio.run(proxy.delete("/setup/complete")) == {"complete": False}
    call = client.last
    assert call["method"] == "DELETE"
    assert call["url"] == "http://127.0.0.1:6789/setup/complete"
    assert call["headers"]["X-Aux-Api-Key"] == "t0k"

    proxy, _server, _client = make_proxy(FakeHttpClient(UnreachableResponse()))
    from moonraker.utils import ServerError
    with pytest.raises(ServerError):
        asyncio.run(proxy.delete("/setup/complete"))


# --------------------------------------------------------------------------
# KAN-403: the EndpointId reaches /server/muon/identity
# --------------------------------------------------------------------------
#
# A real AuxAutoProxy on a server that does provide `database`, with `get`
# replaced on the instance. Anything the handler reaches through self.get
# therefore sees the fake Aux answer.

ENDPOINT_ID = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"

DERIVED: Dict[str, Any] = {
    "serial": "100000008b9791ab",
    "name": "walnut",
    "suffix": "8987",
    "ssid": "Muon-walnut-8987",
    "display": "Walnut · 8987",
    "fingerprint": "SHA256:abc",
}


class _FakeDatabase:
    def __init__(self, override: Optional[str] = None) -> None:
        self.override = override

    def register_local_namespace(self, namespace: str) -> None:
        pass

    async def get_item(self, namespace: str, key: str, default: Any = None) -> Any:
        return self.override if self.override is not None else default


class _ServerWithDatabase(FakeServer):
    def __init__(self, database: _FakeDatabase) -> None:
        super().__init__(FakeHttpClient())
        self.database = database

    def lookup_component(self, name: str, default: Any = None) -> Any:
        if name == "database":
            return self.database
        return super().lookup_component(name, default)


def _identity(derived: Dict[str, Any], override: Optional[str] = None) -> Any:
    proxy = AuxAutoProxy(FakeConfig(_ServerWithDatabase(_FakeDatabase(override))))

    async def fake_get(path: str) -> Any:
        assert path == "/identity", path
        return dict(derived)

    proxy.get = fake_get  # type: ignore[method-assign]
    return asyncio.run(proxy._identity_handler(FakeWebRequest()))


def test_the_endpoint_id_from_aux_is_passed_on():
    body = _identity(dict(DERIVED, endpoint_id=ENDPOINT_ID))
    assert body["endpoint_id"] == ENDPOINT_ID


def test_the_endpoint_id_is_null_before_muon_link_has_published_it():
    body = _identity(dict(DERIVED, endpoint_id=None))
    assert body["endpoint_id"] is None
    assert body["name"] == "walnut"


def test_an_aux_without_the_field_gives_null_not_an_error():
    """Moonraker can be updated before Aux, or run against an older one."""
    body = _identity(DERIVED)
    assert body["endpoint_id"] is None


def test_a_rename_does_not_touch_the_endpoint_id():
    """ID-5: the name carries no authority, and it doesn't move the key."""
    body = _identity(dict(DERIVED, endpoint_id=ENDPOINT_ID), override="bench")
    assert body["name"] == "bench"
    assert body["endpoint_id"] == ENDPOINT_ID
