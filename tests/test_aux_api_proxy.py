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
import json
from typing import Any, Dict, List, Optional, Tuple

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

    def raise_for_status(self) -> None:
        self.raised_for_status = True


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

    def lookup_component(self, name: str, default: Any = None) -> Any:
        if name == "http_client":
            return self.http_client
        return default

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
    "paths": dict(SPEC["paths"], **{"/wifi/show/{ssid}": {"get": {}}}),
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

    assert server.paths() == ["/server/aux/openapi.json"]


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

@pytest.mark.parametrize("verb", ["GET", "POST", "PUT", "PATCH", "DELETE"])
def test_the_generic_proxy_forwards_allowlisted_verbs(verb: str):
    proxy, _server, client = make_proxy()
    proxy._register_from_spec(SPEC_WITH_PARAMS)

    webreq = FakeWebRequest(args={"path": "/wifi/show/home", "method": verb})
    result = asyncio.run(proxy._handle_dynamic_proxy(webreq))

    assert result == {"ok": True}
    assert client.last["method"] == verb
    assert client.last["url"] == "http://localhost:6789/wifi/show/home"


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
        args={"path": "/wifi/scan", "method": "GET", "query": "rescan=1"}
    )))
    assert client.last["url"].endswith("/wifi/scan?rescan=1")

    asyncio.run(proxy._handle_dynamic_proxy(FakeWebRequest(
        args={"path": "/wifi/connect", "method": "POST", "query": "rescan=1"}
    )))
    assert client.last["url"].endswith("/wifi/connect")


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

    assert client.last["url"] == "http://localhost:6789/wifi/scan?rescan=1"
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
        def raise_for_status(self) -> None:
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
    assert client.last["url"] == "http://localhost:6789/update/status"

    asyncio.run(proxy.ota_check_server())
    assert client.last["url"] == "http://localhost:6789/update/check"
    assert json.loads(client.last["body"]) == {"wait": False}

    asyncio.run(proxy.ota_start())
    assert client.last["url"] == "http://localhost:6789/update/install"
    assert json.loads(client.last["body"]) == {}

    asyncio.run(proxy.ota_commit())
    assert client.last["url"] == "http://localhost:6789/update/commit"


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
    assert client.last["headers"] is None


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


def test_the_backend_address_is_the_local_aux_api():
    assert aux_api_proxy.FASTAPI_ROOT == "http://localhost:6789"
    assert aux_api_proxy.MOON_PREFIX == "/server/aux"
