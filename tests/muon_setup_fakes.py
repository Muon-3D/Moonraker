"""Hand-written fakes for muon_setup's tests (KAN-203).

Shared by every test_muon_setup*.py, so each step package tests against the
same server, database and Aux. No sockets, no event loop fixtures: tests build
the component inside asyncio.run, as tests/test_aux_api_proxy.py does, because
conftest's class-scoped `event_loop` fixture is not supported by newer
pytest-asyncio releases.
"""

from __future__ import annotations

import asyncio
import copy
import ipaddress
from typing import Any, Callable, Dict, List, Optional, Tuple

from moonraker.common import RequestType, TransportType, UserInfo, WebRequest
from moonraker.components import muon_setup as muon_setup_pkg
from moonraker.components.muon_setup import MuonSetup
from moonraker.utils.exceptions import ServerError

MISSING = object()


class FakeDatabase:
    def __init__(self, namespaces: Optional[Dict[str, Dict[str, Any]]] = None):
        self.namespaces: Dict[str, Dict[str, Any]] = copy.deepcopy(namespaces or {})
        self.registered: Dict[str, bool] = {}
        self.fail_inserts = False
        #: Every write, in order, shared with FakeServer.log so a test can see
        #: whether a change was saved before it was announced.
        self.log: List[Tuple[str, Any]] = []

    def register_local_namespace(self, namespace: str, forbidden: bool = False):
        if namespace in self.registered:
            raise ServerError(f"Namespace '{namespace}' already registered")
        self.registered[namespace] = forbidden
        self.namespaces.setdefault(namespace, {})

    async def get_item(self, namespace: str, key: Any = None, default: Any = MISSING):
        await asyncio.sleep(0)
        ns = self.namespaces.get(namespace)
        if ns is None:
            if default is MISSING:
                raise ServerError(f"Namespace {namespace} not found", 404)
            return default
        if key is None:
            return copy.deepcopy(ns) if ns else default if default is not MISSING else {}
        if key not in ns:
            if default is MISSING:
                raise ServerError(f"Key '{key}' not found", 404)
            return default
        return copy.deepcopy(ns[key])

    async def insert_item(self, namespace: str, key: str, value: Any) -> None:
        await asyncio.sleep(0)
        if self.fail_inserts:
            raise ServerError("database is broken", 500)
        self.namespaces.setdefault(namespace, {})[key] = copy.deepcopy(value)
        self.log.append(("insert", (namespace, key)))

    async def delete_item(self, namespace: str, key: str) -> Any:
        await asyncio.sleep(0)
        ns = self.namespaces.get(namespace, {})
        if key not in ns:
            raise ServerError(f"Key '{key}' not found", 404)
        self.log.append(("delete", (namespace, key)))
        return ns.pop(key)


Route = Any  # a value, an Exception, or a callable(body) -> value


class FakeAux:
    """aux_api_proxy's get()/post() helpers, with a route table.

    A route missing from the table is a 404, as FastAPI answers for a route
    this image does not have. `down = True` is Aux not answering at all:
    aux_api_proxy turns a refused connection into ServerError(500).
    """

    def __init__(self, routes: Optional[Dict[Tuple[str, str], Route]] = None):
        self.routes: Dict[Tuple[str, str], Route] = dict(routes or {})
        self.calls: List[Tuple[str, str, Any]] = []
        self.down = False
        #: What get_identity() derives from; None is Aux not answering (503).
        self.identity: Optional[Dict[str, Any]] = None
        #: The `muon` namespace's friendly_name, as aux_api_proxy keeps it.
        self.friendly_name: Optional[str] = None

    async def _call(self, method: str, path: str, body: Any) -> Any:
        await asyncio.sleep(0)
        self.calls.append((method, path, copy.deepcopy(body)))
        if self.down:
            raise ServerError(f"HTTP Request Error: {path}", 500)
        if (method, path) not in self.routes:
            raise ServerError("Not Found", 404)
        route = self.routes[(method, path)]
        if isinstance(route, BaseException):
            raise route
        if callable(route):
            return route(body)
        return copy.deepcopy(route)

    async def get(self, path: str) -> Any:
        return await self._call("GET", path, None)

    async def post(self, path: str, body: Any = None) -> Any:
        return await self._call("POST", path, body)

    async def delete(self, path: str) -> Any:
        return await self._call("DELETE", path, None)

    def posted(self, path: str) -> List[Any]:
        return [body for m, p, body in self.calls if m == "POST" and p == path]

    # aux_api_proxy's identity methods (MR-2), with its rules.
    async def get_identity(self) -> Dict[str, Any]:
        await asyncio.sleep(0)
        if self.down or self.identity is None:
            raise ServerError("The Aux API is not answering yet", 503)
        ident = dict(self.identity)
        if self.friendly_name:
            ident.update(name=self.friendly_name, source="owner",
                         display=f"{self.friendly_name.title()} · "
                                 f"{ident.get('suffix', '').upper()}")
        return ident

    async def store_friendly_name(self, name: Any) -> str:
        await asyncio.sleep(0)
        if not isinstance(name, str):
            raise ServerError("'name' must be a string", 400)
        name = name.strip()
        if len(name) > 32:
            raise ServerError("A printer name may be at most 32 characters", 400)
        self.friendly_name = name or None
        return name

    async def set_friendly_name(self, name: Any) -> Dict[str, Any]:
        await self.store_friendly_name(name)
        return await self.get_identity()


class FakeInternalTransport:
    def __init__(self, methods: Optional[Dict[str, Callable[..., Any]]] = None):
        self.methods = dict(methods or {})

    @property
    def transport_type(self) -> TransportType:
        return TransportType.INTERNAL

    async def call_method(self, method_name: str, request_arguments: Any = None,
                          **kwargs: Any) -> Any:
        if method_name not in self.methods:
            raise ServerError(f"No method {method_name} available")
        return self.methods[method_name]()


class FakeMachine:
    def __init__(self, addresses: Optional[List[str]] = None):
        self.addresses = list(addresses or ["192.168.1.37"])

    def get_system_info(self) -> Dict[str, Any]:
        return {"network": {"wlan0": {"ip_addresses": [
            {"family": "ipv4", "address": a, "is_link_local": False}
            for a in self.addresses
        ]}}}


class FakeServer:
    error = ServerError

    def __init__(self) -> None:
        self.components: Dict[str, Any] = {}
        self.endpoints: Dict[str, Tuple[List[str], Callable]] = {}
        self.notifications: List[str] = []
        self.events: List[Tuple[str, Tuple[Any, ...]]] = []
        self.log: List[Tuple[str, Any]] = []

    def lookup_component(self, name: str, default: Any = MISSING) -> Any:
        if name in self.components:
            return self.components[name]
        if default is MISSING:
            raise ServerError(f"Component ({name}) not found")
        return default

    def register_endpoint(self, path: str, verbs: List[str], handler: Callable,
                          **kwargs: Any) -> None:
        assert path not in self.endpoints, path
        self.endpoints[path] = (verbs, handler)

    def register_notification(self, event: str, notify_name: Any = None) -> None:
        self.notifications.append(event)

    def register_event_handler(self, event: str, callback: Callable) -> None:
        pass

    def send_event(self, event: str, *args: Any) -> None:
        self.events.append((event, copy.deepcopy(args)))
        self.log.append(("event", event))

    def changes(self) -> List[Dict[str, Any]]:
        return [args[0] for ev, args in self.events
                if ev == "muon_setup:muon_setup_changed"]


class FakeConfig:
    def __init__(self, server: FakeServer, options: Optional[Dict[str, str]] = None):
        self.server = server
        self.options = dict(options or {})

    def get_server(self) -> FakeServer:
        return self.server

    def error(self, msg: str) -> Exception:
        return ValueError(msg)

    def get(self, option: str, default: Any = MISSING) -> Any:
        if option in self.options:
            return self.options[option]
        if default is MISSING:
            raise ValueError(f"missing option {option}")
        return default

    def getint(self, option: str, default: Any = MISSING, **kwargs: Any) -> int:
        return int(self.get(option, default))

    def getfloat(self, option: str, default: Any = MISSING, **kwargs: Any) -> float:
        return float(self.get(option, default))

    def getlist(self, option: str, default: Any = MISSING,
                separator: str = "\n", **kwargs: Any) -> Any:
        value = self.options.get(option)
        if value is None:
            return default
        return [part.strip() for part in value.split(separator) if part.strip()]


# --------------------------------------------------------------------------
# Callers
# --------------------------------------------------------------------------

PANEL_IP = ipaddress.ip_address("127.0.0.1")
HOTSPOT_IP = ipaddress.ip_address("10.42.0.23")
LAN_IP = ipaddress.ip_address("192.168.1.50")
GATEWAY_IP = ipaddress.ip_address("192.0.2.1")
OTHER_IP = ipaddress.ip_address("203.0.113.9")


class _Request:
    def __init__(self, headers: Dict[str, str]) -> None:
        self.headers = headers


class FakeWebsocket:
    """What JsonRPC hands WebRequest for a websocket call: the connection,
    whose `request` is the upgrade request."""

    def __init__(self, headers: Dict[str, str]) -> None:
        self.request = _Request(headers)

    @property
    def transport_type(self) -> TransportType:
        return TransportType.WEBSOCKET


def user(groups: List[str], source: str = "moonraker") -> UserInfo:
    return UserInfo("_TRUSTED_USER_", "", groups=groups, source=source)


GOOD_HEADERS = {"Host": "10.42.0.1", "Content-Type": "application/json"}


def request(
    kind: str,
    endpoint: str,
    args: Optional[Dict[str, Any]] = None,
    *,
    headers: Optional[Dict[str, str]] = GOOD_HEADERS,
    websocket: bool = False,
    method: str = "POST",
) -> WebRequest:
    """A WebRequest as Moonraker would build it for this kind of caller."""
    rtype = RequestType.POST if method == "POST" else RequestType.GET
    transport: Any = None
    http_headers: Optional[Dict[str, str]] = dict(headers) if headers else None
    if kind == "internal":
        return WebRequest(endpoint, dict(args or {}), rtype,
                          FakeInternalTransport(), None, None)
    if websocket:
        transport = FakeWebsocket(dict(headers or {}))
        http_headers = None
    ip, usr = {
        "panel": (PANEL_IP, user(["panel"])),
        "hotspot": (HOTSPOT_IP, user(["network"])),
        "lan": (LAN_IP, user(["network"])),
        "remote": (GATEWAY_IP, user(["network"], source="muon_gateway")),
        "other": (OTHER_IP, None),
    }[kind]
    if kind == "panel" and headers is GOOD_HEADERS:
        http_headers = {"Host": "localhost", "Content-Type": "application/json"}
    return WebRequest(endpoint, dict(args or {}), rtype, transport, ip, usr,
                      http_headers)


# --------------------------------------------------------------------------
# Building the component
# --------------------------------------------------------------------------

IDENTITY = {
    "name": "walnut", "source": "derived", "derived_name": "walnut",
    "suffix": "8987", "display": "Walnut · 8987", "ssid": "Muon-walnut-8987",
    "fingerprint": "SHA256:placeholder",
}

#: MuonOS#174's region routes, for an EU-tokened unit with the DE fallback
#: applied at boot and nothing declared.
REGION_174 = {
    "reason": "applied", "explanation": "applied the token fallback",
    "domain": "DE", "declared_country": None, "configuration": "de",
    "surroundings": "unknown", "detected_country": None, "basis": None,
    "enforcement": "held", "locked": False,
    "channels": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 36, 40, 44, 48],
}
REGION_OPTIONS_174 = {
    "countries": ["AT", "BE", "CH", "DE", "FR", "GB", "IE", "IT", "NL"],
    "preselect": "DE", "basis": None, "locked": False,
}


def fresh_aux(**extra: Route) -> FakeAux:
    """A new unit's Aux: no marker, no saved networks, hotspot up.

    OS-5's routes are live: POST /wifi/ap/auto_off sets the deadline that
    GET /wifi/ap/stations then reports, as the real lifecycle does.
    """
    ap: Dict[str, Any] = {"up": True, "count": 0, "auto_off_at": None}

    def auto_off(body: Any) -> Dict[str, Any]:
        ap["auto_off_at"] = 1790252700.0
        return {"after_s": body["after_s"], "auto_off_at": ap["auto_off_at"]}

    routes: Dict[Tuple[str, str], Route] = {
        ("GET", "/wifi/ap/stations"): lambda body: dict(ap),
        ("POST", "/wifi/ap/auto_off"): auto_off,
        # OS-7's marker (MuonOS#313).
        ("GET", "/setup/complete"): {"complete": False, "completed_at": None,
                                     "by": None},
        ("GET", "/wifi/saved"): [],
        ("GET", "/wifi/ap/device/status"): {
            "device": "ap0", "device_type": "wifi", "state": "connected",
            "connection": "ap0-con"},
        ("POST", "/wifi/ap/count"): 0,
        ("GET", "/region"): REGION_174,
        ("GET", "/region/options"): REGION_OPTIONS_174,
        ("POST", "/setup/complete"): lambda body: {
            "complete": True, "completed_at": "2026-09-24T12:00:00+00:00",
            "by": body.get("by")},
        ("DELETE", "/setup/complete"): {"complete": False, "completed_at": None,
                                        "by": None},
    }
    for key, value in extra.items():
        method, path = key.split(" ", 1)
        routes[(method, path)] = value
    return FakeAux(routes)


class Harness:
    def __init__(
        self,
        *,
        stored: Optional[Dict[str, Any]] = None,
        aux: Optional[FakeAux] = None,
        namespaces: Optional[Dict[str, Dict[str, Any]]] = None,
        options: Optional[Dict[str, str]] = None,
        identity: Optional[Dict[str, Any]] = IDENTITY,
    ) -> None:
        self.server = FakeServer()
        ns = copy.deepcopy(namespaces or {})
        if stored is not None:
            ns.setdefault("muon_setup", {})["state"] = copy.deepcopy(stored)
        self.db = FakeDatabase(ns)
        self.db.log = self.server.log
        self.aux = aux if aux is not None else fresh_aux()
        if self.aux.identity is None and identity is not None:
            self.aux.identity = copy.deepcopy(identity)
        self.server.components.update({
            "database": self.db,
            "aux_api_proxy": self.aux,
            "machine": FakeMachine(),
            "internal_transport": FakeInternalTransport(),
        })
        opts = {"ready_manifest": "/nonexistent/ready.json"}
        opts.update(options or {})
        self.setup = MuonSetup(FakeConfig(self.server, opts))  # type: ignore[arg-type]

    async def start(self) -> "Harness":
        await self.setup._startup(poll=False)
        await self.setup.refresh_live()
        return self

    async def call(self, kind: str, endpoint: str,
                   args: Optional[Dict[str, Any]] = None, **kw: Any) -> Any:
        verbs, handler = self.server.endpoints[endpoint]
        method = kw.pop("method", verbs[0])
        return await handler(request(kind, endpoint, args, method=method, **kw))

    async def post(self, endpoint: str, args: Optional[Dict[str, Any]] = None,
                   kind: str = "panel", **kw: Any) -> Dict[str, Any]:
        path = f"/server/muon/setup{endpoint}"
        return await self.call(kind, path, args, **kw)

    async def get(self, endpoint: str = "", kind: str = "panel") -> Dict[str, Any]:
        return await self.call(kind, f"/server/muon/setup{endpoint}", method="GET")

    @property
    def doc(self) -> Dict[str, Any]:
        assert self.setup.doc is not None
        return self.setup.doc

    def stored(self) -> Dict[str, Any]:
        return self.db.namespaces["muon_setup"]["state"]


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def state_with(**steps: Dict[str, Any]) -> Dict[str, Any]:
    """A stored in-progress state with the given step fields merged in."""
    from moonraker.components.muon_setup import manifest, model
    doc = model.new_document(manifest.item_ids(manifest.DEFAULT_MANIFEST))
    doc["state"] = "in_progress"
    doc["rev"] = 5
    for step_id, fields in steps.items():
        doc["steps"][step_id].update(fields)
    model.advance(doc)
    return doc


__all__ = [
    "FakeAux", "FakeDatabase", "FakeServer", "Harness", "IDENTITY",
    "REGION_174", "REGION_OPTIONS_174", "fresh_aux", "muon_setup_pkg",
    "request", "run", "state_with",
]
