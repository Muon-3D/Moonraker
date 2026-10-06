"""Fakes for muon_access, muon_access_api and muon_protection: a server, a
database with namespaces, the link and the authorization component. No
sockets and no event loop fixtures; tests drive coroutines with asyncio.run.
"""
from __future__ import annotations

import asyncio
import ipaddress
from typing import Any, Dict, List, Optional, Tuple

from moonraker import muon_access_policy as policy
from moonraker.common import RequestType, WebRequest
from moonraker.components.muon_access import MuonAccess
from moonraker.components.muon_gateway import GatewayUser
from moonraker.components.muon_protection import MuonProtection
from moonraker.utils.exceptions import ServerError

LOOPBACK = ipaddress.ip_address("127.0.0.1")
LAN = ipaddress.ip_address("192.168.1.50")
SENTINEL = ipaddress.ip_address("192.0.2.1")

IP_JSON = [{"ifname": "wlan0", "addr_info": [
    {"family": "inet", "local": "192.168.1.10", "prefixlen": 24}]}]


class Transport:
    def __init__(self, name: str) -> None:
        self.transport_type = type("_T", (), {"name": name})()


HTTP = Transport("HTTP")


class Namespace:
    def __init__(self) -> None:
        self.values: Dict[str, Any] = {}
        self.fail_get = False
        self.fail_insert = False
        self.fail_delete = False

    async def get(self, key: str, default: Any = None) -> Any:
        if self.fail_get:
            return default  # Like get_item: a default swallows read errors.
        return self.values.get(key, default)

    async def insert(self, key: str, value: Any) -> None:
        if self.fail_insert:
            raise RuntimeError("database read-only")
        self.values[key] = value

    async def delete(self, key: str) -> Any:
        if self.fail_delete:
            raise RuntimeError("database read-only")
        if key not in self.values:
            raise ServerError(f"Key '{key}' not found", 404)
        return self.values.pop(key)


class Database:
    def __init__(self) -> None:
        self.namespaces: Dict[str, Namespace] = {}
        self.registered: List[str] = []

    def ns(self, name: str) -> Namespace:
        return self.namespaces.setdefault(name, Namespace())

    async def get_batch(self, namespace: str, keys: List[str]) -> Dict[str, Any]:
        ns = self.ns(namespace)
        if ns.fail_get:
            raise RuntimeError("database unreadable")
        return {key: ns.values[key] for key in keys if key in ns.values}

    async def delete_batch(self, namespace: str, keys: List[str]) -> None:
        ns = self.ns(namespace)
        if ns.fail_delete:
            raise RuntimeError("database read-only")
        for key in keys:
            ns.values.pop(key, None)

    def register_local_namespace(
        self, namespace: str, forbidden: bool = False, parse_keys: bool = False
    ) -> Namespace:
        assert forbidden, namespace
        assert namespace not in self.registered, namespace
        self.registered.append(namespace)
        return self.ns(namespace)

    async def get_item(self, namespace: str, key: str, default: Any = None) -> Any:
        if namespace not in self.namespaces:
            raise ServerError(f"Namespace '{namespace}' not found", 404)
        return await self.ns(namespace).get(key, default)

    async def insert_item(self, namespace: str, key: str, value: Any) -> None:
        await self.ns(namespace).insert(key, value)


class Link:
    def __init__(self, phase: str = "unlinked",
                 account: Optional[str] = None) -> None:
        self.phase = phase
        self.account = account

    async def status(self) -> Dict[str, Any]:
        body: Dict[str, Any] = {"phase": self.phase}
        if self.account:
            body["account"] = self.account
        return body


class Authorization:
    def __init__(self, password_set: bool) -> None:
        self._set = password_set

    def panel_login_set(self) -> bool:
        return self._set


class Server:
    error = ServerError

    def __init__(self) -> None:
        self.database = Database()
        self.components: Dict[str, Any] = {"database": self.database}
        self.handlers: Dict[str, Tuple[List[str], Any]] = {}
        self.events: List[Tuple[str, Tuple[Any, ...]]] = []
        self.event_handlers: Dict[str, List[Any]] = {}

    def lookup_component(self, name: str, default: Any = None) -> Any:
        return self.components.get(name, default)

    def load_component(self, config: Any, name: str, default: Any = None) -> Any:
        return self.components.get(name, default)

    def register_endpoint(self, path: str, verbs: List[str], handler: Any) -> None:
        self.handlers[path] = (verbs, handler)

    def register_notification(self, *args: Any) -> None:
        pass

    def register_event_handler(self, event: str, callback: Any) -> None:
        self.event_handlers.setdefault(event, []).append(callback)

    def send_event(self, event: str, *args: Any) -> None:
        self.events.append((event, args))


class Config:
    error = ValueError

    def __init__(self, server: Server, dual_write: bool = True) -> None:
        self.server = server
        self.dual_write = dual_write

    def get_server(self) -> Server:
        return self.server

    def getboolean(self, name: str, default: bool) -> bool:
        assert name == "dual_write_protection_level"
        return self.dual_write


def fake_interfaces(access: MuonAccess) -> None:
    async def read_interfaces() -> Any:
        return IP_JSON
    access.read_interfaces = read_interfaces  # type: ignore[assignment]


def restart(server: Server) -> Server:
    """A new process on the same database."""
    new = Server()
    new.database = server.database
    new.database.registered = []
    new.components["database"] = new.database
    return new


def printer(
    server: Optional[Server] = None,
    old_level: Any = None,
    record: Any = None,
    link: Optional[Link] = None,
    dual_write: bool = True,
    password_set: bool = False,
    with_access: bool = True,
) -> Tuple[Optional[MuonAccess], MuonProtection, Server]:
    """A printer with muon_protection and (unless with_access is False)
    muon_access, started."""
    server = server or Server()
    if old_level is not None:
        server.database.ns("muon_protection").values["level"] = old_level
    if record is not None:
        server.database.ns("muon_access").values["record"] = record
    if link is not None:
        server.components["muon_link"] = link
    server.components["authorization"] = Authorization(password_set)
    protection = MuonProtection(Config(server))
    server.components["muon_protection"] = protection
    access: Optional[MuonAccess] = None
    if with_access:
        access = MuonAccess(Config(server, dual_write=dual_write))
        server.components["muon_access"] = access
        fake_interfaces(access)

    async def start() -> None:
        await protection.component_init()
        if access is not None:
            await access.component_init()
            await access.close()   # stop the poll; publish the state again
            policy.set_state(access.access_state())
            policy.set_files(access.guard)

    asyncio.run(start())
    return access, protection, server


def caller(case: Dict[str, Any]) -> Tuple[Any, Any, Any]:
    """(transport, ip, user) for a fixture caller."""
    kind = case["kind"]
    if kind == "panel":
        return HTTP, LOOPBACK, None
    if kind == "home":
        from moonraker.common import UserInfo
        return HTTP, LAN, UserInfo("_TRUSTED_USER_", "")
    if kind == "password":
        from moonraker.common import UserInfo
        return HTTP, LAN, UserInfo("admin", "", source="moonraker")
    if kind == "gateway":
        user = GatewayUser(
            "muon-link:0123456789abcdef", "", source="muon_gateway",
            principal=case["principal"],
            access_level=case["level"].replace("-", "_"),
            access_role=case["role"], access_home=case["home"],
        )
        return HTTP, SENTINEL, user
    raise AssertionError(kind)


def call(server: Server, method: str, params: Optional[Dict[str, Any]] = None,
         who: Tuple[Any, Any, Any] = (HTTP, LOOPBACK, None)) -> Any:
    """Call server.muon.access.<method>'s handler as `who`."""
    path = f"/server/muon/access/{method}"
    verbs, handler = server.handlers[path]
    request_type = RequestType.GET if verbs == ["GET"] else RequestType.POST
    transport, ip, user = who
    request = WebRequest(path, dict(params or {}), request_type, transport,
                         ip, user)
    return asyncio.run(handler(request))
