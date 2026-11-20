# MUON, KAN-4812: the panel's live state, and remote navigation of the panel.
# Loaded by components/muon_panel.py, not a component of its own. The contract
# is in docs/muon_panel.md.
#
#   POST server.muon.panel.publish          the panel: {state}
#   GET  server.muon.panel.state            Viewer and up
#   POST server.muon.panel.navigate         Operator and up: {screen, params?,
#                                           if_seq?}
#   POST server.muon.panel.navigate_result  the panel: {req_id, ok, status?,
#                                           reason?, seq?}
#
# WHO THE PANEL IS
#
# Exactly one connection: a local one (a peer at 127.0.0.1 or ::1, or the unix
# socket) that identified itself as client_name "muon-panel" and registered
# the remote method `muon_panel_navigate`. The latest one to identify wins.
# publish and navigate_result are accepted from that connection and from no
# other, which this module checks on every call; muon_access_policy refuses
# them to every remote principal, the owner included, before it gets here.
# Not an HTTP request either: a plain POST has no connection to check.
from __future__ import annotations

import asyncio
import json
import logging
import secrets
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from .. import muon_access_policy as policy
from .. import muon_floor
from ..common import BaseRemoteConnection, RequestType
from ..utils.exceptions import BodyError

if TYPE_CHECKING:
    from ..common import WebRequest
    from ..server import Server

PREFIX = "/server/muon/panel"
PANEL_NAME = "muon-panel"
NAVIGATE_METHOD = "muon_panel_navigate"
NOTIFICATION = "muon_panel_state"
#: How long a navigation waits for the panel's answer.
NAV_TIMEOUT = 2.0
#: Navigations waiting for the panel at once.
MAX_PENDING = 8
#: The most notify_muon_panel_state sends: 10 a second.
NOTIFY_INTERVAL = 0.1
MAX_STATE_BYTES = 64 * 1024
MAX_PARAMS_BYTES = 16 * 1024
MAX_ROUTES = 256
MAX_NAME = 128
#: What a published seq may be: a JSON number a browser reads exactly.
MAX_SEQ = 2 ** 53 - 1
#: One caller's navigations: waiting at once, and started per second.
CALLER_PENDING = 2
CALLER_RATE = 2
CALLER_WINDOW = 1.0
#: What a panel may say when it refuses a navigation.
PASSTHROUGH = (409, 423)


def refusal(status: int, reason: str, **fields: Any) -> BodyError:
    """An error whose answer is {reason, ...}."""
    return BodyError(reason, status, {"reason": reason, **fields})


def _size(value: Any) -> int:
    return len(json.dumps(value, separators=(",", ":")))


def _plain_int(value: Any) -> Optional[int]:
    """An int, or a string of digits (a query string), else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _name(value: Any) -> Optional[str]:
    if isinstance(value, str) and 0 < len(value) <= MAX_NAME:
        return value
    return None


def route_key(screen: str) -> str:
    """A screen id as owner-only routes are compared: lower case, without
    leading or trailing slashes or spaces."""
    return screen.strip().strip("/").strip().lower()


class PanelNav:
    def __init__(self, server: Server) -> None:
        self.server = server
        self._panel: Optional[BaseRemoteConnection] = None
        #: What the panel last published, validated; None until it does.
        self._state: Optional[Dict[str, Any]] = None
        self._last_seq = 0
        #: req_id -> (answer, the connection it was sent to)
        self._pending: Dict[
            str, Tuple[asyncio.Future, BaseRemoteConnection]] = {}
        #: req_id -> whose navigation it is
        self._callers: Dict[str, str] = {}
        #: caller -> when its recent navigations started
        self._starts: Dict[str, List[float]] = {}
        self._last_sent = float("-inf")
        self._dirty = False
        self._timer: Optional[asyncio.TimerHandle] = None
        for name, verb, handler in (
            ("publish", RequestType.POST, self._publish),
            ("state", RequestType.GET, self._get_state),
            ("navigate", RequestType.POST, self._navigate),
            ("navigate_result", RequestType.POST, self._navigate_result),
        ):
            server.register_endpoint(f"{PREFIX}/{name}", verb, handler)
        policy.register_notification_filter(NOTIFICATION, self._visible)
        server.register_event_handler(
            "websockets:client_identified", self._on_identified)
        server.register_event_handler(
            "websockets:client_removed", self._on_removed)

    # -- who is the panel ---------------------------------------------------

    @staticmethod
    def _is_local(conn: BaseRemoteConnection) -> bool:
        # The same address the floor trusts: a loopback peer, which the
        # gateway's sentinel is not, and the unix socket's 127.0.0.1.
        return muon_floor.local_address(
            getattr(conn, "authentication_ip", None))

    def _registered_method(self, conn: BaseRemoteConnection) -> bool:
        extensions: Any = self.server.lookup_component("extensions", None)
        methods = getattr(extensions, "agent_methods", {})
        return NAVIGATE_METHOD in methods.get(conn.uid, ())

    def _qualifies(self, conn: BaseRemoteConnection) -> bool:
        return (
            not conn.is_closed
            and conn.identified
            and conn.client_data.get("name") == PANEL_NAME
            and self._is_local(conn)
            and self._registered_method(conn)
        )

    def _is_panel(self, conn: Optional[BaseRemoteConnection]) -> bool:
        return (
            conn is not None and conn is self._panel and self._qualifies(conn)
        )

    def _require_panel(self, web_request: WebRequest) -> BaseRemoteConnection:
        conn = web_request.get_client_connection()
        if conn is None or not self._is_panel(conn):
            raise refusal(403, "not_panel")
        return conn

    def _on_identified(self, conn: BaseRemoteConnection) -> None:
        if conn.client_data.get("name") != PANEL_NAME:
            return
        if not self._is_local(conn):
            logging.warning(
                "muon_panel: a non-local connection identified as the panel "
                "and is ignored")
            return
        if self._panel is not None and self._panel is not conn:
            self._drop_panel()
        self._panel = conn
        self._state = None
        self._changed()

    def _on_removed(self, conn: BaseRemoteConnection) -> None:
        if conn is self._panel:
            self._drop_panel()
            self._changed()

    def _drop_panel(self) -> None:
        self._panel = None
        self._state = None
        for fut, _ in list(self._pending.values()):
            if not fut.done():
                fut.set_exception(refusal(503, "panel_offline"))

    # -- the state ----------------------------------------------------------

    def view(self) -> Dict[str, Any]:
        if self._panel is None:
            return {"connected": False}
        if self._state is None:
            return {"connected": True}
        return {"connected": True, **self._state}

    def _changed(self) -> None:
        """Tell the other clients, at most NOTIFY_INTERVAL apart: while one
        is waiting its turn, a newer state replaces what it will send."""
        self._dirty = True
        if self._timer is not None:
            return
        loop = self.server.get_event_loop()
        wait = self._last_sent + NOTIFY_INTERVAL - loop.get_loop_time()
        if wait <= 0:
            self._flush()
        else:
            self._timer = loop.delay_callback(wait, self._flush)

    def _flush(self) -> None:
        self._timer = None
        if not self._dirty:
            return
        self._dirty = False
        self._last_sent = self.server.get_event_loop().get_loop_time()
        mask = [self._panel.uid] if self._panel is not None else []
        wsm: Any = self.server.lookup_component("websockets")
        wsm.notify_clients(NOTIFICATION, [self.view()], mask)

    def _visible(self, data: Any, connection: Any) -> Any:
        """Who is sent the state: whoever may read it by GET."""
        current = policy.state()
        if current is None:
            return data
        principal = policy.resolve_principal(
            connection, connection.ip_addr, connection.user_info,
            current.entry, current.home)
        if principal is None or not policy.decide_action(
                policy.READ, principal, current).allowed:
            return None
        return data

    @staticmethod
    def _checked(raw: Any) -> Dict[str, Any]:
        """The published state as the panel may say it, or a 400."""
        if not isinstance(raw, dict):
            raise refusal(400, "bad_state")
        if _size(raw) > MAX_STATE_BYTES:
            raise refusal(400, "state_too_large")
        seq = _plain_int(raw.get("seq", 0))
        if seq is not None and not 0 <= seq <= MAX_SEQ:
            raise refusal(400, "bad_seq")
        screen = _name(raw.get("screen"))
        params = raw.get("params")
        busy = raw.get("busy", False)
        routes = raw.get("owner_only_routes", [])
        updated_at = raw.get("updated_at")
        if (
            seq is None or screen is None
            or not isinstance(params, (dict, type(None)))
            or not isinstance(busy, bool)
            or not isinstance(routes, list) or len(routes) > MAX_ROUTES
            or any(_name(route) is None for route in routes)
            or isinstance(updated_at, bool)
            or not isinstance(updated_at, (int, float, str, type(None)))
        ):
            raise refusal(400, "bad_state")
        return {
            "seq": seq,
            "screen": screen,
            "params": params or {},
            "modal": raw.get("modal"),
            "busy": busy,
            "updated_at": updated_at,
            "owner_only_routes": list(routes),
        }

    async def _publish(self, web_request: WebRequest) -> Dict[str, Any]:
        self._require_panel(web_request)
        state = self._checked(web_request.get("state"))
        # Moonraker's own count, so a client can compare it for if_seq
        # whatever the panel numbers.
        if state["seq"] <= self._last_seq:
            if self._last_seq >= MAX_SEQ:
                raise refusal(400, "bad_seq")
            state["seq"] = self._last_seq + 1
        self._last_seq = state["seq"]
        self._state = state
        self._changed()
        return {"seq": state["seq"]}

    async def _get_state(self, web_request: WebRequest) -> Dict[str, Any]:
        return self.view()

    # -- navigating -----------------------------------------------------

    def _caller(
        self, web_request: WebRequest
    ) -> Optional[policy.Principal]:
        """Who is asking, by muon_access's own reading of the request. None
        is nobody it admits, which is neither the owner nor an Operator."""
        access: Any = self.server.lookup_component("muon_access", None)
        state = (
            access.access_state() if access is not None
            else policy.AccessState())
        return policy.resolve_principal(
            web_request.transport, web_request.get_ip_address(),
            web_request.get_current_user(), state.entry, state.home)

    @staticmethod
    def _caller_key(
        web_request: WebRequest, principal: Optional[policy.Principal]
    ) -> Optional[str]:
        """Whose navigations are counted together: the muon access
        principal. None for the panel and local callers, who are exempt."""
        if principal is None:
            return f"ip:{web_request.get_ip_address()}"
        if principal.level >= policy.PANEL:
            return None
        return f"{principal.kind}:{principal.name}"

    def _check_caller(self, caller: Optional[str]) -> None:
        """429 rate_limited past CALLER_PENDING waiting or CALLER_RATE
        started in the last CALLER_WINDOW; counts this one when it passes."""
        if caller is None:
            return
        now = self.server.get_event_loop().get_loop_time()
        recent = [t for t in self._starts.get(caller, [])
                  if now - t < CALLER_WINDOW]
        waiting = sum(1 for who in self._callers.values() if who == caller)
        if waiting >= CALLER_PENDING or len(recent) >= CALLER_RATE:
            self._starts[caller] = recent
            raise refusal(429, "rate_limited")
        self._starts[caller] = recent + [now]
        if len(self._starts) > 256:
            self._starts = {k: v for k, v in self._starts.items() if v and
                            now - v[-1] < CALLER_WINDOW}

    async def _navigate(self, web_request: WebRequest) -> Dict[str, Any]:
        screen = _name(web_request.get("screen"))
        params = web_request.get("params", None)
        if_seq = web_request.get("if_seq", None)
        if screen is None:
            raise refusal(400, "bad_screen")
        if params is None:
            params = {}
        if not isinstance(params, dict) or _size(params) > MAX_PARAMS_BYTES:
            raise refusal(400, "bad_params")
        if if_seq is not None:
            if_seq = _plain_int(if_seq)
            if if_seq is None:
                raise refusal(400, "bad_if_seq")
        panel, state = self._panel, self._state
        # Until the panel has published, which screens are the owner's is not
        # known, so there is nothing safe to forward.
        if panel is None or state is None or not self._qualifies(panel):
            raise refusal(503, "panel_offline")
        principal = self._caller(web_request)
        owner = principal is not None and principal.level >= policy.ADMIN
        owner_only = {route_key(r) for r in state["owner_only_routes"]}
        if route_key(screen) in owner_only and not owner:
            raise refusal(403, "owner_only")
        if if_seq is not None and if_seq != state["seq"]:
            raise refusal(409, "stale_seq", seq=state["seq"])
        caller = self._caller_key(web_request, principal)
        self._check_caller(caller)
        if len(self._pending) >= MAX_PENDING:
            raise refusal(429, "too_many_navigations")
        req_id = secrets.token_hex(8)
        fut: asyncio.Future = self.server.get_event_loop().create_future()
        self._pending[req_id] = (fut, panel)
        if caller is not None:
            self._callers[req_id] = caller
        try:
            panel.call_method(NAVIGATE_METHOD, {
                "req_id": req_id,
                "screen": screen,
                "params": params,
                "caller_role": principal.role if principal else policy.VIEWER,
                "caller_is_owner": owner,
                "caller_level": (
                    policy.LEVEL_NAMES[principal.level] if principal
                    else "none"),
            })
            try:
                answer = await asyncio.wait_for(fut, NAV_TIMEOUT)
            except asyncio.TimeoutError:
                raise refusal(504, "panel_timeout") from None
        finally:
            self._pending.pop(req_id, None)
            self._callers.pop(req_id, None)
        if answer["ok"]:
            # Moonraker's own count, whatever the panel says it reached
            return {"seq": (self._state or state)["seq"]}
        raise refusal(answer["status"], answer["reason"])

    async def _navigate_result(
        self, web_request: WebRequest
    ) -> Dict[str, Any]:
        conn = web_request.get_client_connection()
        if not self._is_panel(conn):
            logging.debug("muon_panel: navigate_result from a connection "
                          "that is not the panel, dropped")
            raise refusal(403, "not_panel")
        req_id = web_request.get("req_id", None)
        entry = self._pending.get(req_id) if isinstance(req_id, str) else None
        if entry is None or entry[1] is not conn:
            logging.debug("muon_panel: navigate_result for an unknown or "
                          "finished request, dropped")
            return {"accepted": False}
        ok = web_request.get("ok", False) is True
        status = _plain_int(web_request.get("status", None))
        reason = web_request.get("reason", None)
        fut = entry[0]
        if not fut.done():
            fut.set_result({
                "ok": ok,
                "status": status if status in PASSTHROUGH else 409,
                "reason": (
                    reason[:MAX_NAME] if isinstance(reason, str) and reason
                    else "refused"),
            })
        return {"accepted": True}
