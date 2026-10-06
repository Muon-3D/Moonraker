# Moonraker component helper — muon_access_api.py
#
# AB-MR-2: `server.muon.access.*`, the contract of muon3d-app
# docs/plans/access-build.md section 2. Loaded by components/muon_access.py,
# not a component of its own.
#
#   GET  server.muon.access.get                 the state the app draws
#   GET  server.muon.access.capabilities        allowed | ask | refused, per action
#   POST server.muon.access.set_entry           {entry}
#   POST server.muon.access.set_private_uploads {enabled}
#   POST server.muon.access.set_data            {mode}
#   POST server.muon.access.set_levels          {preset} and/or {overrides}
#   POST server.muon.access.request             {ask: {kind: entry, entry}}
#                                               or {ask: {kind: join}}
#   GET  server.muon.access.request_status      {request_id}
#   POST server.muon.access.cancel_request      {request_id}
#   GET  server.muon.access.requests            the panel: requests waiting
#   POST server.muon.access.answer              the panel: {request_id, allow}
#
# The answers follow the shared fixture tests/fixtures/muon_access_contract.json,
# which muon3d-app's mock reads too, so the app, the mock and the printer agree.
#
# WHO MAY CHANGE A SETTING
#
# The four `set_*` methods are the table's "protection" row (access-model
# section 3): an admin's trusted device, or the panel; on a printer with no
# owner, the panel only. Anyone else admitted is answered `{"applied": false}`
# rather than refused, as the mock does, and may then ask the panel with
# `request` (design 2.5). muon_access_policy routes these methods to the
# handler as a delegated row so that this answer can be given.
#
# WHAT IT CANNOT ANSWER YET
#
# People, trusted devices and invites live in muon-link and the console
# (AB-LINK-3, AB-CON-1), so `people`, `members` and the counts of email and
# link invites are not in `get`, and `people`, `update_person`,
# `remove_person`, `trusted_devices` and `revoke_device` are not registered:
# the app falls back as it does for a printer without the method. A `join`
# request is recorded and the panel's answer reported, but letting a device
# in is muon-link's admission (AB-LINK-3); an allowed join changes nothing on
# the printer by itself.

from __future__ import annotations

import hashlib
import itertools
import logging
import secrets
import time
from typing import TYPE_CHECKING, Any, Dict, Optional

from .. import muon_access_policy as policy

if TYPE_CHECKING:
    from ..common import WebRequest
    from .muon_access import MuonAccess

PREFIX = "/server/muon/access"
REQUEST_EVENT = "muon_access:request"
REQUEST_NOTIFY = "muon_access_request"
#: How long a request waits for the panel (design 2.3).
REQUEST_SECONDS = 120.0
MAX_PENDING = 16

DATA_MODES = ("shared", "accounts", "both")
ASK_KINDS = ("entry", "join")


def api_level(level: int) -> str:
    """The contract's spelling of a level: hyphens, and the panel as admin."""
    if level >= policy.PANEL:
        level = policy.ADMIN
    return policy.LEVEL_NAMES[level].replace("_", "-")


def key_code(principal: str) -> str:
    """Four characters both screens show for a device (APP-44's short form)."""
    return hashlib.sha256(principal.encode()).hexdigest()[:4].upper()


class AccessApi:
    def __init__(self, access: MuonAccess) -> None:
        self.access = access
        self.server = access.server
        self.requests: Dict[str, Dict[str, Any]] = {}
        self._ids = itertools.count(1)
        routes = (
            ("get", "GET", self.get),
            ("capabilities", "GET", self.capabilities),
            ("set_entry", "POST", self.set_entry),
            ("set_private_uploads", "POST", self.set_private_uploads),
            ("set_data", "POST", self.set_data),
            ("set_levels", "POST", self.set_levels),
            ("request", "POST", self.request),
            ("request_status", "GET", self.request_status),
            ("cancel_request", "POST", self.cancel_request),
            ("requests", "GET", self.pending),
            ("answer", "POST", self.answer),
        )
        for name, verb, handler in routes:
            self.server.register_endpoint(f"{PREFIX}/{name}", [verb], handler)
        self.server.register_notification(REQUEST_EVENT, REQUEST_NOTIFY)

    # -- who is asking -------------------------------------------------------

    def principal(self, web_request: WebRequest) -> Optional[policy.Principal]:
        state = self.access.access_state()
        return policy.resolve_principal(
            web_request.transport, web_request.get_ip_address(),
            web_request.get_current_user(), state.entry, state.home,
        )

    def _require(self, web_request: WebRequest) -> policy.Principal:
        principal = self.principal(web_request)
        if principal is None:
            # check_access refuses these before the handler; kept for the
            # in-process caller that skips it.
            raise self.server.error("This connection is not admitted.", 403)
        return principal

    def requester(self, web_request: WebRequest) -> str:
        """Who a request belongs to. A principal by its name; a caller with
        none of its own (anyone at home, or not admitted yet) by its
        address, which stays the same when the entry changes under it."""
        principal = self.principal(web_request)
        if principal is not None and principal.kind not in ("home",):
            return principal.name
        return f"home:{web_request.get_ip_address()}"

    def _home_caller(self, web_request: WebRequest) -> Optional[policy.Principal]:
        """The principal, or None for a caller at home that is not admitted;
        403 for anyone else."""
        principal = self.principal(web_request)
        if principal is not None:
            return principal
        state = self.access.access_state()
        if policy.at_home_unadmitted(
            [policy.ACTIONS["access_request"]], web_request.get_ip_address(),
            state,
        ):
            return None
        raise self.server.error("This connection is not admitted.", 403)

    def _may(self, principal: policy.Principal, action: str) -> bool:
        return policy.decide_action(
            policy.ACTIONS[action], principal, self.access.access_state()
        ).allowed

    @staticmethod
    def trusted(principal: policy.Principal) -> bool:
        """A trusted device (ACC-20): an Iroh key the printer holds at the
        admin level. The panel is trusted too."""
        if principal.level >= policy.PANEL:
            return True
        return principal.kind == "gateway" and principal.level >= policy.ADMIN

    # -- reads ---------------------------------------------------------------

    def state_for(self, principal: policy.Principal) -> Dict[str, Any]:
        access = self.access
        state = access.access_state()
        return {
            "owner": access.owner_answer(),
            "entry": state.entry,
            "you": {
                "level": api_level(principal.level),
                "role": principal.role,
                "trusted": self.trusted(principal),
                "principal": principal.name,
            },
            "ways": {
                "email": {"on": False},
                "link": {"on": False},
                "password": {"on": access.password_set()},
                "approve": {"on": False},
            },
            "privateUploads": access.private_uploads(),
            "dataMode": access.data_mode(),
            "levelsPreset": policy.effective_preset(state),
        }

    async def get(self, web_request: WebRequest) -> Dict[str, Any]:
        return self.state_for(self._require(web_request))

    async def capabilities(self, web_request: WebRequest) -> Dict[str, Any]:
        principal = self._require(web_request)
        state = self.access.access_state()
        actions: Dict[str, str] = {}
        for name, action in policy.ACTIONS.items():
            if action.delegated:
                continue
            if policy.decide_action(action, principal, state).allowed:
                actions[name] = "allowed"
            elif self._askable(name, principal):
                actions[name] = "ask"
            else:
                actions[name] = "refused"
        return {"actions": actions}

    @staticmethod
    def _askable(action: str, principal: policy.Principal) -> bool:
        # The panel can be asked from home (design 2.5); only a change of
        # entry is something this printer can apply once allowed.
        return (
            action == "protection"
            and principal.home
            and principal.role != policy.VIEWER
        )

    # -- the settings -------------------------------------------------------

    async def _apply(
        self, web_request: WebRequest, changes: Dict[str, Any]
    ) -> Dict[str, Any]:
        principal = self._require(web_request)
        if not self._may(principal, "protection"):
            return {"applied": False}
        await self.access.update(changes)
        return {"applied": True}

    async def set_entry(self, web_request: WebRequest) -> Dict[str, Any]:
        entry = web_request.get_str("entry")
        if entry not in policy.ENTRIES:
            raise self.server.error(
                f"'entry' must be one of {list(policy.ENTRIES)}", 400)
        return await self._apply(web_request, {"entry": entry})

    async def set_private_uploads(
        self, web_request: WebRequest
    ) -> Dict[str, Any]:
        enabled = web_request.get_boolean("enabled")
        return await self._apply(web_request, {"private_uploads": enabled})

    async def set_data(self, web_request: WebRequest) -> Dict[str, Any]:
        mode = web_request.get_str("mode")
        if mode not in DATA_MODES:
            raise self.server.error(
                f"'mode' must be one of {list(DATA_MODES)}", 400)
        return await self._apply(web_request, {"data_mode": mode})

    async def set_levels(self, web_request: WebRequest) -> Dict[str, Any]:
        changes = self.access.level_changes(web_request)
        if not changes:
            raise self.server.error("Give 'preset' or 'overrides'.", 400)
        return await self._apply(web_request, changes)

    # -- confirm on the printer (design 2.5) --------------------------------

    def _expire(self) -> None:
        now = time.time()
        for request in self.requests.values():
            if request["status"] == "pending" and now > request["expires"]:
                request["status"] = "expired"

    async def request(self, web_request: WebRequest) -> Dict[str, Any]:
        principal = self._home_caller(web_request)
        if principal is not None and not principal.home:
            raise self.server.error(
                "The printer's screen can be asked only from its home "
                "network.", 403)
        ask = web_request.get("ask", None)
        if not isinstance(ask, dict) or ask.get("kind") not in ASK_KINDS:
            raise self.server.error(
                f"'ask' must be an object with 'kind' one of {list(ASK_KINDS)}",
                400)
        if ask["kind"] == "entry" and ask.get("entry") not in policy.ENTRIES:
            raise self.server.error(
                f"'ask.entry' must be one of {list(policy.ENTRIES)}", 400)
        self._expire()
        pending = [r for r in self.requests.values() if r["status"] == "pending"]
        if len(pending) >= MAX_PENDING:
            raise self.server.error("Too many requests are waiting.", 429)
        request_id = f"r{next(self._ids)}-{secrets.token_hex(4)}"
        code = (key_code(principal.name)
                if principal is not None and principal.kind == "gateway"
                else secrets.token_hex(2).upper())
        label = web_request.get("label", None)
        expires = time.time() + REQUEST_SECONDS
        record: Dict[str, Any] = {
            "requestId": request_id,
            "ask": {key: ask[key] for key in ("kind", "entry") if key in ask},
            "code": code,
            "expiresAt": int(expires * 1000),
            "expires": expires,
            "status": "pending",
            "requester": self.requester(web_request),
        }
        if isinstance(label, str) and label:
            record["label"] = label[:64]
        self.requests[request_id] = record
        self.server.send_event(REQUEST_EVENT, self._public(record))
        answer = {key: record[key] for key in ("requestId", "code", "expiresAt")}
        if "label" in record:
            answer["label"] = record["label"]
        return answer

    @staticmethod
    def _public(record: Dict[str, Any]) -> Dict[str, Any]:
        return {key: value for key, value in record.items()
                if key not in ("expires", "requester")}

    def _own(self, web_request: WebRequest) -> Optional[Dict[str, Any]]:
        principal = self._home_caller(web_request)
        request = self.requests.get(web_request.get_str("request_id"))
        if request is None:
            return None
        if principal is not None and principal.level >= policy.PANEL:
            return request
        if request["requester"] != self.requester(web_request):
            return None
        return request

    async def request_status(self, web_request: WebRequest) -> Dict[str, Any]:
        self._expire()
        request = self._own(web_request)
        return {"status": "expired" if request is None else request["status"]}

    async def cancel_request(self, web_request: WebRequest) -> str:
        request = self._own(web_request)
        if request is not None:
            self.requests.pop(request["requestId"], None)
        return "ok"

    def _panel_only(self, web_request: WebRequest) -> None:
        principal = self._require(web_request)
        if principal.level < policy.PANEL:
            raise self.server.error(
                "Requests are answered at the printer's panel.", 403)

    async def pending(self, web_request: WebRequest) -> Dict[str, Any]:
        self._panel_only(web_request)
        self._expire()
        return {"requests": [self._public(r) for r in self.requests.values()
                             if r["status"] == "pending"]}

    async def answer(self, web_request: WebRequest) -> Dict[str, Any]:
        self._panel_only(web_request)
        self._expire()
        request = self.requests.get(web_request.get_str("request_id"))
        if request is None or request["status"] != "pending":
            raise self.server.error("No such request is waiting.", 404)
        allow = web_request.get_boolean("allow")
        if allow and request["ask"]["kind"] == "entry":
            # Applied as the panel's own change: dual-written like any other
            await self.access.update({"entry": request["ask"]["entry"]})
        request["status"] = "allowed" if allow else "refused"
        logging.info(
            "muon_access: request %s (%s) %s at the panel",
            request["requestId"], request["ask"], request["status"],
        )
        return {"status": request["status"]}
