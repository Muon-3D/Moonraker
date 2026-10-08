# MUON, KAN-203 -- the "Remote access" step (spec 02 §5.9). Work package MR-5.
#
# `local` finishes the step at once and `later` skips it; `cloud` runs the
# account link through the muon_link component (muon-link's POST /link/start).
# The orchestrator, not muon-link, issues the code, so `cloud` is refused with
# `no_internet` unless the network step measured internet true, and with
# `clock_unsynced` until the clock is synced.
#
# muon_link emits no change event, so while the cursor is `remote`, the mode
# is `cloud` and the step isn't done, this module polls muon_link.status()
# every two seconds and mirrors the LinkPhase into `steps.remote.link`
# unchanged. Codes never expire on their own: once the synced clock passes
# `expires_at`, start() is called again; a `failed` phase gets one retry;
# start() is never called during `offer`, which would silently drop the
# pending offer. `linked` finishes the step with the account; `unavailable`
# or a 503 leaves the step pending with `link_unavailable`; a second `failed`
# leaves `link_failed`.
#
# `POST /server/muon/setup/remote/cancel` stops the renewal, forwards
# /link/cancel and clears mode and link. It is a no-op once the printer is
# linked, and it goes through the same Level 1 protection check as
# network/cancel rather than write(): at Level 1 the LAN may not cancel a
# link the panel started.
#
# `capabilities.cloud_link` follows GET /server/muon/link: a reachable
# muon-link whose phase isn't `unavailable`. It is false when muon_link is
# missing, when muon-link doesn't answer (503), and when no orchestrator is
# configured.

from __future__ import annotations

import asyncio
import copy
import logging
import time
from typing import TYPE_CHECKING, Any, Dict, Optional

from . import caller, model

if TYPE_CHECKING:
    from . import MuonSetup, WriteContext
    from ...common import WebRequest

#: How often the link phase is polled while the step waits (02 §5.9).
POLL_SECONDS = 2.0
#: The phases muon-link answers a refused start with (its STANDING_PHASES).
STANDING = ("offer", "linked")


def register(setup: MuonSetup) -> None:
    setup.server.register_endpoint(
        "/server/muon/setup/remote", ["POST"],
        lambda webreq: handle_remote(setup, webreq))
    setup.live_refreshers.append(lambda: refresh(setup))


def _link(setup: MuonSetup) -> Any:
    return setup.server.lookup_component("muon_link", None)


# --------------------------------------------------------------------------
# capabilities.cloud_link + the poller's lifetime
# --------------------------------------------------------------------------

async def refresh(setup: MuonSetup) -> None:
    """The live_refreshers entry: cloud_link follows GET /server/muon/link,
    and a stored cloud step that outlived a reboot gets its poller back."""
    link = _link(setup)
    capable = False
    if link is not None:
        try:
            status = await link.call("GET", "/link")
        except Exception:
            pass
        else:
            capable = (isinstance(status, dict)
                       and status.get("phase") != "unavailable")
    setup._live["capabilities"]["cloud_link"] = capable
    if _waiting(setup):
        _ensure_poller(setup)


def _waiting(setup: MuonSetup) -> bool:
    """Whether the step is waiting on the link: the poller's whole life."""
    doc = setup.doc
    if doc is None or setup._closed:
        return False
    step = doc["steps"]["remote"]
    return (doc["cursor"] == "remote" and step.get("mode") == "cloud"
            and step["status"] == "pending" and step.get("error") is None)


def _ensure_poller(setup: MuonSetup) -> None:
    task = getattr(setup, "_remote_poll_task", None)
    if task is not None and not task.done():
        return
    setup._remote_poll_task = setup._spawn(_poll(setup))


# --------------------------------------------------------------------------
# POST /server/muon/setup/remote {rev, mode}
# --------------------------------------------------------------------------

async def handle_remote(
    setup: MuonSetup, webreq: WebRequest
) -> Dict[str, Any]:
    async def handler(ctx: WriteContext) -> Optional[Dict[str, Any]]:
        doc = ctx.doc
        step = doc["steps"]["remote"]
        mode = ctx.args.get("mode")
        if mode == "local":
            step.update(mode="local", status="done", error=None)
            setup.advance()
            return None
        if mode == "later":
            step.update(mode="later", status="skipped", error=None)
            setup.advance()
            return None
        if mode != "cloud":
            return model.error(
                "invalid_mode", "'mode' must be local, cloud or later",
                field="mode")
        # 02 §5.9 step 7: the orchestrator makes the code, so the network
        # must have measured internet and the clock must be synced.
        if doc["steps"]["network"].get("internet") is not True:
            return model.error(
                "no_internet", "cloud linking needs the internet")
        if setup._live["clock"].get("synced") is not True:
            return model.error(
                "clock_unsynced", "cloud linking needs a synced clock")
        link = _link(setup)
        if link is None:
            step["error"] = model.error(
                "link_unavailable", "muon-link is not configured")
            return None
        step.update(mode="cloud", status="pending", error=None)
        try:
            status = await link.start()
        except Exception:
            step["error"] = model.error(
                "link_unavailable", "muon-link is not answering")
            return None
        if isinstance(status, dict) and status.get("phase") == "linked":
            step.update(link=copy.deepcopy(status), status="done",
                        account=status.get("account"), error=None)
            setup.advance()
            return None
        if isinstance(status, dict) and status.get("phase") == "unavailable":
            step.update(link=copy.deepcopy(status))
            step["error"] = model.error(
                "link_unavailable", "no link orchestrator is configured")
            return None
        step["link"] = copy.deepcopy(status)
        _ensure_poller(setup)
        return None
    # remote is writable after `complete` (01 §3).
    return await setup.write(webreq, handler, after_complete=True)


# --------------------------------------------------------------------------
# POST /server/muon/setup/remote/cancel {}  (registered in __init__)
# --------------------------------------------------------------------------

async def handle_cancel(
    setup: MuonSetup, webreq: WebRequest
) -> Dict[str, Any]:
    from . import STARTUP_WAIT
    kind = setup.begin(webreq)
    if not await setup.wait_resolved(STARTUP_WAIT) or setup.doc is None:
        return setup.envelope(model.error(
            "aux_unavailable", "setup state is not ready yet"))
    # The same Level 1 check network/cancel makes (02 §3): at Level 1 the
    # LAN may not decline a link the panel started.
    caller.refuse_if_protected(kind, setup.doc["state"])
    doc = setup.doc
    step = doc["steps"]["remote"]
    if step["status"] == "done":
        return setup.envelope()  # no-op once linked (02 §5.9)
    task = getattr(setup, "_remote_poll_task", None)
    if task is not None and not task.done():
        task.cancel()
        try:
            await asyncio.wait_for(asyncio.shield(task), 5.)
        except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
            pass
    link = _link(setup)
    if link is not None:
        try:
            await link.cancel()
        except Exception as exc:
            logging.info("muon_setup: muon-link cancel failed: %s", exc)
    async with setup._lock:
        if setup.doc is not None:
            setup.doc["steps"]["remote"].update(
                mode=None, link=None, error=None)
            await setup._commit()
    return setup.envelope()


# --------------------------------------------------------------------------
# The two-second poll
# --------------------------------------------------------------------------

async def _poll(setup: MuonSetup) -> None:
    retried = False
    while _waiting(setup):
        await asyncio.sleep(POLL_SECONDS)
        if not _waiting(setup):
            return
        link = _link(setup)
        if link is None:
            await _fail(setup, "link_unavailable",
                        "muon-link is not configured")
            return
        try:
            status = await link.status()
        except Exception:
            await _fail(setup, "link_unavailable",
                        "muon-link is not answering")
            return
        if not isinstance(status, dict):
            continue
        phase = status.get("phase")
        if phase == "unavailable":
            await _mirror(setup, status)
            await _fail(setup, "link_unavailable",
                        "no link orchestrator is configured")
            return
        if phase == "linked":
            await _linked(setup, status)
            return
        if phase == "failed" and not retried:
            # One retry on a failed ceremony (02 §5.9 step 3).
            retried = True
            await _mirror(setup, status)
            try:
                status = await link.start()
            except Exception:
                await _fail(setup, "link_failed",
                            "muon-link is not answering",
                            detail={"message": "the retry could not start"})
                return
            if isinstance(status, dict) and status.get("phase") == "linked":
                await _linked(setup, status)
                return
            await _mirror(setup, status)
            continue
        if phase == "failed":
            await _mirror(setup, status)
            await _fail(setup, "link_failed", "the account link failed",
                        detail={"message": status.get("message")})
            return
        if phase == "code" and _code_expired(setup, status):
            # The code is past its life; ask for another (02 §5.9 step 3).
            # Never during `offer`: starting then drops the pending offer.
            try:
                renewed = await link.start()
            except Exception:
                renewed = None
            if isinstance(renewed, dict) and renewed.get("phase") == "linked":
                await _linked(setup, renewed)
                return
            if isinstance(renewed, dict):
                await _mirror(setup, renewed)
            continue
        await _mirror(setup, status)


def _code_expired(setup: MuonSetup, status: Dict[str, Any]) -> bool:
    expires = status.get("expires_at")
    if not isinstance(expires, int) or isinstance(expires, bool):
        return False
    if setup._live["clock"].get("synced") is not True:
        return False  # an unsynced clock cannot judge an expiry
    return time.time() > expires


async def _mirror(setup: MuonSetup, status: Dict[str, Any]) -> None:
    """Copy the phase object into remote.link unchanged; rev bumps only when
    it changed (it's stored state, 02 §5.9 step 2)."""
    async with setup._lock:
        doc = setup.doc
        if doc is None or doc["steps"]["remote"].get("link") == status:
            return
        doc["steps"]["remote"]["link"] = copy.deepcopy(status)
        await setup._commit()


async def _linked(setup: MuonSetup, status: Dict[str, Any]) -> None:
    async with setup._lock:
        doc = setup.doc
        if doc is None:
            return
        doc["steps"]["remote"].update(
            link=copy.deepcopy(status), status="done",
            account=status.get("account"), error=None)
        setup.advance()
        await setup._commit()


async def _fail(setup: MuonSetup, code: str, message: str,
                detail: Optional[Dict[str, Any]] = None) -> None:
    async with setup._lock:
        doc = setup.doc
        if doc is None:
            return
        step = doc["steps"]["remote"]
        step["status"] = "pending"
        err = model.error(code, message)
        err["detail"].update(detail or {})
        step["error"] = err
        await setup._commit()
