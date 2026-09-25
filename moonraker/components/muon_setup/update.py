# MUON, KAN-203 -- the update step (spec 01 §2, 02 §5.8). Work package MR-4.
#
# "Install now" starts the install through update_manager's MuonOS updater,
# the same path as POST /machine/update/upgrade?name=MuonOS, as a
# component-to-component call: update_manager's print refusal, its lock and
# its notify_update_response lines all apply, and it ends at the same Aux
# POST /update/install. muon_setup never commits an update itself; the OTA
# commit policy (KAN-358) decides that.
#
# Progress and the result come from Aux GET /update/status, never from
# update_manager's cache: OtaDeploy reports "?" until it refreshes, which the
# M1 does weekly, and OtaDeploy.update() can return early (300 s without
# progress, or on losing contact) while the install carries on. So the step
# follows Aux until Aux says the install is over.
#
# An install ends in a reboot, so the operation outlives this process. The
# target version is frozen into `op.target` when the install starts -- the Aux
# status fields change during a commit, so reading the target afterwards would
# compare a value with itself -- and once Aux is `idle`, `commit_pending` or
# `failed`, its `current_version` is compared with it: equal is done,
# anything else rolled back.

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any, Dict, Optional

from . import model

if TYPE_CHECKING:
    from . import MuonSetup, OpHandle, WriteContext
    from ...common import WebRequest

#: The updater the M1's config names: [update_manager MuonOS].
UPDATER = "MuonOS"
#: How often Aux's status is read while an install runs or is being judged.
PROGRESS_POLL = 1.0
#: How long to follow an install before judging it anyway.
FOLLOW_LIMIT = 3600.0
#: After a boot, how long Aux may take to answer before the step is judged
#: from what can be read.
BOOT_LIMIT = 600.0
#: 02 §5.6 step 4: a waited update check, bounded.
CHECK_TIMEOUT = 20.0

#: Aux states in which the install is still running (02 §5.8).
RUNNING = ("installing", "rebooting", "committing")
#: Aux states in which the result can be judged.
SETTLED = ("idle", "commit_pending", "failed")


def register(setup: MuonSetup) -> None:
    setup.server.register_endpoint(
        "/server/muon/setup/update", ["POST"],
        lambda webreq: handle_update(setup, webreq))
    setup.hide_when_current["update"] = lambda doc: hide_update(setup, doc)
    setup.boot_op_handlers["update_install"] = (
        lambda doc: on_boot(setup, doc))
    setup.live_refreshers.append(lambda: refresh(setup))


# --------------------------------------------------------------------------
# What Aux knows (GET /update/status)
# --------------------------------------------------------------------------

def _version(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value not in ("", "?") else None


async def read_status(setup: MuonSetup) -> Optional[Dict[str, Any]]:
    """Aux GET /update/status, or None if Aux cannot say right now."""
    from . import AuxMissing, AuxRefused, AuxUnavailable
    try:
        status = await setup.aux("GET", "/update/status")
    except (AuxMissing, AuxRefused, AuxUnavailable) as exc:
        logging.debug("muon_setup: no update status: %s", exc)
        return None
    return status if isinstance(status, dict) else None


def _progress(status: Dict[str, Any]) -> Optional[float]:
    """Aux reports percent, at the top level or under `install`."""
    pct = status.get("progress")
    if pct is None and isinstance(status.get("install"), dict):
        pct = status["install"].get("progress")
    if isinstance(pct, bool) or not isinstance(pct, (int, float)):
        return None
    return round(min(max(float(pct) / 100.0, 0.0), 1.0), 3)


async def refresh(setup: MuonSetup) -> None:
    """Keep a snapshot for the synchronous visibility rule."""
    status = await read_status(setup)
    if status is not None:
        setup._live["ota"] = status


def versions(setup: MuonSetup) -> Dict[str, Optional[str]]:
    """{current, available} from the last Aux status read."""
    status = setup._live.get("ota") or {}
    current = _version(status.get("current_version"))
    available = None
    if status.get("update_available") is True:
        target = _version(status.get("target_version"))
        if target is not None and target != current:
            available = target
    return {"current": current, "available": available}


def refresh_step(setup: MuonSetup, doc: Dict[str, Any]) -> None:
    """Copy Aux's versions into the step, unless an install is under way --
    then the frozen target is the one that matters."""
    op = doc.get("op")
    if op is not None and op.get("kind") == "update_install":
        return
    step = doc["steps"]["update"]
    found = versions(setup)
    step["current"] = found["current"]
    if step["status"] in (model.PENDING, model.HIDDEN):
        step["available"] = found["available"]


async def check_for_update(setup: MuonSetup) -> None:
    """A fresh update check, waited for (02 §5.6 step 4). `{"wait": false}`
    only schedules one, and the status read straight after it is the old
    answer. MR-3's `update_check` join phase calls this."""
    from . import AuxMissing, AuxRefused, AuxUnavailable
    try:
        await setup.aux("POST", "/update/check", {"wait": True},
                        timeout=CHECK_TIMEOUT)
    except (AuxMissing, AuxRefused, AuxUnavailable) as exc:
        logging.info("muon_setup: update check failed: %s", exc)
    await refresh(setup)


def hide_update(setup: MuonSetup, doc: Dict[str, Any]) -> bool:
    """01 §2: hidden when it becomes current with no internet, no update, or
    no synced clock (KAN-270: TLS needs the clock)."""
    refresh_step(setup, doc)
    return not (
        doc["steps"]["network"].get("internet") is True
        and bool(doc["steps"]["update"].get("available"))
        and setup._live["clock"].get("synced") is True
    )


# --------------------------------------------------------------------------
# POST /server/muon/setup/update {rev, action: install | later}
# --------------------------------------------------------------------------

async def handle_update(setup: MuonSetup, webreq: WebRequest) -> Dict[str, Any]:
    async def handler(ctx: WriteContext) -> Optional[Dict[str, Any]]:
        action = ctx.args.get("action")
        doc = ctx.doc
        step = doc["steps"]["update"]
        if action not in ("install", "later"):
            return model.error(
                "invalid_step", f"unknown update action {action!r}")
        if not model.reachable(doc, "update"):
            return model.error("invalid_step", "the update step is not open")
        if action == "later":
            step["status"] = model.SKIPPED
            step["error"] = None
            setup.advance()
            return None
        await refresh(setup)
        refresh_step(setup, doc)
        target = step.get("available")
        if not target:
            return model.error("invalid_step", "there is no update to install")
        if setup._live["clock"].get("synced") is not True:
            return model.error(
                "clock_unsynced", "the clock is not synchronised yet")
        kconn = setup.server.lookup_component("klippy_connection", None)
        if kconn is not None and kconn.is_printing():
            return model.error("printer_busy", "a print is running")
        step["error"] = None
        setup.start_op("update_install", _runner(setup), target=target,
                       phase="installing")
        return None
    return await setup.write(webreq, handler)


def refusal_code(exc: BaseException) -> str:
    """02 §5.8: Aux refuses with 409 and `detail.code`. `printer_busy`
    (printing, paused or busy; KAN-75) is printer_busy; `busy` and
    `invalid_state` are update_failed. update_manager's own refusal while
    printing is a 503."""
    if getattr(exc, "aux_code", None) == "printer_busy":
        return "printer_busy"
    if getattr(exc, "status_code", None) == 503:
        return "printer_busy"
    return "update_failed"


def _runner(setup: MuonSetup):
    async def run(handle: OpHandle) -> None:
        transport = setup.server.lookup_component("internal_transport")
        try:
            await transport.call_method(
                "machine.update.upgrade", {"name": UPDATER})
        except Exception as exc:
            code = refusal_code(exc)
            message = str(exc)
            logging.info("muon_setup: the update did not start: %s", message)
            await handle.finish(lambda doc: _fail(doc, code, message))
            return
        # OtaDeploy.update() has returned, which does not mean the install
        # has. Follow Aux until it says it is over; a reboot on the way ends
        # this process, and on_boot() takes over.
        await follow(setup, handle, FOLLOW_LIMIT)
    return run


async def follow(setup: MuonSetup, handle: OpHandle, limit: float) -> None:
    """Mirror Aux's progress into `op` until the install settles, then judge.
    A status that cannot be read is waited out, up to `limit`."""
    deadline = time.monotonic() + limit
    last: Optional[Dict[str, Any]] = None
    while handle.current() and time.monotonic() < deadline:
        status = await read_status(setup)
        if status is not None:
            last = status
            setup._live["ota"] = status
            state = str(status.get("state") or "").lower()
            if state in SETTLED:
                break
            fields: Dict[str, Any] = {}
            if state == "rebooting" and handle.current():
                fields["phase"] = "rebooting"
            progress = _progress(status)
            if progress is not None:
                fields["progress"] = progress
            op = (setup.doc or {}).get("op") or {}
            if any(op.get(k) != v for k, v in fields.items()):
                await handle.update(**fields)
        await asyncio.sleep(PROGRESS_POLL)
    await _judge(setup, handle, last)


def _fail(doc: Dict[str, Any], code: str, message: str) -> None:
    step = doc["steps"]["update"]
    step["status"] = model.PENDING
    step["error"] = {"code": code, "message": message}


# --------------------------------------------------------------------------
# After a boot (02 §5.8)
# --------------------------------------------------------------------------

def on_boot(setup: MuonSetup, doc: Dict[str, Any]) -> None:
    """The stored state still shows `update_install`: the printer rebooted
    (or lost power, or Moonraker restarted) during an update. Keep the op --
    the step is `busy` until the verdict -- and follow Aux from here."""
    doc["op"]["phase"] = "verifying"
    doc["rev"] += 1
    setup._spawn(_verify_after_boot(setup, doc["op"].get("id")))


async def _verify_after_boot(setup: MuonSetup, op_id: Any) -> None:
    from . import OpHandle
    await setup.wait_resolved()
    await follow(setup, OpHandle(setup, op_id), BOOT_LIMIT)


async def _judge(setup: MuonSetup, handle: OpHandle,
                 status: Optional[Dict[str, Any]]) -> None:
    """Equal to the frozen target: done. Anything else: it rolled back, or
    it failed. Never judged from update_manager's cache."""
    doc = setup.doc
    if doc is None or not handle.current():
        return
    target = doc["op"].get("target")
    status = status or {}
    current = _version(status.get("current_version"))
    state = str(status.get("state") or "").lower()

    def verdict(doc: Dict[str, Any]) -> None:
        step = doc["steps"]["update"]
        step["current"] = current
        if current is not None and current == target and state != "failed":
            step["status"] = model.DONE
            step["available"] = None
            step["error"] = None
            if doc["state"] != "complete" and doc["cursor"] == "update":
                setup.advance()
        else:
            step["status"] = model.PENDING
            step["error"] = {
                "code": "update_failed",
                "message": f"running {current!r}, expected {target!r}"
                           + (f" ({state})" if state else ""),
            }
    await handle.finish(verdict)
