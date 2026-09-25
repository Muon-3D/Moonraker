# MUON, KAN-203 -- the update step (spec 01 §2, 02 §5.8). Work package MR-4.
#
# "Install now" runs the same path as POST /machine/update/upgrade?name=MuonOS,
# as a component-to-component call, so update_manager's own rules apply:
# refused while printing (503), one update at a time, and every progress line
# goes out as notify_update_response as usual. muon_setup never commits an
# update itself; the OTA commit policy (KAN-358) decides that.
#
# An install ends in a reboot, so the operation outlives this process. The
# target version is frozen into `op.target` when the install starts -- the Aux
# status fields change during a commit, so reading the target afterwards would
# compare a value with itself -- and after the reboot the version the printer
# actually runs is compared with it: equal is done, anything else rolled back.

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
#: How often the install's progress is mirrored into `op.progress`.
PROGRESS_POLL = 1.0
#: How long to wait for the reboot once update_manager says the install is
#: done, before deciding from the versions instead.
REBOOT_WAIT = 900.0
#: After a reboot, how long to wait for update_manager to report a version.
VERSION_WAIT = 300.0
VERSION_POLL = 2.0


def register(setup: MuonSetup) -> None:
    setup.server.register_endpoint(
        "/server/muon/setup/update", ["POST"],
        lambda webreq: handle_update(setup, webreq))
    setup.hide_when_current["update"] = lambda doc: hide_update(setup, doc)
    setup.boot_op_handlers["update_install"] = (
        lambda doc: on_boot(setup, doc))


# --------------------------------------------------------------------------
# What update_manager knows
# --------------------------------------------------------------------------

def updater_status(setup: MuonSetup) -> Optional[Dict[str, Any]]:
    manager = setup.server.lookup_component("update_manager", None)
    if manager is None:
        return None
    updater = manager.get_updaters().get(UPDATER)
    if updater is None:
        return None
    status = updater.get_update_status()
    return status if isinstance(status, dict) else None


def versions(setup: MuonSetup) -> Dict[str, Optional[str]]:
    """{current, available}: `available` only when an update is on offer.

    OtaDeploy reports `remote_version` equal to `version` when there is none.
    A `?` version is its placeholder for "not read yet".
    """
    status = updater_status(setup) or {}
    current = status.get("version")
    remote = status.get("remote_version")
    if not isinstance(current, str) or current in ("", "?"):
        current = None
    available = None
    if (
        status.get("is_valid", True) and isinstance(remote, str)
        and remote not in ("", "?") and remote != current
    ):
        available = remote
    return {"current": current, "available": available}


def refresh_step(setup: MuonSetup, doc: Dict[str, Any]) -> None:
    """Copy update_manager's versions into the step, unless an install is
    under way -- then the frozen target is the one that matters."""
    op = doc.get("op")
    if op is not None and op.get("kind") == "update_install":
        return
    step = doc["steps"]["update"]
    found = versions(setup)
    step["current"] = found["current"]
    if step["status"] in (model.PENDING, model.HIDDEN):
        step["available"] = found["available"]


async def check_for_update(setup: MuonSetup) -> None:
    """Ask for a fresh update check. update_manager's own refresh interval is
    a week on the M1, so the network step's `update_check` phase (MR-3) calls
    this once the internet check has passed."""
    manager = setup.server.lookup_component("update_manager", None)
    updater = manager.get_updaters().get(UPDATER) if manager else None
    if updater is None:
        return
    try:
        await updater.refresh()
    except Exception as exc:
        logging.info("muon_setup: update check failed: %s", exc)


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


def _runner(setup: MuonSetup):
    async def run(handle: OpHandle) -> None:
        mirror = asyncio.ensure_future(_mirror_progress(setup, handle))
        transport = setup.server.lookup_component("internal_transport")
        try:
            await transport.call_method(
                "machine.update.upgrade", {"name": UPDATER})
        except Exception as exc:
            mirror.cancel()
            status = getattr(exc, "status_code", None)
            code = "printer_busy" if status == 503 else "update_failed"
            message = str(exc)
            logging.info("muon_setup: the update did not start: %s", message)
            await handle.finish(lambda doc: _fail(doc, code, message))
            return
        # Installed. The printer reboots into the new slot now; keep the op
        # (and its frozen target) so the next boot can judge the result.
        mirror.cancel()
        await handle.update(phase="rebooting", progress=1.0)
        await asyncio.sleep(REBOOT_WAIT)
        # Still here: no reboot came. Judge from the versions instead.
        await _judge(setup, handle)
    return run


async def _mirror_progress(setup: MuonSetup, handle: OpHandle) -> None:
    """update_manager's OTA progress (0-100) as `op.progress` (0-1)."""
    last: Optional[float] = None
    while True:
        status = updater_status(setup) or {}
        pct = status.get("progress")
        if isinstance(pct, (int, float)) and not isinstance(pct, bool):
            value = round(min(max(float(pct) / 100.0, 0.0), 1.0), 3)
            if last is None or abs(value - last) >= 0.01:
                last = value
                if not await handle.update(progress=value):
                    return
        await asyncio.sleep(PROGRESS_POLL)


def _fail(doc: Dict[str, Any], code: str, message: str) -> None:
    step = doc["steps"]["update"]
    step["status"] = model.PENDING
    step["error"] = {"code": code, "message": message}


# --------------------------------------------------------------------------
# After the reboot (02 §5.8)
# --------------------------------------------------------------------------

def on_boot(setup: MuonSetup, doc: Dict[str, Any]) -> None:
    """The stored state still shows `update_install`: the printer rebooted
    (or lost power) during an update. Keep the op -- the step is `busy`
    until the verdict -- and judge once update_manager can say what runs."""
    doc["op"]["phase"] = "verifying"
    setup._spawn(_verify_after_boot(setup, doc["op"].get("id")))


async def _verify_after_boot(setup: MuonSetup, op_id: Any) -> None:
    from . import OpHandle
    await setup.wait_resolved()
    handle = OpHandle(setup, op_id)
    deadline = time.monotonic() + VERSION_WAIT
    while time.monotonic() < deadline:
        if not handle.current():
            return
        if versions(setup)["current"] is not None:
            break
        await asyncio.sleep(VERSION_POLL)
    await _judge(setup, handle)


async def _judge(setup: MuonSetup, handle: OpHandle) -> None:
    """Equal to the frozen target: done. Anything else: it rolled back."""
    doc = setup.doc
    if doc is None or not handle.current():
        return
    target = doc["op"].get("target")
    current = versions(setup)["current"]

    def verdict(doc: Dict[str, Any]) -> None:
        step = doc["steps"]["update"]
        step["current"] = current
        if current is not None and current == target:
            step["status"] = model.DONE
            step["available"] = None
            step["error"] = None
            if doc["state"] != "complete" and doc["cursor"] == "update":
                setup.advance()
        else:
            step["status"] = model.PENDING
            step["error"] = {
                "code": "update_failed",
                "message": f"running {current!r}, expected {target!r}",
            }
    await handle.finish(verdict)
