# MUON, KAN-203 -- the "Ready to print" step (spec 01 §2.3, 02 §5.10). Work
# package MR-7.
#
# The items come from the manifest (manifest.py): `confirm` items the owner
# acknowledges, `panel_flow` items MuonUI runs and then confirms, and `macro`
# items that run a Klipper macro under an `op`. They need a person at the
# printer, so starting and confirming them is panel-only (02 §3); a phone can
# only skip.
#
# A macro item moves the printer, so it starts only when every earlier
# required item is done (the transport clips come off first), Klipper defines
# the macro at that moment, no print is running or paused, and Klippy is
# ready.
#
# The manifest and the MUON_SELF_TEST macro are provisional (decision D6). A
# pending macro item whose macro Klipper does not define is hidden rather than
# offered as a step that can only fail -- but only once Klipper has said which
# macros it has, so an item does not flicker away while Klippy is starting.

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

from . import caller, model

if TYPE_CHECKING:
    from . import MuonSetup, OpHandle, WriteContext
    from ...common import WebRequest

ACTIONS = ("start", "confirm", "skip")
FAILED = "failed"
#: print_stats states in which nothing may move the toolhead (02 §5.10).
BUSY_PRINT_STATES = ("printing", "paused")


def register(setup: MuonSetup) -> None:
    setup.server.register_endpoint(
        "/server/muon/setup/ready", ["POST"],
        lambda webreq: handle_ready(setup, webreq))
    setup.server.register_event_handler(
        "server:klippy_ready", lambda: refresh_macros(setup))
    # When the state loads, as well as when Klippy becomes ready (02 §5.10).
    setup.live_refreshers.append(lambda: refresh_macros(setup))


def _manifest_items(setup: MuonSetup) -> Dict[str, Dict[str, Any]]:
    return {item["id"]: item for item in setup.manifest["items"]}


# --------------------------------------------------------------------------
# What Klipper can do right now
# --------------------------------------------------------------------------

async def defined_macros(setup: MuonSetup) -> Optional[Set[str]]:
    """The macros Klipper defines, lower-cased, or None if it cannot say."""
    kconn = setup.server.lookup_component("klippy_connection", None)
    klippy = setup.server.lookup_component("klippy_apis", None)
    if kconn is None or klippy is None or not kconn.is_ready():
        return None
    try:
        objects = await klippy.get_object_list()
    except Exception as exc:
        logging.info("muon_setup: cannot list Klipper's objects: %s", exc)
        return None
    prefix = "gcode_macro "
    return {
        obj[len(prefix):].strip().lower() for obj in objects
        if isinstance(obj, str) and obj.lower().startswith(prefix)
    }


async def print_state(setup: MuonSetup) -> Optional[str]:
    """print_stats `state`, or None if Klipper cannot say. is_printing() is
    only true for `printing`; a paused print must stop a self-test too."""
    klippy = setup.server.lookup_component("klippy_apis", None)
    if klippy is None:
        return None
    try:
        result = await klippy.query_objects({"print_stats": ["state"]})
    except Exception as exc:
        logging.info("muon_setup: cannot read print_stats: %s", exc)
        return None
    stats = result.get("print_stats") if isinstance(result, dict) else None
    state = stats.get("state") if isinstance(stats, dict) else None
    return state if isinstance(state, str) else None


def apply_macros(setup: MuonSetup, doc: Dict[str, Any],
                 macros: Optional[Set[str]]) -> None:
    """Hide pending macro items Klipper cannot run; show them again once it
    can. Done or failed items are left as they are, and a macro appearing
    later never reopens a done step."""
    if macros is None:
        return
    items = _manifest_items(setup)
    for state in doc["steps"]["ready"]["items"]:
        item = items.get(state["id"])
        if item is None or item["kind"] != "macro":
            continue
        defined = item["macro"].lower() in macros
        if not defined and state["status"] == model.PENDING:
            state["status"] = model.HIDDEN
        elif defined and state["status"] == model.HIDDEN:
            state["status"] = model.PENDING
    settle(setup, doc)


async def refresh_macros(setup: MuonSetup) -> None:
    """Apply what Klipper defines as its own change, committed and announced,
    so a hide never rides on a write that is then rolled back."""
    if setup.doc is None or setup.read_only_version is not None:
        return
    macros = await defined_macros(setup)
    if macros is None:
        return
    async with setup._lock:
        doc = setup.doc
        if doc is None or doc["op"] is not None:
            return
        before = [dict(i) for i in doc["steps"]["ready"]["items"]]
        status = doc["steps"]["ready"]["status"]
        apply_macros(setup, doc, macros)
        if (doc["steps"]["ready"]["items"] != before
                or doc["steps"]["ready"]["status"] != status):
            await setup._commit()


def settle(setup: MuonSetup, doc: Dict[str, Any]) -> None:
    """The step is done when every required item that is offered is done.

    After `complete`, a skipped step stays `skipped` -- it is what the
    "Finish setup" card lists -- until then (02 §5.10). A done step is never
    taken back.
    """
    step = doc["steps"]["ready"]
    complete = doc["state"] == "complete"
    if step["status"] == model.DONE:
        return
    if step["status"] == model.SKIPPED and not complete:
        return
    items = _manifest_items(setup)
    required: List[Dict[str, Any]] = [
        state for state in step["items"]
        if items.get(state["id"], {}).get("required")
        and state["status"] != model.HIDDEN
    ]
    if all(state["status"] == model.DONE for state in required):
        step["status"] = model.DONE
        if not complete and doc["cursor"] == "ready":
            setup.advance()


def _earlier_required_pending(setup: MuonSetup, doc: Dict[str, Any],
                              item_id: str) -> List[str]:
    """Required items before `item_id` in manifest order that aren't done."""
    states = {s["id"]: s for s in doc["steps"]["ready"]["items"]}
    pending: List[str] = []
    for item in setup.manifest["items"]:
        if item["id"] == item_id:
            break
        state = states.get(item["id"])
        if (item.get("required") and state is not None
                and state["status"] not in (model.DONE, model.HIDDEN)):
            pending.append(item["id"])
    return pending


# --------------------------------------------------------------------------
# POST /server/muon/setup/ready {rev, item, action}
# --------------------------------------------------------------------------

async def handle_ready(setup: MuonSetup, webreq: WebRequest) -> Dict[str, Any]:
    args = webreq.get_args()
    action = args.get("action")
    if action in ("start", "confirm"):
        # 02 §3: these need a person at the printer. Checked first, before
        # `busy`, `stale_rev` or any Klipper query, so a phone always gets 403.
        caller.require(caller.caller_kind(webreq), caller.PANEL_ONLY)
    # Hiding undefined macros is its own change (on load, on klippy_ready and
    # in the poll). Doing it here would bump `rev` under this very write and
    # answer it `stale_rev`; `start` checks the macro again below instead.

    async def handler(ctx: WriteContext) -> Optional[Dict[str, Any]]:
        doc = ctx.doc
        item_id = ctx.args.get("item")
        if action not in ACTIONS:
            return model.error("invalid_step", f"unknown action {action!r}")
        if not isinstance(item_id, str):
            return model.error("invalid_step", "'item' names no ready item")
        complete = doc["state"] == "complete"
        if not complete and not model.reachable(doc, "ready"):
            return model.error("invalid_step", "the ready step is not open")
        item = _manifest_items(setup).get(item_id)
        state = next((s for s in doc["steps"]["ready"]["items"]
                      if s["id"] == item_id), None)
        if item is None or state is None or state["status"] == model.HIDDEN:
            return model.error("invalid_step", f"no ready item {item_id!r}")
        step = doc["steps"]["ready"]
        if step["status"] == model.SKIPPED and not complete:
            # Going back to a skipped step before `complete` reopens it; after
            # `complete` it stays on the card (see settle()).
            step["status"] = model.PENDING
        if action == "skip":
            state["status"] = model.SKIPPED
            state["error"] = None
            settle(setup, doc)
            return None
        if action == "confirm":
            if item["kind"] not in ("confirm", "panel_flow"):
                return model.error(
                    "invalid_step", f"{item_id} is not confirmed, it is run")
            state["status"] = model.DONE
            state["error"] = None
            settle(setup, doc)
            return None
        # start: it moves the printer (02 §5.10).
        if item["kind"] != "macro":
            return model.error("invalid_step", f"{item_id} is not a macro")
        earlier = _earlier_required_pending(setup, doc, item_id)
        if earlier:
            return model.error(
                "invalid_step", f"{', '.join(earlier)} must be done first",
                pending=earlier)
        macros = await defined_macros(setup)
        if macros is None:
            return model.error("printer_not_ready", "Klippy is not ready")
        if item["macro"].lower() not in macros:
            return model.error(
                "invalid_step", f"Klipper does not define {item['macro']}")
        kconn = setup.server.lookup_component("klippy_connection", None)
        if kconn is None or not kconn.is_ready():
            return model.error("printer_not_ready", "Klippy is not ready")
        printing = await print_state(setup)
        if kconn.is_printing() or printing in BUSY_PRINT_STATES:
            return model.error("printer_busy", "a print is running or paused")
        state["error"] = None
        setup.start_op("ready_item", _runner(setup, item_id, item["macro"]),
                       item=item_id, phase="running")
        return None
    return await setup.write(webreq, handler, after_complete=True)


def _runner(setup: MuonSetup, item_id: str, macro: str):
    async def run(handle: OpHandle) -> None:
        klippy = setup.server.lookup_component("klippy_apis")
        error: Optional[str] = None
        try:
            await klippy.run_gcode(macro)
        except Exception as exc:
            error = str(exc) or type(exc).__name__
            logging.info("muon_setup: %s failed: %s", macro, error)

        def outcome(doc: Dict[str, Any]) -> None:
            for state in doc["steps"]["ready"]["items"]:
                if state["id"] != item_id:
                    continue
                if error is None:
                    state["status"] = model.DONE
                    state["error"] = None
                else:
                    state["status"] = FAILED
                    state["error"] = model.error(
                        "self_test_failed", error, gcode_error=error)
            settle(setup, doc)
        await handle.finish(outcome)
    return run
