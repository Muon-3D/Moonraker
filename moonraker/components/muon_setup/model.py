# MUON, KAN-203 -- the setup state document and the rules that move it.
#
# Pure functions over plain dicts, so the order rules can be tested without a
# server. The document shape is spec 02 §6 (specs/m1-first-run-setup in
# Muon-3D/OrcaSlicer); the rules are 01 §2-§3.

from __future__ import annotations

import copy
import time
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = 1

#: Steps always run in this order (01 §2).
STEP_ORDER = ("language", "network", "name", "update", "remote", "ready")
#: `POST .../skip` accepts only these. `language` is required, and `name`
#: cannot end up skipped: "Keep" counts as done.
SKIPPABLE = frozenset({"network", "update", "remote", "ready"})
#: The steps the "Finish setup" card lists when they are skipped (01 §6).
CARD_STEPS = ("network", "remote", "ready")
#: The only steps that still take writes once setup is complete (01 §6).
WRITABLE_AFTER_COMPLETE = frozenset({"network", "name", "remote", "ready"})

STATES = ("new", "in_progress", "complete")
FINISH = "finish"

PENDING = "pending"
DONE = "done"
SKIPPED = "skipped"
HIDDEN = "hidden"

#: Long-running operations, and the step each one belongs to. The step is where
#: an `interrupted` error lands when a power loss cuts the operation short.
OP_STEPS = {
    "region_apply": "network",
    "join": "network",
    "update_install": "update",
    "link": "remote",
    "ready_item": "ready",
}

#: Filled in on every read and never stored (02 §4, §6).
COMPUTED_FIELDS = ("hotspot", "clock", "region", "capabilities")


def default_steps(ready_item_ids: List[str]) -> Dict[str, Any]:
    return {
        "language": {"status": PENDING, "value": None, "source": None},
        "network": {
            "status": PENDING, "kind": None, "ssid": None, "addresses": [],
            "hostname_local": None, "internet": None, "error": None,
            # 02 §5.6a: the region is confirmed after the join.
            "region_confirmed": False, "region_error": None,
        },
        "name": {"status": PENDING, "value": None, "derived": None},
        "update": {
            "status": PENDING, "current": None, "available": None, "error": None,
        },
        "remote": {"status": PENDING, "mode": None, "link": None, "error": None},
        "ready": {
            "status": PENDING,
            "items": [
                {"id": item_id, "status": PENDING, "error": None}
                for item_id in ready_item_ids
            ],
        },
    }


def new_document(ready_item_ids: List[str]) -> Dict[str, Any]:
    """A factory-fresh state: nothing answered, the cursor on language."""
    return {
        "version": SCHEMA_VERSION,
        "rev": 1,
        "state": "new",
        "cursor": STEP_ORDER[0],
        "driver": None,
        "op": None,
        "printer": {
            "name": None, "display": None, "hostname": None, "fingerprint": None,
        },
        "card_dismissed": False,
        "steps": default_steps(ready_item_ids),
    }


def migrated_document(ready_item_ids: List[str]) -> Dict[str, Any]:
    """01 §7: a printer that was in use before setup existed.

    Every step is `done` with `source: "migrated"` and the card stays away,
    because nothing was skipped -- the owner simply did it another way.
    """
    doc = new_document(ready_item_ids)
    doc["state"] = "complete"
    doc["cursor"] = FINISH
    for step in doc["steps"].values():
        step["status"] = DONE
    doc["steps"]["language"]["source"] = "migrated"
    doc["steps"]["network"]["region_confirmed"] = True
    for item in doc["steps"]["ready"]["items"]:
        item["status"] = DONE
    return doc


def storable(doc: Dict[str, Any]) -> Dict[str, Any]:
    """The document minus the fields computed on read (02 §4)."""
    return {k: copy.deepcopy(v) for k, v in doc.items() if k not in COMPUTED_FIELDS}


def first_pending(doc: Dict[str, Any]) -> Optional[str]:
    for step_id in STEP_ORDER:
        if doc["steps"][step_id]["status"] == PENDING:
            return step_id
    return None


def reachable(doc: Dict[str, Any], step_id: str) -> bool:
    """01 §3: back to any earlier step that is done or skipped, forward only as
    far as the first pending one. A hidden step is never a destination."""
    status = doc["steps"][step_id]["status"]
    if status == HIDDEN:
        return False
    if status in (DONE, SKIPPED):
        return True
    return step_id == first_pending(doc)


def advance(doc: Dict[str, Any]) -> None:
    """Put the cursor on the first pending step, or on `finish` if none is left.

    Steps before the cursor are always done, skipped or hidden -- `goto` can
    only move back to those -- so "the first pending step" and "the next
    pending step after the one just finished" are the same step. Visibility is
    decided by the caller before this runs (see MuonSetup._advance).
    """
    nxt = first_pending(doc)
    doc["cursor"] = nxt if nxt is not None else FINISH


def card_steps(doc: Dict[str, Any]) -> List[str]:
    """What the "Finish setup" card lists: skipped network, remote and ready."""
    return [s for s in CARD_STEPS if doc["steps"][s]["status"] == SKIPPED]


def reconcile_ready_items(
    doc: Dict[str, Any], ready_item_ids: List[str]
) -> bool:
    """Keep `steps.ready.items` in step with the manifest the image ships.

    An OTA update can change the manifest under a stored state. Items that
    are still listed keep their status; new ones start pending; dropped ones
    go. Returns True when anything changed.
    """
    ready = doc["steps"]["ready"]
    by_id = {item.get("id"): item for item in ready.get("items", [])}
    items = [
        by_id.get(item_id) or {"id": item_id, "status": PENDING, "error": None}
        for item_id in ready_item_ids
    ]
    if items == ready.get("items"):
        return False
    ready["items"] = items
    return True


def driver_public(
    driver: Optional[Dict[str, Any]], lease: float, now: Optional[float] = None
) -> Optional[Dict[str, Any]]:
    """The driver claim with `lapsed` computed (02 §6).

    Only a phone or web claim lapses. The panel does not renew -- it is
    always there -- so its claim never goes stale.
    """
    if driver is None:
        return None
    now = time.time() if now is None else now
    public = dict(driver)
    renewed = driver.get("renewed") or driver.get("since") or 0.0
    public["lapsed"] = driver.get("kind") != "panel" and now - renewed > lease
    return public


def error(code: str, message: str, **detail: Any) -> Dict[str, Any]:
    """A domain error, shaped as 02 §5 and keyed by the 08 catalogue."""
    return {"code": code, "message": message, "detail": detail}
