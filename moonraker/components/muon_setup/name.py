# MUON, KAN-203 / ID-2 -- the name step (spec 02 §5.7). Work package MR-2.
#
# "Keep" or "Rename". The rename is aux_api_proxy's, stored in the `muon`
# namespace under `friendly_name`, so this step and POST
# /server/muon/identity/name apply one set of rules. The hostname and the
# hotspot SSID keep the derived name whatever the owner types (ID-2).

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict, Optional

from . import model
from ...utils.exceptions import ServerError

if TYPE_CHECKING:
    from . import MuonSetup, WriteContext
    from ...common import WebRequest


#: Where aux_api_proxy keeps the rename (ID-3).
FRIENDLY_NAMESPACE = "muon"
FRIENDLY_NAME_KEY = "friendly_name"


def register(setup: MuonSetup) -> None:
    setup.server.register_endpoint(
        "/server/muon/setup/name", ["POST"],
        lambda webreq: handle_name(setup, webreq))


async def stored_name(setup: MuonSetup) -> Optional[str]:
    """The owner's rename, straight from the `muon` namespace, so Keep works
    before the identity has been read (Aux late at boot)."""
    try:
        name: Any = await setup.database.get_item(
            FRIENDLY_NAMESPACE, FRIENDLY_NAME_KEY, None)
    except Exception:
        return None
    return name if isinstance(name, str) and name else None


async def handle_name(setup: MuonSetup, webreq: WebRequest) -> Dict[str, Any]:
    """POST /server/muon/setup/name {rev, name}. Empty or absent is "Keep"."""
    async def handler(ctx: WriteContext) -> Optional[Dict[str, Any]]:
        name = ctx.args.get("name")
        proxy = setup.server.lookup_component("aux_api_proxy", None)
        if name is not None and not isinstance(name, str):
            raise ServerError("muon_setup: 'name' must be a string", 400)
        if ctx.doc["state"] != "complete" and not model.reachable(
            ctx.doc, "name"
        ):
            # 02 §5 "Order": not ahead of the first pending step.
            return model.error("invalid_step", "the name step is not open")
        if name and name.strip():
            if proxy is None:
                return model.error(
                    "aux_unavailable", "aux_api_proxy is not loaded")
            # Raises 400 for a name over 32 characters; write() then drops
            # the change and the caller sees the refusal.
            value = await proxy.store_friendly_name(name)
        else:
            # Keep never clears an earlier rename (02 §5.7): the stored
            # name, else the identity's, else the derived one.
            value = await stored_name(setup) or setup.effective_name()
        ctx.doc["steps"]["name"]["status"] = model.DONE
        ctx.doc["steps"]["name"]["value"] = value
        if ctx.doc["state"] != "complete":
            setup.advance()
        # The identity follows the rename; Aux being down only delays that.
        try:
            await setup._refresh_printer()
        except Exception as exc:
            logging.info("muon_setup: identity not refreshed: %s", exc)
        return None
    return await setup.write(webreq, handler, after_complete=True)
