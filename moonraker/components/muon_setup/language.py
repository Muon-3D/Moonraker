# MUON, KAN-203 -- the language step (spec 01 §2.3, 02 §5.3). Work package MR-2.
#
# The first question, and the only required one. It sets the panel's language
# (MuonUI reads it from the state) and Fluidd's default locale, so the phone
# page and every later Fluidd session open in the language chosen at the
# printer, unless the owner has already picked one in Fluidd itself.

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict, Optional

from . import model

if TYPE_CHECKING:
    from . import MuonSetup, WriteContext
    from ...common import WebRequest

FLUIDD_NAMESPACE = "fluidd"
FLUIDD_LOCALE_KEY = "uiSettings.general.locale"


def register(setup: MuonSetup) -> None:
    setup.server.register_endpoint(
        "/server/muon/setup/language", ["POST"],
        lambda webreq: handle_language(setup, webreq))


async def handle_language(
    setup: MuonSetup, webreq: WebRequest
) -> Dict[str, Any]:
    """POST /server/muon/setup/language {rev, code}."""
    async def handler(ctx: WriteContext) -> Optional[Dict[str, Any]]:
        code = ctx.args.get("code")
        if code not in setup.languages:
            return model.error(
                "unsupported_language", f"{code!r} is not offered",
                offered=list(setup.languages))
        ctx.doc["steps"]["language"] = {
            "status": model.DONE, "value": code, "source": ctx.kind,
        }
        setup.advance()
        await set_fluidd_default_locale(setup, code)
        return None
    return await setup.write(webreq, handler)


async def set_fluidd_default_locale(setup: MuonSetup, code: str) -> None:
    """Write Fluidd's locale only when nobody has chosen one (02 §5.3).

    Never fatal: the setup answer stands even if Fluidd's settings cannot be
    touched, and a Fluidd that keeps English is a smaller problem than a
    language screen that will not advance.
    """
    try:
        current: Any = await setup.database.get_item(
            FLUIDD_NAMESPACE, FLUIDD_LOCALE_KEY, None)
        if current:
            return
        await setup.database.insert_item(
            FLUIDD_NAMESPACE, FLUIDD_LOCALE_KEY, code)
    except Exception as exc:
        logging.warning("muon_setup: Fluidd's locale was not set: %s", exc)
