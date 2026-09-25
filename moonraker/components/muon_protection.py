# Moonraker component — muon_protection.py
#
# SEC-8: the protection level the owner chooses, and the one place it changes.
#
# Enable it in moonraker.conf:
#     [muon_protection]
#
# WHAT THE LEVELS ARE
#
# Level 0 (Open) is the shipped default (SEC-1): a browser on the LAN or the
# hotspot drives the printer with no sign-in. Level 1 (Protected) takes back
# `/server/aux/*` and `/machine/update/*` from any caller without an identity.
# The panel and a paired client through the gateway keep them. Enforcement is
# `muon_floor.check_protection`, at the same point as the floor; this component
# only stores the level and changes it.
#
# WHO MAY CHANGE IT
#
# The panel, and nobody else (SEC-6, SEC-8). A network caller must not be able
# to lower the level, and it must not be able to raise it either: the owner
# decides, standing at the machine. "The panel" is a loopback origin that is not
# muon-link's gateway sentinel -- `muon_floor.local_address` -- which GATE-2(c)
# (Moonraker#17) is what makes true. A paired client is refused too, whatever
# its role: SEC-5 keeps Owner at the panel, and this is an Owner decision.
#
# The owner cannot lock themselves out, because nothing about Level 1 applies
# to the panel. That is also why a missing or unreadable stored level fails
# closed to Protected rather than open: the panel can always set it back.
#
# WHERE IT IS STORED
#
# Moonraker's database, in a namespace registered `forbidden`, so no client can
# read or write it through /server/database -- the only way to change the level
# is the panel-only endpoint below. /home/printer_data/database survives an OS
# update and does not survive a factory reset, which is the lifetime this needs:
# a reset printer is back at the shipped default, Open.
#
# WHAT THIS DOES NOT DO
#
# It creates no Moonraker user and never touches `force_logins` (MuonOS #87).

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict

from .. import muon_floor
from ..common import RequestType

if TYPE_CHECKING:
    from ..common import WebRequest
    from ..confighelper import ConfigHelper

NAMESPACE = "muon_protection"
LEVEL_KEY = "level"
ENDPOINT = "/server/muon/protection"
EVENT = "muon_protection:level_changed"
NOTIFY_NAME = "muon_protection_changed"


def is_panel(transport: Any, ip_addr: Any) -> bool:
    """May this caller change the level? Only the panel, or an internal call."""
    return muon_floor._is_internal(transport) or muon_floor.local_address(ip_addr)


def parse_stored_level(value: Any) -> int:
    """The stored level, or Protected if it is anything but a known level."""
    if not muon_floor.is_known_level(value):
        logging.error(
            "muon_protection: stored level %r is not a known level, "
            "enforcing Protected until the panel sets one",
            value,
        )
        return muon_floor.LEVEL_PROTECTED
    return value


class MuonProtection:
    def __init__(self, config: ConfigHelper) -> None:
        self.server = config.get_server()
        database = self.server.lookup_component("database")
        self.db = database.register_local_namespace(NAMESPACE, forbidden=True)
        # Fail closed until component_init has read the stored level.
        muon_floor.set_protection_level(muon_floor.LEVEL_PROTECTED)
        self.server.register_endpoint(
            ENDPOINT, ["GET", "POST"], self._handle
        )
        self.server.register_notification(EVENT, NOTIFY_NAME)

    async def component_init(self) -> None:
        try:
            stored = await self.db.get(LEVEL_KEY, muon_floor.LEVEL_OPEN)
        except Exception:
            logging.exception(
                "muon_protection: cannot read the stored level, "
                "enforcing Protected until the panel sets one"
            )
            return
        level = parse_stored_level(stored)
        muon_floor.set_protection_level(level)
        logging.info(
            "muon_protection: level %d (%s)",
            level,
            muon_floor.LEVEL_NAMES[level],
        )

    def status(self, transport: Any, ip_addr: Any, user: Any) -> Dict[str, Any]:
        level = muon_floor.protection_level()
        return {
            "level": level,
            "name": muon_floor.LEVEL_NAMES[level],
            "protected_surfaces": list(muon_floor.PROTECTED_PREFIXES),
            "excluded_surfaces": list(muon_floor.PROTECTED_EXCLUSIONS),
            # So a client can say why a surface is refused, rather than
            # showing a bare 403.
            "caller_has_identity": muon_floor.has_identity(transport, ip_addr, user),
            "changeable_by_caller": is_panel(transport, ip_addr),
        }

    async def _handle(self, web_request: WebRequest) -> Dict[str, Any]:
        transport = web_request.transport
        ip_addr = web_request.get_ip_address()
        user = web_request.get_current_user()
        if web_request.get_request_type() == RequestType.POST:
            if not is_panel(transport, ip_addr):
                raise self.server.error(
                    "Network protection can only be changed at the printer's "
                    "panel.",
                    403,
                )
            level = web_request.get_int("level")
            if not muon_floor.is_known_level(level):
                raise self.server.error(
                    f"'level' must be one of {sorted(muon_floor.LEVEL_NAMES)}",
                    400,
                )
            previous = muon_floor.protection_level()
            # Store first. A level the database did not take would last only
            # until the next restart, so refuse it rather than pretend.
            await self.db.insert(LEVEL_KEY, level)
            muon_floor.set_protection_level(level)
            if level != previous:
                logging.info(
                    "muon_protection: level %d (%s) -> %d (%s), set at the panel",
                    previous,
                    muon_floor.LEVEL_NAMES[previous],
                    level,
                    muon_floor.LEVEL_NAMES[level],
                )
                self.server.send_event(
                    EVENT,
                    {"level": level, "name": muon_floor.LEVEL_NAMES[level]},
                )
        return self.status(transport, ip_addr, user)


def load_component(config: ConfigHelper) -> MuonProtection:
    return MuonProtection(config)
