# Moonraker component — muon_access.py
#
# ACC-23: the settings the level table runs on, and the one place they change.
#
# Enable it in moonraker.conf, after [muon_protection]:
#     [muon_access]
#
# WHAT IT HOLDS
#
# One record in Moonraker's database, in a namespace registered `forbidden` so
# no client reads or writes it through /server/database/item:
#
#   entry      open | protected                          (ACC-3)
#   preset     relaxed | standard | strict, or null to follow the owner and
#              the entry (ACC-23)
#   overrides  {action: level} for the rows that can change
#
# The decision itself is ``muon_access_policy.check_access``, which
# ``APIDefinition.request`` calls after ``muon_floor``'s checks. This component
# only stores the settings and hands them to it.
#
# THE OWNER
#
# Is not stored here: it is whoever the printer is linked to (ACC-1, ACC-2).
# The component asks ``muon_link`` how the link stands at start and every 30 s
# after, and a linked printer has an account owner. Until the link has
# answered the owner is "unknown", and each row needs the strictest of what
# any owner the printer could have would need, with the panel only where that
# is admin: a boot or a link that does not answer never opens the printer
# more than its real owner state would. A poll that fails later keeps the
# owner last known. A printer with no [muon_link] has no owner.
#
# WHO MAY CHANGE IT
#
# POST /server/muon/access is the table's "protection" row: an admin (the
# owner's trusted device), or the panel; on a printer with no owner, the panel
# only. ``check_access`` has decided that before the handler runs.
#
# ROLLBACK (access-model section 6)
#
# The release before this one stores the level in ``muon_protection.level``
# and knows nothing of this record. An A/B rollback boots it with whatever
# that key says, so while a rollback is possible every change of the entry is
# written to both, and is refused if either write fails:
#
#   * Protected writes level 1 and Open writes level 0, through
#     ``muon_protection.store_level`` (which also sets what muon_floor
#     enforces), so a rollback never reopens a Protected printer.
#   * The panel's own ``POST /server/muon/protection`` comes here too, so the
#     two cannot disagree.
#
# On first start the record does not exist, so the entry is read from the old
# key once (level 1 is Protected, anything else Open) and written. After that,
# if the old key no longer holds the level this component last wrote to it,
# the release before this one changed it after a rollback, at the panel, the
# only place it could: that is the newer decision, and the entry follows it.
#
# `dual_write_protection_level: False` stops the dual write once the other
# slot holds this release too. Until then it must stay on.
#
# WHAT THIS DOES NOT DO
#
# It creates no Moonraker user (MR-18, MuonOS #87).

from __future__ import annotations

import asyncio
import copy
import logging
from typing import TYPE_CHECKING, Any, Dict, Optional

from .. import muon_access_policy as policy
from .. import muon_floor
from ..common import RequestType

if TYPE_CHECKING:
    from ..common import WebRequest
    from ..confighelper import ConfigHelper

NAMESPACE = "muon_access"
RECORD_KEY = "record"
RECORD_VERSION = 1
ENDPOINT = "/server/muon/access"
EVENT = "muon_access:changed"
NOTIFY_NAME = "muon_access_changed"
OWNER_POLL_INTERVAL = 30.0

ENTRY_FOR_LEVEL = {
    muon_floor.LEVEL_OPEN: policy.ENTRY_OPEN,
    muon_floor.LEVEL_PROTECTED: policy.ENTRY_PROTECTED,
}
LEVEL_FOR_ENTRY = {entry: level for level, entry in ENTRY_FOR_LEVEL.items()}


def new_record(entry: str, written_level: Optional[int]) -> Dict[str, Any]:
    return {
        "version": RECORD_VERSION,
        "entry": entry,
        "preset": None,
        "overrides": {},
        "written_level": written_level,
    }


def parse_record(value: Any) -> Dict[str, Any]:
    """A stored record, checked. Raises ValueError on anything else."""
    if not isinstance(value, dict) or value.get("version") != RECORD_VERSION:
        raise ValueError(f"not an access record: {value!r}")
    if not policy.known(policy.ENTRIES, value.get("entry")):
        raise ValueError(f"unknown entry {value.get('entry')!r}")
    preset = value.get("preset")
    if preset is not None and not policy.known(policy.PRESETS, preset):
        raise ValueError(f"unknown preset {preset!r}")
    stored = value.get("overrides") or {}
    policy.parse_overrides(
        {name: level for name, level in stored.items()}
    )
    return value


class MuonAccess:
    def __init__(self, config: ConfigHelper) -> None:
        self.server = config.get_server()
        self.dual_write = config.getboolean("dual_write_protection_level", True)
        self.protection = self.server.load_component(
            config, "muon_protection", None
        )
        if self.dual_write and self.protection is None:
            raise config.error(
                "[muon_access] needs [muon_protection] while it writes the "
                "entry to muon_protection.level for rollback"
            )
        database = self.server.lookup_component("database")
        self.db = database.register_local_namespace(NAMESPACE, forbidden=True)
        self.record: Dict[str, Any] = new_record(policy.ENTRY_PROTECTED, None)
        self.owner = policy.OWNER_UNKNOWN
        self._owner_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        # Fail closed until component_init has read the record: Protected.
        self._publish()
        self.server.register_endpoint(ENDPOINT, ["GET", "POST"], self._handle)
        self.server.register_notification(EVENT, NOTIFY_NAME)

    # -- state ------------------------------------------------------------

    def access_state(self) -> policy.AccessState:
        overrides = policy.parse_overrides(self.record.get("overrides") or {})
        return policy.AccessState(
            entry=self.record["entry"],
            preset=self.record.get("preset"),
            overrides=overrides,
            owner=self.owner,
        )

    def _publish(self) -> None:
        policy.set_state(self.access_state())

    # -- start ------------------------------------------------------------

    async def component_init(self) -> None:
        try:
            stored = await self.db.get(RECORD_KEY, None)
            old_level = await self._old_level()
        except Exception:
            logging.exception(
                "muon_access: cannot read the access record, enforcing "
                "Protected until the panel sets the entry"
            )
            return
        try:
            record = self._reconcile(stored, old_level)
        except ValueError as err:
            logging.error(
                "muon_access: %s; enforcing Protected until the panel sets "
                "the entry", err,
            )
            return
        if record is not stored:
            try:
                await self.db.insert(RECORD_KEY, record)
            except Exception:
                logging.exception("muon_access: cannot write the access record")
        self.record = record
        self._publish()
        logging.info(
            "muon_access: entry %s, preset %s",
            record["entry"], record.get("preset") or "follows the owner",
        )
        await self.refresh_owner()
        self._owner_task = asyncio.create_task(self._poll_owner())

    async def _old_level(self) -> Optional[int]:
        if self.protection is None:
            return None
        return await self.protection.stored_level()

    def _reconcile(
        self, stored: Any, old_level: Optional[int]
    ) -> Dict[str, Any]:
        """The record to run on, from what is stored and the old key."""
        if stored is None:
            # First start with this component: read the old key once.
            if old_level is not None and not muon_floor.is_known_level(old_level):
                old_level = muon_floor.LEVEL_PROTECTED
            entry = ENTRY_FOR_LEVEL.get(
                old_level if old_level is not None else muon_floor.LEVEL_OPEN,
                policy.ENTRY_PROTECTED,
            )
            logging.info(
                "muon_access: no access record, migrating level %r to entry %s",
                old_level, entry,
            )
            return new_record(entry, old_level)
        record = parse_record(stored)
        if (
            self.dual_write
            and old_level is not None
            and old_level != record.get("written_level")
        ):
            # The release before this one changed the level after a
            # rollback. Only its panel could, so it is the newer decision.
            if not muon_floor.is_known_level(old_level):
                old_level = muon_floor.LEVEL_PROTECTED
            entry = ENTRY_FOR_LEVEL[old_level]
            logging.warning(
                "muon_access: muon_protection.level is %r, not the %r last "
                "written here; the entry follows it: %s",
                old_level, record.get("written_level"), entry,
            )
            record = dict(record, entry=entry, written_level=old_level)
        return record

    # -- the owner ----------------------------------------------------------

    async def refresh_owner(self) -> None:
        link = self.server.lookup_component("muon_link", None)
        if link is None:
            owner = policy.OWNER_NONE
        else:
            try:
                status = await link.status()
            except Exception as err:
                logging.info("muon_access: the link did not answer: %s", err)
                return
            linked = isinstance(status, dict) and status.get("phase") == "linked"
            owner = policy.OWNER_ACCOUNT if linked else policy.OWNER_NONE
        if owner != self.owner:
            logging.info("muon_access: owner %s -> %s", self.owner, owner)
            self.owner = owner
            self._publish()

    async def _poll_owner(self) -> None:
        while True:
            await asyncio.sleep(OWNER_POLL_INTERVAL)
            await self.refresh_owner()

    # -- changes -----------------------------------------------------------

    async def set_entry(self, entry: str) -> None:
        """Change the entry, writing the old key in the same change."""
        await self._update({"entry": entry})

    async def set_entry_from_level(self, level: int) -> None:
        """muon_protection's POST, from the panel."""
        await self.set_entry(ENTRY_FOR_LEVEL[level])

    async def _update(self, changes: Dict[str, Any]) -> None:
        async with self._lock:
            previous = copy.deepcopy(self.record)
            record = dict(previous, **changes)
            level = LEVEL_FOR_ENTRY[record["entry"]]
            dual = self.dual_write and self.protection is not None
            if dual:
                record["written_level"] = level
            parse_record(record)
            await self.db.insert(RECORD_KEY, record)
            if dual:
                try:
                    await self.protection.store_level(level)
                except Exception:
                    logging.exception(
                        "muon_access: muon_protection.level did not take %d; "
                        "the change is refused", level,
                    )
                    try:
                        await self.db.insert(RECORD_KEY, previous)
                    except Exception:
                        # The record says the new entry and the old key the
                        # old level; component_init then follows the old key.
                        logging.exception(
                            "muon_access: cannot restore the access record"
                        )
                    raise self.server.error(
                        "The access settings could not be stored. Nothing "
                        "was changed.", 500,
                    )
            self.record = record
            self._publish()
        if record != previous:
            self.server.send_event(EVENT, self.settings())

    # -- the endpoint --------------------------------------------------------

    def settings(self) -> Dict[str, Any]:
        state = self.access_state()
        return {
            "entry": state.entry,
            "preset": self.record.get("preset"),
            "effective_preset": policy.effective_preset(state),
            "overrides": policy.describe_overrides(state.overrides),
            "owner": state.owner,
            "table": policy.effective_table(state),
        }

    def status(self, web_request: WebRequest) -> Dict[str, Any]:
        state = self.access_state()
        principal = policy.resolve_principal(
            web_request.transport,
            web_request.get_ip_address(),
            web_request.get_current_user(),
            state.entry,
        )
        result = self.settings()
        result["caller"] = None if principal is None else principal.describe()
        # So a client can lock its controls rather than show bare 403s.
        result["caller_allowed"] = policy.allowed_actions(principal, state)
        return result

    async def _handle(self, web_request: WebRequest) -> Dict[str, Any]:
        if web_request.get_request_type() == RequestType.POST:
            # check_access has already decided this is the protection row.
            changes: Dict[str, Any] = {}
            entry = web_request.get("entry", None)
            if entry is not None:
                if not policy.known(policy.ENTRIES, entry):
                    raise self.server.error(
                        f"'entry' must be one of {list(policy.ENTRIES)}", 400
                    )
                changes["entry"] = entry
            if "preset" in web_request.get_args():
                preset = web_request.get("preset")
                if preset in (None, "auto"):
                    preset = None
                elif not policy.known(policy.PRESETS, preset):
                    raise self.server.error(
                        f"'preset' must be one of {list(policy.PRESETS)} or "
                        "'auto'", 400,
                    )
                changes["preset"] = preset
            overrides = web_request.get("overrides", None)
            if overrides is not None:
                try:
                    current = dict(self.record.get("overrides") or {})
                    if not isinstance(overrides, dict):
                        raise ValueError(
                            "'overrides' must be an object of action: level"
                        )
                    for name, level in overrides.items():
                        if level is None:
                            current.pop(name, None)
                        else:
                            current[name] = level
                    policy.parse_overrides(current)
                except ValueError as err:
                    raise self.server.error(str(err), 400)
                changes["overrides"] = current
            if changes:
                await self._update(changes)
        return self.status(web_request)

    async def close(self) -> None:
        if self._owner_task is not None:
            self._owner_task.cancel()
            self._owner_task = None
        policy.set_state(None)


def load_component(config: ConfigHelper) -> MuonAccess:
    return MuonAccess(config)
