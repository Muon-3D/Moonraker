# MUON -- read one database key, telling "absent" from "could not read".
#
# The security components decide on what they read: muon_protection's level,
# muon_access's record and upload index. Moonraker's `get_item` cannot be
# trusted to tell the two apart. With a default it returns the default for
# every exception, a failed read included; without one it turns any error
# that is not already a ServerError into 404 "not found". Either way a
# database that cannot be read looks like a printer that was never set up,
# and the components would fail open.
#
# `get_batch` runs a plain SELECT with no exception handling: an absent key
# is missing from the answer, and a failure raises. That is the read these
# components need.

from __future__ import annotations

from typing import Any, Tuple


async def read(database: Any, namespace: str, key: str) -> Tuple[bool, Any]:
    """(found, value). Raises if the database cannot be read."""
    found = await database.get_batch(namespace, [key])
    if key in found:
        return True, found[key]
    return False, None


async def delete(database: Any, namespace: str, key: str) -> None:
    """Delete one key; a key that is already gone is not an error."""
    await database.delete_batch(namespace, [key])
