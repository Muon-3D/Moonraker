# MUON, KAN-203 / KAN-270 -- the clock and the time zone (spec 01 §2.2,
# 02 §5.2 and §5.4). Work package MR-2.
#
# The M1 has no RTC. It boots on fake-hwclock's last saved time and is only
# right once NTP has run, which needs the network setup is about to join. The
# phone page therefore posts the phone's own clock and time zone as soon as the
# owner taps Start, and the panel path waits for NTP.
#
# The writes go through Aux's time routes (03 §3, OS-6): GET /time, POST /time
# and POST /time/zone. They are not built on any MuonOS branch yet, so until
# they are, the reads fall back to what an unprivileged process can see for
# itself -- systemd-timesyncd's sync flag and /etc/localtime -- and the writes
# are skipped with a warning rather than failing setup.

from __future__ import annotations

import datetime
import json
import logging
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from . import model
from ...utils.exceptions import ServerError

if TYPE_CHECKING:
    from . import MuonSetup, WriteContext
    from ...common import WebRequest

ZONE_TAB = Path("/usr/share/zoneinfo/zone1970.tab")
ZONEINFO = Path("/usr/share/zoneinfo")
#: Written by MuonOS's build (muon.device-build/v1): `created_at` is when the
#: image was built, and no real clock can be earlier than that.
BUILD_JSON = Path("/etc/muon3d/build.json")
#: systemd-timesyncd creates this once it has synchronised (systemd >= 239).
TIMESYNC_FLAG = Path("/run/systemd/timesync/synchronized")
LOCALTIME = Path("/etc/localtime")

#: 02 §5.4: the clock is only set when it is more than this far out.
CLOCK_TOLERANCE_MS = 2000
#: The floor when the build time cannot be read: before any M1 was built.
FALLBACK_FLOOR_MS = 1767225600000  # 2026-01-01T00:00:00Z

_ZONE_RE = re.compile(r"^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+){0,2}$")
_COUNTRY_RE = re.compile(r"^[A-Za-z]{2}$")


# --------------------------------------------------------------------------
# tzdata
# --------------------------------------------------------------------------

def _zone_rows(tab: Path) -> List[List[str]]:
    try:
        text = tab.read_text(encoding="utf-8")
    except OSError as exc:
        logging.warning("muon_setup: cannot read %s: %s", tab, exc)
        return []
    rows = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 3:
            rows.append(parts)
    return rows


def zones_for_country(country: str, tab: Optional[Path] = None) -> List[str]:
    """A country's zones, principal zone first.

    zone1970.tab lists each country's zones most populous first where
    geography allows, which is the order 02 §5.2 wants. A row may name
    several countries (`AT,BA,...`); it counts for each of them.
    """
    if not _COUNTRY_RE.match(country or ""):
        return []
    code = country.upper()
    zones: List[str] = []
    for parts in _zone_rows(tab or ZONE_TAB):
        if code in parts[0].split(",") and parts[2] not in zones:
            zones.append(parts[2])
    return zones


def valid_zone(tz: Any, root: Optional[Path] = None) -> bool:
    """A name tzdata knows. Checked by name shape first, so a value like
    `../../etc/passwd` never reaches the filesystem."""
    if not isinstance(tz, str) or not _ZONE_RE.match(tz) or ".." in tz:
        return False
    return (root or ZONEINFO).joinpath(tz).is_file()


def build_floor_ms(path: Optional[Path] = None) -> int:
    """The image's build time in ms, from build.json's `created_at`."""
    try:
        record = json.loads((path or BUILD_JSON).read_text(encoding="utf-8"))
        created = str(record["created_at"]).replace("Z", "+00:00")
        stamp = datetime.datetime.fromisoformat(created)
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=datetime.timezone.utc)
        return int(stamp.timestamp() * 1000)
    except (OSError, ValueError, KeyError, TypeError):
        return FALLBACK_FLOOR_MS


def local_zone() -> Optional[str]:
    """The zone /etc/localtime points at, when Aux cannot say."""
    try:
        target = os.readlink(LOCALTIME)
    except OSError:
        return None
    marker = "zoneinfo/"
    if marker not in target:
        return None
    zone = target.split(marker, 1)[1]
    return zone if _ZONE_RE.match(zone) else None


# --------------------------------------------------------------------------
# The live `clock` block (02 §6)
# --------------------------------------------------------------------------

async def refresh(setup: MuonSetup) -> None:
    from . import AuxMissing, AuxRefused, AuxUnavailable
    clock = setup._live["clock"]
    try:
        now = await setup.aux("GET", "/time")
    except AuxMissing:
        now = None
    except (AuxUnavailable, AuxRefused):
        return
    if isinstance(now, dict):
        synced = now.get("ntp_synced") is True
        tz = now.get("tz") if isinstance(now.get("tz"), str) else None
    else:
        # No OS-6 in this image: read what any process can.
        synced = TIMESYNC_FLAG.exists()
        tz = local_zone()
    clock["synced"] = synced
    if synced:
        clock["source"] = "ntp"
    elif setup._clock_from_phone:
        clock["source"] = "phone"
    else:
        clock["source"] = "fake_hwclock"
    clock["tz"] = tz


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------

def register(setup: MuonSetup) -> None:
    reg = setup.server.register_endpoint
    reg("/server/muon/setup/clock", ["POST"],
        lambda webreq: handle_clock(setup, webreq))
    reg("/server/muon/setup/timezone", ["POST"],
        lambda webreq: handle_timezone(setup, webreq))


async def _set_zone(setup: MuonSetup, tz: str) -> None:
    """POST /time/zone, raising AuxMissing / AuxUnavailable / AuxRefused."""
    await setup.aux("POST", "/time/zone", {"tz": tz})


async def handle_clock(setup: MuonSetup, webreq: WebRequest) -> Dict[str, Any]:
    """POST /server/muon/setup/clock {epoch_ms, tz} (02 §5.4).

    The phone's clock and zone, posted when the owner taps Start. No `rev`,
    and it never changes `rev`: it is not the owner answering a question.
    """
    from . import AuxMissing, AuxRefused, AuxUnavailable, STARTUP_WAIT
    setup.begin(webreq)
    args = webreq.get_args()
    epoch_ms = args.get("epoch_ms")
    tz = args.get("tz")
    if isinstance(epoch_ms, bool) or not isinstance(epoch_ms, int):
        raise ServerError("muon_setup: 'epoch_ms' must be an integer", 400)
    if not await setup.wait_resolved(STARTUP_WAIT) or setup.doc is None:
        return setup.envelope(model.error(
            "aux_unavailable", "setup state is not ready yet"))
    if setup.doc["op"] is not None:
        return setup.envelope(model.error(
            "busy", f"{setup.doc['op']['kind']} is running",
            op=setup.doc["op"]["kind"]))
    if epoch_ms <= build_floor_ms():
        # 08: silent on the surfaces, logged here. S9: a hotspot client can at
        # worst set a wrong clock until NTP corrects it; never an older one.
        logging.info("muon_setup: refused a clock before the image build time")
        return setup.envelope(model.error(
            "invalid_clock", "that time is before this image was built"))
    try:
        now = await setup.aux("GET", "/time")
    except AuxMissing:
        logging.warning(
            "muon_setup: this image has no Aux /time (OS-6); the phone's "
            "clock and zone were not applied")
        return setup.envelope()
    except (AuxUnavailable, AuxRefused) as exc:
        logging.info("muon_setup: cannot read the clock: %s", exc)
        return setup.envelope(model.error(
            "aux_unavailable", "the Aux API is not answering"))
    changed = False
    if isinstance(now, dict) and now.get("ntp_synced") is not True:
        current = now.get("epoch_ms")
        if not isinstance(current, int) or abs(
            current - epoch_ms
        ) > CLOCK_TOLERANCE_MS:
            try:
                await setup.aux("POST", "/time", {"epoch_ms": epoch_ms})
            except AuxRefused as exc:
                # 409 ntp_synced: NTP won the race, which is the better clock.
                logging.info("muon_setup: clock not set: %s", exc)
            except (AuxMissing, AuxUnavailable) as exc:
                logging.warning("muon_setup: clock not set: %s", exc)
            else:
                setup._clock_from_phone = True
                changed = True
    if tz is not None:
        if valid_zone(tz):
            try:
                await _set_zone(setup, tz)
            except (AuxMissing, AuxUnavailable, AuxRefused) as exc:
                logging.warning("muon_setup: zone %s not set: %s", tz, exc)
            else:
                setup._internal["tz_source"] = "phone"
                await setup._persist_internal()
                changed = True
        else:
            logging.info("muon_setup: ignored an unknown zone from the phone")
    if changed:
        await refresh(setup)
        setup._notify()
    return setup.envelope()


async def handle_timezone(
    setup: MuonSetup, webreq: WebRequest
) -> Dict[str, Any]:
    """POST /server/muon/setup/timezone {rev, tz} (02 §5.4): the owner picks
    one of the declared country's zones, on the panel's P7b."""
    from . import AuxMissing, AuxRefused, AuxUnavailable

    async def handler(ctx: WriteContext) -> Optional[Dict[str, Any]]:
        tz = ctx.args.get("tz")
        region = setup._live.get("region") or {}
        country = region.get("country") if region.get("declared") else None
        if not country or tz not in zones_for_country(country):
            return model.error(
                "invalid_timezone", f"{tz!r} is not a zone of {country!r}",
                country=country)
        try:
            await _set_zone(setup, tz)
        except (AuxMissing, AuxUnavailable, AuxRefused) as exc:
            return model.error(
                "aux_unavailable", f"could not set the zone: {exc}")
        setup._internal["tz_source"] = "owner"
        await setup._persist_internal()
        await refresh(setup)
        ctx.changed = True
        return None
    return await setup.write(webreq, handler)
