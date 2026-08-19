# Preheat the bed when a job is added to the queue
#
# KAN-162: recommendation 2 -- start heating the bed as soon as a job is
# queued rather than at the top of PRINT_START, so the bed ramp overlaps
# with the user walking to the printer instead of blocking the print.
#
# Copyright (C) 2026 Muon 3D
#
# This file may be distributed under the terms of the GNU GPLv3 license.
#
# SAFETY NOTES
#
# This component turns on a 170W heater without a human pressing anything,
# so it is built around a single invariant:
#
#   The bed is only ever turned OFF by this component while it can prove,
#   from freshly queried Klipper state, that the bed target is still the
#   exact value this component commanded and that no print is running.
#
# Ownership ("armed") is tracked in memory only and is never persisted.
# A restart therefore forgets any preheat, which means this component can
# never turn off a heater it did not demonstrably set.  A preheat orphaned
# by a Moonraker restart is cleaned up by Klipper's [idle_timeout], which
# is always loaded (klippy/toolhead.py) and whose default gcode is
# TURN_OFF_HEATERS/M84 after 600s.

from __future__ import annotations
import asyncio
import logging

from ..common import KlippyState

# Annotation imports
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    List,
    Optional,
    Tuple,
)
if TYPE_CHECKING:
    from asyncio import TimerHandle
    from ..confighelper import ConfigHelper
    from ..common import UserInfo
    from .klippy_apis import KlippyAPI
    from .klippy_connection import KlippyConnection
    from .file_manager.file_manager import FileManager

# print_stats states in which the bed belongs to the print, never to us
BUSY_PRINT_STATES = ("printing", "paused")
# Tolerance when comparing our commanded target against Klipper's report
TARGET_EPSILON = 0.1
# Metadata key holding the slicer's first layer bed temperature.  Note the
# sibling nozzle key is "first_layer_extr_temp", not "..._extruder_temp".
BED_TEMP_KEY = "first_layer_bed_temp"


class PreheatOnQueue:
    def __init__(self, config: ConfigHelper) -> None:
        self.server = config.get_server()
        self.enabled = config.getboolean("enable", False)
        self.timeout = config.getfloat("timeout", 480., above=0.)
        self.min_bed_temp = config.getfloat("min_bed_temp", 40., above=0.)
        self.max_bed_temp = config.getfloat(
            "max_bed_temp", 120., above=self.min_bed_temp
        )
        # Ownership state.  In memory only -- see the SAFETY NOTES above.
        self.lock = asyncio.Lock()
        self.armed: bool = False
        self.owned_target: float = 0.
        # Set once a subscription update has actually reported our target.
        # Until then a mismatch means a snapshot sampled before our M140
        # landed, not another client, so it must not release ownership.
        self.target_confirmed: bool = False
        self.deadline: Optional[TimerHandle] = None
        # Last known Klipper state, seeded and refreshed by the subscription
        self.bed_target: Optional[float] = None
        self.print_state: str = ""

        if not self.enabled:
            # Register nothing when disabled so the component is inert
            return
        self.server.register_event_handler(
            "server:klippy_ready", self._on_klippy_ready
        )
        self.server.register_event_handler(
            "server:klippy_disconnect", self._on_klippy_gone
        )
        self.server.register_event_handler(
            "server:klippy_shutdown", self._on_klippy_gone
        )
        self.server.register_event_handler(
            "job_queue:job_queue_changed", self._on_queue_changed
        )
        self.server.register_event_handler(
            "klippy_apis:job_start_complete", self._on_job_start
        )

    async def component_init(self) -> None:
        if not self.enabled:
            logging.info("[preheat_on_queue] disabled by configuration")
            return
        logging.info(
            "[preheat_on_queue] enabled: preheat bed on queued job, "
            "timeout %.0fs, accepted metadata range %.0f-%.0fC",
            self.timeout, self.min_bed_temp, self.max_bed_temp
        )

    # ***** Klippy lifecycle *****
    async def _on_klippy_ready(self) -> None:
        # A fresh Klippy session means all heaters are off and nothing we
        # may have set previously survives.  Drop ownership unconditionally.
        await self._release("klippy connection (re)established")
        kapis: KlippyAPI = self.server.lookup_component("klippy_apis")
        sub: Dict[str, Optional[List[str]]] = {
            "heater_bed": ["target"],
            "print_stats": ["state"],
        }
        try:
            result = await kapis.subscribe_objects(sub, self._status_update)
        except self.server.error:
            logging.exception(
                "[preheat_on_queue] unable to subscribe to heater_bed and "
                "print_stats, queue preheat is inactive this session"
            )
            return
        bed: Dict[str, Any] = result.get("heater_bed", {})
        stats: Dict[str, Any] = result.get("print_stats", {})
        self.bed_target = bed.get("target")
        self.print_state = str(stats.get("state", ""))

    async def _on_klippy_gone(self) -> None:
        # Klippy is gone or shut down: its heaters are off and we can no
        # longer reason about them.  Release, never send gcode.
        await self._release("klippy disconnected or shut down")

    async def _status_update(self, data: Dict[str, Any], _: float) -> None:
        bed: Optional[Dict[str, Any]] = data.get("heater_bed")
        if bed is not None and "target" in bed:
            self.bed_target = float(bed["target"])
        stats: Optional[Dict[str, Any]] = data.get("print_stats")
        if stats is not None and "state" in stats:
            self.print_state = str(stats["state"])
        await self._reconcile()

    # ***** Job queue hook *****
    async def _on_queue_changed(self, payload: Dict[str, Any]) -> None:
        action: str = payload.get("action", "")
        queue: Optional[List[Dict[str, Any]]] = payload.get("updated_queue")
        if action == "job_loaded":
            # The head of the queue was handed to Klipper.  Hand the bed
            # over with it: release ownership, never send gcode.  This is
            # the transition that keeps a queue-emptied cancel from firing
            # underneath a print that is already heating.
            await self._release("job handed off to klippy")
        elif action == "jobs_added":
            if queue:
                await self._arm(str(queue[0].get("filename", "")))
        elif action == "jobs_removed":
            if not queue:
                await self._cancel("job queue is empty")
        # "state_changed" carries updated_queue=None and never alters what
        # is queued, so there is nothing to do for it.

    async def _on_job_start(self, user: Optional[UserInfo] = None) -> None:
        # Fires from klippy_apis.start_print for both queue driven and
        # direct print starts, before the queue event is delivered.
        await self._release("a print was started")

    # ***** State transitions *****
    async def _arm(self, filename: str) -> None:
        if not filename:
            return
        temp = self._lookup_bed_temp(filename)
        if temp is None:
            return
        async with self.lock:
            if self.armed:
                # Already holding a preheat.  Never raise an existing
                # target for a job that is not at the head of the queue.
                return
            kconn: KlippyConnection = self.server.lookup_component(
                "klippy_connection"
            )
            if kconn.state != KlippyState.READY:
                logging.info(
                    "[preheat_on_queue] klippy is %s, not preheating",
                    kconn.state
                )
                return
            live = await self._query_printer()
            if live is None:
                return
            state, target = live
            if state in BUSY_PRINT_STATES:
                logging.debug(
                    "[preheat_on_queue] print state is '%s', not preheating",
                    state
                )
                return
            if abs(target) > TARGET_EPSILON:
                logging.info(
                    "[preheat_on_queue] bed already targeted at %.1fC by "
                    "another client, leaving it alone", target
                )
                return
            kapis: KlippyAPI = self.server.lookup_component("klippy_apis")
            try:
                await kapis.run_gcode(f"M140 S{temp:.1f}")
            except self.server.error:
                logging.exception(
                    "[preheat_on_queue] failed to set bed target"
                )
                return
            self.armed = True
            self.owned_target = temp
            self.bed_target = temp
            self.target_confirmed = False
            event_loop = self.server.get_event_loop()
            self.deadline = event_loop.delay_callback(
                self.timeout, self._on_timeout
            )
            logging.info(
                "[preheat_on_queue] preheating bed to %.1fC for queued job "
                "'%s', cancelling in %.0fs if no print starts",
                temp, filename, self.timeout
            )

    async def _cancel(self, reason: str) -> None:
        """Turn the preheat back off, but only if it is provably still
        ours and no print is running."""
        async with self.lock:
            if not self.armed:
                return
            # Always decide on freshly queried state.  A cached value can
            # be stale by exactly the window this check exists to close:
            # a print that started while this cancel was queued.
            live = await self._query_printer()
            if live is None:
                # Klippy is unreachable, so we cannot safely act and we
                # cannot turn anything off anyway.  Keep ownership so a
                # later event can retry; klippy's [idle_timeout] backstops.
                logging.warning(
                    "[preheat_on_queue] cannot verify printer state, "
                    "leaving bed preheat in place (%s)", reason
                )
                return
            state, target = live
            if state in BUSY_PRINT_STATES:
                self._disown(f"{reason}, but a print is running")
                return
            if abs(target - self.owned_target) > TARGET_EPSILON:
                self._disown(f"{reason}, but the bed target changed to {target}")
                return
            kapis: KlippyAPI = self.server.lookup_component("klippy_apis")
            try:
                await kapis.run_gcode("M140 S0")
            except self.server.error:
                logging.exception(
                    "[preheat_on_queue] failed to clear bed target"
                )
                return
            self.bed_target = 0.
            self._disown(f"{reason}, bed preheat turned off")

    async def _release(self, reason: str) -> None:
        """Drop ownership without touching the heater."""
        async with self.lock:
            if not self.armed:
                return
            self._disown(reason)

    async def _reconcile(self) -> None:
        """Drop ownership as soon as the bed stops being ours.  Only ever
        releases -- it never heats and never cools."""
        async with self.lock:
            if not self.armed:
                return
            if self.print_state in BUSY_PRINT_STATES:
                self._disown("a print has taken over the bed")
                return
            matches = (
                self.bed_target is not None
                and abs(self.bed_target - self.owned_target) <= TARGET_EPSILON
            )
            if matches:
                self.target_confirmed = True
                return
            if not self.target_confirmed:
                # We have not yet seen our own target come back, so this may
                # be a snapshot sampled before our M140 landed rather than
                # another client.  Only a live read can tell the two apart.
                live = await self._query_printer()
                if live is None:
                    return
                state, target = live
                if state in BUSY_PRINT_STATES:
                    self._disown("a print has taken over the bed")
                    return
                if abs(target - self.owned_target) <= TARGET_EPSILON:
                    self.target_confirmed = True
                    self.bed_target = target
                    return
            self._disown("bed target changed by another client")

    def _disown(self, reason: str) -> None:
        """Clear ownership state.  Caller must hold self.lock."""
        if self.deadline is not None:
            self.deadline.cancel()
            self.deadline = None
        self.armed = False
        self.owned_target = 0.
        self.target_confirmed = False
        logging.info("[preheat_on_queue] released bed preheat: %s", reason)

    async def _on_timeout(self) -> None:
        self.deadline = None
        await self._cancel(
            f"no print started within {self.timeout:.0f}s of queueing"
        )

    # ***** Helpers *****
    async def _query_printer(self) -> Optional[Tuple[str, float]]:
        """Return a live (print_stats.state, heater_bed.target) pair, or
        None if Klipper could not be queried."""
        kapis: KlippyAPI = self.server.lookup_component("klippy_apis")
        try:
            result = await kapis.query_objects(
                {"print_stats": ["state"], "heater_bed": ["target"]}
            )
            state = str(result["print_stats"]["state"])
            target = float(result["heater_bed"]["target"])
        except Exception:
            logging.exception(
                "[preheat_on_queue] unable to query printer state"
            )
            return None
        self.print_state = state
        self.bed_target = target
        return state, target

    def _lookup_bed_temp(self, filename: str) -> Optional[float]:
        """Read the slicer's first layer bed temperature.  Returns None
        whenever the value is missing or implausible -- we never guess."""
        fm: FileManager = self.server.lookup_component("file_manager")
        metadata: Dict[str, Any] = fm.get_file_metadata(filename)
        if not metadata:
            logging.info(
                "[preheat_on_queue] no metadata for '%s', not preheating",
                filename
            )
            return None
        raw: Any = metadata.get(BED_TEMP_KEY)
        if raw is None:
            logging.info(
                "[preheat_on_queue] '%s' has no %s, not preheating",
                filename, BED_TEMP_KEY
            )
            return None
        try:
            temp = float(raw)
        except (TypeError, ValueError):
            logging.info(
                "[preheat_on_queue] '%s' has a non numeric %s (%r), "
                "not preheating", filename, BED_TEMP_KEY, raw
            )
            return None
        if not self.min_bed_temp <= temp <= self.max_bed_temp:
            logging.info(
                "[preheat_on_queue] '%s' requests %.1fC, outside the "
                "accepted %.0f-%.0fC range, not preheating",
                filename, temp, self.min_bed_temp, self.max_bed_temp
            )
            return None
        return temp

    # ***** Shutdown *****
    async def on_exit(self) -> None:
        # Runs while klippy is still connected.  We are about to forget
        # that we own this heater, so turn it off while we still can.
        if self.enabled and self.armed:
            await self._cancel("moonraker is shutting down")

    async def close(self) -> None:
        async with self.lock:
            if self.deadline is not None:
                self.deadline.cancel()
                self.deadline = None


def load_component(config: ConfigHelper) -> PreheatOnQueue:
    return PreheatOnQueue(config)
