# Moonraker component -- muon_setup
#
# MUON, KAN-203: the M1's first-run setup state machine.
#
# Enable it in moonraker.conf:
#     [muon_setup]
#
# Spec: specs/m1-first-run-setup/ in Muon-3D/OrcaSlicer, chiefly 01 (the flow),
# 02 (this component's API) and 08 (the error codes). The panel (MuonUI), the
# phone page (the /setup route in Fluidd) and later the Bluetooth bridge all
# render this state and send it intents. None of them keeps its own copy of
# progress, so a phone that drops off the hotspot, or a power cut, loses
# nothing: the state is here, in Moonraker's database, and every change is
# saved before it is announced.
#
# This package is the core (work package MR-1): the document, persistence,
# `rev`/`driver`/`op`, who may call what, migration of printers already in the
# field, and the navigation endpoints. Each step's own endpoints arrive in its
# own module (MR-2 language/clock/name, MR-3 network, MR-4 update, MR-5 remote,
# MR-7 ready) through the hooks below, so the step packages do not all edit
# one file.

from __future__ import annotations

import asyncio
import copy
import logging
import os
import re
import secrets
import socket
import time
from typing import (
    TYPE_CHECKING, Any, Awaitable, Callable, Dict, FrozenSet, List, Optional,
    Set, Tuple
)
from urllib.parse import urlencode

from . import caller, clock, language, manifest, model, name, region
from .model import DONE, FINISH, HIDDEN, PENDING, SKIPPED
from ...utils.exceptions import ServerError

if TYPE_CHECKING:
    from ...common import WebRequest
    from ...confighelper import ConfigHelper

NAMESPACE = "muon_setup"
STATE_KEY = "state"
#: Bookkeeping that is not part of the document: whether the completion marker
#: reached Aux, and when the hotspot was asked to turn itself off.
INTERNAL_KEY = "internal"

DEFAULT_READY_MANIFEST = "/usr/share/muon/setup/ready.json"
#: OS-7's completion marker (MuonOS#313, 02 §4). The only marker route: #174's
#: `/setup` is replaced by it, and H1 never reads a marker written there.
MARKER_PATH = "/setup/complete"
DEFAULT_LANGUAGES = "en, de, fr, es, it"

#: Wi-Fi profiles that say nothing about earlier use (01 §7): the hotspot's
#: own, and the one every M1-dev image bakes in (MuonOS layers/output-dev.toml).
IGNORED_WIFI_PROFILES = frozenset({"ap0-con", "Muon3D_Dev"})

#: How long GET waits at boot for the migration check before it answers.
STARTUP_WAIT = 10.0
#: The most scanned SSIDs asked about one by one on images without
#: GET /wifi/saved (each is one `nmcli connection show`).
WIFI_SHOW_LIMIT = 30
#: How often to retry the migration check while it cannot decide.
MIGRATION_RETRY = 3.0
#: How long "can't tell yet" from the Wi-Fi scan or muon-link may hold the
#: decision. Aux not answering holds it for as long as that lasts.
MIGRATION_UNSURE_LIMIT = 600.0
#: How often to retry writing or clearing the marker while Aux is down.
MARKER_RETRY = 30.0
#: 02 §6: poll the hotspot's station count every 2 s while setup runs.
POLL_ACTIVE = 2.0
POLL_IDLE = 30.0

#: The languages the setup screens offer, by their own name.
ENDONYMS = {
    "en": "English", "de": "Deutsch", "fr": "Français", "es": "Español",
    "it": "Italiano", "nl": "Nederlands", "pl": "Polski", "pt": "Português",
    "sv": "Svenska", "da": "Dansk", "nb": "Norsk bokmål", "fi": "Suomi",
    "cs": "Čeština", "ja": "日本語", "ko": "한국어", "zh-Hans": "简体中文",
}
_LANGUAGE_RE = re.compile(r"^[a-z]{2,3}(-[A-Z][a-z]{3})?(-[A-Z]{2})?$")
_CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

#: 02 §5.11. `app` is the Muon3D phone app (KAN-399), on the hotspot or LAN.
DRIVER_KINDS = ("panel", "phone", "web", "app")

#: A migration signal that cannot say yet (01 §7), as distinct from "no".
UNSURE = "unsure"

Handler = Callable[["WriteContext"], Awaitable[Optional[Dict[str, Any]]]]
OpRunner = Callable[["OpHandle"], Awaitable[None]]


class AuxUnavailable(Exception):
    """Aux did not answer, or answered with a server error."""


class AuxMissing(Exception):
    """This image's Aux API has no such route (yet)."""


class AuxRefused(Exception):
    """Aux answered with a 4xx. `code` is its `detail.code`, when it gave one
    (02 §1: the 409 and 422 mappings need it)."""

    def __init__(self, status: int, message: str,
                 code: Optional[str] = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class WriteContext:
    """What a step handler gets: who called, with what, and when."""

    def __init__(
        self, setup: MuonSetup, kind: str, args: Dict[str, Any], now: float
    ) -> None:
        self.setup = setup
        self.kind = kind
        self.args = args
        self.now = now
        #: Set by a handler whose change lives outside the document (the
        #: time zone's `tz_source`), so it is still committed and announced.
        self.changed = False

    @property
    def doc(self) -> Dict[str, Any]:
        assert self.setup.doc is not None
        return self.setup.doc


class OpHandle:
    """A running operation's view of the state (01 §3 `op`).

    Every update is persisted and announced. Once the operation has been
    cancelled or replaced, updates are dropped: a runner that outlives its
    operation cannot write over whatever came next.
    """

    def __init__(self, setup: MuonSetup, op_id: str) -> None:
        self.setup = setup
        self.op_id = op_id

    def current(self) -> bool:
        doc = self.setup.doc
        return bool(doc and doc["op"] and doc["op"].get("id") == self.op_id)

    async def update(self, **fields: Any) -> bool:
        async with self.setup._lock:
            if not self.current():
                return False
            assert self.setup.doc is not None
            self.setup.doc["op"].update(fields)
            await self.setup._commit()
            return True

    async def finish(
        self, mutate: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> bool:
        """Clear the operation and apply its outcome in one change."""
        async with self.setup._lock:
            if not self.current():
                return False
            doc = self.setup.doc
            assert doc is not None
            doc["op"] = None
            if mutate is not None:
                mutate(doc)
            await self.setup._commit()
            return True


class MuonSetup:
    def __init__(self, config: ConfigHelper) -> None:
        self.server = config.get_server()
        self.languages: List[str] = [
            code for code in
            config.getlist("languages", None, separator=",") or []
            if code
        ] or [c.strip() for c in DEFAULT_LANGUAGES.split(",")]
        for code in self.languages:
            if not _LANGUAGE_RE.match(code):
                raise config.error(
                    f"[muon_setup] '{code}' is not a BCP 47 language code"
                )
        self.hotspot_off_delay = config.getint("hotspot_off_delay", 900, minval=0)
        self.driver_lease = config.getfloat("driver_lease", 30., above=0.)
        self.join_timeout = config.getint("join_timeout", 45, minval=5)
        self.manifest_path = config.get("ready_manifest", DEFAULT_READY_MANIFEST)
        self.manifest = manifest.load(self.manifest_path)

        self.database = self.server.lookup_component("database")
        self.database.register_local_namespace(NAMESPACE, forbidden=True)
        self.server.register_notification("muon_setup:muon_setup_changed")

        #: The stored document. None until the migration check has decided
        #: what this printer is (see _startup).
        self.doc: Optional[Dict[str, Any]] = None
        #: A document of a schema version this build does not know, from a
        #: newer build. Shown as complete and never written (02 §4).
        self.read_only_version: Optional[Any] = None
        self._resolved = asyncio.Event()
        self._lock = asyncio.Lock()
        #: `marker_written` / `marker_by`: the marker's POST reached Aux, and
        #: with which `by`. `marker_clear_pending`: a reset's DELETE has not
        #: yet. `tz_source`: who set the time zone (02 §6 `clock`).
        self._internal: Dict[str, Any] = {
            "marker_written": False, "tz_source": None,
        }
        self._marker_task: Optional[asyncio.Task] = None
        self._live: Dict[str, Any] = {
            "printer": None,
            "derived_name": None,
            "hotspot": {
                "up": False, "ssid": None, "clients": 0, "auto_off_at": None,
                "address": caller.HOTSPOT_ADDRESS,
            },
            "clock": {"synced": False, "source": None, "tz": None,
                      "tz_source": None},
            "region": None,
            "capabilities": {
                "ethernet": False, "enterprise": False, "cloud_link": False,
                "self_hosted": False, "bluetooth": False,
            },
        }
        self._op_task: Optional[asyncio.Task] = None
        self._pending_op: Optional[Tuple[str, OpRunner]] = None
        self._tasks: Set[asyncio.Task] = set()
        self._lapse_timer: Optional[asyncio.TimerHandle] = None
        self._poll_task: Optional[asyncio.Task] = None
        self._stations_route = True
        self._clock_from_phone = False
        self._closed = False

        #: Hooks for the step packages. `hide_when_current[step](doc)` decides
        #: whether a step is hidden at the moment it becomes current (01 §2);
        #: `boot_op_handlers[kind](doc)` takes over an operation found in the
        #: stored state at boot, instead of marking it `interrupted`.
        self.hide_when_current: Dict[str, Callable[[Dict[str, Any]], bool]] = {
            "update": self._hide_update,
        }
        self.boot_op_handlers: Dict[str, Callable[[Dict[str, Any]], None]] = {}

        reg = self.server.register_endpoint
        reg("/server/muon/setup", ["GET"], self._handle_get)
        reg("/server/muon/setup/options", ["GET"], self._handle_options)
        reg("/server/muon/setup/driver", ["POST"], self._handle_driver)
        reg("/server/muon/setup/goto", ["POST"], self._handle_goto)
        reg("/server/muon/setup/skip", ["POST"], self._handle_skip)
        reg("/server/muon/setup/finish", ["POST"], self._handle_finish)
        reg("/server/muon/setup/card/dismiss", ["POST"], self._handle_card_dismiss)
        reg("/server/muon/setup/reset", ["POST"], self._handle_reset)
        reg("/server/muon/setup/network/cancel", ["POST"],
            self._handle_network_cancel)
        # The steps' own endpoints, one module each.
        for step_module in (language, clock, name):
            step_module.register(self)

    # ------------------------------------------------------------------
    # Startup, migration and shutdown
    # ------------------------------------------------------------------

    async def component_init(self) -> None:
        # Never blocks on Aux and never raises because of it (02 §1): the
        # decision about what this printer is runs in the background, and
        # GET waits a bounded time for it.
        self._spawn(self._startup())

    async def _startup(self, poll: bool = True) -> None:
        stored = await self.database.get_item(NAMESPACE, STATE_KEY, None)
        internal = await self.database.get_item(NAMESPACE, INTERNAL_KEY, None)
        if isinstance(internal, dict):
            self._internal.update(internal)
        if isinstance(stored, dict):
            self._load(stored)
        else:
            await self._migrate()
        if poll:
            self._poll_task = self._spawn(self._poll())
        if self.doc is not None and self.read_only_version is None:
            # A marker write or clear that an earlier boot could not finish.
            if self.doc["state"] == "complete":
                if not self._internal.get("marker_written"):
                    self._start_marker_sync()
            elif self._internal.get("marker_clear_pending"):
                self._start_marker_sync()

    def _load(self, stored: Dict[str, Any]) -> None:
        if stored.get("version") != model.SCHEMA_VERSION:
            # A newer build wrote this. Treat it as complete, so a downgrade
            # never re-runs setup, and never write over it.
            logging.warning(
                "muon_setup: stored state has version %r; this build knows %d. "
                "Treating setup as complete and leaving the state read-only.",
                stored.get("version"), model.SCHEMA_VERSION,
            )
            self.read_only_version = stored.get("version")
            doc = model.migrated_document(manifest.item_ids(self.manifest))
            doc["steps"]["language"]["source"] = None
            self.doc = doc
            self._resolved.set()
            return
        doc = copy.deepcopy(stored)
        changed = model.reconcile_ready_items(doc, manifest.item_ids(self.manifest))
        op = doc.get("op")
        if op is not None:
            handler = self.boot_op_handlers.get(op.get("kind"))
            if handler is not None:
                handler(doc)
            else:
                # 01 §3: an operation a power cut stopped is failed, not resumed.
                self._mark_interrupted(doc, op)
            changed = True
        self.doc = doc
        self._resolved.set()
        if changed:
            self._spawn(self._persist_quietly())

    @staticmethod
    def _mark_interrupted(doc: Dict[str, Any], op: Dict[str, Any]) -> None:
        doc["op"] = None
        step_id = model.OP_STEPS.get(op.get("kind") or "")
        err = {"code": "interrupted", "at_phase": op.get("phase")}
        if step_id == "ready":
            for item in doc["steps"]["ready"]["items"]:
                if item.get("id") == op.get("item"):
                    item["status"] = PENDING
                    item["error"] = err
        elif step_id is not None:
            doc["steps"][step_id]["error"] = err
        doc["rev"] += 1

    async def _migrate(self) -> None:
        """01 §7: a printer updated from firmware with no setup flow must not
        be sent into setup. Decide once, before anything is stored, and store
        nothing until the answer is certain: a `new` saved on a guess traps a
        field unit in setup on every later boot."""
        loop = asyncio.get_event_loop()
        first_unsure: Optional[float] = None
        while not self._closed:
            verdict = await self._field_signals()
            if verdict == UNSURE:
                now = loop.time()
                first_unsure = now if first_unsure is None else first_unsure
                if now - first_unsure >= MIGRATION_UNSURE_LIMIT:
                    logging.warning(
                        "muon_setup: the Wi-Fi scan or muon-link still cannot "
                        "say after %.0f s; deciding without them",
                        MIGRATION_UNSURE_LIMIT)
                    verdict = False
            if verdict is True or verdict is False:
                ids = manifest.item_ids(self.manifest)
                if verdict:
                    logging.info(
                        "muon_setup: this printer was in use before setup "
                        "existed; marking setup complete (migrated)")
                    doc = model.migrated_document(ids)
                else:
                    doc = model.new_document(ids)
                self.doc = doc
                await self._persist()
                self._resolved.set()
                self._notify()
                if verdict:
                    # 02 §4: without the marker, OS-5's H1 keeps a field
                    # unit's hotspot up for good.
                    self._internal["marker_by"] = "migrated"
                    self._start_marker_sync()
                return
            logging.info(
                "muon_setup: cannot tell yet whether this printer is new; "
                "retrying in %.0f s", MIGRATION_RETRY)
            await asyncio.sleep(MIGRATION_RETRY)

    async def _field_signals(self) -> Any:
        """True if any sign of earlier use is found, False if every source
        answered and none did. None while Aux is not answering, and UNSURE
        while the Wi-Fi scan or muon-link cannot say yet."""
        fluidd = await self.database.get_item("fluidd", None, {})
        if isinstance(fluidd, dict) and fluidd.get("uiSettings"):
            return True
        verdict: Any = False
        for probe in (self._marker_present, self._wifi_saved, self._linked):
            try:
                found = await probe()
            except AuxUnavailable as exc:
                logging.info("muon_setup: migration check: %s", exc)
                verdict = None
                continue
            if found is True:
                return True
            if found == UNSURE and verdict is False:
                verdict = UNSURE
        return verdict

    async def _marker_present(self) -> bool:
        # OS-7's marker (MuonOS#313): GET /setup/complete -> {complete, ...}.
        try:
            marker = await self.aux("GET", MARKER_PATH)
        except AuxMissing:
            return False
        return isinstance(marker, dict) and marker.get("complete") is True

    async def _wifi_saved(self) -> Any:
        """A saved Wi-Fi profile other than the hotspot's and the dev image's.

        MuonOS#210's GET /wifi/saved answers exactly. Images without it are
        asked about the networks in range (01 §7): the connection in use, then
        GET /wifi/show?ssid= for each scanned SSID. An empty scan, or no radio
        yet, is UNSURE, never "none": NetworkManager may simply not be up.
        """
        try:
            saved = await self.aux("GET", "/wifi/saved")
        except AuxMissing:
            saved = None
        if isinstance(saved, list):
            return any(
                isinstance(p, dict) and p.get("name") not in IGNORED_WIFI_PROFILES
                for p in saved
            )
        try:
            current = await self.aux("GET", "/wifi/current")
        except (AuxMissing, AuxRefused):
            current = None
        if isinstance(current, dict):
            ssid = current.get("ssid")
            if ssid and ssid not in IGNORED_WIFI_PROFILES:
                return True
        try:
            scan = await self.aux("GET", "/wifi/scan")
        except (AuxMissing, AuxRefused):
            return UNSURE
        ssids: List[str] = []
        for net in scan if isinstance(scan, list) else []:
            ssid = net.get("ssid") if isinstance(net, dict) else None
            if (isinstance(ssid, str) and ssid and ssid not in ssids
                    and ssid not in IGNORED_WIFI_PROFILES):
                ssids.append(ssid)
        if not ssids:
            return UNSURE
        for ssid in ssids[:WIFI_SHOW_LIMIT]:
            try:
                await self.aux("GET", "/wifi/show?" + urlencode({"ssid": ssid}))
            except (AuxMissing, AuxRefused):
                continue
            return True
        return False

    async def _linked(self) -> Any:
        # muon-link's GET /link answers {"phase": "linked", ...} once an
        # account is linked (LinkPhase), through the muon_link component
        # (Moonraker#20) when it is configured. A 503 is muon-link not
        # answering yet: UNSURE, not "never linked".
        link = self.server.lookup_component("muon_link", None)
        if link is None or not hasattr(link, "call"):
            return False
        try:
            status = await link.call("GET", "/link")
        except ServerError as exc:
            if exc.status_code >= 500:
                return UNSURE
            logging.info("muon_setup: migration check: link status: %s", exc)
            return False
        except Exception as exc:
            logging.info("muon_setup: migration check: link status: %s", exc)
            return UNSURE
        return isinstance(status, dict) and status.get("phase") == "linked"

    async def close(self) -> None:
        self._closed = True
        if self._lapse_timer is not None:
            self._lapse_timer.cancel()
        tasks = list(self._tasks)
        if self._op_task is not None:
            tasks.append(self._op_task)
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    def _spawn(self, coro: Awaitable[Any]) -> asyncio.Task:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def drain(self) -> None:
        """Wait for the background work already started, except the poller.
        For tests."""
        while True:
            pending = [
                t for t in self._tasks if not t.done() and t is not self._poll_task
            ]
            if self._op_task is not None and not self._op_task.done():
                pending.append(self._op_task)
            if not pending:
                return
            await asyncio.gather(*pending, return_exceptions=True)

    # ------------------------------------------------------------------
    # Aux, through aux_api_proxy's helpers (02 §1)
    # ------------------------------------------------------------------

    async def aux(self, method: str, path: str, body: Any = None,
                  timeout: Optional[float] = None) -> Any:
        """Call the Aux API, sorting failures into unavailable / missing /
        refused. aux_api_proxy adds the token and turns an HTTP error into a
        ServerError that keeps the status code and Aux's `detail.code`."""
        proxy = self.server.lookup_component("aux_api_proxy", None)
        if proxy is None:
            raise AuxUnavailable("aux_api_proxy is not loaded")
        try:
            if method == "GET":
                return await proxy.get(path)
            if method == "DELETE":
                if not hasattr(proxy, "delete"):
                    raise AuxMissing(path)
                return await proxy.delete(path)
            if timeout is not None:
                return await proxy.post(path, body, timeout=timeout)
            return await proxy.post(path, body)
        except ServerError as exc:
            status = exc.status_code
            if status in (404, 405):
                raise AuxMissing(path) from exc
            if status >= 500 or status in (401, 403):
                raise AuxUnavailable(f"{method} {path}: {exc}") from exc
            raise AuxRefused(
                status, str(exc), getattr(exc, "aux_code", None)) from exc

    # ------------------------------------------------------------------
    # The document as clients see it
    # ------------------------------------------------------------------

    def public_state(self) -> Dict[str, Any]:
        doc = self.doc
        if doc is None:
            # Still deciding whether this printer is new (see _migrate). Say
            # "complete": a printer in the field that briefly reads "new"
            # would be sent into setup by the panel's boot-time guard, which
            # is exactly what 01 §7 forbids, while a new printer that briefly
            # reads "complete" is corrected by the next change notification.
            doc = model.new_document(manifest.item_ids(self.manifest))
            doc["state"] = "complete"
            doc["cursor"] = FINISH
        public = copy.deepcopy(doc)
        public["driver"] = model.driver_public(doc.get("driver"), self.driver_lease)
        live = self._live
        if live["printer"] is not None:
            public["printer"] = copy.deepcopy(live["printer"])
            # 02 §6: `value` is the effective name, so until the owner keeps
            # or renames it, it follows the identity; `derived` always does.
            name_step = public["steps"]["name"]
            if name_step["status"] == PENDING or not name_step.get("value"):
                name_step["value"] = live["printer"]["name"]
            if live.get("derived_name"):
                name_step["derived"] = live["derived_name"]
        public["hotspot"] = dict(live["hotspot"])
        clock = dict(live["clock"])
        clock["tz_source"] = self._internal.get("tz_source")
        public["clock"] = clock
        public["region"] = copy.deepcopy(live["region"])
        public["capabilities"] = dict(live["capabilities"])
        # Key order as in 02 §6, for anyone reading a dump.
        order = ("version", "rev", "state", "cursor", "driver", "op", "printer",
                 "hotspot", "clock", "region", "capabilities", "card_dismissed",
                 "steps")
        return {k: public[k] for k in order if k in public}

    def _notify(self) -> None:
        self.server.send_event("muon_setup:muon_setup_changed", self.public_state())

    async def _persist(self) -> None:
        assert self.doc is not None
        stored = model.storable(self.doc)
        if self._live["printer"] is not None:
            stored["printer"] = copy.deepcopy(self._live["printer"])
        await self.database.insert_item(NAMESPACE, STATE_KEY, stored)

    async def _persist_internal(self) -> None:
        await self.database.insert_item(
            NAMESPACE, INTERNAL_KEY, dict(self._internal))

    async def _persist_quietly(self) -> None:
        async with self._lock:
            try:
                await self._persist()
            except Exception:
                logging.exception("muon_setup: could not save the state")
        self._notify()

    async def _commit(self) -> None:
        """Bump `rev`, save, then announce. Save before announcing (02 §4):
        a client must never see a state that a power cut could take back."""
        assert self.doc is not None
        self.doc["rev"] += 1
        await self._persist()
        self._notify()

    # ------------------------------------------------------------------
    # The write pipeline (02 §5)
    # ------------------------------------------------------------------

    def envelope(
        self, err: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        return {"ok": err is None, "error": err, "state": self.public_state()}

    def allowed_hosts(self) -> Set[str]:
        addresses: List[str] = []
        machine = self.server.lookup_component("machine", None)
        if machine is not None:
            network = machine.get_system_info().get("network", {})
            for info in network.values():
                for addr in info.get("ip_addresses", []):
                    if isinstance(addr.get("address"), str):
                        addresses.append(addr["address"])
        return caller.allowed_hosts(socket.gethostname(), addresses)

    def begin(
        self, webreq: WebRequest, allowed: FrozenSet[str] = caller.WRITE
    ) -> str:
        """Classify, authorise and hygiene-check a write. Returns the kind."""
        kind = caller.caller_kind(webreq)
        caller.require(kind, allowed)
        caller.check_hygiene(webreq, self.allowed_hosts())
        return kind

    async def wait_resolved(self, timeout: Optional[float] = None) -> bool:
        if self._resolved.is_set():
            return True
        try:
            await asyncio.wait_for(self._resolved.wait(), timeout)
        except asyncio.TimeoutError:
            return False
        return True

    @staticmethod
    def parse_rev(args: Dict[str, Any]) -> int:
        rev = args.get("rev")
        if isinstance(rev, bool) or not isinstance(rev, int):
            raise ServerError("muon_setup: 'rev' must be an integer", 400)
        return rev

    async def write(
        self,
        webreq: WebRequest,
        handler: Handler,
        *,
        allowed: FrozenSet[str] = caller.WRITE,
        needs_rev: bool = True,
        after_complete: bool = False,
        busy_exempt: bool = False,
    ) -> Dict[str, Any]:
        """Run one state change under 02 §5's rules.

        The order of refusals: who you are (403), what you sent (415/403/400),
        then the domain -- read-only, not yet resolved, complete, `busy`,
        `stale_rev` -- and only then the step's own handler. A handler returns
        None for success or a model.error() dict; on an error, any change it
        made is thrown away.
        """
        kind = self.begin(webreq, allowed)
        args = webreq.get_args()
        rev = self.parse_rev(args) if needs_rev else None
        if self.read_only_version is not None:
            raise ServerError(
                "muon_setup: the stored setup state is from a newer version "
                f"({self.read_only_version!r}) and is read-only", 409)
        if not await self.wait_resolved(STARTUP_WAIT) or self.doc is None:
            return self.envelope(model.error(
                "aux_unavailable", "setup state is not ready yet"))
        started_op: Optional[Tuple[str, OpRunner]] = None
        async with self._lock:
            doc = self.doc
            if doc["state"] == "complete" and not after_complete:
                return self.envelope(model.error(
                    "invalid_step", "setup is complete"))
            if doc["op"] is not None and not busy_exempt:
                return self.envelope(model.error(
                    "busy", f"{doc['op']['kind']} is running",
                    op=doc["op"]["kind"]))
            if needs_rev and rev != doc["rev"]:
                return self.envelope(model.error(
                    "stale_rev", f"rev {rev} is stale; current is {doc['rev']}",
                    current_rev=doc["rev"]))
            before = copy.deepcopy(doc)
            ctx = WriteContext(self, kind, args, time.time())
            self._pending_op = None
            try:
                err = await handler(ctx)
            except BaseException:
                self.doc = before
                self._pending_op = None
                raise
            if err is not None:
                self.doc = before
                self._pending_op = None
                return self.envelope(err)
            if self.doc != before or ctx.changed:
                self._take_driver(ctx)
                if self.doc["state"] == "new":
                    self.doc["state"] = "in_progress"
                try:
                    await self._commit()
                except BaseException:
                    self.doc = before
                    self._pending_op = None
                    raise
            started_op, self._pending_op = self._pending_op, None
        if started_op is not None:
            self._op_task = asyncio.ensure_future(self._run_op(*started_op))
        return self.envelope()

    def _take_driver(self, ctx: WriteContext) -> None:
        """01 §3: a write from a surface that is not the driver makes it the
        driver. Part of the same change, so it rides the same `rev`."""
        surface = caller.SURFACE_FOR_KIND.get(ctx.kind)
        if surface is None:
            return
        doc = ctx.doc
        driver = doc.get("driver")
        client_id = ctx.args.get("client_id")
        if not (isinstance(client_id, str) and _CLIENT_ID_RE.match(client_id)):
            client_id = None
        if driver is not None and driver.get("kind") == surface:
            driver["renewed"] = ctx.now
            if client_id is not None:
                driver["client_id"] = client_id
            return
        doc["driver"] = {
            "kind": surface, "client_id": client_id,
            "since": ctx.now, "renewed": ctx.now,
        }

    def advance(self) -> None:
        """Move the cursor on, hiding steps that are not wanted when they come
        up (01 §2: `update` with no internet, no update or no clock)."""
        doc = self.doc
        assert doc is not None
        while True:
            model.advance(doc)
            current = doc["cursor"]
            if current == FINISH:
                return
            hide = self.hide_when_current.get(current)
            if hide is None or not hide(doc):
                return
            doc["steps"][current]["status"] = HIDDEN

    def _hide_update(self, doc: Dict[str, Any]) -> bool:
        network = doc["steps"]["network"]
        update = doc["steps"]["update"]
        return not (
            network.get("internet") is True
            and bool(update.get("available"))
            and self._live["clock"].get("synced") is True
        )

    # ------------------------------------------------------------------
    # Operations (01 §3 `op`)
    # ------------------------------------------------------------------

    def start_op(self, kind: str, runner: OpRunner, **fields: Any) -> str:
        """Start a long-running operation from inside a write handler.

        The state shows `op` in the same change as the write, so the HTTP
        answer comes back at once with the operation visible; the runner
        starts once that change is saved. Everything it reports goes through
        its OpHandle.
        """
        doc = self.doc
        assert doc is not None
        # Random, not counted: a counter restarts at every boot and after a
        # reset, and an old OpHandle must never match a new operation.
        op_id = f"op_{secrets.token_hex(4)}"
        doc["op"] = {
            "kind": kind, "id": op_id, "started": time.time(),
            "phase": fields.pop("phase", None), "progress": None, **fields,
        }
        self._pending_op = (op_id, runner)
        return op_id

    async def _run_op(self, op_id: str, runner: OpRunner) -> None:
        handle = OpHandle(self, op_id)
        try:
            await runner(handle)
        except asyncio.CancelledError:
            pass
        except Exception:
            logging.exception("muon_setup: operation %s failed", op_id)
        finally:
            # Whatever the runner did or did not do, an operation that has
            # stopped must not leave the state `busy` -- unless Moonraker is
            # shutting down. Then the operation stays stored: the next boot
            # marks it `interrupted` (01 §3), or, for an update, judges the
            # reboot it was waiting for (02 §5.8).
            async with self._lock:
                if handle.current() and not self._closed:
                    assert self.doc is not None
                    self.doc["op"] = None
                    try:
                        await self._commit()
                    except Exception:
                        logging.exception("muon_setup: could not save the state")

    async def cancel_op(self, kinds: Tuple[str, ...]) -> bool:
        """Stop the running operation if it is one of `kinds`."""
        doc = self.doc
        if doc is None or doc["op"] is None or doc["op"].get("kind") not in kinds:
            return False
        task = self._op_task
        if task is not None and not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(task), 15.)
            except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
                pass
        async with self._lock:
            if self.doc is not None and self.doc["op"] is not None and (
                self.doc["op"].get("kind") in kinds
            ):
                self.doc["op"] = None
                await self._commit()
        return True

    # ------------------------------------------------------------------
    # Endpoints
    # ------------------------------------------------------------------

    async def _handle_get(self, webreq: WebRequest) -> Dict[str, Any]:
        caller.require(caller.caller_kind(webreq), caller.READ_STATE)
        await self.wait_resolved(STARTUP_WAIT)
        return self.public_state()

    async def _handle_options(self, webreq: WebRequest) -> Dict[str, Any]:
        caller.require(caller.caller_kind(webreq), caller.READ)
        options: Dict[str, Any] = {
            "languages": [
                {"code": code, "endonym": ENDONYMS.get(code, code)}
                for code in self.languages
            ],
            # Aux GET /region/options, verbatim (02 §5.2).
            "region": await self._options_region(),
            "ready_manifest": copy.deepcopy(self.manifest),
        }
        country = webreq.get_args().get("country")
        if isinstance(country, str) and country:
            options["timezones"] = clock.zones_for_country(country)
        return options

    async def _options_region(self) -> Optional[Dict[str, Any]]:
        try:
            options = await self.aux("GET", "/region/options")
        except (AuxUnavailable, AuxMissing, AuxRefused) as exc:
            logging.debug("muon_setup: no region data: %s", exc)
            return None
        if not isinstance(options, dict):
            return None
        return copy.deepcopy(options)

    async def _handle_driver(self, webreq: WebRequest) -> Dict[str, Any]:
        """Claim or renew the driver (02 §5.11). Never changes `rev`, and is
        not refused while an operation runs: the phone renews every 10 s,
        including through a 45 s join."""
        kind = self.begin(webreq)
        args = webreq.get_args()
        surface = args.get("kind")
        client_id = args.get("client_id")
        if surface not in DRIVER_KINDS:
            raise ServerError("muon_setup: 'kind' must be panel, phone or web", 400)
        if (surface == "panel") != (kind in caller.PANEL_ONLY):
            raise ServerError(
                f"muon_setup: a {kind} caller cannot drive as {surface}", 403)
        if not (isinstance(client_id, str) and _CLIENT_ID_RE.match(client_id)):
            raise ServerError("muon_setup: 'client_id' is not a valid id", 400)
        if self.read_only_version is not None or not await self.wait_resolved(
            STARTUP_WAIT
        ) or self.doc is None:
            return self.envelope(model.error(
                "aux_unavailable", "setup state is not ready yet"))
        async with self._lock:
            doc = self.doc
            now = time.time()
            driver = doc.get("driver")
            if (
                driver is not None and driver.get("kind") == surface
                and driver.get("client_id") == client_id
            ):
                was_lapsed = model.driver_public(driver, self.driver_lease, now)
                driver["renewed"] = now
                if was_lapsed and was_lapsed["lapsed"]:
                    self._notify()
            else:
                doc["driver"] = {
                    "kind": surface, "client_id": client_id,
                    "since": now, "renewed": now,
                }
                await self._persist()
                self._notify()
            self._arm_lapse_timer()
        return self.envelope()

    def _arm_lapse_timer(self) -> None:
        # Tell the panel when a phone's claim lapses, since renewals are not
        # announced. One timer, re-armed on every renewal.
        if self._lapse_timer is not None:
            self._lapse_timer.cancel()
        loop = asyncio.get_event_loop()
        self._lapse_timer = loop.call_later(
            self.driver_lease + 0.5, self._on_lapse)

    def _on_lapse(self) -> None:
        self._lapse_timer = None
        if self.doc is None or self.doc.get("driver") is None:
            return
        public = model.driver_public(self.doc["driver"], self.driver_lease)
        if public and public["lapsed"]:
            self._notify()

    async def _handle_goto(self, webreq: WebRequest) -> Dict[str, Any]:
        async def handler(ctx: WriteContext) -> Optional[Dict[str, Any]]:
            step = ctx.args.get("step")
            doc = ctx.doc
            if step == FINISH:
                if model.first_pending(doc) is not None:
                    return model.error("invalid_step", "steps are still pending")
                doc["cursor"] = FINISH
                return None
            if step not in model.STEP_ORDER or not model.reachable(doc, step):
                return model.error(
                    "invalid_step", f"cannot go to {step!r} from here", step=step)
            doc["cursor"] = step
            return None
        return await self.write(webreq, handler)

    async def _handle_skip(self, webreq: WebRequest) -> Dict[str, Any]:
        async def handler(ctx: WriteContext) -> Optional[Dict[str, Any]]:
            step = ctx.args.get("step")
            doc = ctx.doc
            complete = doc["state"] == "complete"
            if step in ("language", "name"):
                return model.error(
                    "not_skippable", f"{step} cannot be skipped", step=step)
            if step not in model.SKIPPABLE:
                return model.error("invalid_step", f"unknown step {step!r}")
            if complete:
                # 02 §5: after `complete` the only skip is `ready`'s, from
                # the "Finish setup" card, and it never undoes a done step.
                # Anything else would put a finished step back on the card.
                if step != "ready" or doc["steps"][step]["status"] == DONE:
                    return model.error(
                        "invalid_step", f"{step} cannot be skipped now")
            elif not model.reachable(doc, step):
                return model.error(
                    "invalid_step", f"cannot skip {step!r} from here", step=step)
            doc["steps"][step]["status"] = SKIPPED
            # 01 §6: a new skip brings a dismissed card back.
            doc["card_dismissed"] = False
            if not complete:
                self.advance()
            return None
        return await self.write(webreq, handler, after_complete=True)

    def effective_name(self) -> Optional[str]:
        """The name "Keep" keeps: the identity's current name (the owner's
        rename if there is one), else the derived name, else the last one
        stored. Never None while any of them is known."""
        printer = self._live.get("printer") or {}
        if printer.get("name"):
            return printer["name"]
        if self._live.get("derived_name"):
            return str(self._live["derived_name"]).title()
        stored = (self.doc or {}).get("printer") or {}
        return stored.get("name")

    async def _handle_finish(self, webreq: WebRequest) -> Dict[str, Any]:
        async def handler(ctx: WriteContext) -> Optional[Dict[str, Any]]:
            doc = ctx.doc
            if doc["state"] == "complete":
                return None
            steps = doc["steps"]
            if steps["language"]["status"] != DONE:
                return model.error(
                    "required_steps_pending", "language is not done",
                    steps=["language"])
            for step_id in model.STEP_ORDER:
                step = steps[step_id]
                if step["status"] != PENDING:
                    continue
                # "Keep" is the name step's default answer; it cannot end
                # up skipped (01 §2), and it keeps a real name, not null.
                if step_id == "name":
                    step["status"] = DONE
                    step["value"] = step.get("value") or self.effective_name()
                else:
                    step["status"] = SKIPPED
            doc["state"] = "complete"
            doc["cursor"] = FINISH
            self._spawn(self._on_complete())
            return None
        return await self.write(webreq, handler, after_complete=True)

    async def _on_complete(self) -> None:
        """02 §5.11: the marker, then `muon_setup:complete`, then the hotspot
        auto-off, in that order. Runs once the change is saved and announced:
        write() holds the lock until it has committed."""
        async with self._lock:
            pass
        if self.doc is None or self.doc["state"] != "complete":
            return
        self._internal["marker_by"] = "muon_setup"
        if await self._marker_once() == "retry":
            self._start_marker_sync()
        if self.doc is None or self.doc["state"] != "complete":
            return
        self.server.send_event("muon_setup:complete", self.public_state())
        await self.schedule_hotspot_off()

    # --------------------------------------------------------------
    # The completion marker follows `state` (02 §4, 03 §7)
    # --------------------------------------------------------------

    def _start_marker_sync(self) -> None:
        """(Re)start the task that makes Aux's marker match `state`."""
        if self._marker_task is not None and not self._marker_task.done():
            self._marker_task.cancel()
        self._marker_task = self._spawn(self._marker_sync())

    async def _marker_sync(self) -> None:
        while not self._closed:
            outcome = await self._marker_once()
            if outcome != "retry":
                return
            await asyncio.sleep(MARKER_RETRY)

    async def _marker_once(self) -> str:
        """One attempt to make the marker match `state`, re-read every time,
        so a retry that outlives a `reset` never writes the marker back.
        Returns "done", "retry" (Aux down) or "stop" (nothing to do, or it
        cannot be done on this image)."""
        doc = self.doc
        if doc is None or self.read_only_version is not None:
            return "stop"
        if doc["state"] == "complete":
            if self._internal.get("marker_written"):
                return "stop"
            method, body = "POST", {
                "by": self._internal.get("marker_by") or "muon_setup"}
        elif self._internal.get("marker_clear_pending"):
            method, body = "DELETE", None
        else:
            return "stop"
        try:
            await self.aux(method, MARKER_PATH, body)
        except AuxMissing:
            logging.warning(
                "muon_setup: this image has no Aux %s %s (OS-7); the setup "
                "marker was not changed", method, MARKER_PATH)
            return "stop"
        except AuxRefused as exc:
            logging.error("muon_setup: Aux refused the setup marker: %s", exc)
            return "stop"
        except AuxUnavailable as exc:
            logging.info(
                "muon_setup: setup marker not changed yet (%s); retrying", exc)
            return "retry"
        # The state may have moved on while Aux answered: record only what
        # still holds, and let the next attempt put the marker right.
        if self.doc is not None and self.doc["state"] == "complete":
            if method == "DELETE":
                return "retry"
            self._internal["marker_written"] = True
        else:
            if method == "POST":
                self._internal["marker_clear_pending"] = True
                return "retry"
            self._internal["marker_clear_pending"] = False
        await self._persist_internal()
        return "done"

    async def schedule_hotspot_off(self) -> None:
        """01 §6 / 03 §1 H3: the hotspot goes off `hotspot_off_delay` after
        finish, or after a join once setup is complete (E5), but only if an
        uplink has an address to fall back on. The deadline is the OS's; it
        comes back through GET /wifi/ap/stations, never stored here."""
        assert self.doc is not None
        network = self.doc["steps"]["network"]
        if network.get("status") != DONE or not network.get("addresses"):
            return
        try:
            answer = await self.aux(
                "POST", "/wifi/ap/auto_off", {"after_s": self.hotspot_off_delay})
        except AuxMissing:
            logging.warning(
                "muon_setup: this image has no Aux POST /wifi/ap/auto_off "
                "(OS-5); the hotspot stays up")
            return
        except (AuxUnavailable, AuxRefused) as exc:
            logging.warning("muon_setup: hotspot auto-off not scheduled: %s", exc)
            return
        if isinstance(answer, dict) and "auto_off_at" in answer:
            self._live["hotspot"]["auto_off_at"] = answer["auto_off_at"]
        await self._refresh_hotspot(check_up=True)
        self._notify()

    async def _handle_card_dismiss(self, webreq: WebRequest) -> Dict[str, Any]:
        async def handler(ctx: WriteContext) -> Optional[Dict[str, Any]]:
            ctx.doc["card_dismissed"] = True
            return None
        return await self.write(webreq, handler, after_complete=True)

    async def _handle_network_cancel(
        self, webreq: WebRequest
    ) -> Dict[str, Any]:
        self.begin(webreq)
        if not await self.wait_resolved(STARTUP_WAIT) or self.doc is None:
            return self.envelope(model.error(
                "aux_unavailable", "setup state is not ready yet"))
        await self.cancel_op(("region_apply", "join"))
        return self.envelope()

    async def _handle_reset(self, webreq: WebRequest) -> Dict[str, Any]:
        """Development and support only (02 §5.11, 07 S11). Floored, and
        panel-only here as well -- not even another component may call it.
        Resets setup state; it is not a factory reset and touches nothing
        else. `rev` keeps increasing, so screens holding the old state take
        the new one."""
        self.begin(webreq, caller.RESET)
        await self.wait_resolved(STARTUP_WAIT)
        if self._marker_task is not None and not self._marker_task.done():
            self._marker_task.cancel()
        if self._op_task is not None and not self._op_task.done():
            self._op_task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(self._op_task), 15.)
            except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
                pass
        async with self._lock:
            old_rev = self.doc["rev"] if self.doc is not None else 0
            if self.read_only_version is not None:
                stored = await self.database.get_item(NAMESPACE, STATE_KEY, None)
                if isinstance(stored, dict) and isinstance(stored.get("rev"), int):
                    old_rev = max(old_rev, stored["rev"])
            for key in (STATE_KEY, INTERNAL_KEY):
                try:
                    await self.database.delete_item(NAMESPACE, key)
                except Exception:
                    pass
            self.read_only_version = None
            self._internal = {
                "marker_written": False, "tz_source": None,
                "marker_clear_pending": True,
            }
            doc = model.new_document(manifest.item_ids(self.manifest))
            doc["rev"] = old_rev + 1
            self.doc = doc
            await self._persist()
            await self._persist_internal()
            self._resolved.set()
            self._notify()
        # OS-7's DELETE /setup/complete, so the hotspot's H1 rule sees a new
        # printer again. Retried every 30 s while Aux is down, for as long as
        # the state stays short of `complete`.
        if await self._marker_once() == "retry":
            self._start_marker_sync()
        logging.info("muon_setup: setup state reset by the panel")
        return self.envelope()

    # ------------------------------------------------------------------
    # Live fields: the printer, the hotspot, the region, capabilities
    # ------------------------------------------------------------------

    async def _poll(self) -> None:
        tick = 0
        while not self._closed:
            try:
                changed = await self.refresh_live(full=tick % 15 == 0)
            except asyncio.CancelledError:
                raise
            except Exception:
                logging.exception("muon_setup: live refresh failed")
                changed = False
            if changed and self.doc is not None:
                self._notify()
            tick += 1
            active = self.doc is not None and self.doc["state"] != "complete"
            await asyncio.sleep(POLL_ACTIVE if active else POLL_IDLE)

    async def refresh_live(self, full: bool = True) -> bool:
        """Refresh the computed fields. Returns True if any changed."""
        before = copy.deepcopy(self._live)
        await self._refresh_hotspot(check_up=full or not self._live["hotspot"]["up"])
        if full:
            await self._refresh_printer()
            await self._refresh_region()
            await clock.refresh(self)
            self._refresh_capabilities()
        return self._live != before

    async def _refresh_hotspot(self, check_up: bool) -> None:
        """02 §6: `hotspot` is OS-5's GET /wifi/ap/stations
        {up, count, auto_off_at}. Only the OS knows the auto-off deadline
        after a reboot or an owner's "off", so it is never stored here.
        Images without OS-5 fall back to the device state and the bare
        POST /wifi/ap/count, with no deadline."""
        hotspot = self._live["hotspot"]
        if self._stations_route:
            try:
                stations = await self.aux("GET", "/wifi/ap/stations")
            except AuxMissing:
                self._stations_route = False
            except (AuxUnavailable, AuxRefused):
                return
            else:
                if isinstance(stations, dict):
                    hotspot["up"] = stations.get("up") is True
                    count = stations.get("count")
                    hotspot["clients"] = (
                        count if isinstance(count, int)
                        and not isinstance(count, bool) else 0)
                    deadline = stations.get("auto_off_at")
                    hotspot["auto_off_at"] = (
                        deadline if isinstance(deadline, (int, float))
                        and not isinstance(deadline, bool) else None)
                return
        hotspot["auto_off_at"] = None
        if check_up:
            try:
                status = await self.aux("GET", "/wifi/ap/device/status")
            except AuxMissing:
                hotspot["up"] = False
            except (AuxUnavailable, AuxRefused):
                pass
            else:
                state = str(status.get("state", "")) if isinstance(status, dict) else ""
                hotspot["up"] = state.startswith("connected")
        if not hotspot["up"]:
            hotspot["clients"] = 0
            return
        try:
            count = await self.aux("POST", "/wifi/ap/count")
        except (AuxUnavailable, AuxRefused, AuxMissing):
            return
        if isinstance(count, int) and not isinstance(count, bool):
            hotspot["clients"] = count

    async def _refresh_printer(self) -> None:
        """The name and fingerprint, from aux_api_proxy.get_identity(), so
        there is one definition of the name (the owner's rename over the
        derived one)."""
        proxy = self.server.lookup_component("aux_api_proxy", None)
        identity: Any = None
        if proxy is not None and hasattr(proxy, "get_identity"):
            try:
                identity = await proxy.get_identity()
            except Exception as exc:
                logging.debug("muon_setup: identity unavailable: %s", exc)
        hostname = socket.gethostname()
        if not isinstance(identity, dict):
            if self._live["printer"] is None and self.doc is not None:
                stored = self.doc.get("printer") or {}
                if stored.get("name"):
                    self._live["printer"] = dict(stored, hostname=hostname)
            return
        derived = identity.get("derived_name")
        name = identity.get("name") or derived
        if isinstance(name, str) and identity.get("source") != "owner":
            name = name.title()
        self._live["printer"] = {
            "name": name,
            "display": identity.get("display"),
            "hostname": hostname,
            "fingerprint": identity.get("fingerprint"),
        }
        self._live["derived_name"] = derived
        self._live["hotspot"]["ssid"] = identity.get("ssid")

    async def _refresh_region(self) -> None:
        try:
            state = await self.aux("GET", "/region")
            options = await self.aux("GET", "/region/options")
        except AuxMissing:
            self._live["region"] = None
            return
        except (AuxUnavailable, AuxRefused):
            return
        if isinstance(state, dict) and isinstance(options, dict):
            # Aux GET /region verbatim, plus the derived market (02 §6).
            self._live["region"] = region.state_region(state, options)

    def _refresh_capabilities(self) -> None:
        caps = self._live["capabilities"]
        caps["ethernet"] = os.path.exists("/sys/class/net/eth0")
        caps["cloud_link"] = self.server.lookup_component("muon_link", None) is not None


def load_component(config: ConfigHelper) -> MuonSetup:
    return MuonSetup(config)
