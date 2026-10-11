# Moonraker component -- muon_toolpath.py
#
# B9-MR-1 (muon3d-app docs/plans/live-printer-viewer.md, section 2, step 2).
#
#   GET /server/muon/toolpath?filename=<path in gcodes>
#
# answers the file's toolpath as `application/octet-stream`, in the MUTP format
# that moonraker/muon_toolpath_format.py documents and makes. The app and
# Fluidd draw the part from it instead of downloading the whole G-code file.
#
# Enable it in moonraker.conf:
#     [muon_toolpath]
#
# WHEN A TOOLPATH IS MADE
#
#   - At upload, by gcode_preprocessor, straight after the excluded-zone pass
#     and its marker: the bytes the printer will run are final then, so the
#     offsets in the toolpath are the offsets Klipper will report.
#   - On the first request for a file that has none: files uploaded before this
#     component, or rewritten since (Moonraker's object processing rewrites a
#     file after upload when the slicer did not label its objects, and the
#     print-time safety pass re-stamps a file it has to re-process).
#
# Either way the G-code is read by a separate, niced Python process, one file
# at a time, so a 40 MB file costs the Pi some seconds of a low-priority core
# and never stalls Moonraker's event loop.
#
# THE CACHE
#
# Toolpaths live under `<data_path>/muon_toolpath/`, named by the G-code file's
# size and modification time (`<size>-<mtime_ns>.mutp`) and nothing else. Not
# the path, because the upload-time build reads the staged file before
# file_manager moves it into place, and a move keeps size and mtime but not
# the name; a renamed or moved file keeps its toolpath for the same reason. A
# changed file gets a new key and a new toolpath. The oldest toolpaths are
# deleted once the directory passes `cache_size` MB.
#
# ANSWERS
#
#   200  the toolpath
#   400  no filename, a path outside the gcodes root, or not a G-code file
#   404  no such file
#   409  the toolpath is being made; ask again in a few seconds
#   500  reading the file failed (the log says why); not retried for that
#        size and mtime until Moonraker restarts
#
# A request waits up to `request_wait` seconds for a build before answering
# 409, so a small file is usually answered on the first request.
#
# WHO MAY CALL IT
#
# It is a read of a file every client that may list the gcodes root may
# already download whole, so it is not on any floor list. muon-link gives it
# to Viewer and above (B9-LINK-2).

from __future__ import annotations

import asyncio
import collections
import contextlib
import logging
import os
import sys
import time
from typing import TYPE_CHECKING, BinaryIO, Deque, Dict, List, Optional, Tuple

from .. import muon_toolpath_format
from ..common import RequestType, TransportType
from ..utils.exceptions import ServerError

if TYPE_CHECKING:
    from ..common import WebRequest
    from ..confighelper import ConfigHelper

LOG = logging.getLogger(__name__)

ENDPOINT = "/server/muon/toolpath"
CACHE_DIR = "muon_toolpath"
SUFFIX = ".mutp"
GCODE_EXTS = (".gcode", ".g", ".gco")
FORMAT_SCRIPT = os.path.abspath(muon_toolpath_format.__file__)
#: Builds that failed, remembered so a client polling a bad file does not start
#: a process on every request. Bounded; the oldest is forgotten first.
FAILED_LIMIT = 64


def cache_key(st: os.stat_result) -> str:
    return f"{st.st_size}-{st.st_mtime_ns}{SUFFIX}"


class MuonToolpath:
    def __init__(self, config: ConfigHelper) -> None:
        self.server = config.get_server()
        data_path = self.server.get_app_args().get("data_path", ".")
        self.cache_dir: str = config.get(
            "cache_path", os.path.join(data_path, CACHE_DIR)
        )
        self.cache_bytes = int(config.getfloat("cache_size", 256.0) * 1024 * 1024)
        self.request_wait = config.getfloat("request_wait", 3.0)
        self.build_timeout = config.getfloat("build_timeout", 600.0)
        self._builds: Dict[str, asyncio.Task] = {}
        self._failed: Dict[str, str] = {}
        self._failed_order: Deque[str] = collections.deque()
        self._lock = asyncio.Lock()
        self.server.register_endpoint(
            ENDPOINT,
            RequestType.GET,
            self._handle_toolpath,
            transports=TransportType.HTTP,
            wrap_result=False,
            content_type="application/octet-stream",
        )

    # -- the route ----------------------------------------------------------

    async def _handle_toolpath(self, web_request: WebRequest) -> bytes:
        filename = web_request.get_str("filename")
        path = self._resolve(filename)
        try:
            key = cache_key(os.stat(path))
        except FileNotFoundError:
            raise ServerError(f"No G-code file '{filename}'", 404)
        data = await self._read_cached(key)
        if data is not None:
            return data
        if key in self._failed:
            raise ServerError(
                f"Could not read the toolpath of '{filename}': {self._failed[key]}",
                500,
            )
        task = self._builds.get(key)
        if task is None:
            try:
                key, task = self._start(path)
            except FileNotFoundError:
                raise ServerError(f"No G-code file '{filename}'", 404)
        try:
            await asyncio.wait_for(asyncio.shield(task), self.request_wait)
        except asyncio.TimeoutError:
            raise ServerError(
                f"The toolpath of '{filename}' is being made; try again shortly",
                409,
            )
        data = await self._read_cached(key)
        if data is None:
            reason = self._failed.get(key, "the toolpath was not written")
            raise ServerError(
                f"Could not read the toolpath of '{filename}': {reason}", 500
            )
        return data

    def _resolve(self, filename: str) -> str:
        fm = self.server.lookup_component("file_manager")
        root = fm.get_directory("gcodes")
        if not root:
            raise ServerError("The gcodes root is not available", 404)
        rel = filename.strip().lstrip("/")
        if rel.startswith("gcodes/"):
            rel = rel[len("gcodes/"):]
        full = os.path.normpath(os.path.join(root, rel))
        if not full.startswith(os.path.join(os.path.normpath(root), "")):
            raise ServerError(f"'{filename}' is outside the gcodes root", 400)
        if os.path.splitext(full)[1].lower() not in GCODE_EXTS:
            raise ServerError(f"'{filename}' is not a G-code file", 400)
        return full

    async def _read_cached(self, key: str) -> Optional[bytes]:
        eventloop = self.server.get_event_loop()
        return await eventloop.run_in_thread(
            self._read_and_touch, os.path.join(self.cache_dir, key)
        )

    @staticmethod
    def _read_and_touch(path: str) -> Optional[bytes]:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return None
        # The modification time is the cache's last-used time: pruning deletes
        # the least recently served toolpaths first.
        with contextlib.suppress(OSError):
            os.utime(path)
        return data

    # -- building -------------------------------------------------------------

    def build_soon(self, path: str) -> None:
        """Make the toolpath of the G-code at `path`, in the background.

        For gcode_preprocessor, which calls it on the staged file just before
        file_manager moves that file into the gcodes root. The file is opened
        here, before returning, so the build reads these bytes even after the
        move; on Linux an open file outlives a rename or an unlink. Never
        raises: a toolpath is a convenience, and must not fail an upload.
        """
        try:
            self._start(path)
        except Exception:
            LOG.exception("[muon_toolpath] cannot start a toolpath for '%s'", path)

    def _start(self, path: str) -> Tuple[str, asyncio.Task]:
        source = open(path, "rb")
        try:
            key = cache_key(os.fstat(source.fileno()))
        except BaseException:
            source.close()
            raise
        task = self._builds.get(key)
        if task is not None:
            source.close()
            return key, task
        task = asyncio.ensure_future(self._build(key, source, path))
        self._builds[key] = task
        task.add_done_callback(lambda _t: self._builds.pop(key, None))
        return key, task

    async def _build(self, key: str, source: BinaryIO, path: str) -> None:
        try:
            async with self._lock:
                if await self._read_cached(key) is not None:
                    return
                error = await self._run(key, source)
        except Exception as e:
            LOG.exception("[muon_toolpath] toolpath of '%s' failed", path)
            error = str(e) or type(e).__name__
        finally:
            source.close()
        if error is None:
            LOG.info("[muon_toolpath] toolpath made for '%s' (%s)", path, key)
            eventloop = self.server.get_event_loop()
            await eventloop.run_in_thread(self._prune, key)
            return
        LOG.error("[muon_toolpath] toolpath of '%s' failed: %s", path, error)
        self._failed[key] = error
        self._failed_order.append(key)
        while len(self._failed_order) > FAILED_LIMIT:
            self._failed.pop(self._failed_order.popleft(), None)

    async def _run(self, key: str, source: BinaryIO) -> Optional[str]:
        """Run the reader on `source`. Returns None, or why it failed."""
        os.makedirs(self.cache_dir, exist_ok=True)
        out = os.path.join(self.cache_dir, key)
        # -I: the script's own directory (moonraker/) must not shadow the
        # standard library, and the user's site-packages are not wanted.
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-I", FORMAT_SCRIPT, out,
            stdin=source,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.build_timeout
            )
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(Exception):
                await proc.wait()
            return f"timed out after {self.build_timeout:.0f}s"
        if proc.returncode != 0:
            tail = stderr.decode(errors="replace").strip().splitlines()[-1:]
            return f"exit {proc.returncode}" + (f": {tail[0]}" if tail else "")
        if not os.path.isfile(out):
            return "the toolpath was not written"
        return None

    def _prune(self, keep: str) -> None:
        """Delete the least recently used toolpaths beyond `cache_bytes`, never
        `keep` (the one just made), and any half-written file a crashed build
        left behind."""
        try:
            names = os.listdir(self.cache_dir)
        except OSError:
            return
        entries: List[Tuple[float, int, str]] = []
        for name in names:
            path = os.path.join(self.cache_dir, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            if name.endswith(SUFFIX):
                entries.append((st.st_mtime, st.st_size, path))
            elif SUFFIX + ".part-" in name and self._is_stale(st):
                with contextlib.suppress(OSError):
                    os.remove(path)
        entries.sort()
        total = sum(size for _, size, _ in entries)
        for _, size, path in entries:
            if total <= self.cache_bytes:
                break
            if os.path.basename(path) == keep:
                continue
            with contextlib.suppress(OSError):
                os.remove(path)
                total -= size

    def _is_stale(self, st: os.stat_result) -> bool:
        return time.time() - st.st_mtime > self.build_timeout * 2

    async def close(self) -> None:
        for task in list(self._builds.values()):
            task.cancel()


def load_component(config: ConfigHelper) -> MuonToolpath:
    return MuonToolpath(config)
