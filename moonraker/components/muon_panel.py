# MUON: serves the printer's touch-panel page for Control over Bluetooth or the
# relay, where the gateway reaches Moonraker (127.0.0.1:7125) and not nginx.
from __future__ import annotations

import asyncio
import dataclasses
import gzip
import hashlib
import json
import os
import stat
from typing import TYPE_CHECKING, Any, Optional, Tuple

import tornado.web

from ..common import RequestType
from .application import AuthorizedRequestHandler, _check_file_access
from .muon_panel_nav import PanelNav

if TYPE_CHECKING:
    from ..confighelper import ConfigHelper
    from ..server import Server

ENDPOINT = "/server/muon/panel/index.html"
DEFAULT_PATH = "/usr/share/muon-panel/index.html"
MAX_BYTES = 8 * 1024 * 1024


class PanelError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclasses.dataclass(frozen=True)
class Page:
    key: Tuple[int, int]
    etag: str
    version: str
    raw: bytes
    gz: bytes


def load_page(path: str, cached: Optional[Page]) -> Page:
    """Blocking: runs in an executor. Re-reads only when mtime or size moved."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise PanelError(404, "The panel page is not installed.") from None
    except OSError:
        raise PanelError(500, "The panel page cannot be read.") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise PanelError(500, "The panel page is not a regular file.")
    if st.st_size > MAX_BYTES:
        raise PanelError(500, "The panel page is too large.")
    key = (st.st_mtime_ns, st.st_size)
    if cached is not None and cached.key == key:
        return cached
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise PanelError(500, "The panel page is not a regular file.")
            raw = handle.read(MAX_BYTES + 1)
    except OSError:
        raise PanelError(500, "The panel page cannot be read.") from None
    if len(raw) > MAX_BYTES:
        raise PanelError(500, "The panel page is too large.")
    digest = hashlib.sha256(raw).hexdigest()
    return Page(key, digest[:32], digest[:12], raw,
                gzip.compress(raw, 9, mtime=0))


def accepts_gzip(header: str) -> bool:
    for part in header.split(","):
        coding, _, params = part.partition(";")
        if coding.strip().lower() not in ("gzip", "x-gzip"):
            continue
        params = params.replace(" ", "").lower()
        return not (params.startswith("q=") and _q_is_zero(params[2:]))
    return False


def _q_is_zero(value: str) -> bool:
    try:
        return float(value) == 0.0
    except ValueError:
        return False


def etag_matches(header: str, etag: str) -> bool:
    for part in header.split(","):
        part = part.strip()
        if part == "*":
            return True
        if part.startswith("W/"):
            part = part[2:]
        if part == f'"{etag}"':
            return True
    return False


class MuonPanel:
    def __init__(self, config: ConfigHelper) -> None:
        self.server: Server = config.get_server()
        self.path = config.get("path", DEFAULT_PATH)
        self._page: Optional[Page] = None
        self._lock = asyncio.Lock()
        app: Any = self.server.lookup_component("application")
        app.register_handler(
            ENDPOINT.replace(".", r"\."), PanelHandler, {"panel": self})
        # KAN-4812: the live state, and navigating the panel
        self.nav = PanelNav(self.server)

    async def get_page(self) -> Page:
        async with self._lock:
            loop = self.server.get_event_loop()
            self._page = await loop.run_in_thread(
                load_page, self.path, self._page)
            return self._page


class PanelHandler(AuthorizedRequestHandler):
    def initialize(self, panel: Optional[MuonPanel] = None) -> None:  # type: ignore
        super().initialize()
        assert panel is not None
        self.panel = panel

    def write_error(self, status_code: int, **kwargs: Any) -> None:
        # A short JSON error: never the traceback the shared writer adds
        exc = kwargs.get("exc_info", (None, None))[1]
        message = getattr(exc, "reason", None) or self._reason
        self.set_header("Content-Type", "application/json; charset=UTF-8")
        self.finish(json.dumps(
            {"error": {"code": status_code, "message": message}}))

    def compute_etag(self) -> Optional[str]:
        return None

    async def get(self) -> None:
        # The same classification as any GET under /server: a read
        _check_file_access(
            self.request, self.current_user, ENDPOINT, RequestType.GET, {})
        try:
            page = await self.panel.get_page()
        except PanelError as err:
            raise tornado.web.HTTPError(err.status, reason=err.message)
        self.set_header("ETag", f'"{page.etag}"')
        self.set_header("X-Muon-Panel-Version", page.version)
        self.set_header("Cache-Control", "no-cache")
        self.set_header("X-Content-Type-Options", "nosniff")
        self.set_header("Vary", "Accept-Encoding")
        if etag_matches(self.request.headers.get("If-None-Match", ""),
                        page.etag):
            self.set_status(304)
            self.finish()
            return
        body = page.raw
        if accepts_gzip(self.request.headers.get("Accept-Encoding", "")):
            self.set_header("Content-Encoding", "gzip")
            body = page.gz
        self.set_header("Content-Type", "text/html; charset=utf-8")
        self.set_header("Content-Length", str(len(body)))
        if self.request.method == "HEAD":
            self.finish()
        else:
            self.finish(body)

    async def head(self) -> None:
        await self.get()


def load_component(config: ConfigHelper) -> MuonPanel:
    return MuonPanel(config)
