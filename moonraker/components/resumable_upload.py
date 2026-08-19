# moonraker/components/resumable_upload.py
#
# Resumable, integrity-checked print-file upload (KAN-193).
#
# WHY THIS EXISTS
# ---------------
# Print files are tens to hundreds of MB and arrive over printer Wi-Fi that is
# frequently poor.  Moonraker's shipped ingest is a single multipart POST into
# one temp file, all-or-nothing (`application.py:931` FileUploadHandler): a drop
# at 60% throws away 60% of a 200 MB transfer and the client starts again.
#
# KAN-101 is the same failure already shipped in the OTA path -- `wget -t 0 -O -`
# piped into `rugix-ctrl update install -` cannot rewind on retry, so a drop
# mid-body restarts at byte 0 and appends a fresh copy onto the bytes already
# consumed, and nothing checks the byte count.  This component is deliberately
# built so that the same shape of bug is not possible here:
#
#   * every chunk carries its own SHA-256 and is only committed if it verifies;
#   * the server, not the client, is the authority on how many bytes it holds,
#     and a wrong offset is answered WITH that number so the client resyncs
#     instead of restarting;
#   * the assembled file is re-hashed FROM DISK before it is accepted, so a
#     short or duplicated body is rejected rather than printed.
#
# WHAT THIS DOES NOT DO -- AND MUST NOT
# -------------------------------------
# It does not write into the gcodes root and it does not reimplement any part of
# Moonraker's file handling.  `finalize` builds exactly the `form_args` dict that
# `FileUploadHandler.post()` builds (`application.py:1002-1013`) and calls
# `FileManager.finalize_upload` (`file_manager.py:830`).  That routes the file
# through `_finish_gcode_upload` (`:906`) -> `_process_uploaded_file` (`:975`) ->
# the G-code safety postprocessor (`:990-1006`) -> `shutil.move` (`:1030`).
#
# Landing bytes in the gcodes root by any other route would create a fifth
# bypass of the excluded-zone check (KAN-193 / invariant I5), which is precisely
# how the previous four holes were introduced -- by code that thought it was
# "just" moving a file.  tests/test_resumable_upload.py asserts that a file
# uploaded through this triad carries the postprocessor's marker.
#
# The `_has_valid_data` short-circuit (`file_manager.py:2599-2603`) is worth
# naming explicitly here: a *resumed* transfer is the single most likely way to
# reproduce a known file's exact size and mtime, which is the condition that
# short-circuits `parse_metadata`.  Since KAN-193 the guard is no longer on the
# metadata path, so that short-circuit is a cache decision and not a safety one.
# test_resumable_upload.py pins that with a test.
#
# STAGING AND WHY IT NEEDS A JANITOR
# ----------------------------------
# Partials live under TMPDIR, which `moonraker.service.template:18` sets to
# `/home/printer_admin/.tmp`.  That is on the persisted `/home` volume, which is
# what makes resume-across-reboot work at all -- and is also why an abandoned
# session does NOT disappear on reboot the way a `/tmp` file would.  Without an
# expiry and a total-size cap a buggy or hostile client can fill the volume that
# also holds `/home/printer_data/gcodes`, and a printer that cannot write its
# gcodes root is a printer that cannot print.  Both controls are enforced here:
#
#   * `session_expiry` -- idle sessions are removed by the janitor;
#   * `max_staging_size` -- a *reservation* against declared size, checked at
#     create, so the cap binds before the bytes arrive rather than after;
#   * `max_sessions` -- bounds the number of concurrent reservations.
#
# The cap is deterministic (declared sizes are refused once the sum would exceed
# it) rather than a free-space probe, because a free-space check races with
# every other writer on the volume.  Operators must therefore set
# `max_staging_size` below the free space they are willing to lose.

from __future__ import annotations

import os
import time
import shutil
import hashlib
import logging
import secrets
import tempfile
import contextlib

import tornado.web
from tornado.http1connection import HTTP1Connection

from ..common import RequestType
from ..utils import json_wrapper as jsonw
from .application import AuthorizedRequestHandler

# Annotation imports
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Optional,
    Tuple,
)

if TYPE_CHECKING:
    from ..common import UserInfo, WebRequest
    from ..confighelper import ConfigHelper
    from ..server import Server
    from .application import MoonrakerApp
    from .file_manager.file_manager import FileManager

LOG = logging.getLogger(__name__)

MIB = 1024 * 1024

# The staging layout.  One directory per session so that removing a session is a
# single recursive unlink and cannot leave a half-identified partial behind.
STAGING_DIRNAME = "muon-upload"
PART_NAME = "part.bin"
META_NAME = "meta.json"
META_TMP_NAME = "meta.json.tmp"
META_VERSION = 1

# Hex SHA-256, lowercase.  Fixed length so a malformed value is rejected at the
# door rather than silently never matching.
DIGEST_LEN = 64
_HEX = set("0123456789abcdef")

DEFAULT_CHUNK_SIZE = 4 * MIB
MIN_CHUNK_SIZE = 256 * 1024
DEFAULT_MAX_CHUNK_SIZE = 16 * MIB
DEFAULT_EXPIRY = 24 * 60 * 60.0
DEFAULT_MAX_STAGING = 4096 * MIB
DEFAULT_MAX_SESSIONS = 8
DEFAULT_GC_INTERVAL = 300.0

# Session ids are bearer capabilities: Moonraker authenticates but does not
# authorize (`UserInfo.groups` at common.py:191 defaults to ["admin"] and is
# read nowhere), so an id that could be guessed or enumerated would let one
# authenticated caller write into another's staged file.  16 bytes of urandom.
ID_BYTES = 16


def is_digest(value: str) -> bool:
    return len(value) == DIGEST_LEN and not (set(value) - _HEX)


def rel_is_safe(rel: str) -> bool:
    """Reject traversal before staging rather than after 200 MB have arrived.

    This is a fail-fast convenience, NOT the security boundary:
    `FileManager._parse_upload_args` (file_manager.py:872-877) re-derives the
    destination and refuses anything that does not land under the root, and that
    check still runs at finalize.  Duplicating it loosely here would be worse
    than useless -- so this only rejects the unambiguous cases.
    """
    if "\x00" in rel:
        return False
    parts = rel.replace("\\", "/").split("/")
    return ".." not in parts


def fsync_dir(path: str) -> None:
    """Make a rename in ``path`` durable.

    Renaming meta.json.tmp over meta.json is atomic, but on Linux the directory
    entry itself is not durable until the directory is fsynced.  Since the whole
    point of staging on the persisted volume is surviving a power cut, do it.
    Not available on every platform (Windows cannot open a directory), hence the
    suppression -- the tests run there, the printer does not.
    """
    with contextlib.suppress(OSError):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class UploadSession:
    """One in-flight transfer.  The authority on how many bytes we hold."""

    __slots__ = (
        "upload_id", "root", "path", "filename", "size", "checksum",
        "received", "created", "updated", "user", "directory", "busy"
    )

    def __init__(
        self,
        upload_id: str,
        root: str,
        path: str,
        filename: str,
        size: int,
        checksum: str,
        received: int,
        created: float,
        updated: float,
        user: Optional[str],
        directory: str,
    ) -> None:
        self.upload_id = upload_id
        self.root = root
        self.path = path
        self.filename = filename
        self.size = size
        self.checksum = checksum
        self.received = received
        self.created = created
        self.updated = updated
        self.user = user
        self.directory = directory
        # Guards the part file for the duration of one append request.  A plain
        # flag rather than an asyncio.Lock on purpose: an append holds it across
        # the whole streamed body, so waiting on it would let one stalled client
        # pin a coroutine indefinitely.  A concurrent append gets 409 with the
        # current offset and resyncs, which is the same answer the protocol
        # already gives for any other offset disagreement.
        self.busy = False

    @property
    def part_path(self) -> str:
        return os.path.join(self.directory, PART_NAME)

    @property
    def meta_path(self) -> str:
        return os.path.join(self.directory, META_NAME)

    def expires_at(self, expiry: float) -> float:
        return self.updated + expiry

    def as_meta(self) -> Dict[str, Any]:
        return {
            "version": META_VERSION,
            "upload_id": self.upload_id,
            "root": self.root,
            "path": self.path,
            "filename": self.filename,
            "size": self.size,
            "checksum": self.checksum,
            "received": self.received,
            "created": self.created,
            "updated": self.updated,
            "user": self.user,
        }

    def status(self, expiry: float) -> Dict[str, Any]:
        return {
            "upload_id": self.upload_id,
            "root": self.root,
            "path": self.path,
            "filename": self.filename,
            "size": self.size,
            "checksum": self.checksum,
            "received": self.received,
            "next_offset": self.received,
            "expires_at": self.expires_at(expiry),
        }

    def identity(self) -> Tuple[str, str, str, int, str, Optional[str]]:
        """What makes two create requests the same transfer.

        Used so a client that lost its upload_id -- the interesting case being a
        client that rebooted, since the staging volume is persisted -- gets its
        partial back instead of starting a second one alongside it.
        """
        return (
            self.root, self.path, self.filename,
            self.size, self.checksum, self.user
        )

    def write_meta(self) -> None:
        """Persist metadata atomically.

        Ordering matters and is the same ordering the recovery path assumes:
        the part file is fsynced BEFORE this is called, so meta.json can only
        ever describe a prefix that is already durable.  A crash between the two
        leaves part.bin longer than `received`, which `_load_session` truncates.
        The reverse -- meta ahead of data -- is what would be unrecoverable, and
        this ordering makes it impossible.
        """
        tmp = os.path.join(self.directory, META_TMP_NAME)
        data = jsonw.dumps(self.as_meta())
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.meta_path)
        fsync_dir(self.directory)


class ResumableUpload:
    def __init__(self, config: ConfigHelper) -> None:
        self.server: Server = config.get_server()
        self.event_loop = self.server.get_event_loop()

        app: MoonrakerApp = self.server.lookup_component("application")
        # Reuse the operator's existing per-file ceiling rather than inventing a
        # second one that could disagree with it.  `[server] max_upload_size` is
        # in MiB and already bounds the multipart path (application.py:203-204).
        self.max_file_size: int = app.max_upload_size

        self.chunk_size: int = max(
            MIN_CHUNK_SIZE,
            config.getint("chunk_size", DEFAULT_CHUNK_SIZE // MIB) * MIB
        )
        self.max_chunk_size: int = max(
            self.chunk_size,
            config.getint("max_chunk_size", DEFAULT_MAX_CHUNK_SIZE // MIB) * MIB
        )
        self.expiry: float = config.getfloat("session_expiry", DEFAULT_EXPIRY)
        self.max_staging_size: int = (
            config.getint("max_staging_size", DEFAULT_MAX_STAGING // MIB) * MIB
        )
        self.max_sessions: int = config.getint("max_sessions", DEFAULT_MAX_SESSIONS)
        self.gc_interval: float = config.getfloat("gc_interval", DEFAULT_GC_INTERVAL)

        staging = config.get("staging_path", None)
        if staging is None:
            # tempfile.gettempdir() honours TMPDIR, which the unit pins to
            # /home/printer_admin/.tmp (moonraker.service.template:18).  Sharing
            # the volume with the gcodes root is deliberate: it makes the
            # shutil.move in _process_uploaded_file (file_manager.py:1030) a
            # rename rather than a 200 MB copy.
            staging = os.path.join(tempfile.gettempdir(), STAGING_DIRNAME)
        self.staging_path: str = os.path.abspath(os.path.expanduser(staging))

        self.sessions: Dict[str, UploadSession] = {}

        self.server.register_endpoint(
            "/server/files/upload/session",
            RequestType.POST | RequestType.DELETE,
            self._handle_session_request,
        )
        self.server.register_endpoint(
            "/server/files/upload/status",
            RequestType.GET,
            self._handle_status_request,
        )
        self.server.register_endpoint(
            "/server/files/upload/finalize",
            RequestType.POST,
            self._handle_finalize_request,
        )

        # The chunk endpoint cannot go through register_endpoint: a
        # DynamicRequestHandler buffers the whole body and hands the callback a
        # parsed argument dict (application.py:646-665), which is exactly wrong
        # for a raw 4 MiB body.  It is registered as its own
        # @stream_request_body handler, the same construction FileUploadHandler
        # uses (application.py:930), so authentication runs in prepare() before
        # a single body byte is read.  Registering through the router directly
        # keeps the whole feature in this one file, so the fork's divergence
        # from upstream Moonraker for this work is one added file plus one
        # config section.
        app.mutable_router.add_handler(
            f"{app.route_prefix}/server/files/upload/chunk",
            UploadChunkHandler,
            {"component": self},
        )

    async def component_init(self) -> None:
        # Deferred out of __init__ so that a broken or unreadable staging
        # directory degrades to "resumable uploads unavailable" rather than
        # "Moonraker does not start".
        try:
            os.makedirs(self.staging_path, exist_ok=True)
        except OSError:
            LOG.exception(
                "[resumable_upload] cannot create staging directory '%s'; "
                "resumable uploads will fail", self.staging_path
            )
            return
        await self.event_loop.run_in_thread(self.recover_sessions)
        self._schedule_gc()

    # ------------------------------------------------------------------
    # staging store
    # ------------------------------------------------------------------

    def recover_sessions(self) -> None:
        """Rebuild the session table from disk, then collect the garbage.

        Runs at startup because the staging volume is persisted: everything in
        it predates this process, and some of it belongs to a Moonraker that
        died mid-transfer.
        """
        try:
            entries = sorted(os.listdir(self.staging_path))
        except OSError:
            LOG.exception(
                "[resumable_upload] cannot read staging directory '%s'",
                self.staging_path
            )
            return
        for name in entries:
            directory = os.path.join(self.staging_path, name)
            if not os.path.isdir(directory):
                # Stray file in the staging root -- not ours to interpret, and
                # not something we will start accounting for.  Remove it.
                self._remove_path(directory)
                continue
            session = self._load_session(directory)
            if session is None:
                LOG.warning(
                    "[resumable_upload] discarding unreadable staging dir '%s'",
                    directory
                )
                self._remove_path(directory)
                continue
            self.sessions[session.upload_id] = session
        if self.sessions:
            LOG.info(
                "[resumable_upload] recovered %d staged upload session(s) from %s",
                len(self.sessions), self.staging_path
            )
        self.collect(time.time())

    def _load_session(self, directory: str) -> Optional[UploadSession]:
        meta_path = os.path.join(directory, META_NAME)
        try:
            with open(meta_path, "rb") as f:
                meta = jsonw.loads(f.read())
        except (OSError, ValueError, jsonw.JSONDecodeError):
            # Named explicitly because the wrapper swaps implementations:
            # jsonw.JSONDecodeError is json.JSONDecodeError (a ValueError) on
            # the stdlib path but msgspec.DecodeError when msgspec is importable
            # (utils/json_wrapper.py:20-27), and msgspec is not pinned in
            # scripts/moonraker-requirements.txt so its exception hierarchy is
            # not ours to assume.  A corrupt meta.json must discard one staging
            # directory, never abort startup.
            return None
        if not isinstance(meta, dict) or meta.get("version") != META_VERSION:
            return None
        try:
            upload_id = str(meta["upload_id"])
            size = int(meta["size"])
            received = int(meta["received"])
            checksum = str(meta["checksum"]).lower()
            session = UploadSession(
                upload_id=upload_id,
                root=str(meta["root"]),
                path=str(meta["path"]),
                filename=str(meta["filename"]),
                size=size,
                checksum=checksum,
                received=received,
                created=float(meta["created"]),
                updated=float(meta["updated"]),
                user=meta["user"] if meta["user"] is None else str(meta["user"]),
                directory=directory,
            )
        except (KeyError, TypeError, ValueError):
            return None
        if (
            os.path.basename(directory) != upload_id
            or not is_digest(checksum)
            or size < 0 or received < 0 or received > size
        ):
            return None
        try:
            actual = os.path.getsize(session.part_path)
        except OSError:
            return None
        if actual > received:
            # Crashed mid-append: the tail past `received` was never verified.
            # Truncating is the whole reason meta.json is written after the data
            # is fsynced -- the durable prefix is always at least `received`.
            LOG.info(
                "[resumable_upload] session %s: dropping %d unverified byte(s)",
                upload_id, actual - received
            )
            try:
                os.truncate(session.part_path, received)
            except OSError:
                return None
        elif actual < received:
            # meta.json claims bytes the part file does not have.  Our write
            # ordering makes this impossible, so something outside this
            # component touched the file; trust the smaller number, which is
            # still a verified prefix, and make the client resend the rest.
            LOG.warning(
                "[resumable_upload] session %s: part file is %d bytes but meta "
                "claims %d; clamping", upload_id, actual, received
            )
            session.received = actual
        return session

    def _remove_path(self, path: str) -> None:
        """Remove a staging entry.

        Deliberately not ``ignore_errors=True``.  A removal that fails silently
        is a permanent leak on the persisted volume with nothing in the log to
        find it by -- which is the disk-exhaustion failure this component is
        supposed to prevent, arriving by the janitor's own back door.  The
        behavioural backstop is ``_sweep_orphans``, which retries; the log line
        is what makes a *repeated* failure diagnosable rather than invisible.
        """
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            elif os.path.exists(path):
                os.remove(path)
        except OSError:
            LOG.exception(
                "[resumable_upload] could not remove staging entry '%s'; it will "
                "be retried on the next janitor pass", path
            )

    def drop_session(self, session: UploadSession, reason: str) -> None:
        self.sessions.pop(session.upload_id, None)
        self._remove_path(session.directory)
        LOG.info(
            "[resumable_upload] removed session %s (%s): %s",
            session.upload_id, reason, session.filename
        )

    def reserved_bytes(self) -> int:
        """Declared, not received.

        Reserving against the declared size is what makes the cap bind before
        the disk fills rather than at the moment it is already full.
        """
        return sum(s.size for s in self.sessions.values())

    def collect(self, now: float) -> int:
        """Expire idle sessions, evict while over quota, sweep orphans."""
        removed = 0
        for session in list(self.sessions.values()):
            if now - session.updated > self.expiry:
                self.drop_session(session, "expired")
                removed += 1
        # The create-time reservation keeps us under the cap in steady state, so
        # this only fires for sessions recovered from disk under a cap that has
        # since been lowered.
        if self.reserved_bytes() > self.max_staging_size:
            by_age = sorted(self.sessions.values(), key=lambda s: s.updated)
            for session in by_age:
                if self.reserved_bytes() <= self.max_staging_size:
                    break
                self.drop_session(session, "staging quota exceeded")
                removed += 1
        self._sweep_orphans()
        return removed

    def _sweep_orphans(self) -> None:
        """Remove staging directories no live session accounts for.

        Two things end up here: a removal that failed the first time (a file
        still open, a transient permission error), and anything a crash left
        between dropping a session from the table and unlinking its directory.
        Neither holds quota, so neither would ever be noticed -- but the volume
        is persisted, so neither would ever go away either.

        Safe against a create in progress because a session is entered into
        ``self.sessions`` before its directory exists, never after.
        """
        try:
            entries = os.listdir(self.staging_path)
        except OSError:
            return
        for name in entries:
            if name in self.sessions:
                continue
            LOG.warning(
                "[resumable_upload] sweeping orphaned staging entry '%s'", name
            )
            self._remove_path(os.path.join(self.staging_path, name))

    def _schedule_gc(self) -> None:
        self.event_loop.delay_callback(self.gc_interval, self._run_gc)

    def _run_gc(self) -> None:
        try:
            self.collect(time.time())
        except Exception:
            LOG.exception("[resumable_upload] janitor pass failed")
        finally:
            # Rescheduled unconditionally: a janitor that stops on one bad pass
            # is a janitor that lets the disk fill.
            self._schedule_gc()

    # ------------------------------------------------------------------
    # lookup helpers shared with the chunk handler
    # ------------------------------------------------------------------

    @staticmethod
    def username(user: Optional[UserInfo]) -> Optional[str]:
        return None if user is None else user.username

    def lookup(self, upload_id: str, user: Optional[UserInfo]) -> UploadSession:
        """Resolve a session id, 404 if unknown, 403 if it is not the caller's.

        The owner check is not redundant with authentication.  Moonraker has no
        authorization model at all (PLAN.md conflict 4), so without it any
        authenticated caller could append to any other caller's staged file --
        including one that is about to be printed.
        """
        session = self.sessions.get(upload_id)
        if session is None:
            raise self.server.error(f"Unknown upload session: {upload_id}", 404)
        if time.time() - session.updated > self.expiry:
            self.drop_session(session, "expired")
            raise self.server.error(f"Upload session expired: {upload_id}", 404)
        if session.user != self.username(user):
            raise self.server.error(
                f"Upload session {upload_id} belongs to another user", 403
            )
        return session

    # ------------------------------------------------------------------
    # endpoints
    # ------------------------------------------------------------------

    async def _handle_session_request(self, web_request: WebRequest) -> Dict[str, Any]:
        if web_request.get_request_type() == RequestType.DELETE:
            return await self._delete_session(web_request)
        return await self._create_session(web_request)

    async def _create_session(self, web_request: WebRequest) -> Dict[str, Any]:
        fm: FileManager = self.server.lookup_component("file_manager")
        fm.check_write_enabled()

        root: str = web_request.get_str("root", "gcodes").lower()
        rel_path: str = web_request.get_str("path", "").strip().lstrip("/")
        filename: str = web_request.get_str("filename").strip().lstrip("/")
        size: int = web_request.get_int("size")
        checksum: str = web_request.get_str("checksum").strip().lower()

        if root not in fm.get_registered_dirs():
            raise self.server.error(f"Root {root} not available", 404)
        if not filename:
            raise self.server.error("No file name specified", 400)
        if not rel_is_safe(filename) or not rel_is_safe(rel_path):
            raise self.server.error(
                f"Refusing path traversal in upload request: {rel_path}/{filename}",
                400
            )
        if size < 0:
            raise self.server.error(f"Invalid size: {size}", 400)
        if size > self.max_file_size:
            raise self.server.error(
                f"File size {size} exceeds the maximum upload size "
                f"{self.max_file_size}", 413
            )
        if not is_digest(checksum):
            raise self.server.error(
                "Invalid checksum: a lowercase hex SHA-256 digest is required", 400
            )

        user = self.username(web_request.get_current_user())
        now = time.time()
        self.collect(now)

        # Resume an identical, still-live transfer rather than opening a second
        # reservation beside it.  This is the path a client takes when it lost
        # its upload_id -- most plausibly because it restarted, which is exactly
        # the case staging on a persisted volume is meant to survive.
        wanted = (root, rel_path, filename, size, checksum, user)
        for existing in self.sessions.values():
            if existing.identity() == wanted:
                existing.updated = now
                result = existing.status(self.expiry)
                result["chunk_size"] = self.chunk_size
                result["resumed"] = True
                return result

        if len(self.sessions) >= self.max_sessions:
            raise self.server.error(
                f"Too many concurrent upload sessions ({self.max_sessions}); "
                "finalize or delete an existing session first", 507
            )
        if self.reserved_bytes() + size > self.max_staging_size:
            raise self.server.error(
                f"Upload staging quota exhausted: {self.reserved_bytes()} of "
                f"{self.max_staging_size} bytes reserved, {size} more requested",
                507
            )

        upload_id = secrets.token_hex(ID_BYTES)
        directory = os.path.join(self.staging_path, upload_id)
        session = UploadSession(
            upload_id=upload_id, root=root, path=rel_path, filename=filename,
            size=size, checksum=checksum, received=0, created=now, updated=now,
            user=user, directory=directory,
        )
        # Entered into the table BEFORE the directory is created, and therefore
        # before the await below.  Two reasons, both of which bite only under
        # concurrency and so would not show up in casual use:
        #
        #   * the quota and session-count checks above and the reservation they
        #     authorise have to be one atomic step.  With the insert after the
        #     await, two creates arriving together would both pass a check that
        #     neither's reservation was counted in, and the cap would be a
        #     suggestion.
        #   * _sweep_orphans removes staging directories no session accounts
        #     for.  A directory that exists before its session is in the table
        #     is exactly that, and a concurrent janitor pass would delete it.
        self.sessions[upload_id] = session
        try:
            await self.event_loop.run_in_thread(self._create_staging, session)
        except OSError as e:
            self.sessions.pop(upload_id, None)
            self._remove_path(directory)
            raise self.server.error(
                f"Unable to create upload staging directory: {e}", 500
            ) from e
        LOG.info(
            "[resumable_upload] session %s opened for %s (%d bytes)",
            upload_id, filename, size
        )
        result = session.status(self.expiry)
        result["chunk_size"] = self.chunk_size
        result["resumed"] = False
        return result

    def _create_staging(self, session: UploadSession) -> None:
        os.makedirs(session.directory, mode=0o700, exist_ok=False)
        # Create the part file eagerly so every later code path can assume it
        # exists and `os.path.getsize` is meaningful.
        with open(session.part_path, "wb"):
            pass
        session.write_meta()

    async def _delete_session(self, web_request: WebRequest) -> Dict[str, Any]:
        upload_id = web_request.get_str("upload_id")
        session = self.lookup(upload_id, web_request.get_current_user())
        # Deliberately not refused while a chunk is in flight.  `busy` is held
        # for the whole of a streamed body, so a cancel that could be blocked by
        # it would be unavailable exactly when a client most wants it -- during
        # a transfer that is going wrong.  The in-flight chunk discovers the
        # session is gone in UploadChunkHandler.post and returns 404.
        self.drop_session(session, "deleted by client")
        return {"upload_id": upload_id, "removed": True}

    async def _handle_status_request(self, web_request: WebRequest) -> Dict[str, Any]:
        upload_id = web_request.get_str("upload_id")
        session = self.lookup(upload_id, web_request.get_current_user())
        result = session.status(self.expiry)
        result["chunk_size"] = self.chunk_size
        return result

    async def _handle_finalize_request(
        self, web_request: WebRequest
    ) -> Dict[str, Any]:
        fm: FileManager = self.server.lookup_component("file_manager")
        fm.check_write_enabled()
        upload_id = web_request.get_str("upload_id")
        start_print = web_request.get_boolean("print", False)
        session = self.lookup(upload_id, web_request.get_current_user())
        if session.busy:
            raise self.server.error(
                f"Upload session {upload_id} has a chunk in flight", 409
            )

        if session.received != session.size:
            # A truncated transfer.  Refusing here is the whole point: a G-code
            # file that stops mid-layer is a print that stops with a 200 C+
            # hotend parked on the part.
            raise self.server.error(
                f"Upload is incomplete: {session.received} of {session.size} "
                f"bytes received", 422
            )

        # Hash what is actually on disk.  A running hash carried across requests
        # would agree with itself after a crash even when the bytes did not
        # survive, and would not notice anything that modified the part file
        # between chunks.
        digest = await self.event_loop.run_in_thread(
            self.digest_file, session.part_path
        )
        if not secrets.compare_digest(digest, session.checksum):
            # All chunks verified individually, so these are the bytes the
            # client sent; a whole-file mismatch means the declared digest was
            # wrong from the start and no amount of re-sending will fix it.
            # Keeping the session would only hold quota for a transfer that can
            # never succeed.
            self.drop_session(session, "whole-file checksum mismatch")
            raise self.server.error(
                f"File checksum mismatch: expected {session.checksum}, "
                f"calculated {digest}", 422
            )

        # Exactly the dict FileUploadHandler.post() builds
        # (application.py:1002-1013), handed to exactly the function it hands it
        # to.  Anything else here would be a new way into the gcodes root.
        form_args = {
            "filename": session.filename,
            "root": session.root,
            "path": session.path,
            "print": "true" if start_print else "false",
            "tmp_file_path": session.part_path,
            "current_user": web_request.get_current_user(),
        }
        try:
            result = await fm.finalize_upload(form_args)
        finally:
            # finalize_upload removes tmp_file_path on ANY failure
            # (file_manager.py:846-851), so once this returns or raises the
            # staged bytes are gone either way.  Dropping the session keeps the
            # table honest -- the alternative is a session advertising an offset
            # for a file that no longer exists, which is worse for the client
            # than being told to re-upload.
            self.drop_session(session, "finalized")
        result = dict(result)
        result["upload_id"] = upload_id
        return result

    @staticmethod
    def digest_file(path: str) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                digest.update(block)
        return digest.hexdigest()


@tornado.web.stream_request_body
class UploadChunkHandler(AuthorizedRequestHandler):
    """POST /server/files/upload/chunk -- append one verified chunk.

    Headers:
        X-Upload-Id      the session id returned by create
        X-Upload-Offset  the offset this chunk starts at; must equal the offset
                         the server holds
        X-Chunk-Sha256   SHA-256 of this chunk's bytes

    A wrong offset is answered 409 with the server's actual offset in both the
    JSON body and an `X-Upload-Offset` response header, because a client that is
    told only "no" can do nothing but start over -- which is the KAN-101 failure
    this component exists to avoid.

    CLIENTS SHOULD SEND ``Expect: 100-continue``.
    Every check that can reject a chunk without looking at its bytes -- unknown
    session, wrong owner, expired, busy, wrong offset, oversized -- is made in
    ``prepare()``, which tornado runs before reading any body
    (tornado/web.py:1863-1877).  With ``Expect: 100-continue`` tornado only
    emits the continue when the handler has not already responded
    (tornado/http1connection.py:_read_message, the
    ``not self._write_finished`` guard), so a rejection costs one round trip
    instead of a whole 4 MiB chunk over a bad link.  That matters most for the
    offset mismatch, which is the *expected* case after a reconnect.

    Without it the rejection still happens before any byte is written, but
    tornado has to close the connection to avoid draining the body
    (`HTTP1Connection.finish`: "Closing the connection is the only way to avoid
    reading the whole input body"), and a client still mid-write may see the
    reset rather than the status code.
    """

    def initialize(  # type: ignore[override]
        self, component: ResumableUpload
    ) -> None:
        super(UploadChunkHandler, self).initialize()
        self.component = component
        self.session: Optional[UploadSession] = None
        self.declared_offset: int = 0
        self.declared_digest: str = ""
        self.content_length: int = 0
        self._file: Any = None
        self._hash = hashlib.sha256()
        self._written: int = 0
        self._released: bool = False
        # Surfaced in every error response so a client can resync from any
        # failure rather than guessing.
        self._server_offset: Optional[int] = None

    # -- request lifecycle -------------------------------------------------

    async def prepare(self) -> None:
        # AuthorizedRequestHandler.prepare performs authentication
        # (application.py:496-507).  Because this class is
        # @stream_request_body, tornado runs it before reading a single body
        # byte (tornado/web.py:1863-1877), so an unauthenticated caller cannot
        # make us write anything at all.
        ret = super(UploadChunkHandler, self).prepare()
        if ret is not None:
            await ret
        if self.request.method != "POST":
            raise tornado.web.HTTPError(405)

        server = self.component.server
        fm: FileManager = server.lookup_component("file_manager")
        try:
            fm.check_write_enabled()
        except server.error as e:
            raise tornado.web.HTTPError(e.status_code, str(e)) from e

        upload_id = self.request.headers.get("X-Upload-Id", "")
        if not upload_id:
            raise tornado.web.HTTPError(400, "X-Upload-Id header is required")
        try:
            session = self.component.lookup(upload_id, self.current_user)
        except server.error as e:
            raise tornado.web.HTTPError(e.status_code, str(e)) from e
        self._server_offset = session.received

        digest = self.request.headers.get("X-Chunk-Sha256", "").strip().lower()
        if not is_digest(digest):
            raise tornado.web.HTTPError(
                400, "X-Chunk-Sha256 must be a lowercase hex SHA-256 digest"
            )
        try:
            offset = int(self.request.headers.get("X-Upload-Offset", ""))
        except ValueError:
            raise tornado.web.HTTPError(
                400, "X-Upload-Offset must be an integer"
            ) from None
        try:
            length = int(self.request.headers.get("Content-Length", ""))
        except ValueError:
            raise tornado.web.HTTPError(
                411, "Content-Length is required for a chunk upload"
            ) from None

        if session.busy:
            # Sequential by construction: no sparse bookkeeping, no
            # out-of-order state machine, nothing to get wrong under
            # concurrency.
            raise tornado.web.HTTPError(
                409, f"Upload session {upload_id} already has a chunk in flight"
            )
        if offset != session.received:
            raise tornado.web.HTTPError(
                409,
                f"Offset mismatch: server holds {session.received}, "
                f"chunk declares {offset}"
            )
        if length <= 0:
            raise tornado.web.HTTPError(400, "Empty chunk")
        if length > self.component.max_chunk_size:
            raise tornado.web.HTTPError(
                413,
                f"Chunk of {length} bytes exceeds the maximum "
                f"{self.component.max_chunk_size}"
            )
        if offset + length > session.size:
            raise tornado.web.HTTPError(
                413,
                f"Chunk would write {offset + length} bytes into a file "
                f"declared as {session.size}"
            )

        # Bound the body at the connection layer too, so an oversized body is
        # cut off by tornado rather than by us.
        if isinstance(self.request.connection, HTTP1Connection):
            self.request.connection.set_max_body_size(self.component.max_chunk_size)

        self.session = session
        self.declared_offset = offset
        self.declared_digest = digest
        self.content_length = length
        session.busy = True
        try:
            self._file = await self.component.event_loop.run_in_thread(
                self._open_part, session
            )
        except OSError as e:
            session.busy = False
            self.session = None
            raise tornado.web.HTTPError(
                500, f"Unable to open staged upload: {e}"
            ) from e

    @staticmethod
    def _open_part(session: UploadSession) -> Any:
        # Truncate to the verified offset before writing, so that an append
        # always starts against a file that is exactly `received` bytes long.
        #
        # A dropped connection leaves unverified bytes past that offset.  A
        # client that resumes with the same chunk size happens to overwrite
        # them -- but a client that just lost a connection is exactly the one
        # most likely to back off to a smaller chunk, and then they outlive the
        # write while still sitting inside the range `finalize` digests.  Doing
        # it here makes that a local invariant rather than something that has to
        # be re-derived from the offset rules every time this is read, and it
        # does not depend on a disconnect callback having run.
        os.truncate(session.part_path, session.received)
        handle = open(session.part_path, "r+b")
        handle.seek(session.received)
        return handle

    async def data_received(self, chunk: bytes) -> None:
        if self.session is None or self._file is None:
            # prepare() rejected this request.  Tornado still feeds us the body
            # (tornado/web.py:2483-2488 calls data_received regardless of
            # whether _execute returned early), so discard it.
            return
        if self._written + len(chunk) > self.content_length:
            # Cannot normally happen -- tornado enforces Content-Length -- but a
            # write past the declared length is the one thing that could corrupt
            # a neighbouring region of the part file, so it is checked.  post()
            # sees _written != content_length and rolls the chunk back.
            self._written = self.content_length + len(chunk)
            return
        await self.component.event_loop.run_in_thread(self._write_block, chunk)

    def _write_block(self, chunk: bytes) -> None:
        self._file.write(chunk)
        self._hash.update(chunk)
        self._written += len(chunk)

    async def post(self) -> None:
        session = self.session
        if session is None or self._file is None:
            raise tornado.web.HTTPError(500, "Chunk upload was not prepared")
        if session.upload_id not in self.component.sessions:
            # Deleted or expired while this chunk was on the wire.  Cancelling a
            # session is allowed at any time -- a cancel that could be blocked by
            # a stalled upload would be useless -- so this is a normal outcome,
            # and it deserves the status code that says so rather than the 500
            # that writing meta.json into a removed directory would produce.
            self._release()
            raise tornado.web.HTTPError(
                404, f"Upload session {session.upload_id} no longer exists"
            )
        loop = self.component.event_loop
        try:
            if self._written != self.content_length:
                await loop.run_in_thread(self._rollback)
                raise tornado.web.HTTPError(
                    400,
                    f"Chunk body was {self._written} bytes, "
                    f"Content-Length declared {self.content_length}"
                )
            if not secrets.compare_digest(
                self._hash.hexdigest(), self.declared_digest
            ):
                # The session deliberately survives: the client re-sends this
                # chunk at the same offset and everything before it is still
                # good.  That is the difference between a retry and a restart.
                await loop.run_in_thread(self._rollback)
                raise tornado.web.HTTPError(
                    422,
                    f"Chunk checksum mismatch at offset {self.declared_offset}"
                )
            await loop.run_in_thread(self._commit, session)
        finally:
            self._release()
        self._server_offset = session.received
        self.set_header("Content-Type", "application/json; charset=UTF-8")
        self.set_header("X-Upload-Offset", str(session.received))
        self.finish(jsonw.dumps({
            "result": {
                "upload_id": session.upload_id,
                "received": session.received,
                "next_offset": session.received,
                "size": session.size,
                "complete": session.received == session.size,
                "expires_at": session.expires_at(self.component.expiry),
            }
        }))

    def _rollback(self) -> None:
        session = self.session
        if session is None:
            return
        with contextlib.suppress(OSError):
            self._file.flush()
            os.truncate(session.part_path, session.received)

    def _commit(self, session: UploadSession) -> None:
        # fsync the data BEFORE meta.json records it.  The recovery path in
        # _load_session depends on this ordering: part.bin may legitimately be
        # longer than `received` after a crash, never shorter.
        self._file.flush()
        os.fsync(self._file.fileno())
        session.received = self.declared_offset + self._written
        session.updated = time.time()
        session.write_meta()

    def _release(self) -> None:
        if self._released:
            return
        self._released = True
        if self._file is not None:
            with contextlib.suppress(OSError):
                self._file.close()
            self._file = None
        if self.session is not None:
            self.session.busy = False

    def on_finish(self) -> None:
        self._release()

    def on_connection_close(self) -> None:
        # A dropped connection mid-chunk.  Nothing is committed, the offset in
        # meta.json is untouched, and the next append truncates the partial
        # bytes away in _open_part.
        self._release()
        super(UploadChunkHandler, self).on_connection_close()

    def write_error(self, status_code: int, **kwargs) -> None:
        # Moonraker's error envelope (application.py:526-533) plus the one field
        # a resuming client actually needs.
        err: Dict[str, Any] = {"code": status_code, "message": self._reason}
        body: Dict[str, Any] = {"error": err}
        if self._server_offset is not None:
            body["received"] = self._server_offset
            body["next_offset"] = self._server_offset
            self.set_header("X-Upload-Offset", str(self._server_offset))
        self.set_header("Content-Type", "application/json; charset=UTF-8")
        self.finish(jsonw.dumps(body))


def load_component(config: ConfigHelper) -> ResumableUpload:
    return ResumableUpload(config)
