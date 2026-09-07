# moonraker/components/gcode_preprocessor.py
#
# G-code safety postprocessor (invariant I5 / KAN-193).
#
# WHAT THIS PROTECTS
# ------------------
# `avoid_excluded_zone` rewrites G-code so that travel moves hop over a region
# of the bed the toolhead must not cross.  A file that reaches Klipper without
# that rewrite can drive a 200 C+ hotend through the excluded zone.  So the
# property we need is not "the postprocessor is usually invoked" but "the bytes
# Klipper executes were produced by the postprocessor".
#
# WHY THIS FILE WAS REWRITTEN
# ---------------------------
# The previous implementation monkeypatched two bound methods in __init__:
# `MetadataStorage._run_extract_metadata` and `KlippyAPI.start_print`.  Four
# verified holes followed from that construction, and none of them can be fixed
# from inside a monkeypatch:
#
#   1. The metadata hook runs during `parse_metadata`, which
#      `file_manager.py:919-920` calls *after* `_process_uploaded_file` has
#      already done `shutil.move` into the gcodes root
#      (`file_manager.py:981-982`).  Unprocessed G-code was therefore visible --
#      and startable -- at its final path.
#   2. `parse_metadata` returns an already-set event when
#      `_has_valid_data(fname, path_info)` is true (`file_manager.py:2549-2553`),
#      i.e. whenever size and mtime match a known file.  A re-upload or a
#      resumed transfer skipped the postprocessor entirely.
#   3. For `.ufp`, `_process_uploaded_file` moves nothing
#      (`file_manager.py:973-976`); the `.gcode` is produced later by the
#      metadata script.  The patch ran the binary *before* the original
#      (old gcode_preprocessor.py:29-30), against a path that did not yet exist.
#   4. `get_file_list` builds from a filesystem walk
#      (`file_manager.py:1004-1023`), so a file can reach the gcodes root by
#      move, copy, SD card, SSH or a dev-mode config swap and never touch an
#      upload path at all.
#
# The patched `start_print(filename, user=None)` also could not accept
# `job_queue.py:139-141`'s `start_print(filename, wait_klippy_started=True,
# user=job.user)`, so starting a queued job raised TypeError -- and
# `job_queue.py:142` catches only `self.server.error`, so it escaped as a crash.
#
# THE TWO ENFORCEMENT POINTS THAT REPLACE IT
# ------------------------------------------
# (a) Ingress, in `file_manager._process_uploaded_file`, on the *staged* file
#     before the move.  Nothing unprocessed is ever published, and
#     `_has_valid_data` stops being load-bearing because the guard is no longer
#     on the metadata path.
# (b) Print time, in `klippy_apis.start_print` -- authoritative.  This one
#     covers hole 4, because it checks the bytes on disk rather than trusting
#     the route the file arrived by.
#
# Both call into this component explicitly; there is no monkeypatching left.
#
# THE MARKER
# ----------
# After the binary runs we append one trailer line:
#
#   ; muon-safety-pass v1 sha256=<hex> tag=<hex>
#
# `sha256` is over the processed body *excluding the trailer block*, because a
# digest that covered its own bytes could not be computed at all.  That alone
# would be trivially self-validating: anyone who can write into the gcodes root
# can hash their own body and append a matching line.  `tag` closes that -- it
# is HMAC-SHA256 over (marker version, postprocessor binary digest, body digest)
# under a device-local key, so a trailer can only be produced by this component
# on this device.  Folding the binary's digest in means replacing
# `avoid_excluded_zone` (a new excluded region, say) invalidates every existing
# marker and every file is re-processed before its next print.
#
# The trailer is emitted here rather than by the Rust binary because
#   - the binary lives in a separate submodule (files/moonraker/GCodePostprocessor)
#     that MuonOS has no build path for -- 21-install.moonraker.sh:42-43 installs
#     a prebuilt artefact -- so a change there could not ship with this one;
#   - the HMAC key is device-local and the binary has no access to it;
#   - writer and verifier must agree byte-for-byte on how the body is delimited,
#     and one implementation of that rule is much safer than two.

from __future__ import annotations

import os
import re
import hmac
import shutil
import signal
import asyncio
import hashlib
import logging
import tempfile
import contextlib

from moonraker.confighelper import ConfigHelper

# Create a module-level logger
LOG = logging.getLogger(__name__)

MARKER_VERSION = b"muon-safety-pass v1"

# The trailer occupies exactly one line.  Both digests are lowercase hex so the
# pattern is unambiguous and cannot be padded with look-alike characters.
MARKER_RE = re.compile(
    rb"^; muon-safety-pass v1 sha256=([0-9a-f]{64}) tag=([0-9a-f]{64})[ \t\r]*$"
)

DEFAULT_TIMEOUT = 120.0
KEY_BYTES = 32


def split_marker(data: bytes) -> tuple[bytes, tuple[str, str] | None]:
    """Split ``data`` into (body, marker_fields).

    ``body`` is the file with its trailing marker block removed and *every other
    byte preserved exactly*, including the newline that terminates the last real
    G-code line.  Getting that boundary wrong in either direction silently
    breaks verification for every file, so it is spelled out rather than done
    with a regex over the whole buffer:

      - a marker only counts at the very end of the file.  A marker line pasted
        into the middle is ordinary content and is hashed as such.
      - stacked markers are all stripped (so re-processing cannot accumulate
        them) but the fields returned are those of the last line in the file,
        which is the one verification must check.
      - the marker line's own newline goes with the marker, not the body.
    """
    fields: tuple[str, str] | None = None
    end = len(data)
    while end:
        chunk = data[:end]
        # Drop the line's terminating newline, if it has one, before locating
        # the start of that line.
        without_nl = chunk[:-1] if chunk.endswith(b"\n") else chunk
        line_start = without_nl.rfind(b"\n") + 1
        match = MARKER_RE.match(without_nl[line_start:])
        if match is None:
            break
        if fields is None:
            fields = (match.group(1).decode(), match.group(2).decode())
        end = line_start
    return data[:end], fields


class GCodePreprocessorComponent:
    def __init__(self, config: ConfigHelper):
        self.server = config.get_server()

        # Read our Rust binary path
        self.binary = config.get("binary", None)
        if not self.binary:
            raise self.server.error("gcode_preprocessor: missing 'binary' setting")

        # The old implementation ran the binary with no timeout at all, so a
        # postprocessor that hung hung the upload -- and, through start_print,
        # the print request -- forever.
        self.timeout: float = config.getfloat("timeout", DEFAULT_TIMEOUT)

        key_path: str | None = config.get("marker_key_path", None)
        if key_path is None:
            data_path = self.server.get_app_args().get("data_path", ".")
            key_path = os.path.join(data_path, ".gcode_safety_marker.key")
        self.key_path = key_path
        self._key: bytes | None = None
        self._binary_digest: str | None = None

        # NOTE: no component lookups here.  The old version resolved
        # file_manager and klippy_apis in __init__ purely to patch them, which
        # made this component's correctness depend on config section order.
        # Both enforcement points now call in, so nothing is needed until the
        # first upload or print.

    # ------------------------------------------------------------------
    # key material
    # ------------------------------------------------------------------

    def _load_key(self) -> bytes:
        """Device-local HMAC key, created on first use.

        Losing this key is not a safety failure: every existing marker stops
        verifying and every file is re-processed before its next print.  That is
        why an unwritable key path degrades to an in-memory key rather than
        refusing to run -- the degraded mode is strictly more conservative.
        """
        if self._key is not None:
            return self._key
        try:
            with open(self.key_path, "rb") as f:
                key = f.read()
            if len(key) >= KEY_BYTES:
                self._key = key
                return key
            LOG.error(
                "[gcode_preprocessor] marker key at '%s' is too short (%d bytes); "
                "regenerating", self.key_path, len(key)
            )
        except FileNotFoundError:
            pass
        except OSError:
            LOG.exception(
                "[gcode_preprocessor] cannot read marker key '%s'; using an "
                "ephemeral key, every file will be re-processed", self.key_path
            )
            self._key = os.urandom(KEY_BYTES)
            return self._key
        key = os.urandom(KEY_BYTES)
        try:
            # Exclusive create so two Moonraker instances racing on first boot
            # cannot each install a different key; the loser re-reads.
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, key)
            finally:
                os.close(fd)
        except FileExistsError:
            with open(self.key_path, "rb") as f:
                key = f.read()
        except OSError:
            LOG.exception(
                "[gcode_preprocessor] cannot create marker key '%s'; using an "
                "ephemeral key, every file will be re-processed", self.key_path
            )
        self._key = key
        return key

    def _get_binary_digest(self) -> str:
        """SHA-256 of the postprocessor binary, folded into every marker.

        Computed lazily: doing it in __init__ would turn a missing binary into a
        Moonraker startup failure, and the binary is installed by a separate
        step (21-install.moonraker.sh:42-43).  Failing here instead means a
        missing binary blocks uploads and prints -- fail closed -- without
        taking the whole server down.
        """
        if self._binary_digest is not None:
            return self._binary_digest
        digest = hashlib.sha256()
        with open(self.binary, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                digest.update(block)
        self._binary_digest = digest.hexdigest()
        return self._binary_digest

    def _tag(self, body_digest: str) -> str:
        msg = b"\n".join(
            (MARKER_VERSION, self._get_binary_digest().encode(), body_digest.encode())
        )
        return hmac.new(self._load_key(), msg, hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------
    # marker read/write (synchronous; callers run these off the event loop)
    # ------------------------------------------------------------------

    def verify_bytes(self, data: bytes) -> bool:
        body, fields = split_marker(data)
        if fields is None:
            return False
        body_digest, tag = fields
        if not hmac.compare_digest(hashlib.sha256(body).hexdigest(), body_digest):
            return False
        try:
            expected = self._tag(body_digest)
        except OSError:
            # Binary unreadable -> cannot authenticate anything -> fail closed.
            LOG.exception("[gcode_preprocessor] cannot digest '%s'", self.binary)
            return False
        return hmac.compare_digest(expected, tag)

    def _write_marker(self, path: str) -> str:
        """Re-write ``path`` with a fresh trailer.  Returns the body digest."""
        with open(path, "rb") as f:
            raw = f.read()
        body, _ = split_marker(raw)
        # The digest must cover the bytes as they will be stored, so normalise
        # the final newline *before* hashing.  A file that did not end in a
        # newline gains one; that is the only content change this makes.
        if body and not body.endswith(b"\n"):
            body += b"\n"
        body_digest = hashlib.sha256(body).hexdigest()
        marker = b"; %s sha256=%s tag=%s\n" % (
            MARKER_VERSION, body_digest.encode(), self._tag(body_digest).encode()
        )
        directory = os.path.dirname(path) or "."
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".muon-marker-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(body)
                f.write(marker)
                f.flush()
                os.fsync(f.fileno())
            shutil.copymode(path, tmp_path)
            # os.replace is atomic within a directory, so a crash here leaves
            # either the pre-marker file or the marked one, never a torn file.
            os.replace(tmp_path, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.remove(tmp_path)
            raise
        return body_digest

    def _read(self, path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read()

    # ------------------------------------------------------------------
    # enforcement entry points
    # ------------------------------------------------------------------

    async def process_path(self, path: str) -> None:
        """Run the postprocessor on ``path`` and stamp it.  Raises on failure.

        Always runs the binary, even when ``path`` already carries a valid
        marker: a marker proves only that *some* version of the postprocessor
        ran, and on the ingress path we would rather spend the CPU than reason
        about which one.
        """
        if not os.path.isfile(path):
            raise self.server.error(
                f"gcode_preprocessor: nothing to process at '{path}'", 500
            )
        await self._invoke_preprocessor(path)
        eventloop = self.server.get_event_loop()
        await eventloop.run_in_thread(self._write_marker, path)

    async def ensure_verified(self, filename: str) -> None:
        """Print-time gate.  ``filename`` is relative to the gcodes root.

        This is the authoritative enforcement point: it inspects the bytes that
        are about to be handed to Klipper rather than trusting how they got
        there, which is the only thing that covers files arriving by move, copy,
        SD card, SSH or a dev-mode config swap (`file_manager.py:1004-1023`
        builds the file list from a filesystem walk).
        """
        gc_path = self._gcode_root()
        if not gc_path:
            return
        full_path = os.path.normpath(os.path.join(gc_path, filename))
        if not full_path.startswith(os.path.join(gc_path, "")):
            raise self.server.error(
                f"gcode_preprocessor: '{filename}' is outside the gcodes root", 400
            )
        if not os.path.isfile(full_path):
            # Not our error to raise -- let Klipper report the missing file.
            return
        eventloop = self.server.get_event_loop()
        data = await eventloop.run_in_thread(self._read, full_path)
        if self.verify_bytes(data):
            return
        LOG.info(
            "[gcode_preprocessor] '%s' has no valid safety marker; processing "
            "before print", filename
        )
        await self.process_path(full_path)

    def _gcode_root(self) -> str:
        fm = self.server.lookup_component("file_manager", None)
        if fm is None:
            LOG.error("[gcode_preprocessor] file_manager unavailable")
            return ""
        return fm.get_directory("gcodes")

    async def _invoke_preprocessor(self, file_path: str) -> None:
        """Run the binary on ``file_path``, bounded by ``self.timeout``."""
        kwargs = {}
        if hasattr(os, "setsid"):
            # Own process group so a hung postprocessor that has forked can be
            # reaped whole rather than leaving orphans holding the file.
            kwargs["start_new_session"] = True
        proc = await asyncio.create_subprocess_exec(
            self.binary, file_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            **kwargs
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )
        except asyncio.TimeoutError:
            self._kill_process_group(proc)
            with contextlib.suppress(Exception):
                await proc.wait()
            LOG.error(
                "[gcode_preprocessor] '%s' timed out after %.1fs on %s",
                self.binary, self.timeout, file_path
            )
            raise self.server.error(
                f"G-code safety postprocessor timed out after {self.timeout:.0f}s", 500
            )

        if proc.returncode != 0:
            LOG.error(
                "[gcode_preprocessor] '%s' failed (exit %s):\n%s",
                self.binary, proc.returncode,
                stderr.decode(errors="ignore")
            )
            raise self.server.error(
                f"G-code safety postprocessor exited {proc.returncode}", 500
            )

        # Log any summary the Rust tool printed
        summary = stdout.decode(errors="ignore").strip()
        if summary:
            LOG.info("[gcode_preprocessor] %s", summary)

    @staticmethod
    def _kill_process_group(proc: asyncio.subprocess.Process) -> None:
        # Kill the whole group where the platform has groups (the printer), so a
        # postprocessor that forked cannot leave a child holding the file open.
        if hasattr(os, "killpg") and proc.pid:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                return
            except (OSError, ProcessLookupError):
                pass
        with contextlib.suppress(Exception):
            proc.kill()


def load_component(config: ConfigHelper):
    return GCodePreprocessorComponent(config)
