# OTA Image Deployment for Moonraker Update Manager
# Copyright (C) 2025
# License: GNU GPLv3 (same as Moonraker components)

from __future__ import annotations
import asyncio
import logging
from typing import Any, Dict, Optional

from .base_deploy import BaseDeploy

AUX_PREFIX = "/server/aux"          # matches your AuxAutoProxy MOON_PREFIX
UPDATE_BASE = f"{AUX_PREFIX}/update"

CONNECT_TIMEOUT = 3.0
REQUEST_TIMEOUT = 10.0

class OtaDeploy(BaseDeploy):
    """
    A very small adapter that exposes your OS-image OTA service to
    Moonraker's update_manager. It behaves like any other updater so
    Fluidd/Mainsail can reuse their existing UI.
    """

    def __init__(self, config):
        # Name is parsed from section header, eg. [update_manager os] -> "os"
        # Prefix controls the log lines sent to the UI
        super().__init__(config, prefix="OTA")
        self.config = config
        self._status: Dict[str, Any] = {}
        self._is_valid: bool = True
        self._warnings: list[str] = []
        self._anomalies: list[str] = []

        # Optional overrides (rarely needed)
        self._aux_prefix = config.get("aux_prefix", AUX_PREFIX)
        self._update_base = f"{self._aux_prefix}/update"

    # ---------- lifecycle -------------------------------------------------

    async def initialize(self) -> Dict[str, Any]:
        storage = await super().initialize()
        # nothing to restore yet; we always query live status
        return storage

    async def refresh(self) -> None:
        """Fetch current OTA status and store a small cache for /status."""
        try:
            self._status = await self._get_status()
            self._is_valid = True
        except Exception as e:
            self._is_valid = False
            self._warnings.append(f"OTA status fetch failed: {e}")
            self.log_exc("OTA: failed to refresh status", traceback=False)
        finally:
            self._save_state()

    async def update(self) -> bool:
        """
        Trigger an image update. We do *not* long-poll here because the
        device will typically reboot into the spare slot immediately after
        install. We just initiate, log, and return.
        """
        client = self.cmd_helper.get_http_client()
        self.notify_status("Starting OS image update... This device may reboot.")
        rsp = await client.post(
            f"{self._update_base}/start",
            json={}, connect_timeout=CONNECT_TIMEOUT, request_timeout=REQUEST_TIMEOUT
        )
        # Raise for HTTP errors
        try:
            rsp.raise_for_status()
        except Exception:
            self.notify_status("Start request failed.", is_complete=True)
            raise

        # Best-effort: fetch one last status snapshot so UI updates quickly.
        try:
            snap = await self._get_status()
            self._status = snap
            state = snap.get("state", "unknown")
            prog = snap.get("progress", None)
            if prog is not None:
                self.notify_status(f"Progress: {int(prog)}%")
            self.notify_status(f"State: {state}")
        except Exception:
            # Ignore, as a reboot may already be in progress
            pass

        # Done for this request; after reboot Moonraker will come back and auto-refresh
        self.notify_status("Update initiated.", is_complete=True)
        return True

    async def rollback(self) -> bool:
        """
        Optional future work: call your AUX rollback endpoint here
        (e.g., POST /server/aux/update/rollback). For now we raise a clear error.
        """
        raise self.server.error("Rollback not implemented for OS image")

    async def commit(self) -> bool:
        """
        Commit to the newly installed slot (A/B scheme). Maps to
        POST /server/aux/update/commit. UI should enable this if
        'requires_commit' is true in status.
        """
        client = self.cmd_helper.get_http_client()
        self.notify_status("Committing OS image...")
        rsp = await client.post(
            f"{self._update_base}/commit",
            json={}, connect_timeout=CONNECT_TIMEOUT, request_timeout=REQUEST_TIMEOUT
        )
        try:
            rsp.raise_for_status()
        except Exception:
            self.notify_status("Commit request failed.", is_complete=True)
            raise

        # Refresh and announce completion
        try:
            await self.refresh()
        finally:
            self.notify_status("Commit complete.", is_complete=True)
        return True

    # ---------- status shape Moonraker/Fluidd understands ----------------

    def get_update_status(self) -> Dict[str, Any]:
        s = self._status or {}
        # Prefer semver-like strings; also provide *hash* fallbacks so
        # Fluidd can still detect changes when versions aren't strictly semver.
        version = s.get("current_version") or "?"
        remote_version = (
            s.get("target_version") if s.get("update_available") else version
        ) or version
        status: Dict[str, Any] = {
            "name": self.name,
            "configured_type": "ota",
            "version": version,
            "remote_version": remote_version,
            "current_hash": s.get("current_version") or version,
            "remote_hash": s.get("target_version") or remote_version,
            "requires_commit": bool(s.get("requires_commit", False)),
            "progress": s.get("progress", None),
            "is_valid": self._is_valid,
            "warnings": list(self._warnings),
            "anomalies": list(self._anomalies),
            # helpful tag for UIs
            "info_tags": ["desc=System Image"],
        }
        return status

    def get_persistent_data(self) -> Dict[str, Any]:
        # Reuse base data; no extra persistence required
        return super().get_persistent_data()

    # ---------- helpers ---------------------------------------------------

    async def _get_status(self) -> Dict[str, Any]:
        client = self.cmd_helper.get_http_client()
        rsp = await client.get(
            f"{self._update_base}/status",
            connect_timeout=CONNECT_TIMEOUT, request_timeout=REQUEST_TIMEOUT
        )
        rsp.raise_for_status()
        data = rsp.json()
        if not isinstance(data, dict):
            raise self.server.error("Invalid OTA status payload")
        return data
