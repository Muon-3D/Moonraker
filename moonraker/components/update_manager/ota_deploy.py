# OTA Image Deployment for Moonraker Update Manager
# Improved adaptive + robust version
# License: GNU GPLv3 (same as Moonraker components)

from __future__ import annotations
import asyncio
from typing import Any, Dict, Optional, cast
from .base_deploy import BaseDeploy

POLL_SECS = 1.0                   # seconds between polls
PROGRESS_IDLE_TIMEOUT = 60.0      # stop if no progress/state change for N seconds
MAX_CONSECUTIVE_ERRORS = 5        # retry transient failures before assuming reboot

class OtaDeploy(BaseDeploy):
    """
    Adapter exposing your OS-image OTA service to Moonraker's update_manager.
    Talks directly to the `aux_api_proxy` component (no HTTP).
    """

    def __init__(self, config):
        super().__init__(config, prefix="OTA")
        self.config = config
        self._status: Dict[str, Any] = {}
        self._is_valid: bool = True
        self._warnings: list[str] = []
        self._anomalies: list[str] = []
        # cached fields for quick get_update_status()
        self._current: Optional[str] = None
        self._target: Optional[str] = None
        self._requires_commit: bool = False
        self._progress: Optional[float] = None
        self._state: Optional[str] = None

    # ---------- lifecycle -------------------------------------------------

    async def initialize(self) -> Dict[str, Any]:
        storage = await super().initialize()
        return storage

    async def refresh(self) -> None:
        """Fetch current OTA status and cache mapped fields."""
        try:
            s = await self._aux_status()
            self._status = s
            self._map_status(s)
            self._is_valid = True
        except Exception as e:
            self._is_valid = False
            self._warnings.append(f"OTA status fetch failed: {e}")
            self.log_exc("OTA: failed to refresh status", traceback=False)
        finally:
            self._save_state()

    async def update(self) -> bool:
        """Start an image update; poll adaptively so the UI shows progress."""
        self.notify_status("Starting OS image update… device may reboot.")
        aux = self._aux()
        await aux.ota_start()  # fire-and-forget; FastAPI does the heavy lifting

        # Adaptive progress polling
        last_progress: Optional[float] = None
        last_state: Optional[str] = None
        last_change_time = asyncio.get_event_loop().time()
        consecutive_errors = 0

        try:
            while True:
                try:
                    s = await aux.ota_status()
                    self._status = s
                    self._map_status(s)
                    consecutive_errors = 0  # reset error counter

                    # push Versions tile refresh (Moonraker throttles)
                    self.cmd_helper.notify_update_refreshed()

                    pct = self._progress
                    st = (self._state or "").lower()

                    # update timestamp if anything changed
                    if pct != last_progress or st != last_state:
                        last_change_time = asyncio.get_event_loop().time()
                        last_progress = pct
                        last_state = st

                        # pretty progress message
                        if pct is not None:
                            self.notify_status(f"Installing… {pct:.1f}%")

                    # stop if commit/idle/fail
                    if st in ("idle", "failed"):
                        break

                    # detect stall
                    now = asyncio.get_event_loop().time()
                    if now - last_change_time > PROGRESS_IDLE_TIMEOUT:
                        self._warnings.append(
                            "No progress reported for a while; assuming reboot or stall."
                        )
                        break

                    await asyncio.sleep(POLL_SECS)

                except Exception as e:
                    consecutive_errors += 1
                    if consecutive_errors > MAX_CONSECUTIVE_ERRORS:
                        self._warnings.append(f"Lost contact with OTA service: {e}")
                        break
                    await asyncio.sleep(POLL_SECS * 2)

        except Exception:
            # likely reboot in progress; just exit gracefully
            pass

        # --- Final messages ---
        st = (self._state or "").lower()
        if st == "failed":
            self.notify_status("OTA failed", is_complete=True)
            raise self.server.error(self._status.get("error", "OTA failed"))
        elif st == "installing":
            self.notify_status(
                "Update still in progress… device may reboot soon.", is_complete=False
            )
        else:
            self.notify_status("Update initiated.", is_complete=True)

        return True

    async def commit(self) -> bool:
        """Commit to newly installed slot (A/B)."""
        self.notify_status("Committing OS image…")
        aux = self._aux()
        await aux.ota_commit()
        await self.refresh()
        self.notify_status("Commit complete.", is_complete=True)
        return True

    async def rollback(self) -> bool:
        raise self.server.error("Rollback not implemented for OS image")

    # ---------- status for Moonraker/clients ------------------------------

    def get_update_status(self) -> Dict[str, Any]:
        version = self._current or "?"
        remote_version = self._target or version
        return {
            "name": self.name,
            "configured_type": "ota",
            "version": version,
            "remote_version": remote_version,
            "current_hash": self._current or version,
            "remote_hash": self._target or remote_version,
            "requires_commit": self._requires_commit,
            "progress": self._progress,
            "is_valid": self._is_valid,
            "warnings": list(self._warnings),
            "anomalies": list(self._anomalies),
            "info_tags": ["desc=System Image"],
        }

    def get_persistent_data(self) -> Dict[str, Any]:
        return super().get_persistent_data()

    # ---------- helpers ---------------------------------------------------

    def _aux(self):
        aux = self.server.lookup_component("aux_api_proxy", None)
        if aux is None:
            raise self.server.error("aux_api_proxy component not loaded")
        return aux

    async def _aux_status(self) -> Dict[str, Any]:
        data = await self._aux().ota_status()
        if not isinstance(data, dict):
            raise self.server.error("Invalid OTA status payload (not a dict)")
        return cast(Dict[str, Any], data)

    def _map_status(self, s: Dict[str, Any]) -> None:
        self._state = (s.get("state") or "").lower()
        self._current = s.get("current_version") or self._current
        if s.get("update_available"):
            self._target = s.get("target_version") or self._target
        else:
            self._target = self._current
        self._requires_commit = bool(s.get("requires_commit", False))
        prog = s.get("progress")
        if isinstance(prog, (int, float)):
            self._progress = round(float(prog), 1)
        else:
            self._progress = None
