# OTA Image Deployment for Moonraker Update Manager
# Component-to-component version (no HTTP self-calls)
# License: GNU GPLv3 (same as Moonraker components)

from __future__ import annotations
import asyncio
from typing import Any, Dict, Optional, cast

from .base_deploy import BaseDeploy

POLL_SECS = 1.0
POLL_MAX_SECS = 30.0  # stop polling after boot kicks us, keep UI snappy

class OtaDeploy(BaseDeploy):
    """
    Adapter exposing your OS-image OTA service to Moonraker's update_manager.
    Talks directly to the `aux_api_proxy` component (no HTTP).
    """

    def __init__(self, config):
        # Section name (eg. [update_manager os]) becomes self.name automatically.
        # Prefix adds a label to log lines shown in the client.
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
        # Let BaseDeploy restore/sanitize any persisted state
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
        """Start an image update; briefly poll so the UI shows movement, then return."""
        self.notify_status("Starting OS image update… device may reboot.")
        aux = self._aux()
        await aux.ota_start()  # fire-and-forget; FastAPI does the heavy lifting

        # Best-effort: short poll to surface early progress / state before reboot
        total = 0.0
        last_pct: Optional[int] = None
        try:
            while total < POLL_MAX_SECS:
                s = await aux.ota_status()
                self._status = s
                self._map_status(s)
                # push a Versions tile refresh (Moonraker throttles these)
                self.cmd_helper.notify_update_refreshed()

                pct = self._progress
                if pct is not None:
                    ipct = int(pct)
                    if last_pct != ipct:
                        self.notify_status(f"Installing… {ipct}%")
                        last_pct = ipct

                st = (self._state or "").lower()
                if st in ("idle", "committing", "failed"):
                    break

                await asyncio.sleep(POLL_SECS)
                total += POLL_SECS
        except Exception:
            # Likely reboot in progress; just finish gracefully
            pass

        # Final line for this request
        if (self._state or "").lower() == "failed":
            self.notify_status("OTA failed", is_complete=True)
            raise self.server.error(self._status.get("error", "OTA failed"))
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
        """Skeleton for future rollback support."""
        raise self.server.error("Rollback not implemented for OS image")

    # ---------- status for Moonraker/clients ------------------------------

    def get_update_status(self) -> Dict[str, Any]:
        # Fluidd/Mainsail understand these fields; hashes let the UI light up even
        # if versions aren't strict semver.
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
        # No custom persistence beyond base behavior
        return super().get_persistent_data()

    # ---------- helpers ---------------------------------------------------

    def _aux(self):
        aux = self.server.lookup_component("aux_api_proxy", None)
        if aux is None:
            # As per your constraint, this should always exist
            raise self.server.error("aux_api_proxy component not loaded")
        return aux

    async def _aux_status(self) -> Dict[str, Any]:
        data = await self._aux().ota_status()
        if not isinstance(data, dict):
            raise self.server.error("Invalid OTA status payload (not a dict)")
        return cast(Dict[str, Any], data)

    def _map_status(self, s: Dict[str, Any]) -> None:
        # Map AUX API → fields the UI uses
        self._state = (s.get("state") or "").lower()
        self._current = s.get("current_version") or self._current
        # Only show target when update_available, else keep current to avoid false “update”
        if s.get("update_available"):
            self._target = s.get("target_version") or self._target
        else:
            self._target = self._current
        self._requires_commit = bool(s.get("requires_commit", False))
        prog = s.get("progress", None)
        self._progress = float(prog) if isinstance(prog, (int, float)) else None
