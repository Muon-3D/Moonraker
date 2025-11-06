# OTA Image Deployment for Moonraker Update Manager
# Component-to-component version (no HTTP self-calls)
# License: GNU GPLv3 (same as Moonraker components)

from __future__ import annotations
import asyncio
from typing import Any, Dict, Optional, cast

from .base_deploy import BaseDeploy

POLL_SECS = 0.75
PROGRESS_IDLE_TIMEOUT = 60.0
MAX_CONSECUTIVE_ERRORS = 5

PROGRESS_ANNOUNCE_STEP = 0.5
REBOOT_NOTICE_PCT = 98.5

# New: near-end behavior + preemptive notice window
REBOOT_SAFETY_BAND = 1.0        # start “near end” at (REBOOT_NOTICE_PCT - band)
NEAR_END_MIN_SLEEP = 0.2        # tighten polling near the end
REBOOT_PRENOTICE_SECS = 2.5     # if ETA < this, announce reboot now

ETA_WINDOW_SECS   = 30.0   # history used for slope fit
ETA_MIN_DPCT      = 1.0    # require >=1.0% movement to trust ETA
ETA_SMOOTHING     = 0.25   # 0..1, higher = more responsive, lower = steadier
ETA_MAX_JUMP_SECS = 45.0   # clamp per-update ETA change (seconds)

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
            await self._aux().ota_check_server()
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
        """Start an image update; adaptive polling with spinner/bar/ETA and preemptive reboot notice."""
        self.notify_status("Starting OS image update… device may reboot.")
        aux = self._aux()
        await aux.ota_start()

        last_progress: Optional[float] = None
        last_announced_pct: Optional[float] = None
        last_state: Optional[str] = None
        last_change_time = asyncio.get_event_loop().time()
        consecutive_errors = 0
        reboot_announced = False

        # ETA over a short rolling window (keeps it responsive)
        progress_history: list[tuple[float, float]] = []  # [(time, pct)]

        # Spinner + progress bar
        spinner = ['|', '/', '-', '\\']
        spin_idx = 0
        bar_len = 20

        smoothed_eta_secs: Optional[float] = None

        try:
            while True:
                try:
                    s = await aux.ota_status()
                    self._status = s
                    self._map_status(s)
                    consecutive_errors = 0

                    self.cmd_helper.notify_update_refreshed()

                    pct = self._progress
                    st = (self._state or "").lower()
                    now = asyncio.get_event_loop().time()

                    # Track state/progress changes
                    if pct != last_progress or st != last_state:
                        last_change_time = now
                        last_progress = pct
                        last_state = st

                    # If backend reports explicit error+failed, surface immediately
                    err_msg = self._status.get("error") or ""
                    if err_msg and st == "failed":
                        self.notify_status(f"✖ OTA failed: {err_msg}", is_complete=True)
                        raise self.server.error(err_msg)

                    # If we see 'committing', we know reboot is imminent—announce before leaving
                    if st == "committing" and not reboot_announced:
                        self.notify_status("⏳ Update installed. Preparing to reboot into the new system…", is_complete=True)
                        return True

                    # Terminal states handled cleanly
                    if st in ("idle", "failed"):
                        break

                    # Installing → drive UI
                    if st == "installing" and pct is not None:
                        # Maintain short ETA window (15s)
                        progress_history.append((now, pct))
                        progress_history = [(t, p) for (t, p) in progress_history if now - t <= 15.0]

                        # Compute ETA if possible
                        eta_secs: Optional[float] = None

                        # keep last N seconds of samples
                        progress_history.append((now, pct))
                        progress_history = [(t, p) for (t, p) in progress_history if now - t <= ETA_WINDOW_SECS]

                        if len(progress_history) >= 3:
                            # linear regression of pct over time → slope (pct/sec)
                            import math
                            n = len(progress_history)
                            sum_t = sum(t for t, _ in progress_history)
                            sum_p = sum(p for _, p in progress_history)
                            sum_tt = sum(t*t for t, _ in progress_history)
                            sum_tp = sum(t*p for t, p in progress_history)
                            denom = (n * sum_tt - sum_t * sum_t)
                            if denom != 0:
                                slope = (n * sum_tp - sum_t * sum_p) / denom  # % per second
                                moved = progress_history[-1][1] - progress_history[0][1]
                                if slope > 0 and moved >= ETA_MIN_DPCT:
                                    remaining = max(0.0, 100.0 - pct)
                                    inst_eta = remaining / slope
                                    # EMA smoothing + clamp jumps
                                    if smoothed_eta_secs is None:
                                        smoothed_eta_secs = inst_eta
                                    else:
                                        prev = smoothed_eta_secs
                                        candidate = prev * (1.0 - ETA_SMOOTHING) + inst_eta * ETA_SMOOTHING
                                        # clamp per-update jump
                                        delta = max(-ETA_MAX_JUMP_SECS, min(ETA_MAX_JUMP_SECS, candidate - prev))
                                        smoothed_eta_secs = prev + delta
                                    eta_secs = smoothed_eta_secs

                        # PREEMPTIVE REBOOT NOTICE: if ETA says reboot is < X seconds away,
                        # announce now so the line lands before Moonraker goes down.
                        if eta_secs is not None and eta_secs <= REBOOT_PRENOTICE_SECS and not reboot_announced:
                            reboot_announced = True
                            self.notify_status("⏳ Update installed. Preparing to reboot into the new system…", is_complete=True)
                            return True

                        # Secondary threshold safety: if we actually hit ≥ REBOOT_NOTICE_PCT, announce too.
                        if pct >= REBOOT_NOTICE_PCT and not reboot_announced:
                            reboot_announced = True
                            self.notify_status("⏳ Update installed. Preparing to reboot into the new system…", is_complete=True)
                            return True

                        # Otherwise, keep logging styled progress (throttled)
                        if (last_announced_pct is None) or (pct - last_announced_pct >= PROGRESS_ANNOUNCE_STEP):
                            spin_char = spinner[spin_idx % len(spinner)]
                            spin_idx += 1
                            filled_len = int(bar_len * pct / 100)
                            bar = "█" * filled_len + "·" * (bar_len - filled_len)

                            eta_str = ""
                            if eta_secs is not None and eta_secs > 5:
                                mins, secs = divmod(int(eta_secs), 60)
                                eta_str = f" (≈{mins}m {secs:02d}s)" if mins > 0 else f" (≈{secs}s)"

                            self.notify_status(f"Installing {bar} {pct:5.1f}%{eta_str}")
                            last_announced_pct = pct

                    # Stall detection (covers long gaps or comms loss)
                    if asyncio.get_event_loop().time() - last_change_time > PROGRESS_IDLE_TIMEOUT:
                        self._warnings.append("No progress reported for a while; assuming reboot or stall.")
                        break

                    # Near-end: tighten polling so we don’t miss the reboot window
                    if (last_progress is not None) and (last_progress >= (REBOOT_NOTICE_PCT - REBOOT_SAFETY_BAND)):
                        await asyncio.sleep(min(NEAR_END_MIN_SLEEP, POLL_SECS))
                    else:
                        await asyncio.sleep(POLL_SECS)

                except Exception as e:
                    # Don’t emit anything here—Moonraker may go down with the reboot.
                    # Just do bounded retries; if we were near end, we likely already pre-announced.
                    consecutive_errors += 1
                    if consecutive_errors > MAX_CONSECUTIVE_ERRORS:
                        self._warnings.append(f"Lost contact with OTA service: {e}")
                        break
                    await asyncio.sleep(POLL_SECS * 2)

        except Exception:
            # Likely reboot in progress; exit gracefully.
            pass

        # --- Final messages if we didn’t early-return ---
        st = (self._state or "").lower()
        err_msg = self._status.get("error") or ""

        if st == "failed" or err_msg:
            if err_msg:
                self.notify_status(f"✖ OTA failed: {err_msg}", is_complete=True)
            else:
                self.notify_status("✖ OTA failed (no error message)", is_complete=True)
            raise self.server.error(err_msg or "OTA failed")

        if st == "installing":
            # We didn’t pre-announce but stopped (stall/timeout); be transparent:
            self.notify_status("⏳ Update still in progress… device may reboot soon.", is_complete=False)
        else:
            # idle/committing, or we timed out after good progress
            self.notify_status("✔ Update initiated. The device may reboot to finish installation.", is_complete=True)

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
