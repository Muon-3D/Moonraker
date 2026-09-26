"""muon_setup's update step (KAN-203, MR-4; spec 02 §5.8 and §8 test 11).

Aux GET /update/status is the source of truth (02 §5.8), faked with the
fields OtaDeploy maps (`state`, `current_version`, `target_version`,
`update_available`, `progress` in percent). update_manager is faked too, and
reports "?" after a boot the way OtaDeploy does before its weekly refresh --
nothing may be judged from it. The reboot is simulated by building a second
component on the stored state.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import pytest

from moonraker.components.muon_setup import update
from moonraker.utils.exceptions import ServerError

from muon_setup_fakes import Harness, fresh_aux, run, state_with


class AuxOta:
    """The Aux OTA status, moved on by the test like the real install."""

    def __init__(self, current: str = "1.3.2", target: str = "1.4.0",
                 available: bool = True) -> None:
        self.status: Dict[str, Any] = {
            "state": "idle", "current_version": current,
            "target_version": target, "update_available": available,
            "progress": None,
        }
        self.checks: List[Any] = []

    def get(self, body: Any) -> Dict[str, Any]:
        return dict(self.status)

    def check(self, body: Any) -> Dict[str, Any]:
        self.checks.append(body)
        return {"state": "idle"}


class StaleUpdater:
    """update_manager's MuonOS updater before its weekly refresh."""

    def get_update_status(self) -> Dict[str, Any]:
        return {"name": "MuonOS", "version": "?", "remote_version": "?",
                "progress": None, "is_valid": True}

    async def refresh(self) -> None:
        pass


class FakeUpdateManager:
    def get_updaters(self) -> Dict[str, Any]:
        return {"MuonOS": StaleUpdater()}


class FakeKlippy:
    def __init__(self) -> None:
        self.printing = False

    def is_printing(self) -> bool:
        return self.printing


def at_update(**network: Any) -> Dict[str, Any]:
    """A stored state with the cursor on `update`: joined, with internet."""
    return state_with(
        language={"status": "done", "value": "en"},
        network=dict({"status": "done", "kind": "wifi", "ssid": "HomeWiFi",
                      "addresses": ["192.168.1.37"], "internet": True},
                     **network),
        name={"status": "done", "value": "Walnut"})


def harness(stored: Dict[str, Any], ota: AuxOta, upgrade: Any = None,
            synced: bool = True) -> Harness:
    aux = fresh_aux(**{
        "GET /update/status": ota.get,
        "POST /update/check": ota.check,
        # MR-2's clock refresh reads this; `synced` must survive it.
        "GET /time": {"epoch_ms": 1790251200000, "ntp_synced": synced,
                      "tz": "Europe/London"},
    })
    h = Harness(stored=stored, aux=aux)
    h.server.components["update_manager"] = FakeUpdateManager()
    h.server.components["klippy_connection"] = FakeKlippy()
    h.server.components["internal_transport"].methods[
        "machine.update.upgrade"] = upgrade or (lambda args: "ok")
    return h


@pytest.fixture(autouse=True)
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update, "PROGRESS_POLL", 0.01)
    monkeypatch.setattr(update, "FOLLOW_LIMIT", 2.0)
    monkeypatch.setattr(update, "BOOT_LIMIT", 2.0)


class TestVisibility:
    @pytest.mark.parametrize("why", ["no_internet", "no_update", "no_clock"])
    def test_update_hides_when_it_comes_up_without_what_it_needs(self, why: str):
        ota = AuxOta(available=why != "no_update")
        stored = at_update(internet=False if why == "no_internet" else True)
        stored["steps"]["name"]["status"] = "pending"
        stored["cursor"] = "name"

        async def go():
            h = await harness(stored, ota, synced=why != "no_clock").start()
            h.doc["steps"]["name"]["status"] = "done"
            h.setup.advance()
            return h
        h = run(go())
        assert h.doc["steps"]["update"]["status"] == "hidden"
        assert h.doc["cursor"] == "remote"

    def test_update_shows_with_internet_an_update_and_a_clock(self):
        stored = at_update()
        stored["steps"]["name"]["status"] = "pending"
        stored["cursor"] = "name"

        async def go():
            h = await harness(stored, AuxOta()).start()
            h.doc["steps"]["name"]["status"] = "done"
            h.setup.advance()
            return h
        h = run(go())
        assert h.doc["cursor"] == "update"
        assert h.doc["steps"]["update"]["current"] == "1.3.2"
        assert h.doc["steps"]["update"]["available"] == "1.4.0"

    def test_the_update_check_waits_for_its_answer(self):
        """02 §5.6 step 4: {"wait": true}, then the status is read again."""
        ota = AuxOta(available=False)

        async def go():
            h = await harness(at_update(), ota).start()
            ota.status.update(update_available=True, target_version="1.5.0")
            await update.check_for_update(h.setup)
            return h
        h = run(go())
        assert ota.checks == [{"wait": True}]
        assert update.versions(h.setup)["available"] == "1.5.0"


class TestLaterAndRefusals:
    def test_later_skips_the_step(self):
        async def go():
            h = await harness(at_update(), AuxOta()).start()
            return await h.post("/update", {"rev": 5, "action": "later"})
        result = run(go())
        assert result["state"]["steps"]["update"]["status"] == "skipped"
        assert result["state"]["cursor"] == "remote"

    def test_install_without_an_update_is_invalid(self):
        async def go():
            h = await harness(at_update(), AuxOta(available=False)).start()
            return await h.post("/update", {"rev": 5, "action": "install"})
        assert run(go())["error"]["code"] == "invalid_step"

    def test_install_without_a_synced_clock_is_clock_unsynced(self):
        async def go():
            h = await harness(at_update(), AuxOta(), synced=False).start()
            return await h.post("/update", {"rev": 5, "action": "install"})
        assert run(go())["error"]["code"] == "clock_unsynced"

    def test_install_while_printing_is_printer_busy(self):
        async def go():
            h = await harness(at_update(), AuxOta()).start()
            h.server.components["klippy_connection"].printing = True
            return await h.post("/update", {"rev": 5, "action": "install"})
        assert run(go())["error"]["code"] == "printer_busy"

    def test_an_unknown_action_is_invalid(self):
        async def go():
            h = await harness(at_update(), AuxOta()).start()
            return await h.post("/update", {"rev": 5, "action": "now"})
        assert run(go())["error"]["code"] == "invalid_step"


def refused(code: Optional[str], status: int = 409) -> ServerError:
    exc = ServerError(f"refused ({code})", status)
    setattr(exc, "aux_code", code)
    return exc


class TestInstall:
    def test_install_follows_aux_and_ends_done_when_it_settles(self):
        """Progress is Aux's, in percent, and the verdict waits for Aux to
        settle -- not for OtaDeploy.update() to return."""
        ota = AuxOta()
        seen: List[float] = []
        started = asyncio.Event()

        async def upgrade(args: Dict[str, Any]) -> str:
            # OtaDeploy.update() gives up early; the install carries on.
            ota.status.update(state="installing", progress=10.0)
            started.set()
            return "ok"

        async def go():
            h = await harness(at_update(), ota, upgrade).start()
            result = await h.post("/update", {"rev": 5, "action": "install"})
            op = result["state"]["op"]
            assert op["kind"] == "update_install"
            assert op["target"] == "1.4.0"
            await asyncio.wait_for(started.wait(), 1)
            busy = await h.post("/skip", {"rev": h.doc["rev"], "step": "remote"})
            assert busy["error"]["code"] == "busy"
            for pct in (42.0, 99.0):
                ota.status["progress"] = pct
                for _ in range(20):
                    await asyncio.sleep(0.01)
                    if h.doc["op"] and h.doc["op"]["progress"] is not None:
                        seen.append(h.doc["op"]["progress"])
            assert h.doc["op"] is not None      # still following
            ota.status.update(state="idle", current_version="1.4.0",
                              update_available=False, progress=None)
            await asyncio.wait_for(h.setup.drain(), 2)
            calls = h.server.components["internal_transport"].calls
            assert [c for c in calls if c[0] == "machine.update.upgrade"] == [
                ("machine.update.upgrade", {"name": "MuonOS"})]
            return h
        h = run(go())
        assert 0.42 in seen
        assert h.doc["op"] is None
        assert h.doc["steps"]["update"]["status"] == "done"

    def test_a_reboot_mid_install_keeps_the_op_and_its_target(self):
        ota = AuxOta()

        async def upgrade(args: Dict[str, Any]) -> str:
            ota.status.update(state="rebooting", progress=100.0)
            return "ok"

        async def go():
            h = await harness(at_update(), ota, upgrade).start()
            await h.post("/update", {"rev": 5, "action": "install"})
            for _ in range(200):
                await asyncio.sleep(0.01)
                # Wait for the save, not just the in-memory change.
                if (h.stored().get("op") or {}).get("phase") == "rebooting":
                    break
            assert h.doc["op"]["phase"] == "rebooting"
            # The printer reboots: Moonraker shuts down mid-operation.
            await h.setup.close()
            return h
        h = run(go())
        assert h.stored()["op"]["target"] == "1.4.0"
        assert h.stored()["op"]["phase"] == "rebooting"

    @pytest.mark.parametrize("error,code", [
        (refused("printer_busy"), "printer_busy"),     # paused or busy, KAN-75
        (refused("busy"), "update_failed"),
        (refused("invalid_state"), "update_failed"),  # commit pending
        (ServerError("Update Refused: Klippy is printing", 503), "printer_busy"),
    ])
    def test_refusals_map_by_aux_code(self, error: ServerError, code: str):
        async def upgrade(args: Dict[str, Any]) -> str:
            raise error

        async def go():
            h = await harness(at_update(), AuxOta(), upgrade).start()
            await h.post("/update", {"rev": 5, "action": "install"})
            await h.setup.drain()
            return h
        step = run(go()).doc["steps"]["update"]
        assert step["status"] == "pending"
        assert step["error"]["code"] == code


class TestAfterTheBoot:
    """02 §8 test 11, judged from Aux, never from update_manager's `?`."""

    def _stored(self) -> Dict[str, Any]:
        stored = at_update()
        stored["op"] = {"kind": "update_install", "id": "op_1", "started": 1.0,
                        "phase": "rebooting", "progress": 1.0,
                        "target": "1.4.0"}
        return stored

    def test_the_target_version_running_is_done(self):
        """The review's blocking case: update_manager says `?`, Aux knows."""
        ota = AuxOta(current="1.4.0", target="1.4.0", available=False)

        async def go():
            h = await harness(self._stored(), ota).start()
            await h.setup.drain()
            return h
        h = run(go())
        assert h.doc["op"] is None
        step = h.doc["steps"]["update"]
        assert step["status"] == "done"
        assert step["current"] == "1.4.0"
        assert step["error"] is None
        assert h.doc["cursor"] == "remote"

    def test_a_commit_pending_boot_into_the_target_is_done(self):
        ota = AuxOta(current="1.4.0", target="1.4.0", available=False)
        ota.status["state"] = "commit_pending"

        async def go():
            h = await harness(self._stored(), ota).start()
            await h.setup.drain()
            return h
        assert run(go()).doc["steps"]["update"]["status"] == "done"

    def test_the_old_version_running_is_a_rollback(self):
        async def go():
            h = await harness(self._stored(), AuxOta(current="1.3.2")).start()
            await h.setup.drain()
            return h
        step = run(go()).doc["steps"]["update"]
        assert step["status"] == "pending"
        assert step["error"]["code"] == "update_failed"

    def test_the_target_is_the_one_frozen_at_install_not_todays(self):
        """target_version moves mid-commit (KAN-358). With 1.3.2 running and
        1.5.0 now on offer, 1.4.0 still rolled back."""
        ota = AuxOta(current="1.3.2", target="1.5.0")

        async def go():
            h = await harness(self._stored(), ota).start()
            await h.setup.drain()
            return h
        step = run(go()).doc["steps"]["update"]
        assert step["error"]["code"] == "update_failed"
        assert "1.4.0" in step["error"]["message"]

    def test_an_install_still_running_after_the_boot_is_followed(self):
        """Moonraker restarted mid-install: keep the op, keep mirroring."""
        ota = AuxOta()
        ota.status.update(state="installing", progress=60.0)

        async def go():
            h = await harness(self._stored(), ota).start()
            for _ in range(20):
                await asyncio.sleep(0.01)
            assert h.doc["op"] is not None
            assert h.doc["op"]["progress"] == 0.6
            busy = await h.post("/skip", {"rev": h.doc["rev"], "step": "remote"})
            assert busy["error"]["code"] == "busy"
            ota.status.update(state="idle", current_version="1.4.0")
            await asyncio.wait_for(h.setup.drain(), 2)
            return h
        assert run(go()).doc["steps"]["update"]["status"] == "done"

    def test_the_boot_verdict_moves_rev(self):
        """on_boot changes the phase, and that is a change like any other."""
        ota = AuxOta()
        ota.status["state"] = "installing"

        async def go():
            stored = self._stored()
            h = await harness(stored, ota).start()
            assert h.doc["rev"] > stored["rev"]
            await h.setup.close()
        run(go())
