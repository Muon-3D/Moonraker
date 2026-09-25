"""muon_setup's update step (KAN-203, MR-4; spec 02 §5.8 and §8 test 11).

update_manager and its MuonOS updater are faked with the fields OtaDeploy
really reports (`version`, `remote_version`, `progress` in percent). The
reboot is simulated by building a second component on the stored state.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import pytest

from moonraker.components.muon_setup import update
from moonraker.utils.exceptions import ServerError

from muon_setup_fakes import Harness, run, state_with


class FakeUpdater:
    def __init__(self, version: str = "1.3.2", remote: str = "1.4.0") -> None:
        self.version = version
        self.remote = remote
        self.progress: Optional[float] = None
        self.refreshed = 0

    def get_update_status(self) -> Dict[str, Any]:
        return {"name": "MuonOS", "configured_type": "ota",
                "version": self.version, "remote_version": self.remote,
                "progress": self.progress, "is_valid": True}

    async def refresh(self) -> None:
        self.refreshed += 1


class FakeUpdateManager:
    def __init__(self, updater: FakeUpdater) -> None:
        self.updater = updater

    def get_updaters(self) -> Dict[str, Any]:
        return {"MuonOS": self.updater}


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


def harness(stored: Dict[str, Any], updater: FakeUpdater,
            upgrade: Any = None, synced: bool = True) -> Harness:
    h = Harness(stored=stored)
    h.server.components["update_manager"] = FakeUpdateManager(updater)
    h.server.components["klippy_connection"] = FakeKlippy()
    h.server.components["internal_transport"].methods[
        "machine.update.upgrade"] = upgrade or (lambda args: "ok")
    h.setup._live["clock"]["synced"] = synced
    return h


@pytest.fixture(autouse=True)
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update, "PROGRESS_POLL", 0.01)
    monkeypatch.setattr(update, "REBOOT_WAIT", 0.05)
    monkeypatch.setattr(update, "VERSION_POLL", 0.01)
    monkeypatch.setattr(update, "VERSION_WAIT", 1.0)


class TestVisibility:
    @pytest.mark.parametrize("why", ["no_internet", "no_update", "no_clock"])
    def test_update_hides_when_it_comes_up_without_what_it_needs(self, why: str):
        updater = FakeUpdater(remote="1.3.2" if why == "no_update" else "1.4.0")
        stored = at_update(internet=False if why == "no_internet" else True)
        stored["steps"]["name"]["status"] = "pending"
        stored["cursor"] = "name"

        async def go():
            h = await harness(stored, updater, synced=why != "no_clock").start()
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
            h = await harness(stored, FakeUpdater()).start()
            h.doc["steps"]["name"]["status"] = "done"
            h.setup.advance()
            return h
        h = run(go())
        assert h.doc["cursor"] == "update"
        assert h.doc["steps"]["update"]["current"] == "1.3.2"
        assert h.doc["steps"]["update"]["available"] == "1.4.0"


class TestLaterAndRefusals:
    def test_later_skips_the_step(self):
        async def go():
            h = await harness(at_update(), FakeUpdater()).start()
            return await h.post("/update", {"rev": 5, "action": "later"})
        result = run(go())
        assert result["state"]["steps"]["update"]["status"] == "skipped"
        assert result["state"]["cursor"] == "remote"

    def test_install_without_an_update_is_invalid(self):
        async def go():
            h = await harness(at_update(), FakeUpdater(remote="1.3.2")).start()
            return await h.post("/update", {"rev": 5, "action": "install"})
        assert run(go())["error"]["code"] == "invalid_step"

    def test_install_without_a_synced_clock_is_clock_unsynced(self):
        async def go():
            h = await harness(at_update(), FakeUpdater(), synced=False).start()
            return await h.post("/update", {"rev": 5, "action": "install"})
        assert run(go())["error"]["code"] == "clock_unsynced"

    def test_install_while_printing_is_printer_busy(self):
        async def go():
            h = await harness(at_update(), FakeUpdater()).start()
            h.server.components["klippy_connection"].printing = True
            return await h.post("/update", {"rev": 5, "action": "install"})
        assert run(go())["error"]["code"] == "printer_busy"

    def test_an_unknown_action_is_invalid(self):
        async def go():
            h = await harness(at_update(), FakeUpdater()).start()
            return await h.post("/update", {"rev": 5, "action": "now"})
        assert run(go())["error"]["code"] == "invalid_step"


class TestInstall:
    def test_install_runs_the_upgrade_path_and_mirrors_progress(self):
        updater = FakeUpdater()
        seen: List[float] = []
        started = asyncio.Event()

        async def upgrade(args: Dict[str, Any]) -> str:
            started.set()
            for pct in (10.0, 42.0, 99.0):
                updater.progress = pct
                await asyncio.sleep(0.05)
            return "ok"

        async def go():
            h = await harness(at_update(), updater, upgrade).start()
            result = await h.post("/update", {"rev": 5, "action": "install"})
            op = result["state"]["op"]
            assert op["kind"] == "update_install"
            assert op["target"] == "1.4.0"
            await asyncio.wait_for(started.wait(), 1)
            # Everything else is busy while it installs.
            busy = await h.post("/skip", {"rev": h.doc["rev"], "step": "remote"})
            assert busy["error"]["code"] == "busy"
            for _ in range(40):
                if h.doc["op"] and h.doc["op"].get("phase") == "rebooting":
                    break
                if h.doc["op"] and h.doc["op"].get("progress") is not None:
                    seen.append(h.doc["op"]["progress"])
                await asyncio.sleep(0.01)
            calls = h.server.components["internal_transport"].calls
            assert [c for c in calls if c[0] == "machine.update.upgrade"] == [
                ("machine.update.upgrade", {"name": "MuonOS"})]
            # The printer reboots: Moonraker shuts down mid-operation, and the
            # op with its frozen target must still be stored for the next boot.
            await h.setup.close()
            return h
        h = run(go())
        assert 0.42 in seen
        assert h.stored()["op"]["target"] == "1.4.0"

    def test_an_upgrade_refused_while_printing_is_printer_busy(self):
        async def upgrade(args: Dict[str, Any]) -> str:
            raise ServerError("Update Refused: Klippy is printing", 503)

        async def go():
            h = await harness(at_update(), FakeUpdater(), upgrade).start()
            await h.post("/update", {"rev": 5, "action": "install"})
            await h.setup.drain()
            return h
        step = run(go()).doc["steps"]["update"]
        assert step["status"] == "pending"
        assert step["error"]["code"] == "printer_busy"

    def test_no_reboot_and_the_old_version_is_update_failed(self):
        """The install said done but nothing rebooted and nothing changed."""
        async def go():
            h = await harness(at_update(), FakeUpdater()).start()
            await h.post("/update", {"rev": 5, "action": "install"})
            await h.setup.drain()
            return h
        h = run(go())
        assert h.doc["op"] is None
        assert h.doc["steps"]["update"]["error"]["code"] == "update_failed"


class TestAfterTheReboot:
    """02 §8 test 11: a version that matches the target after the reboot is
    done, and a rollback is update_failed."""

    def _stored(self) -> Dict[str, Any]:
        stored = at_update()
        stored["op"] = {"kind": "update_install", "id": "op_1", "started": 1.0,
                        "phase": "rebooting", "progress": 1.0,
                        "target": "1.4.0"}
        return stored

    def test_the_target_version_running_is_done(self):
        async def go():
            h = await harness(self._stored(),
                              FakeUpdater(version="1.4.0", remote="1.4.0")).start()
            await h.setup.drain()
            return h
        h = run(go())
        assert h.doc["op"] is None
        step = h.doc["steps"]["update"]
        assert step["status"] == "done"
        assert step["current"] == "1.4.0"
        assert step["error"] is None
        assert h.doc["cursor"] == "remote"

    def test_the_old_version_running_is_a_rollback(self):
        async def go():
            h = await harness(self._stored(), FakeUpdater(version="1.3.2")).start()
            await h.setup.drain()
            return h
        step = run(go()).doc["steps"]["update"]
        assert step["status"] == "pending"
        assert step["error"]["code"] == "update_failed"

    def test_the_target_is_the_one_frozen_at_install_not_todays(self):
        """KAN-358's lesson: target_version moves mid-commit. If the updater
        now offers 1.5.0 while 1.3.2 still runs, that is still a rollback of
        1.4.0, not an install of 1.5.0 pending."""
        async def go():
            h = await harness(self._stored(),
                              FakeUpdater(version="1.3.2", remote="1.5.0")).start()
            await h.setup.drain()
            return h
        step = run(go()).doc["steps"]["update"]
        assert step["error"]["code"] == "update_failed"
        assert "1.4.0" in step["error"]["message"]

    def test_it_waits_for_update_manager_to_read_the_version(self):
        updater = FakeUpdater(version="?", remote="?")

        async def go():
            h = await harness(self._stored(), updater).start()
            assert h.doc["op"]["phase"] == "verifying"
            busy = await h.post("/skip", {"rev": h.doc["rev"], "step": "remote"})
            assert busy["error"]["code"] == "busy"
            updater.version = updater.remote = "1.4.0"
            await h.setup.drain()
            return h
        assert run(go()).doc["steps"]["update"]["status"] == "done"
