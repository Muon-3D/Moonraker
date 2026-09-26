"""muon_setup's "Ready to print" step (KAN-203, MR-7; spec 02 §5.10).

Klippy is faked: an object list (so macros can be defined or not) and a
run_gcode that succeeds or raises the way klippy_apis does.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from moonraker.components.muon_setup import manifest, ready
from moonraker.utils.exceptions import ServerError

from muon_setup_fakes import Harness, run, state_with


class FakeKlippyConnection:
    def __init__(self) -> None:
        self.ready = True
        self.printing = False

    def is_ready(self) -> bool:
        return self.ready

    def is_printing(self) -> bool:
        return self.printing


class FakeKlippyApis:
    def __init__(self, macros: List[str]) -> None:
        self.objects = ["toolhead", "print_stats"] + [
            f"gcode_macro {m}" for m in macros]
        self.ran: List[str] = []
        self.fail_with: Optional[str] = None
        self.gate: Optional[asyncio.Event] = None
        self.print_state = "standby"

    async def get_object_list(self) -> List[str]:
        return list(self.objects)

    async def query_objects(self, objects: Dict[str, Any]) -> Dict[str, Any]:
        assert objects == {"print_stats": ["state"]}
        return {"print_stats": {"state": self.print_state}}

    async def run_gcode(self, script: str) -> str:
        self.ran.append(script)
        if self.gate is not None:
            await self.gate.wait()
        if self.fail_with is not None:
            raise ServerError(self.fail_with, 400)
        return "ok"


def at_ready(**items: str) -> Dict[str, Any]:
    stored = state_with(
        language={"status": "done", "value": "en"},
        network={"status": "skipped"}, name={"status": "done"},
        update={"status": "hidden"}, remote={"status": "done", "mode": "local"})
    for state in stored["steps"]["ready"]["items"]:
        if state["id"] in items:
            state["status"] = items[state["id"]]
    return stored


def harness(stored: Dict[str, Any], macros: Optional[List[str]] = None,
            **options: str) -> Harness:
    h = Harness(stored=stored, options=options)
    h.server.components["klippy_connection"] = FakeKlippyConnection()
    h.server.components["klippy_apis"] = FakeKlippyApis(
        ["MUON_SELF_TEST"] if macros is None else macros)
    return h


def post(h: Harness, item: str, action: str, kind: str = "panel") -> Any:
    return h.post("/ready", {"rev": h.doc["rev"], "item": item,
                             "action": action}, kind=kind)


class TestItems:
    def test_confirming_the_clips_and_passing_the_self_test_finishes_it(self):
        async def go():
            h = await harness(at_ready()).start()
            assert h.doc["cursor"] == "ready"
            confirm = await post(h, "transport_clips", "confirm")
            assert confirm["ok"] is True
            assert confirm["state"]["steps"]["ready"]["status"] == "pending"
            start = await post(h, "self_test", "start")
            assert start["state"]["op"]["kind"] == "ready_item"
            assert start["state"]["op"]["item"] == "self_test"
            await h.setup.drain()
            return h
        h = run(go())
        assert h.server.components["klippy_apis"].ran == ["MUON_SELF_TEST"]
        ready_step = h.doc["steps"]["ready"]
        assert [i["status"] for i in ready_step["items"]] == [
            "done", "done", "pending"]
        # load_filament is optional, so the step is done without it.
        assert ready_step["status"] == "done"
        assert h.doc["cursor"] == "finish"

    def test_a_failing_self_test_says_why_and_can_be_run_again(self):
        async def go():
            h = await harness(at_ready(transport_clips="done")).start()
            h.server.components["klippy_apis"].fail_with = "Endstop x still triggered"
            await post(h, "self_test", "start")
            await h.setup.drain()
            item = h.doc["steps"]["ready"]["items"][1]
            assert item["status"] == "failed"
            assert item["error"] == {
                "code": "self_test_failed",
                "message": "Endstop x still triggered",
                "detail": {"gcode_error": "Endstop x still triggered"}}
            assert h.doc["steps"]["ready"]["status"] == "pending"
            h.server.components["klippy_apis"].fail_with = None
            await post(h, "self_test", "start")
            await h.setup.drain()
            return h
        h = run(go())
        assert h.doc["steps"]["ready"]["items"][1]["status"] == "done"
        assert h.doc["steps"]["ready"]["status"] == "done"

    def test_a_running_macro_makes_every_other_write_busy(self):
        async def go():
            h = await harness(at_ready(transport_clips="done")).start()
            apis = h.server.components["klippy_apis"]
            apis.gate = asyncio.Event()
            start = await post(h, "self_test", "start")
            assert start["state"]["op"] == {
                "kind": "ready_item", "id": start["state"]["op"]["id"],
                "started": start["state"]["op"]["started"],
                "phase": "running", "progress": None, "item": "self_test"}
            busy = await post(h, "load_filament", "confirm")
            assert busy["error"]["code"] == "busy"
            apis.gate.set()
            await h.setup.drain()
        run(go())

    def test_a_panel_flow_item_is_confirmed_once_muonui_has_run_it(self):
        async def go():
            h = await harness(at_ready()).start()
            return await post(h, "load_filament", "confirm")
        items = run(go())["state"]["steps"]["ready"]["items"]
        assert items[2]["status"] == "done"

    @pytest.mark.parametrize("item,action", [
        ("transport_clips", "start"), ("self_test", "confirm"),
        ("no_such_item", "confirm"), ("self_test", "run"),
    ])
    def test_the_wrong_action_or_item_is_invalid(self, item: str, action: str):
        async def go():
            h = await harness(at_ready()).start()
            return await post(h, item, action)
        assert run(go())["error"]["code"] == "invalid_step"

    def test_skipping_an_item_does_not_count_as_doing_it(self):
        async def go():
            h = await harness(at_ready(transport_clips="done")).start()
            return await post(h, "self_test", "skip", kind="hotspot")
        result = run(go())
        assert result["state"]["steps"]["ready"]["items"][1]["status"] == "skipped"
        assert result["state"]["steps"]["ready"]["status"] == "pending"


class TestMotionGuards:
    """02 §5.10: the self-test moves the printer."""

    def test_the_self_test_waits_for_the_transport_clips(self):
        async def go():
            h = await harness(at_ready()).start()
            result = await post(h, "self_test", "start")
            return h, result
        h, result = run(go())
        assert result["error"]["code"] == "invalid_step"
        assert result["error"]["detail"]["pending"] == ["transport_clips"]
        assert h.server.components["klippy_apis"].ran == []

    @pytest.mark.parametrize("state", ["printing", "paused"])
    def test_nothing_moves_over_a_print_running_or_paused(self, state: str):
        async def go():
            h = await harness(at_ready(transport_clips="done")).start()
            h.server.components["klippy_apis"].print_state = state
            return h, await post(h, "self_test", "start")
        h, result = run(go())
        assert result["error"]["code"] == "printer_busy"
        assert h.server.components["klippy_apis"].ran == []

    def test_the_macro_is_checked_again_at_start(self):
        """Defined when the step loaded, gone by the time of the press."""
        async def go():
            h = await harness(at_ready(transport_clips="done")).start()
            apis = h.server.components["klippy_apis"]
            apis.objects.remove("gcode_macro MUON_SELF_TEST")
            return h, await post(h, "self_test", "start")
        h, result = run(go())
        assert result["error"]["code"] == "invalid_step"
        assert h.server.components["klippy_apis"].ran == []

    def test_a_phone_gets_403_even_while_busy(self):
        """The caller is checked before busy, stale_rev or Klipper."""
        async def go():
            h = await harness(at_ready()).start()
            h.doc["op"] = {"kind": "join", "id": "op_x", "started": 0.0,
                           "phase": "dhcp", "progress": None}
            with pytest.raises(ServerError) as info:
                await h.post("/ready", {"rev": 0, "item": "self_test",
                                        "action": "start"}, kind="hotspot")
            assert info.value.status_code == 403
        run(go())


class TestGuards:
    @pytest.mark.parametrize("kind", ["hotspot", "lan"])
    @pytest.mark.parametrize("action,item", [
        ("start", "self_test"), ("confirm", "transport_clips")])
    def test_start_and_confirm_are_panel_only(self, kind: str, action: str,
                                              item: str):
        async def go():
            h = await harness(at_ready()).start()
            with pytest.raises(ServerError) as info:
                await post(h, item, action, kind=kind)
            assert info.value.status_code == 403
            assert h.doc["steps"]["ready"]["items"][0]["status"] == "pending"
        run(go())

    def test_nothing_starts_while_printing(self):
        async def go():
            h = await harness(at_ready(transport_clips="done")).start()
            h.server.components["klippy_connection"].printing = True
            return h, await post(h, "self_test", "start")
        h, result = run(go())
        assert result["error"]["code"] == "printer_busy"
        assert h.server.components["klippy_apis"].ran == []

    def test_nothing_starts_before_klippy_is_ready(self):
        async def go():
            h = await harness(at_ready(transport_clips="done")).start()
            h.server.components["klippy_connection"].ready = False
            return await post(h, "self_test", "start")
        assert run(go())["error"]["code"] == "printer_not_ready"

    def test_the_step_is_closed_until_the_cursor_reaches_it(self):
        async def go():
            h = await harness(state_with(
                language={"status": "done", "value": "en"})).start()
            return await post(h, "transport_clips", "confirm")
        assert run(go())["error"]["code"] == "invalid_step"


class TestUndefinedMacros:
    def test_a_macro_klipper_does_not_define_is_hidden_not_required(self):
        """Until the hardware team's MUON_SELF_TEST exists, confirming the
        clips is enough to be ready."""
        async def go():
            h = await harness(at_ready(), macros=[]).start()
            await ready.refresh_macros(h.setup)
            assert h.doc["steps"]["ready"]["items"][1]["status"] == "hidden"
            hidden = await post(h, "self_test", "start")
            assert hidden["error"]["code"] == "invalid_step"
            return await post(h, "transport_clips", "confirm")
        result = run(go())
        assert result["state"]["steps"]["ready"]["status"] == "done"

    def test_it_comes_back_when_the_macro_is_defined(self):
        async def go():
            h = await harness(at_ready(), macros=[]).start()
            await ready.refresh_macros(h.setup)
            h.server.components["klippy_apis"].objects.append(
                "gcode_macro muon_self_test")
            await ready.refresh_macros(h.setup)
            return h
        assert run(go()).doc["steps"]["ready"]["items"][1]["status"] == "pending"

    def test_hiding_a_macro_does_not_finish_a_skipped_step(self):
        """The owner skipped `ready`; a macro disappearing later must not
        quietly turn that skip into `done`."""
        async def go():
            stored = at_ready(transport_clips="done")
            stored["steps"]["ready"]["status"] = "skipped"
            stored["cursor"] = "finish"
            h = harness(stored, macros=[])
            h.server.components["klippy_connection"].ready = False
            await h.start()
            h.server.components["klippy_connection"].ready = True
            await ready.refresh_macros(h.setup)
            return h
        h = run(go())
        assert h.doc["steps"]["ready"]["items"][1]["status"] == "hidden"
        assert h.doc["steps"]["ready"]["status"] == "skipped"

    def test_the_macro_check_runs_when_the_state_loads(self):
        """Not only on klippy_ready: a Moonraker restart with Klippy already
        up must still hide an undefined macro."""
        async def go():
            return await harness(at_ready(), macros=[]).start()
        h = run(go())
        assert h.doc["steps"]["ready"]["items"][1]["status"] == "hidden"
        assert h.stored()["steps"]["ready"]["items"][1]["status"] == "hidden"

    def test_nothing_is_hidden_while_klippy_cannot_say(self):
        async def go():
            h = harness(at_ready(), macros=[])
            h.server.components["klippy_connection"].ready = False
            await h.start()
            await ready.refresh_macros(h.setup)
            return h
        assert run(go()).doc["steps"]["ready"]["items"][1]["status"] == "pending"


class TestAfterSetupCard:
    def test_the_card_keeps_ready_until_its_required_items_are_done(self):
        """Stopping halfway (clips confirmed, the self-test failed) must not
        drop `ready` off the "Finish setup" card (02 §5.10)."""
        async def go():
            h = await harness(at_ready()).start()
            await h.post("/skip", {"rev": h.doc["rev"], "step": "ready"})
            await h.post("/finish", {"rev": h.doc["rev"]})
            await h.setup.drain()
            await post(h, "transport_clips", "confirm")
            assert h.doc["steps"]["ready"]["status"] == "skipped"
            h.server.components["klippy_apis"].fail_with = "probe failed"
            await post(h, "self_test", "start")
            await h.setup.drain()
            return h
        h = run(go())
        assert h.doc["steps"]["ready"]["status"] == "skipped"
        assert h.doc["steps"]["ready"]["items"][1]["status"] == "failed"

    def test_a_done_step_is_never_taken_back(self):
        async def go():
            h = await harness(at_ready()).start()
            await post(h, "transport_clips", "confirm")
            await post(h, "self_test", "start")
            await h.setup.drain()
            assert h.doc["steps"]["ready"]["status"] == "done"
            await h.post("/finish", {"rev": h.doc["rev"]})
            await h.setup.drain()
            h.server.components["klippy_apis"].fail_with = "probe failed"
            await post(h, "self_test", "start")
            await h.setup.drain()
            return h
        assert run(go()).doc["steps"]["ready"]["status"] == "done"


class TestAfterSetup:
    def test_the_card_can_finish_a_skipped_ready_step(self):
        """E4: after `complete`, the card reopens `ready`, and finishing its
        items takes it off the card."""
        async def go():
            h = await harness(at_ready()).start()
            await h.post("/skip", {"rev": h.doc["rev"], "step": "ready"})
            await h.post("/finish", {"rev": h.doc["rev"]})
            await h.setup.drain()
            assert h.doc["steps"]["ready"]["status"] == "skipped"
            await post(h, "transport_clips", "confirm")
            await post(h, "self_test", "start")
            await h.setup.drain()
            return h
        h = run(go())
        assert h.doc["state"] == "complete"
        assert h.doc["steps"]["ready"]["status"] == "done"
        assert h.doc["cursor"] == "finish"


def test_a_shipped_manifest_drives_the_items(tmp_path: Path):
    shipped = {"version": 1, "items": [
        {"id": "remove_foam", "kind": "confirm", "required": True,
         "title_key": "setup.ready.foam.title",
         "body_key": "setup.ready.foam.body"}]}
    path = tmp_path / "ready.json"
    path.write_text(json.dumps(shipped), encoding="utf-8")
    stored = at_ready()
    stored["steps"]["ready"]["items"] = [
        {"id": "remove_foam", "status": "pending", "error": None}]

    async def go():
        h = await harness(stored, ready_manifest=str(path)).start()
        return await post(h, "remove_foam", "confirm")
    assert run(go())["state"]["steps"]["ready"]["status"] == "done"
    assert manifest.load(str(path)) == shipped
