"""muon_setup's core: the state document, its rules, and who may change it.

KAN-203, work package MR-1. The numbered tests are spec 02 §8's minimum set
(specs/m1-first-run-setup in Muon-3D/OrcaSlicer): 1-4, 7, 8 and 13 belong to
this package; 5, 6 and 9-12 arrive with the step packages that own those
endpoints.

Everything runs against the fakes in muon_setup_fakes.py: no server, no
sockets, no Aux API.
"""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from moonraker.common import RequestType, TransportType, WebRequest
from moonraker.components import muon_setup as pkg
from moonraker.components.muon_setup import caller, manifest, model, region
from moonraker.utils.exceptions import ServerError

from muon_setup_fakes import (
    GOOD_HEADERS, FakeAux, Harness, REGION_174, REGION_OPTIONS_174, fresh_aux,
    request, run, state_with,
)


# ==========================================================================
# 1. Fresh start and migration (01 §7)
# ==========================================================================

class TestFreshStartAndMigration:
    def test_a_new_printer_starts_new_at_language_and_saves_it(self):
        async def go():
            h = await Harness().start()
            state = await h.get()
            assert state["state"] == "new"
            assert state["cursor"] == "language"
            assert state["rev"] == 1
            # Saved on first start, so a reboot does not re-run the check.
            assert h.stored()["state"] == "new"
            return state
        state = run(go())
        assert [i["id"] for i in state["steps"]["ready"]["items"]] == [
            "transport_clips", "self_test", "load_filament"]

    @pytest.mark.parametrize("signal", [
        "marker", "saved_wifi", "connected_wifi_on_an_older_image",
        "fluidd_settings", "link",
    ])
    def test_a_printer_already_in_use_is_marked_complete_not_sent_to_setup(
        self, signal: str
    ):
        aux = fresh_aux()
        namespaces: Dict[str, Dict[str, Any]] = {}
        extra: Dict[str, Any] = {}
        if signal == "marker":
            aux.routes[("GET", "/setup")] = {
                "complete": True, "language": "en", "completed_at": None}
        elif signal == "saved_wifi":
            aux.routes[("GET", "/wifi/saved")] = [
                {"name": "HomeWiFi", "uuid": "u1", "device": None}]
        elif signal == "connected_wifi_on_an_older_image":
            del aux.routes[("GET", "/wifi/saved")]
            aux.routes[("GET", "/wifi/current")] = {"ssid": "HomeWiFi"}
        elif signal == "fluidd_settings":
            namespaces["fluidd"] = {"uiSettings": {"general": {"locale": "en"}}}
            aux.down = True  # no Aux needed for this one
        elif signal == "link":
            class Link:
                async def call(self, method: str, path: str) -> Dict[str, Any]:
                    assert (method, path) == ("GET", "/link")
                    return {"phase": "linked", "account": "a@b.c",
                            "connected": True}
            extra["muon_link"] = Link()

        async def go():
            h = Harness(aux=aux, namespaces=namespaces)
            h.server.components.update(extra)
            await h.start()
            return h
        h = run(go())
        state = h.setup.public_state()
        assert state["state"] == "complete"
        assert state["cursor"] == "finish"
        assert state["steps"]["language"]["source"] == "migrated"
        assert all(
            s["status"] == "done" for s in state["steps"].values()
        ), state["steps"]
        # Nothing was skipped, so no "Finish setup" card.
        assert model.card_steps(state) == []
        # A migrated printer has no marker to write.
        assert aux.posted("/setup") == []

    def test_an_image_without_the_newer_routes_reads_as_new(self):
        """Every signal route absent (404) means no signal, not "unknown":
        an image that has no marker route never wrote a marker."""
        aux = FakeAux({})

        async def go():
            return await Harness(aux=aux).start()
        assert run(go()).doc["state"] == "new"

    def test_while_aux_is_down_nothing_is_decided_or_stored(self, monkeypatch):
        """A printer in the field must never read `new`, even briefly: the
        panel's guard would send it into setup at boot."""
        monkeypatch.setattr(pkg, "STARTUP_WAIT", 0.05)
        monkeypatch.setattr(pkg, "MIGRATION_RETRY", 0.05)
        aux = fresh_aux()
        aux.down = True

        async def go():
            h = Harness(aux=aux)
            start = asyncio.ensure_future(h.setup._startup(poll=False))
            state = await h.get()
            assert state["state"] == "complete"
            assert "state" not in h.db.namespaces["muon_setup"]
            # Writes are refused with the Aux code until it is decided.
            result = await h.post("/goto", {"rev": 1, "step": "language"})
            assert result["ok"] is False
            assert result["error"]["code"] == "aux_unavailable"
            aux.down = False
            await asyncio.wait_for(start, 2)
            assert h.doc["state"] == "new"
            assert h.server.changes()[-1]["state"] == "new"
        run(go())

    def test_a_stored_state_is_loaded_not_migrated_again(self):
        stored = state_with(language={"status": "done", "value": "de"})
        aux = fresh_aux()
        aux.routes[("GET", "/setup")] = {"complete": True}

        async def go():
            return await Harness(stored=stored, aux=aux).start()
        h = run(go())
        assert h.doc["state"] == "in_progress"
        assert h.doc["cursor"] == "network"
        assert ("GET", "/setup", None) not in aux.calls

    def test_an_unknown_schema_version_is_complete_and_read_only(self):
        """02 §4: a downgrade never re-runs setup, and never writes over the
        newer build's state."""
        stored = {"version": 2, "rev": 9, "state": "in_progress"}

        async def go():
            h = await Harness(stored=stored).start()
            assert h.setup.public_state()["state"] == "complete"
            with pytest.raises(ServerError) as info:
                await h.post("/card/dismiss", {"rev": 1})
            assert info.value.status_code == 409
            assert h.stored() == stored
        run(go())

    def test_an_operation_cut_short_by_a_power_loss_is_marked_interrupted(self):
        stored = state_with(language={"status": "done", "value": "en"})
        stored["op"] = {"kind": "join", "id": "op_3", "started": 1.0,
                        "phase": "dhcp", "progress": None}

        async def go():
            h = await Harness(stored=stored).start()
            await h.setup.drain()
            return h
        h = run(go())
        assert h.doc["op"] is None
        assert h.doc["steps"]["network"]["error"] == {
            "code": "interrupted", "at_phase": "dhcp"}
        assert h.doc["steps"]["network"]["status"] == "pending"
        assert h.stored()["op"] is None

    def test_a_manifest_change_under_a_stored_state_keeps_known_items(
        self, tmp_path: Path
    ):
        stored = state_with()
        stored["steps"]["ready"]["items"][0]["status"] = "done"
        shipped = copy.deepcopy(manifest.DEFAULT_MANIFEST)
        shipped["items"] = [shipped["items"][0], {
            "id": "wipe_nozzle", "kind": "confirm", "required": False,
            "title_key": "setup.ready.wipe.title",
            "body_key": "setup.ready.wipe.body"}]
        path = tmp_path / "ready.json"
        path.write_text(json.dumps(shipped), encoding="utf-8")

        async def go():
            return await Harness(
                stored=stored, options={"ready_manifest": str(path)}).start()
        items = run(go()).doc["steps"]["ready"]["items"]
        assert items == [
            {"id": "transport_clips", "status": "done", "error": None},
            {"id": "wipe_nozzle", "status": "pending", "error": None},
        ]


# ==========================================================================
# 2. Order rules (01 §3)
# ==========================================================================

class TestOrderRules:
    def test_goto_forward_past_the_first_pending_step_is_invalid(self):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()
            result = await h.post("/goto", {"rev": 5, "step": "name"})
            assert result["ok"] is False
            assert result["error"]["code"] == "invalid_step"
            assert result["state"]["cursor"] == "network"
            assert h.doc["rev"] == 5
        run(go())

    def test_goto_back_to_a_done_step_moves_the_cursor_and_keeps_later_steps(
        self
    ):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"},
                network={"status": "skipped"})).start()
            assert h.doc["cursor"] == "name"
            result = await h.post("/goto", {"rev": 5, "step": "language"})
            assert result["ok"] is True
            assert result["state"]["cursor"] == "language"
            assert result["state"]["steps"]["network"]["status"] == "skipped"
            assert result["state"]["rev"] == 6
        run(go())

    @pytest.mark.parametrize("step", ["language", "name"])
    def test_language_and_name_cannot_be_skipped(self, step: str):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"},
                network={"status": "done"})).start()
            if step == "language":
                await h.post("/goto", {"rev": 5, "step": "language"})
            result = await h.post("/skip", {"rev": h.doc["rev"], "step": step})
            assert result["ok"] is False
            assert result["error"]["code"] == "not_skippable"
        run(go())

    def test_a_skip_advances_and_hides_update_without_internet(self):
        """01 §2: `update` is hidden when it becomes current with no internet,
        no update or no synced clock. With the network skipped, it has none."""
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()
            result = await h.post("/skip", {"rev": 5, "step": "network"})
            assert result["ok"] is True
            steps = result["state"]["steps"]
            assert steps["network"]["status"] == "skipped"
            assert result["state"]["cursor"] == "name"
            await h.post("/goto", {"rev": 6, "step": "name"})
            # "Keep" arrives with MR-2; stand in for it here.
            h.doc["steps"]["name"]["status"] = "done"
            h.setup.advance()
            assert h.doc["steps"]["update"]["status"] == "hidden"
            assert h.doc["cursor"] == "remote"
        run(go())

    def test_skipping_a_step_ahead_of_the_cursor_is_invalid(self):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()
            result = await h.post("/skip", {"rev": 5, "step": "remote"})
            assert result["error"]["code"] == "invalid_step"
        run(go())

    def test_a_new_skip_brings_a_dismissed_card_back(self):
        async def go():
            stored = state_with(language={"status": "done", "value": "en"})
            stored["card_dismissed"] = True
            h = await Harness(stored=stored).start()
            result = await h.post("/skip", {"rev": 5, "step": "network"})
            assert result["state"]["card_dismissed"] is False
        run(go())


# ==========================================================================
# 3. rev and the driver (01 §3, 02 §5.11)
# ==========================================================================

class TestRevAndDriver:
    def test_an_old_rev_gets_stale_rev_and_the_current_state(self):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()
            result = await h.post("/skip", {"rev": 4, "step": "network"})
            assert result == {
                "ok": False,
                "error": {"code": "stale_rev",
                          "message": "rev 4 is stale; current is 5",
                          "detail": {"current_rev": 5}},
                "state": h.setup.public_state(),
            }
            assert h.doc["steps"]["network"]["status"] == "pending"
        run(go())

    @pytest.mark.parametrize("bad", [None, "5", 5.0, True])
    def test_a_write_without_an_integer_rev_is_a_400(self, bad: Any):
        async def go():
            h = await Harness().start()
            body: Dict[str, Any] = {"step": "language"}
            if bad is not None:
                body["rev"] = bad
            with pytest.raises(ServerError) as info:
                await h.post("/goto", body)
            assert info.value.status_code == 400
        run(go())

    def test_a_driver_claim_and_its_renewals_never_change_rev(self):
        async def go():
            h = await Harness().start()
            body = {"rev": 1, "kind": "phone", "client_id": "b7f3-1"}
            first = await h.post("/driver", body, kind="hotspot")
            assert first["ok"] is True
            assert first["state"]["rev"] == 1
            assert first["state"]["driver"]["kind"] == "phone"
            assert first["state"]["driver"]["lapsed"] is False
            since = first["state"]["driver"]["since"]
            announced = len(h.server.changes())
            # A renewal with a stale rev still renews: the phone renews every
            # 10 s whatever else changed.
            renewed = await h.post("/driver", dict(body, rev=0), kind="hotspot")
            assert renewed["state"]["rev"] == 1
            assert renewed["state"]["driver"]["since"] == since
            assert renewed["state"]["driver"]["renewed"] >= since
            # Renewals are not announced; they would be noise every 10 s.
            assert len(h.server.changes()) == announced
        run(go())

    def test_a_claim_lapses_after_the_lease_but_the_panels_never_does(self):
        doc = {"kind": "phone", "client_id": "x", "since": 100.0,
               "renewed": 100.0}
        assert model.driver_public(doc, 30., now=129.0)["lapsed"] is False
        assert model.driver_public(doc, 30., now=131.0)["lapsed"] is True
        panel = dict(doc, kind="panel")
        assert model.driver_public(panel, 30., now=10_000.0)["lapsed"] is False

    def test_a_write_from_another_surface_takes_the_driver(self):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()
            await h.post("/driver", {"rev": 5, "kind": "phone",
                                     "client_id": "p1"}, kind="hotspot")
            result = await h.post("/skip", {"rev": 5, "step": "network"})
            assert result["state"]["driver"]["kind"] == "panel"
            assert result["state"]["rev"] == 6
        run(go())

    @pytest.mark.parametrize("kind,surface", [
        ("hotspot", "panel"), ("lan", "panel"), ("panel", "phone"),
    ])
    def test_a_caller_cannot_claim_another_surface(self, kind: str, surface: str):
        async def go():
            h = await Harness().start()
            with pytest.raises(ServerError) as info:
                await h.post("/driver", {"rev": 1, "kind": surface,
                                         "client_id": "c1"}, kind=kind)
            assert info.value.status_code == 403
        run(go())

    def test_the_first_write_moves_new_to_in_progress(self):
        async def go():
            h = await Harness().start()
            await h.post("/card/dismiss", {"rev": 1})
            assert h.doc["state"] == "in_progress"
        run(go())


# ==========================================================================
# 4. Operations: busy, and cancel (01 §3)
# ==========================================================================

class TestOperations:
    def test_a_second_write_during_a_join_is_busy_and_cancel_clears_it(self):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()
            started = asyncio.Event()
            cleaned_up: List[bool] = []

            async def runner(handle: pkg.OpHandle) -> None:
                await handle.update(phase="associating")
                started.set()
                try:
                    await asyncio.sleep(3600)
                except asyncio.CancelledError:
                    # MR-3 deletes the half-made profile here.
                    cleaned_up.append(True)
                    raise

            async def start_join(ctx: pkg.WriteContext) -> None:
                h.setup.start_op("join", runner, phase="saving")
                return None

            web = request("hotspot", "/server/muon/setup/network", {"rev": 5})
            result = await h.setup.write(web, start_join)
            assert result["ok"] is True
            assert result["state"]["op"]["kind"] == "join"
            assert result["state"]["op"]["phase"] == "saving"
            await asyncio.wait_for(started.wait(), 1)
            assert h.doc["op"]["phase"] == "associating"

            busy = await h.post("/skip", {"rev": h.doc["rev"], "step": "network"})
            assert busy["ok"] is False
            assert busy["error"]["code"] == "busy"

            # The driver renewal is not refused mid-join.
            renew = await h.post("/driver", {"rev": 0, "kind": "phone",
                                             "client_id": "p1"}, kind="hotspot")
            assert renew["ok"] is True

            cancel = await h.post("/network/cancel", {}, kind="hotspot")
            assert cancel["ok"] is True
            assert cancel["state"]["op"] is None
            assert cleaned_up == [True]
            assert h.stored()["op"] is None
            ok = await h.post("/skip", {"rev": h.doc["rev"], "step": "network"})
            assert ok["ok"] is True
        run(go())

    def test_an_update_from_a_cancelled_operation_is_dropped(self):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()
            handles: List[pkg.OpHandle] = []

            async def runner(handle: pkg.OpHandle) -> None:
                handles.append(handle)
                await asyncio.sleep(3600)

            async def start_join(ctx: pkg.WriteContext) -> None:
                h.setup.start_op("join", runner)
                return None

            await h.setup.write(request("panel", "/x", {"rev": 5}), start_join)
            await asyncio.sleep(0)
            await h.post("/network/cancel", {})
            rev = h.doc["rev"]
            assert await handles[0].update(phase="dhcp") is False
            assert h.doc["rev"] == rev
        run(go())

    def test_a_runner_that_crashes_does_not_leave_the_state_busy(self):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()

            async def runner(handle: pkg.OpHandle) -> None:
                raise RuntimeError("boom")

            async def start(ctx: pkg.WriteContext) -> None:
                h.setup.start_op("join", runner)
                return None

            await h.setup.write(request("panel", "/x", {"rev": 5}), start)
            await h.setup.drain()
            assert h.doc["op"] is None
            assert h.stored()["op"] is None
        run(go())


# ==========================================================================
# 7. Access: caller kinds x endpoints (02 §3)
# ==========================================================================

KINDS = ["panel", "hotspot", "lan", "remote", "other"]

#: (endpoint, verb, body, callers allowed)
ACCESS = [
    ("", "GET", None, {"panel", "hotspot", "lan", "remote"}),
    ("/options", "GET", None, {"panel", "hotspot", "lan"}),
    ("/driver", "POST", {"rev": 5, "kind": "web", "client_id": "c"},
     {"hotspot", "lan"}),
    ("/goto", "POST", {"rev": 5, "step": "language"},
     {"panel", "hotspot", "lan"}),
    ("/skip", "POST", {"rev": 5, "step": "network"},
     {"panel", "hotspot", "lan"}),
    ("/finish", "POST", {"rev": 5}, {"panel", "hotspot", "lan"}),
    ("/card/dismiss", "POST", {"rev": 5}, {"panel", "hotspot", "lan"}),
    ("/network/cancel", "POST", {}, {"panel", "hotspot", "lan"}),
    ("/reset", "POST", {}, {"panel"}),
]


class TestAccess:
    @pytest.mark.parametrize("kind", KINDS)
    @pytest.mark.parametrize("endpoint,verb,body,allowed", ACCESS)
    def test_the_access_table(
        self, kind: str, endpoint: str, verb: str, body: Any, allowed: set
    ):
        args = copy.deepcopy(body)
        if endpoint == "/driver" and kind == "panel":
            # The panel drives as the panel; `web` is refused (tested below).
            args["kind"] = "panel"
            allowed = allowed | {"panel"}

        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()
            path = f"/server/muon/setup{endpoint}"
            if kind in allowed:
                result = await h.call(kind, path, args, method=verb)
                assert isinstance(result, dict)
            else:
                with pytest.raises(ServerError) as info:
                    await h.call(kind, path, args, method=verb)
                assert info.value.status_code == 403
                assert str(info.value) == f"muon_setup: not allowed from {kind}"
        run(go())

    def test_an_internal_caller_is_treated_as_the_panel(self):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()
            result = await h.call(
                "internal", "/server/muon/setup/skip",
                {"rev": 5, "step": "network"})
            assert result["ok"] is True
            # An internal call is no surface, so it takes no driver.
            assert result["state"]["driver"] is None
        run(go())

    def test_caller_kind_classification(self):
        for kind in KINDS:
            web = request(kind, "/server/muon/setup")
            assert caller.caller_kind(web) == kind
        assert caller.caller_kind(request("internal", "/x")) == "internal"
        # No address at all (MQTT) is `other`, and may not write.
        web = WebRequest("/x", {}, RequestType.POST, None, None, None)
        assert caller.caller_kind(web) == "other"


class TestWriteHygiene:
    """02 §3 / 07 S6: form CSRF and DNS rebinding from a page the owner's
    browser visits. Checked after the caller, before anything else."""

    def _skip(self, h: Harness, **kw: Any) -> Any:
        return h.post("/skip", {"rev": 5, "step": "network"}, kind="lan", **kw)

    def test_a_write_without_a_json_content_type_is_a_415(self):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()
            for ctype in ("text/plain", "application/x-www-form-urlencoded", ""):
                headers = {"Host": "10.42.0.1", "Content-Type": ctype}
                with pytest.raises(ServerError) as info:
                    await self._skip(h, headers=headers)
                assert info.value.status_code == 415
            assert h.doc["steps"]["network"]["status"] == "pending"
        run(go())

    @pytest.mark.parametrize("host", [
        "evil.example", "evil.example:80", "muon-walnut-8987.evil.example",
        "192.168.1.99",
    ])
    def test_a_foreign_host_is_refused(self, host: str):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()
            headers = {"Host": host, "Content-Type": "application/json"}
            with pytest.raises(ServerError) as info:
                await self._skip(h, headers=headers)
            assert info.value.status_code == 403
        run(go())

    @pytest.mark.parametrize("host", [
        "10.42.0.1", "10.42.0.1:80", "muon3d.local", "192.168.1.37",
        "localhost", "127.0.0.1:100", "[::1]", "MUON3D.LOCAL",
    ])
    def test_the_printers_own_names_pass(self, host: str):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()
            headers = {"Host": host, "Content-Type": "application/json"}
            assert (await self._skip(h, headers=headers))["ok"] is True
        run(go())

    def test_the_hostname_passes_bare_and_with_local(self, monkeypatch):
        monkeypatch.setattr(pkg.socket, "gethostname", lambda: "Muon-walnut-8987")

        async def go():
            for host in ("muon-walnut-8987", "Muon-walnut-8987.local"):
                h = await Harness(stored=state_with(
                    language={"status": "done", "value": "en"})).start()
                headers = {"Host": host, "Content-Type": "application/json"}
                assert (await self._skip(h, headers=headers))["ok"] is True
        run(go())

    @pytest.mark.parametrize("origin,ok", [
        ("http://10.42.0.1", True),
        ("http://muon3d.local", True),
        ("http://evil.example", False),
        ("http://nas.local", False),
        ("null", False),
    ])
    def test_an_origin_must_name_the_printer_when_present(
        self, origin: str, ok: bool
    ):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()
            headers = dict(GOOD_HEADERS, Origin=origin)
            if ok:
                assert (await self._skip(h, headers=headers))["ok"] is True
            else:
                with pytest.raises(ServerError) as info:
                    await self._skip(h, headers=headers)
                assert info.value.status_code == 403
        run(go())

    def test_a_websocket_write_is_host_checked_but_not_content_checked(self):
        """Beyond 02 §3: under DNS rebinding, Tornado's same-origin check on
        the upgrade compares two attacker-chosen names and passes, so the
        upgrade's Host is checked here too."""
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()
            bad = {"Host": "evil.example", "Origin": "http://evil.example"}
            with pytest.raises(ServerError) as info:
                await self._skip(h, headers=bad, websocket=True)
            assert info.value.status_code == 403
            good = {"Host": "10.42.0.1", "Origin": "http://localhost:8080"}
            assert (await self._skip(h, headers=good, websocket=True))["ok"]
        run(go())

    def test_bare_host_normalises_ports_brackets_and_zones(self):
        assert caller.bare_host("10.42.0.1:80") == "10.42.0.1"
        assert caller.bare_host("[fe80::1%wlan0]:80") == "fe80::1"
        assert caller.bare_host("fe80::1") == "fe80::1"
        assert caller.bare_host("Muon-Walnut-8987.local.") == "muon-walnut-8987.local"
        assert caller.bare_host("") is None
        assert caller.origin_host("http://user@10.42.0.1:80/x") == "10.42.0.1"
        assert caller.origin_host("file:///etc/passwd") is None


class TestHeaderAccessor:
    """The `# MUON` accessor 02 §3 asked for, on WebRequest."""

    def test_plain_http_carries_its_own_headers(self):
        web = WebRequest("/x", {}, RequestType.POST, None, None, None,
                         {"Host": "h"})
        assert web.get_http_headers() == {"Host": "h"}
        assert web.is_plain_http() is True

    def test_a_websocket_call_reports_the_upgrade_headers(self):
        from muon_setup_fakes import FakeWebsocket
        ws = FakeWebsocket({"Host": "10.42.0.1"})
        web = WebRequest("/x", {}, RequestType.POST, ws, None, None)
        assert web.get_http_headers() == {"Host": "10.42.0.1"}
        assert web.is_plain_http() is False

    def test_an_internal_call_has_none(self):
        class Internal:
            transport_type = TransportType.INTERNAL
        web = WebRequest("/x", {}, RequestType.POST, Internal(), None, None)
        assert web.get_http_headers() is None

    def test_the_api_definition_passes_headers_through(self):
        from moonraker.common import APIDefinition
        seen: List[Any] = []

        async def cb(web: WebRequest) -> None:
            seen.append(web.get_http_headers())
        api = APIDefinition("/server/muon/test_headers", "/server/muon/test_headers",
                            [], RequestType.POST, TransportType.HTTP, cb, True)
        asyncio.run(api.request({}, RequestType.POST, None, None, None,
                                {"Host": "10.42.0.1"}))
        asyncio.run(api.request({}, RequestType.POST))
        assert seen == [{"Host": "10.42.0.1"}, None]

    def test_the_http_handler_hands_the_request_headers_on(self):
        """application.py's DynamicRequestHandler is what fills them in for a
        plain HTTP request; drive it with a real Tornado request."""
        from unittest import mock

        import tornado.web
        from tornado.httputil import HTTPHeaders, HTTPServerRequest

        from moonraker.common import APIDefinition
        from moonraker.components.application import DynamicRequestHandler

        seen: List[Any] = []

        async def cb(web: WebRequest) -> Dict[str, Any]:
            headers = web.get_http_headers()
            seen.append((web.is_plain_http(), headers.get("Host"),
                         headers.get("Content-Type"), web.get_args()))
            return {"ok": True}

        api = APIDefinition(
            "/server/muon/test_http_headers", "/server/muon/test_http_headers",
            [], RequestType.POST, TransportType.HTTP, cb, True)

        class Server:
            def is_verbose_enabled(self) -> bool:
                return False

        async def go() -> None:
            app = tornado.web.Application(server=Server())
            req = HTTPServerRequest(
                method="POST", uri="/server/muon/test_http_headers",
                headers=HTTPHeaders({"Host": "10.42.0.1",
                                     "Content-Type": "application/json"}),
                body=b'{"rev": 3}', connection=mock.Mock())
            req.remote_ip = "10.42.0.23"
            handler = DynamicRequestHandler(app, req, api_definition=api)
            handler.current_user = None
            handler.path_kwargs = {}
            handler._transforms = []
            await handler._process_http_request(RequestType.POST)
        asyncio.run(go())
        assert seen == [(True, "10.42.0.1", "application/json", {"rev": 3})]


# ==========================================================================
# 8. finish (01 §6, 02 §5.11)
# ==========================================================================

class TestFinish:
    def _stored(self, **network: Any) -> Dict[str, Any]:
        return state_with(
            language={"status": "done", "value": "de", "source": "panel"},
            network=dict({"status": "done", "kind": "wifi", "ssid": "HomeWiFi",
                          "addresses": ["192.168.1.37"], "internet": True},
                         **network))

    def test_finish_skips_what_is_left_writes_the_marker_and_fires_complete(self):
        async def go():
            h = await Harness(stored=self._stored()).start()
            result = await h.post("/finish", {"rev": 5})
            await h.setup.drain()
            return h, result
        h, result = run(go())
        state = result["state"]
        assert result["ok"] is True
        assert state["state"] == "complete"
        assert state["cursor"] == "finish"
        steps = state["steps"]
        assert steps["name"]["status"] == "done"     # "Keep", never skipped
        assert steps["update"]["status"] == "skipped"
        assert steps["remote"]["status"] == "skipped"
        assert steps["ready"]["status"] == "skipped"
        assert model.card_steps(state) == ["remote", "ready"]
        # The marker, in MuonOS#174's shape.
        (marker,) = h.aux.posted("/setup")
        assert marker["complete"] is True
        assert marker["language"] == "de"
        assert isinstance(marker["completed_at"], str)
        assert h.db.namespaces["muon_setup"]["internal"]["marker_written"] is True
        # The in-process event, for other components.
        (complete,) = [a for e, a in h.server.events if e == "muon_setup:complete"]
        assert complete[0]["state"] == "complete"
        # The hotspot goes off in 15 minutes, because an uplink has an address.
        assert h.aux.posted("/wifi/ap/auto_off") == [{"after_s": 900}]
        assert h.setup.public_state()["hotspot"]["auto_off_at"] is not None

    def test_no_auto_off_without_an_uplink_address(self):
        async def go():
            h = await Harness(stored=self._stored(
                status="skipped", addresses=[])).start()
            await h.post("/finish", {"rev": 5})
            await h.setup.drain()
            return h
        h = run(go())
        assert h.aux.posted("/wifi/ap/auto_off") == []
        assert h.setup.public_state()["hotspot"]["auto_off_at"] is None

    def test_finish_needs_language(self):
        async def go():
            h = await Harness().start()
            result = await h.post("/finish", {"rev": 1})
            assert result["error"]["code"] == "required_steps_pending"
            assert h.doc["state"] == "new"
        run(go())

    def test_the_marker_is_retried_while_aux_is_down(self, monkeypatch):
        monkeypatch.setattr(pkg, "MARKER_RETRY", 0.01)

        async def go():
            h = await Harness(stored=self._stored()).start()
            h.aux.down = True
            await h.post("/finish", {"rev": 5})
            for _ in range(20):
                await asyncio.sleep(0.01)
            assert len(h.aux.posted("/setup")) >= 2   # tried, and tried again
            internal = h.db.namespaces["muon_setup"].get("internal", {})
            assert not internal.get("marker_written")
            h.aux.down = False
            await asyncio.wait_for(h.setup.drain(), 2)
            assert h.db.namespaces["muon_setup"]["internal"]["marker_written"]
        run(go())

    def test_an_image_without_the_new_routes_still_completes(self):
        """No POST /setup (before MuonOS#174) and no auto_off (before OS-5):
        setup completes, the hotspot stays up, and nothing loops."""
        aux = fresh_aux()
        del aux.routes[("POST", "/setup")]
        del aux.routes[("POST", "/wifi/ap/auto_off")]

        async def go():
            h = await Harness(stored=self._stored(), aux=aux).start()
            result = await h.post("/finish", {"rev": 5})
            await asyncio.wait_for(h.setup.drain(), 2)
            assert result["state"]["state"] == "complete"
        run(go())

    def test_after_complete_only_the_card_steps_take_writes(self):
        async def go():
            h = await Harness(stored=self._stored()).start()
            await h.post("/finish", {"rev": 5})
            await h.setup.drain()
            rev = h.doc["rev"]
            goto = await h.post("/goto", {"rev": rev, "step": "language"})
            assert goto["error"]["code"] == "invalid_step"
            skip_update = await h.post("/skip", {"rev": rev, "step": "update"})
            assert skip_update["error"]["code"] == "invalid_step"
            dismiss = await h.post("/card/dismiss", {"rev": rev})
            assert dismiss["ok"] and dismiss["state"]["card_dismissed"] is True
            again = await h.post("/finish", {"rev": rev + 1})
            assert again["ok"] is True
            assert again["state"]["rev"] == rev + 1   # a no-op
        run(go())


# ==========================================================================
# Persistence and reset
# ==========================================================================

class TestPersistence:
    def test_every_change_is_saved_before_it_is_announced(self):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()
            h.server.log.clear()
            await h.post("/skip", {"rev": 5, "step": "network"})
            return h
        h = run(go())
        assert h.server.log == [
            ("insert", ("muon_setup", "state")),
            ("event", "muon_setup:muon_setup_changed"),
        ]
        assert h.stored()["steps"]["network"]["status"] == "skipped"

    def test_the_computed_fields_are_not_stored(self):
        async def go():
            return await Harness().start()
        stored = run(go()).stored()
        for field in ("hotspot", "clock", "region", "capabilities"):
            assert field not in stored

    def test_a_failed_save_rolls_the_change_back(self):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()
            h.db.fail_inserts = True
            with pytest.raises(ServerError):
                await h.post("/skip", {"rev": 5, "step": "network"})
            assert h.doc["rev"] == 5
            assert h.doc["steps"]["network"]["status"] == "pending"
        run(go())


class TestReset:
    def test_reset_starts_over_as_new_and_cancels_the_operation(self):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()

            async def runner(handle: pkg.OpHandle) -> None:
                await asyncio.sleep(3600)

            async def start(ctx: pkg.WriteContext) -> None:
                h.setup.start_op("join", runner)
                return None
            await h.setup.write(request("panel", "/x", {"rev": 5}), start)
            result = await h.post("/reset", {})
            assert result["ok"] is True
            assert result["state"]["state"] == "new"
            assert result["state"]["op"] is None
            assert h.stored()["state"] == "new"
            # MuonOS#174's marker cannot be cleared, and reset does not try:
            # no write reaches Aux's /setup at all.
            assert [c for c in h.aux.calls if c[:2] != ("GET", "/setup")
                    and c[1] == "/setup"] == []
            # Reset does not re-run the migration check, which would find the
            # marker and call the printer migrated.
            assert ("GET", "/setup", None) not in h.aux.calls
        run(go())


# ==========================================================================
# 13. Aux unavailable (02 §1)
# ==========================================================================

class TestAuxUnavailable:
    def test_the_component_loads_and_serves_state_with_aux_down(self):
        stored = state_with(language={"status": "done", "value": "en"})
        aux = fresh_aux()
        aux.down = True

        async def go():
            h = await Harness(stored=stored, aux=aux).start()
            state = await h.get()
            assert state["state"] == "in_progress"
            options = await h.get("/options")
            assert options["region"] is None
            assert [x["code"] for x in options["languages"]] == [
                "en", "de", "fr", "es", "it"]
            # The navigation writes need no Aux, so they still work.
            assert (await h.post("/skip", {"rev": 5, "step": "network"}))["ok"]
        run(go())

    def test_with_no_state_and_aux_down_every_write_says_aux_unavailable(
        self, monkeypatch
    ):
        monkeypatch.setattr(pkg, "STARTUP_WAIT", 0.02)
        monkeypatch.setattr(pkg, "MIGRATION_RETRY", 0.02)
        aux = fresh_aux()
        aux.down = True

        async def go():
            h = Harness(aux=aux)
            task = asyncio.ensure_future(h.setup._startup(poll=False))
            for endpoint, body in (
                ("/goto", {"rev": 1, "step": "language"}),
                ("/skip", {"rev": 1, "step": "network"}),
                ("/finish", {"rev": 1}),
                ("/card/dismiss", {"rev": 1}),
                ("/driver", {"rev": 1, "kind": "panel", "client_id": "k"}),
                ("/network/cancel", {}),
            ):
                result = await h.post(endpoint, body)
                assert result["ok"] is False, endpoint
                assert result["error"]["code"] == "aux_unavailable", endpoint
            assert (await h.get())["state"] == "complete"
            h.setup._closed = True
            await asyncio.wait_for(task, 1)
        run(go())


# ==========================================================================
# The pieces: live fields, options, manifest, region mapping
# ==========================================================================

class TestLiveFields:
    def test_printer_hotspot_and_name_come_from_identity_and_aux(
        self, monkeypatch
    ):
        monkeypatch.setattr(pkg.socket, "gethostname", lambda: "Muon-walnut-8987")
        aux = fresh_aux()
        aux.routes[("POST", "/wifi/ap/count")] = 2

        async def go():
            return (await Harness(aux=aux).start()).setup.public_state()
        state = run(go())
        assert state["printer"] == {
            "name": "Walnut", "display": "Walnut · 8987",
            "hostname": "Muon-walnut-8987", "fingerprint": "SHA256:placeholder"}
        assert state["hotspot"] == {
            "up": True, "ssid": "Muon-walnut-8987", "clients": 2,
            "auto_off_at": None, "address": "10.42.0.1"}
        assert state["steps"]["name"]["value"] == "Walnut"
        assert state["steps"]["name"]["derived"] == "walnut"
        assert state["region"] == {"market": "picker", "country": "DE",
                                   "declared": False, "config": "de",
                                   "source": "default"}

    def test_the_stations_route_is_preferred_when_the_image_has_it(self):
        aux = fresh_aux(**{"GET /wifi/ap/stations": {"up": True, "count": 3}})

        async def go():
            return (await Harness(aux=aux).start()).setup.public_state()
        assert run(go())["hotspot"]["clients"] == 3
        assert ("POST", "/wifi/ap/count", None) not in aux.calls

    def test_the_state_document_has_the_spec_keys_in_order(self):
        async def go():
            return (await Harness().start()).setup.public_state()
        assert list(run(go())) == [
            "version", "rev", "state", "cursor", "driver", "op", "printer",
            "hotspot", "clock", "region", "capabilities", "card_dismissed",
            "steps"]


class TestOptions:
    def test_options_report_languages_region_and_the_manifest(self):
        async def go():
            return await (await Harness().start()).get("/options")
        options = run(go())
        assert options["languages"][:2] == [
            {"code": "en", "endonym": "English"},
            {"code": "de", "endonym": "Deutsch"}]
        assert options["region"]["market"] == "picker"
        assert options["region"]["default_country"] == "DE"
        assert options["ready_manifest"] == manifest.DEFAULT_MANIFEST

    def test_the_configured_languages_are_offered_in_order(self):
        async def go():
            h = await Harness(options={"languages": "fr, en"}).start()
            return await h.get("/options")
        assert [x["code"] for x in run(go())["languages"]] == ["fr", "en"]

    def test_a_malformed_language_is_a_config_error(self):
        with pytest.raises(ValueError):
            Harness(options={"languages": "en, english"})


class TestManifest:
    def test_the_default_manifest_is_valid(self):
        assert manifest.validate(copy.deepcopy(manifest.DEFAULT_MANIFEST))

    def test_a_missing_manifest_falls_back_to_the_default(self, caplog):
        assert manifest.load("/nonexistent/ready.json") == manifest.DEFAULT_MANIFEST
        assert "using the built-in default" in caplog.text

    @pytest.mark.parametrize("breakage", [
        lambda m: m.update(version=2),
        lambda m: m["items"].append(dict(m["items"][0])),          # repeated id
        lambda m: m["items"][0].update(kind="video"),
        lambda m: m["items"][0].update(required="yes"),
        lambda m: m["items"][1].pop("macro"),
        lambda m: m["items"][2].pop("flow"),
        lambda m: m["items"][0].update(title_key="Remove the clips"),  # copy
        lambda m: m["items"][0].update(image="../../etc/passwd"),
        lambda m: m["items"][1].update(est_seconds=-1),
    ])
    def test_an_invalid_manifest_is_refused_and_the_default_used(
        self, breakage: Any, tmp_path: Path
    ):
        bad = copy.deepcopy(manifest.DEFAULT_MANIFEST)
        breakage(bad)
        with pytest.raises(manifest.ManifestError):
            manifest.validate(bad)
        path = tmp_path / "ready.json"
        path.write_text(json.dumps(bad), encoding="utf-8")
        assert manifest.load(str(path)) == manifest.DEFAULT_MANIFEST

    def test_a_valid_shipped_manifest_is_used(self, tmp_path: Path):
        shipped = copy.deepcopy(manifest.DEFAULT_MANIFEST)
        shipped["items"] = shipped["items"][:1]
        path = tmp_path / "ready.json"
        path.write_text(json.dumps(shipped), encoding="utf-8")
        assert manifest.load(str(path)) == shipped


class TestRegionMapping:
    """MuonOS#174's region routes, reshaped into 02 §5.2 and §6."""

    def test_an_eu_unit_with_the_fallback_applied(self):
        assert region.state_region(REGION_174, REGION_OPTIONS_174) == {
            "market": "picker", "country": "DE", "declared": False,
            "config": "de", "source": "default"}
        opts = region.options_region(REGION_174, REGION_OPTIONS_174)
        assert opts["applied"] == {"country": "DE", "config": "de",
                                   "declared": False}
        assert opts["default_country"] == "DE"
        assert opts["permitted_channels"][-1] == 48
        # Not served by #174: left empty rather than guessed.
        assert opts["for_language"] == []
        assert opts["all"] is None
        assert opts["support_code"] is None

    def test_a_declared_country_detected_from_the_joined_network(self):
        declared = dict(REGION_174, declared_country="GB", domain="GB",
                        configuration="gb", detected_country="GB",
                        basis="joined-network")
        options = dict(REGION_OPTIONS_174, preselect="GB",
                       basis="joined-network")
        state = region.state_region(declared, options)
        assert state == {"market": "picker", "country": "GB", "declared": True,
                         "config": "gb", "source": "ap"}
        # A detection hides the token default behind `preselect`.
        assert region.options_region(declared, options)["default_country"] is None

    def test_a_us_locked_unit(self):
        us = dict(REGION_174, domain="US", configuration="us", locked=True)
        options = {"countries": ["US"], "preselect": "US", "basis": None,
                   "locked": True}
        assert region.market(us, options) == "locked"

    def test_a_unit_with_no_token(self):
        none = dict(REGION_174, reason="no-token", domain="00",
                    configuration=None, channels=[])
        options = {"countries": [], "preselect": None, "basis": None,
                   "locked": False}
        state = region.state_region(none, options)
        assert state == {"market": "none", "country": None, "declared": False,
                         "config": None, "source": None}
