"""muon_setup's first steps: language, clock, time zone and name (KAN-203, MR-2).

Spec 02 §5.2-§5.4 and §5.7 (specs/m1-first-run-setup in Muon-3D/OrcaSlicer).
Aux's time routes (OS-6) are faked in the shape 03 §3 proposes; they are not
built on any MuonOS branch yet, and the tests for an image without them pin
what happens meanwhile.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from moonraker.components.muon_setup import clock
from moonraker.utils.exceptions import ServerError

from muon_setup_fakes import Harness, fresh_aux, request, run, state_with

# 2026-09-24T12:00:00Z, after the fake image's build time below.
NOW_MS = 1790251200000

#: zone.tab's real rows, trimmed: one country per row, principal zone first.
ZONE_TAB = "\n".join([
    "# tz zone descriptions, trimmed for the tests",
    "CH\t+4723+00832\tEurope/Zurich",
    "DE\t+5230+01322\tEurope/Berlin\tmost of Germany",
    "DE\t+4742+00841\tEurope/Busingen\tBusingen",
    "GB\t+513030-0000731\tEurope/London",
    "NO\t+5955+01045\tEurope/Oslo",
    "US\t+404251-0740023\tAmerica/New_York\tEastern (most areas)",
    "US\t+415100-0873900\tAmerica/Chicago\tCentral (most areas)",
    "US\t+340308-1181434\tAmerica/Los_Angeles\tPacific",
    "",
])
#: zone1970.tab's rows for the same zones. Its multi-country rows are why it
#: is not read: DE would start with Europe/Zurich, and NO get Europe/Berlin.
ZONE1970_TAB = "\n".join([
    "CH,DE,LI\t+4723+00832\tEurope/Zurich\tBusingen",
    "DE,DK,NO,SE,SJ\t+5230+01322\tEurope/Berlin\tmost of Germany",
    "",
])


@pytest.fixture(autouse=True)
def tzdata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A small tzdata and build record, so nothing depends on the host."""
    root = tmp_path / "zoneinfo"
    root.mkdir()
    tab = root / "zone.tab"
    tab.write_text(ZONE_TAB, encoding="utf-8")
    (root / "zone1970.tab").write_text(ZONE1970_TAB, encoding="utf-8")
    for zone in ("Europe/London", "Europe/Berlin", "Europe/Busingen",
                 "Europe/Zurich", "Europe/Oslo", "America/New_York",
                 "America/Chicago", "America/Los_Angeles"):
        path = root / zone
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"TZif")
    build = tmp_path / "build.json"
    build.write_text(json.dumps({
        "schema": "muon.device-build/v1", "build_id": "1",
        "created_at": "2026-09-01T00:00:00Z"}), encoding="utf-8")
    monkeypatch.setattr(clock, "ZONE_TAB", tab)
    monkeypatch.setattr(clock, "ZONEINFO", root)
    monkeypatch.setattr(clock, "BUILD_JSON", build)
    monkeypatch.setattr(clock, "TIMESYNC_FLAG", tmp_path / "synchronized")
    monkeypatch.setattr(clock, "LOCALTIME", tmp_path / "localtime")
    return tmp_path


def time_aux(synced: bool = False, epoch_ms: int = NOW_MS - 3_600_000,
             tz: str = "Etc/UTC") -> Any:
    """An Aux with OS-6's time routes: a clock an hour slow, not synced."""
    return fresh_aux(**{
        "GET /time": {"epoch_ms": epoch_ms, "ntp_synced": synced, "tz": tz},
        "POST /time": lambda body: {"epoch_ms": body["epoch_ms"]},
        "POST /time/zone": lambda body: {"tz": body["tz"]},
    })


# ==========================================================================
# Language (02 §5.3)
# ==========================================================================

class TestLanguage:
    def test_choosing_a_language_answers_the_step_and_moves_on(self):
        async def go():
            h = await Harness().start()
            result = await h.post("/language", {"rev": 1, "code": "de"})
            return h, result
        h, result = run(go())
        state = result["state"]
        assert result["ok"] is True
        assert state["state"] == "in_progress"
        assert state["steps"]["language"] == {
            "status": "done", "value": "de", "source": "panel"}
        assert state["cursor"] == "network"
        assert state["rev"] == 2

    def test_the_source_is_the_caller_kind(self):
        async def go():
            h = await Harness().start()
            return await h.post("/language", {"rev": 1, "code": "fr"},
                                kind="hotspot")
        state = run(go())["state"]
        assert state["steps"]["language"]["source"] == "hotspot"
        assert state["driver"]["kind"] == "phone"

    def test_a_language_not_configured_is_unsupported(self):
        async def go():
            h = await Harness().start()
            result = await h.post("/language", {"rev": 1, "code": "nl"})
            assert result["ok"] is False
            assert result["error"]["code"] == "unsupported_language"
            assert h.doc["steps"]["language"]["status"] == "pending"
            assert h.doc["rev"] == 1
        run(go())

    def test_fluidds_default_locale_is_set_when_nobody_chose_one(self):
        async def go():
            h = await Harness().start()
            await h.post("/language", {"rev": 1, "code": "it"})
            return h
        h = run(go())
        assert h.db.namespaces["fluidd"]["uiSettings.general.locale"] == "it"

    def test_a_locale_the_owner_chose_in_fluidd_is_kept(self):
        async def go():
            h = await Harness(stored=state_with(), namespaces={
                "fluidd": {"uiSettings.general.locale": "es"}}).start()
            h.doc["cursor"] = "language"
            await h.post("/language", {"rev": 5, "code": "de"})
            return h
        h = run(go())
        assert h.db.namespaces["fluidd"]["uiSettings.general.locale"] == "es"

    def test_a_fluidd_settings_failure_does_not_block_the_step(self):
        async def go():
            h = await Harness().start()

            async def broken(*args: Any, **kwargs: Any) -> Any:
                raise ServerError("database is broken", 500)
            h.db.get_item = broken  # type: ignore[assignment]
            return await h.post("/language", {"rev": 1, "code": "de"})
        assert run(go())["ok"] is True

    def test_language_is_closed_after_setup(self):
        async def go():
            h = await Harness().start()
            await h.post("/language", {"rev": 1, "code": "en"})
            await h.post("/finish", {"rev": 2})
            await h.setup.drain()
            result = await h.post("/language", {"rev": h.doc["rev"], "code": "de"})
            assert result["error"]["code"] == "invalid_step"
        run(go())


# ==========================================================================
# Clock (02 §5.4)
# ==========================================================================

class TestClock:
    def _post(self, h: Harness, body: Dict[str, Any], kind: str = "hotspot") -> Any:
        return h.post("/clock", body, kind=kind)

    def test_the_phones_clock_and_zone_are_applied_without_changing_rev(self):
        async def go():
            h = await Harness(aux=time_aux()).start()
            result = await self._post(
                h, {"epoch_ms": NOW_MS, "tz": "Europe/London"})
            return h, result
        h, result = run(go())
        assert result["ok"] is True
        assert result["state"]["rev"] == 1
        assert h.aux.posted("/time") == [{"epoch_ms": NOW_MS}]
        assert h.aux.posted("/time/zone") == [{"tz": "Europe/London"}]
        assert result["state"]["clock"]["tz_source"] == "phone"
        assert result["state"]["clock"]["source"] == "phone"

    @pytest.mark.parametrize("kind", ["panel", "lan", "remote"])
    def test_only_the_hotspot_may_post_the_clock(self, kind: str):
        """02 §3, §5.4: the phone page on 10.42.0.1 is the only surface that
        knows the owner's local time."""
        async def go():
            h = await Harness(aux=time_aux()).start()
            with pytest.raises(ServerError) as info:
                await self._post(h, {"epoch_ms": NOW_MS}, kind=kind)
            assert info.value.status_code == 403
            assert h.aux.posted("/time") == []
        run(go())

    def test_the_zone_is_applied_even_when_the_clock_is_refused(self):
        async def go():
            h = await Harness(aux=time_aux()).start()
            return h, await self._post(
                h, {"epoch_ms": 1700000000000, "tz": "Europe/London"})
        h, result = run(go())
        assert result["error"]["code"] == "invalid_clock"
        assert h.aux.posted("/time") == []
        assert h.aux.posted("/time/zone") == [{"tz": "Europe/London"}]
        assert result["state"]["clock"]["tz_source"] == "phone"

    def test_aux_refusing_the_clock_is_invalid_clock_not_ok(self):
        """OS-6 answers 422 for a time more than 20 years past the build."""
        async def go():
            aux = time_aux()
            aux.routes[("POST", "/time")] = ServerError(
                "more than 20 years after the build", 422)
            h = await Harness(aux=aux).start()
            return await self._post(h, {"epoch_ms": NOW_MS})
        assert run(go())["error"]["code"] == "invalid_clock"

    def test_aux_refusing_the_zone_is_invalid_timezone(self):
        async def go():
            aux = time_aux()
            aux.routes[("POST", "/time/zone")] = ServerError("not a zone", 422)
            h = await Harness(aux=aux).start()
            return await self._post(h, {"epoch_ms": NOW_MS,
                                        "tz": "Europe/London"})
        assert run(go())["error"]["code"] == "invalid_timezone"

    def test_a_clock_within_two_seconds_is_left_alone(self):
        async def go():
            h = await Harness(aux=time_aux(epoch_ms=NOW_MS - 1500)).start()
            await self._post(h, {"epoch_ms": NOW_MS})
            return h
        assert run(go()).aux.posted("/time") == []

    def test_a_clock_ntp_has_set_is_never_overridden(self):
        async def go():
            h = await Harness(aux=time_aux(synced=True)).start()
            result = await self._post(h, {"epoch_ms": NOW_MS})
            return h, result
        h, result = run(go())
        assert h.aux.posted("/time") == []
        assert result["state"]["clock"]["synced"] is True
        assert result["state"]["clock"]["source"] == "ntp"

    def test_a_time_before_the_image_was_built_is_invalid(self):
        async def go():
            h = await Harness(aux=time_aux()).start()
            result = await self._post(h, {"epoch_ms": 1700000000000})
            return h, result
        h, result = run(go())
        assert result["error"]["code"] == "invalid_clock"
        assert h.aux.posted("/time") == []

    def test_an_unknown_zone_is_ignored_and_the_clock_still_set(self):
        async def go():
            h = await Harness(aux=time_aux()).start()
            result = await self._post(
                h, {"epoch_ms": NOW_MS, "tz": "../../etc/passwd"})
            return h, result
        h, result = run(go())
        assert result["ok"] is True
        assert h.aux.posted("/time/zone") == []
        assert h.aux.posted("/time") == [{"epoch_ms": NOW_MS}]

    def test_an_image_without_the_time_routes_skips_it_quietly(self, caplog):
        """No OS-6 yet: the phone page must not see an error for this."""
        async def go():
            h = await Harness().start()
            return h, await self._post(
                h, {"epoch_ms": NOW_MS, "tz": "Europe/London"})
        h, result = run(go())
        assert result["ok"] is True
        assert h.aux.posted("/time") == []
        assert "no Aux /time" in caplog.text

    def test_with_aux_down_the_clock_says_aux_unavailable(self):
        async def go():
            h = await Harness(aux=time_aux()).start()
            h.aux.down = True
            return await self._post(h, {"epoch_ms": NOW_MS})
        assert run(go())["error"]["code"] == "aux_unavailable"

    @pytest.mark.parametrize("bad", [None, "1790251200000", 1.7e12, True])
    def test_epoch_ms_must_be_an_integer(self, bad: Any):
        async def go():
            h = await Harness(aux=time_aux()).start()
            with pytest.raises(ServerError) as info:
                await self._post(h, {"epoch_ms": bad})
            assert info.value.status_code == 400
        run(go())

    def test_the_clock_waits_while_an_operation_runs(self):
        async def go():
            h = await Harness(aux=time_aux(), stored=state_with(
                language={"status": "done", "value": "en"})).start()
            h.doc["op"] = {"kind": "join", "id": "op_1", "started": 0.0,
                           "phase": "dhcp", "progress": None}
            return await self._post(h, {"epoch_ms": NOW_MS})
        assert run(go())["error"]["code"] == "busy"

    def test_the_live_clock_falls_back_to_timesyncd_without_os6(
        self, tzdata: Path
    ):
        (tzdata / "synchronized").write_text("", encoding="utf-8")

        async def go():
            return (await Harness().start()).setup.public_state()
        assert run(go())["clock"]["synced"] is True


# ==========================================================================
# Time zone (02 §5.4, panel P7b) and options ?country=
# ==========================================================================

def declared(country: str, config: str) -> Dict[str, Any]:
    return {"reason": "applied", "domain": country, "declared_country": country,
            "configuration": config, "locked": False, "channels": [1, 6, 11]}


class TestTimezone:
    def _harness(self, country: str = "US") -> Harness:
        aux = time_aux()
        aux.routes[("GET", "/region")] = declared(country, country.lower())
        aux.routes[("GET", "/region/options")] = {
            "countries": [country], "preselect": country, "basis": None,
            "locked": False}
        return Harness(aux=aux, stored=state_with(
            language={"status": "done", "value": "en"},
            network={"status": "done", "addresses": ["192.168.1.37"]}))

    def test_one_of_the_declared_countrys_zones_is_set(self):
        async def go():
            h = await self._harness().start()
            result = await h.post("/timezone", {"rev": 5, "tz": "America/Chicago"})
            return h, result
        h, result = run(go())
        assert result["ok"] is True
        assert result["state"]["rev"] == 6
        assert result["state"]["clock"]["tz_source"] == "owner"
        assert h.aux.posted("/time/zone") == [{"tz": "America/Chicago"}]
        assert h.server.changes()[-1]["clock"]["tz_source"] == "owner"

    def test_aux_refusing_the_owners_zone_is_invalid_timezone(self):
        async def go():
            h = self._harness()
            h.aux.routes[("POST", "/time/zone")] = ServerError("no", 422)
            await h.start()
            return await h.post("/timezone", {"rev": 5,
                                              "tz": "America/Chicago"})
        assert run(go())["error"]["code"] == "invalid_timezone"

    def test_a_zone_of_another_country_is_invalid(self):
        async def go():
            h = await self._harness().start()
            return h, await h.post("/timezone", {"rev": 5, "tz": "Europe/London"})
        h, result = run(go())
        assert result["error"]["code"] == "invalid_timezone"
        assert h.aux.posted("/time/zone") == []
        assert h.doc["rev"] == 5

    def test_with_no_declared_country_there_is_no_list_to_pick_from(self):
        async def go():
            h = await Harness(aux=time_aux(), stored=state_with(
                language={"status": "done", "value": "en"})).start()
            return await h.post("/timezone", {"rev": 5, "tz": "Europe/Berlin"})
        assert run(go())["error"]["code"] == "invalid_timezone"

    def test_options_list_a_countrys_zones_principal_first(self):
        async def go():
            h = await Harness().start()
            verbs, handler = h.server.endpoints["/server/muon/setup/options"]
            web = request("hotspot", "/server/muon/setup/options",
                          {"country": "US"}, method="GET")
            return await handler(web)
        assert run(go())["timezones"] == [
            "America/New_York", "America/Chicago", "America/Los_Angeles"]

    def test_options_without_a_country_carry_no_zones(self):
        async def go():
            return await (await Harness().start()).get("/options")
        assert "timezones" not in run(go())


class TestTzdata:
    def test_zones_come_from_zone_tab_principal_first(self):
        """02 §5.2: DE is Berlin then Busingen, not zone1970's Zurich first,
        and NO is Oslo, not Berlin."""
        assert clock.ZONE_TAB.name == "zone.tab"
        assert clock.zones_for_country("DE") == [
            "Europe/Berlin", "Europe/Busingen"]
        assert clock.zones_for_country("no") == ["Europe/Oslo"]

    @pytest.mark.parametrize("country", ["", "GBR", "1", None])
    def test_a_malformed_country_has_no_zones(self, country: Any):
        assert clock.zones_for_country(country) == []

    @pytest.mark.parametrize("tz,ok", [
        ("Europe/London", True),
        ("Europe/Nowhere", False),
        ("../zoneinfo/Europe/London", False),
        ("/etc/passwd", False),
        (7, False),
    ])
    def test_a_zone_must_exist_in_tzdata(self, tz: Any, ok: bool):
        assert clock.valid_zone(tz) is ok

    def test_the_build_floor_comes_from_build_json(self, tzdata: Path):
        assert clock.build_floor_ms() == 1788220800000
        assert clock.build_floor_ms(tzdata / "absent.json") == \
            clock.FALLBACK_FLOOR_MS


# ==========================================================================
# Name (02 §5.7)
# ==========================================================================

class TestName:
    def _harness(self) -> Harness:
        return Harness(stored=state_with(
            language={"status": "done", "value": "en"},
            network={"status": "skipped"}))

    def test_keep_answers_the_step_with_the_current_name(self):
        async def go():
            h = await self._harness().start()
            return h, await h.post("/name", {"rev": 5, "name": ""})
        h, result = run(go())
        name = result["state"]["steps"]["name"]
        assert name["status"] == "done"
        assert name["value"] == "Walnut"
        assert h.aux.friendly_name is None
        # update has no internet to offer, so it hides and remote is next.
        assert result["state"]["cursor"] == "remote"

    def test_leaving_the_name_out_is_keep_too(self):
        async def go():
            h = await self._harness().start()
            return await h.post("/name", {"rev": 5})
        assert run(go())["state"]["steps"]["name"]["status"] == "done"

    def test_a_rename_is_stored_where_the_identity_endpoint_keeps_it(self):
        async def go():
            h = await self._harness().start()
            return h, await h.post("/name", {"rev": 5, "name": "  Workshop "})
        h, result = run(go())
        assert h.aux.friendly_name == "Workshop"
        assert result["state"]["steps"]["name"]["value"] == "Workshop"
        assert result["state"]["printer"]["name"] == "Workshop"
        # The derived name stays what the hardware says (ID-2).
        assert result["state"]["steps"]["name"]["derived"] == "walnut"

    def test_a_name_over_32_characters_is_refused_and_nothing_changes(self):
        async def go():
            h = await self._harness().start()
            with pytest.raises(ServerError) as info:
                await h.post("/name", {"rev": 5, "name": "x" * 33})
            assert info.value.status_code == 400
            assert h.doc["steps"]["name"]["status"] == "pending"
            assert h.aux.friendly_name is None
        run(go())

    @pytest.mark.parametrize("bad", ["Wal\nnut", "Wal\x07nut", "Wal\x85nut"])
    def test_a_name_with_control_characters_is_a_400(self, bad: str):
        """02 §5.7: C0 and C1, newlines included."""
        async def go():
            h = await self._harness().start()
            with pytest.raises(ServerError) as info:
                await h.post("/name", {"rev": 5, "name": bad})
            assert info.value.status_code == 400
            assert h.aux.friendly_name is None
        run(go())

    def test_thirty_two_code_points_is_the_limit_not_bytes(self):
        async def go():
            h = await self._harness().start()
            result = await h.post("/name", {"rev": 5, "name": "é" * 32})
            assert result["ok"] is True
        run(go())

    def test_keep_before_the_identity_is_read_keeps_a_name_not_null(self):
        """Aux late at boot: Keep falls back to the stored or derived name."""
        async def go():
            h = self._harness()
            h.aux.identity = None
            h.setup._live["derived_name"] = "walnut"
            await h.setup._startup(poll=False)
            return await h.post("/name", {"rev": 5, "name": ""})
        assert run(go())["state"]["steps"]["name"]["value"] == "Walnut"

    def test_name_ahead_of_the_first_pending_step_is_invalid(self):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()
            return await h.post("/name", {"rev": 5, "name": "Oak"})
        assert run(go())["error"]["code"] == "invalid_step"

    def test_a_name_that_is_not_a_string_is_a_400(self):
        async def go():
            h = await self._harness().start()
            with pytest.raises(ServerError) as info:
                await h.post("/name", {"rev": 5, "name": 7})
            assert info.value.status_code == 400
        run(go())

    def test_a_rename_still_works_after_setup(self):
        async def go():
            h = await self._harness().start()
            await h.post("/finish", {"rev": 5})
            await h.setup.drain()
            result = await h.post("/name", {"rev": h.doc["rev"], "name": "Oak"})
            assert result["ok"] is True
            assert result["state"]["cursor"] == "finish"
            assert h.aux.friendly_name == "Oak"
        run(go())

    def test_a_rename_is_saved_while_aux_is_down(self):
        """The name lives in Moonraker's database, not in Aux."""
        async def go():
            h = await self._harness().start()
            h.aux.down = True
            return h, await h.post("/name", {"rev": 5, "name": "Oak"})
        h, result = run(go())
        assert result["ok"] is True
        assert h.aux.friendly_name == "Oak"
        assert result["state"]["steps"]["name"]["value"] == "Oak"
