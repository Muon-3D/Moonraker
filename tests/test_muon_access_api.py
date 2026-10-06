"""AB-MR-2: server.muon.access.*, the migration and the rollback dual write.

The answers are checked against tests/assets/muon_access_contract.json, the
fixture muon3d-app's mock answers from too, so the printer, the mock and the
app agree on every field.
"""
from __future__ import annotations

import asyncio
import json
import pathlib
import time
from typing import Any, Dict

import pytest

from moonraker import muon_access_policy as policy
from moonraker import muon_floor
from moonraker.common import APIDefinition, RequestType, UserInfo, WebRequest
from moonraker.components import muon_access_api
from moonraker.utils.exceptions import ServerError

from muon_access_fakes import (
    HTTP, LAN, LOOPBACK, SENTINEL, Link, Server, call, caller, printer,
    restart,
)

FIXTURE = json.loads(
    (pathlib.Path(__file__).parent / "assets" / "muon_access_contract.json")
    .read_text(encoding="utf-8")
)
CASES = FIXTURE["cases"]

HOME = caller({"kind": "home"})
PANEL = caller({"kind": "panel"})


@pytest.fixture(autouse=True)
def _reset():
    yield
    policy.set_state(None)
    muon_floor.set_protection_level(muon_floor.LEVEL_OPEN)


def printer_for(case: Dict[str, Any]) -> Any:
    p = case["printer"]
    link = (Link("linked", p.get("email")) if p["owner"] == "account"
            else Link("unlinked"))
    old_level = 1 if p["entry"] == "protected" else 0
    access, protection, server = printer(old_level=old_level, link=link)
    return access, server


# ---------------------------------------------------------------------------
# The contract
# ---------------------------------------------------------------------------


class TestTheContract:
    def test_the_fixture_names_what_the_printer_registers(self):
        _access, server = printer_for(CASES[0])
        registered = {path.rsplit("/", 1)[1] for path in server.handlers
                      if path.startswith("/server/muon/access/")}
        for method in ("get", "capabilities", "set_entry",
                       "set_private_uploads", "set_data", "set_levels",
                       "request", "request_status", "cancel_request"):
            assert method in registered, method
        for method in FIXTURE["notYetOnThePrinter"]["methods"]:
            assert method not in registered, method

    def test_the_vocabularies(self):
        assert FIXTURE["levels"] == [
            muon_access_api.api_level(level)
            for level in (policy.SIGNED_OUT_GUEST, policy.SIGNED_IN_GUEST,
                          policy.MEMBER, policy.ADMIN)]
        assert FIXTURE["roles"] == list(policy.ROLES)
        assert FIXTURE["entries"] == list(policy.ENTRIES)
        assert FIXTURE["dataModes"] == list(muon_access_api.DATA_MODES)

    @pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
    def test_get_answers_as_the_fixture(self, case):
        _access, server = printer_for(case)
        assert call(server, "get", who=caller(case["caller"])) == case["get"]

    @pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
    def test_capabilities_answer_as_the_fixture(self, case):
        _access, server = printer_for(case)
        actions = call(server, "capabilities", who=caller(case["caller"]))[
            "actions"]
        assert set(actions.values()) <= set(FIXTURE["capabilityValues"])
        for action, expected in case["capabilities"].items():
            assert actions[action] == expected, (action, actions[action])

    @pytest.mark.parametrize(
        "case", [c for c in CASES if "set_entry" in c],
        ids=[c["name"] for c in CASES if "set_entry" in c])
    def test_set_entry_answers_as_the_fixture(self, case):
        access, server = printer_for(case)
        before = access.record["entry"]
        result = call(server, "set_entry", case["set_entry"]["params"],
                      who=caller(case["caller"]))
        assert result == case["set_entry"]["result"]
        after = access.record["entry"]
        if result["applied"]:
            assert after == case["set_entry"]["params"]["entry"]
        else:
            assert after == before

    def test_a_guest_reaches_the_handler_and_is_told_not_applied(self):
        # Through APIDefinition.request: the table must not 403 set_entry,
        # or the app could not tell "ask the screen" from "not admitted".
        access, server = printer_for(CASES[4])
        verbs, handler = server.handlers["/server/muon/access/set_entry"]
        api = APIDefinition.create("/server/muon/access/set_entry", ["POST"],
                                   handler)
        result = asyncio.run(api.request({"entry": "protected"},
                                         RequestType.POST, *HOME))
        assert result == {"applied": False}

    def test_answer_is_the_panels_alone_through_the_request_path(self):
        access, server = printer_for(CASES[3])
        verbs, handler = server.handlers["/server/muon/access/answer"]
        api = APIDefinition.create("/server/muon/access/answer", ["POST"],
                                   handler)
        with pytest.raises(ServerError) as err:
            asyncio.run(api.request({"request_id": "x", "allow": True},
                                    RequestType.POST,
                                    *caller(CASES[3]["caller"])))
        assert err.value.status_code == 403


class TestTheOtherSettings:
    def test_private_uploads_data_and_levels_need_the_protection_row(self):
        trusted = caller(CASES[3]["caller"])
        guest = caller(CASES[4]["caller"])
        access, server = printer_for(CASES[3])
        assert call(server, "set_private_uploads", {"enabled": True},
                    who=trusted) == {"applied": True}
        assert call(server, "get", who=trusted)["privateUploads"] is True
        assert call(server, "set_data", {"mode": "both"},
                    who=trusted) == {"applied": True}
        assert call(server, "get", who=trusted)["dataMode"] == "both"
        assert call(server, "set_levels", {"preset": "strict"},
                    who=trusted) == {"applied": True}
        assert call(server, "get", who=trusted)["levelsPreset"] == "strict"
        access, server = printer_for(CASES[4])
        for method, params in (("set_private_uploads", {"enabled": True}),
                               ("set_data", {"mode": "accounts"}),
                               ("set_levels", {"preset": "strict"})):
            assert call(server, method, params, who=guest) == {
                "applied": False}, method

    def test_bad_values_are_400(self):
        _access, server = printer_for(CASES[3])
        trusted = caller(CASES[3]["caller"])
        for method, params in (("set_entry", {"entry": "ajar"}),
                               ("set_data", {"mode": "cloud"}),
                               ("set_levels", {}),
                               ("set_levels", {"overrides": {"protection": "member"}})):
            with pytest.raises(ServerError) as err:
                call(server, method, params, who=trusted)
            assert err.value.status_code == 400, method

    def test_private_uploads_default_by_owner(self):
        # ACC-32: off with one owner or none; an organisation is on
        access, _s = printer_for(CASES[3])
        assert access.private_uploads() is False
        access.owner = policy.OWNER_ORGANISATION
        assert access.private_uploads() is True

    def test_the_password_way_follows_moonraker_32(self):
        _a, _p, server = printer(old_level=0, password_set=True)
        assert call(server, "get", who=PANEL)["ways"]["password"] == {"on": True}


class TestConfirmOnThePrinter:
    def test_ask_answer_and_the_change_applies(self):
        access, server = printer_for(CASES[4])   # one owner, Open, a guest
        ask = call(server, "request",
                   {"ask": {"kind": "entry", "entry": "protected"},
                    "label": "Pixel 8"}, who=HOME)
        assert set(FIXTURE["requestAnswerKeys"]) <= set(ask)
        assert ask["label"] == "Pixel 8"
        assert len(ask["code"]) == 4
        assert ask["expiresAt"] > time.time() * 1000
        rid = ask["requestId"]
        assert call(server, "request_status", {"request_id": rid},
                    who=HOME) == {"status": "pending"}
        waiting = call(server, "requests", who=PANEL)["requests"]
        assert [r["requestId"] for r in waiting] == [rid]
        assert "requester" not in waiting[0]
        assert call(server, "answer", {"request_id": rid, "allow": True},
                    who=PANEL) == {"status": "allowed"}
        assert access.record["entry"] == "protected"
        assert call(server, "request_status", {"request_id": rid},
                    who=HOME) == {"status": "allowed"}

    def test_a_refusal_changes_nothing(self):
        access, server = printer_for(CASES[4])
        rid = call(server, "request", {"ask": {"kind": "entry",
                                               "entry": "protected"}},
                   who=HOME)["requestId"]
        call(server, "answer", {"request_id": rid, "allow": False}, who=PANEL)
        assert access.record["entry"] == "open"
        assert call(server, "request_status", {"request_id": rid},
                    who=HOME) == {"status": "refused"}

    def test_requests_expire(self, monkeypatch):
        _access, server = printer_for(CASES[4])
        rid = call(server, "request", {"ask": {"kind": "join"}},
                   who=HOME)["requestId"]
        later = time.time() + muon_access_api.REQUEST_SECONDS + 1
        monkeypatch.setattr(muon_access_api.time, "time", lambda: later)
        assert call(server, "request_status", {"request_id": rid},
                    who=HOME) == {"status": "expired"}
        with pytest.raises(ServerError):
            call(server, "answer", {"request_id": rid, "allow": True},
                 who=PANEL)

    def test_only_the_requester_reads_its_request(self):
        _access, server = printer_for(CASES[4])
        rid = call(server, "request", {"ask": {"kind": "join"}},
                   who=HOME)["requestId"]
        other = caller({"kind": "gateway", "level": "admin", "role": "operator",
                        "home": True, "principal": "device:other"})
        assert call(server, "request_status", {"request_id": rid},
                    who=other) == {"status": "expired"}
        assert call(server, "cancel_request", {"request_id": rid},
                    who=other) == "ok"
        assert call(server, "request_status", {"request_id": rid},
                    who=HOME) == {"status": "pending"}
        call(server, "cancel_request", {"request_id": rid}, who=HOME)
        assert call(server, "request_status", {"request_id": rid},
                    who=HOME) == {"status": "expired"}

    def test_the_screen_is_asked_only_from_home(self):
        _access, server = printer_for(CASES[3])
        away = caller(CASES[3]["caller"])
        with pytest.raises(ServerError) as err:
            call(server, "request", {"ask": {"kind": "join"}}, who=away)
        assert err.value.status_code == 403

    def test_the_waiting_list_and_the_answer_are_the_panels(self):
        _access, server = printer_for(CASES[4])
        for method, params in (("requests", {}),
                               ("answer", {"request_id": "r", "allow": True})):
            with pytest.raises(ServerError) as err:
                call(server, method, params, who=HOME)
            assert err.value.status_code == 403

    def test_a_bad_ask_is_400(self):
        _access, server = printer_for(CASES[4])
        for ask in (None, {"kind": "owner"}, {"kind": "entry", "entry": "x"}):
            with pytest.raises(ServerError) as err:
                call(server, "request", {"ask": ask}, who=HOME)
            assert err.value.status_code == 400

    def test_a_gateway_device_is_shown_by_its_key_code(self):
        _access, server = printer_for(CASES[4])
        device = caller({"kind": "gateway", "level": "signed-in-guest",
                         "role": "operator", "home": True,
                         "principal": "device:pixel"})
        ask = call(server, "request", {"ask": {"kind": "join"}}, who=device)
        assert ask["code"] == muon_access_api.key_code("device:pixel")


# ---------------------------------------------------------------------------
# Migration and rollback (access-model section 6)
# ---------------------------------------------------------------------------


class TestMigration:
    @pytest.mark.parametrize("old,entry", [(0, "open"), (1, "protected")])
    def test_from_each_old_level(self, old, entry):
        access, _p, server = printer(old_level=old)
        assert access.record["entry"] == entry
        stored = server.database.ns("muon_access").values["record"]
        assert stored["entry"] == entry and stored["written_level"] == old

    def test_a_read_error_fails_closed_to_protected(self):
        server = Server()
        server.database.ns("muon_access").fail_get = True
        access, _p, _s = printer(server=server, old_level=0)
        assert policy.state().entry == "protected"
        assert muon_floor.protection_level() == muon_floor.LEVEL_PROTECTED

    def test_open_to_protected_after_migration_writes_level_1(self):
        access, _p, server = printer(old_level=0)
        assert call(server, "set_entry", {"entry": "protected"},
                    who=PANEL) == {"applied": True}
        assert server.database.ns("muon_protection").values["level"] == 1
        assert muon_floor.protection_level() == muon_floor.LEVEL_PROTECTED

    def test_a_failed_legacy_write_refuses_the_change(self):
        access, _p, server = printer(old_level=0)
        server.database.ns("muon_protection").fail_insert = True
        with pytest.raises(ServerError) as err:
            call(server, "set_entry", {"entry": "protected"}, who=PANEL)
        assert err.value.status_code == 500
        assert access.record["entry"] == "open"
        assert server.database.ns("muon_access").values["record"][
            "entry"] == "open"
        assert muon_floor.protection_level() == muon_floor.LEVEL_OPEN

    def test_an_allowed_request_is_dual_written_too(self):
        access, _p, server = printer(old_level=0)
        rid = call(server, "request", {"ask": {"kind": "entry",
                                               "entry": "protected"}},
                   who=HOME)["requestId"]
        call(server, "answer", {"request_id": rid, "allow": True}, who=PANEL)
        assert server.database.ns("muon_protection").values["level"] == 1


class TestTheDualWriteStops:
    """The printer cannot tell what either slot holds (Rugix reports hashes
    and times, not releases), so the stop is an explicit flag a later MuonOS
    change sets: dual_write_protection_level False."""

    def test_the_old_key_is_deleted_once_and_never_written_again(self):
        server = Server()
        access, _p, server = printer(server=server, old_level=1)
        assert server.database.ns("muon_protection").values["level"] == 1
        # The release with the flag set
        access2, _p2, server = printer(server=restart(server), dual_write=False)
        assert "level" not in server.database.ns("muon_protection").values
        stored = server.database.ns("muon_access").values["record"]
        assert stored["written_level"] is None
        assert access2.record["entry"] == "protected"
        call(server, "set_entry", {"entry": "open"}, who=PANEL)
        assert "level" not in server.database.ns("muon_protection").values
        # what check_protection enforces still follows the entry
        assert muon_floor.protection_level() == muon_floor.LEVEL_OPEN

    def test_a_restart_after_deletion_keeps_the_entry(self):
        server = Server()
        _a, _p, server = printer(server=server, old_level=1)
        _a, _p, server = printer(server=restart(server), dual_write=False)
        access, _p, server = printer(server=restart(server), dual_write=False)
        assert access.record["entry"] == "protected"
        assert muon_floor.protection_level() == muon_floor.LEVEL_PROTECTED

    def test_a_failed_delete_keeps_the_dual_write_state(self):
        server = Server()
        _a, _p, server = printer(server=server, old_level=1)
        server.database.ns("muon_protection").fail_delete = True
        access, _p, server = printer(server=restart(server), dual_write=False)
        assert server.database.ns("muon_access").values["record"][
            "written_level"] == 1


class TestReleaseNsGuard:
    """The release before muon_access, or one with [muon_access] left out:
    muon_protection reads the access record and never reopens."""

    def test_a_record_saying_protected_holds_a_stale_open_level(self):
        server = Server()
        server.database.ns("muon_access").values["record"] = {
            "version": 1, "entry": "protected", "preset": None,
            "overrides": {}, "written_level": 0}
        printer(server=server, old_level=0, with_access=False)
        assert muon_floor.protection_level() == muon_floor.LEVEL_PROTECTED

    def test_an_open_record_leaves_the_level_alone(self):
        server = Server()
        server.database.ns("muon_access").values["record"] = {
            "version": 1, "entry": "open", "preset": None, "overrides": {},
            "written_level": 0}
        printer(server=server, old_level=0, with_access=False)
        assert muon_floor.protection_level() == muon_floor.LEVEL_OPEN

    def test_no_record_is_todays_muon_protection(self):
        printer(old_level=0, with_access=False)
        assert muon_floor.protection_level() == muon_floor.LEVEL_OPEN

    def test_the_panel_can_still_open_it_and_the_record_follows(self):
        server = Server()
        server.database.ns("muon_access").values["record"] = {
            "version": 1, "entry": "protected", "preset": None,
            "overrides": {}, "written_level": 1}
        _a, protection, server = printer(server=server, old_level=1,
                                         with_access=False)
        request = WebRequest("/server/muon/protection", {"level": 0},
                             RequestType.POST, HTTP, LOOPBACK,
                             UserInfo("_TRUSTED_USER_", ""))
        asyncio.run(protection._handle(request))
        assert server.database.ns("muon_access").values["record"][
            "entry"] == "open"
        # after a reboot the guard does not hold it Protected
        printer(server=restart(server), with_access=False)
        assert muon_floor.protection_level() == muon_floor.LEVEL_OPEN

    def test_the_guard_steps_aside_when_muon_access_is_loaded(self):
        server = Server()
        access, _p, server = printer(server=server, old_level=0)
        assert muon_floor.protection_level() == muon_floor.LEVEL_OPEN
        assert LAN is not None and SENTINEL is not None   # fakes in use


class TestANewDeviceAsks:
    """ACC-6: on a Protected printer a new device is not admitted, and that
    is exactly the caller that must be able to ask the panel."""

    def _through(self, server, path, verb, params, who):
        verbs, handler = server.handlers[path]
        api = APIDefinition.create(path, [verb], handler)
        request_type = RequestType.GET if verb == "GET" else RequestType.POST
        return asyncio.run(api.request(dict(params), request_type, *who))

    def test_ask_and_poll_before_being_admitted(self):
        access, server = printer_for(CASES[1])   # no owner, Protected
        assert policy.resolve_principal(*HOME, "protected",
                                        policy.state().home) is None
        ask = self._through(server, "/server/muon/access/request", "POST",
                            {"ask": {"kind": "join"}}, HOME)
        rid = ask["requestId"]
        assert self._through(server, "/server/muon/access/request_status",
                             "GET", {"request_id": rid}, HOME) == {
            "status": "pending"}
        call(server, "answer", {"request_id": rid, "allow": True}, who=PANEL)
        assert self._through(server, "/server/muon/access/request_status",
                             "GET", {"request_id": rid}, HOME) == {
            "status": "allowed"}

    def test_but_nothing_else(self):
        _access, server = printer_for(CASES[1])
        with pytest.raises(ServerError) as err:
            self._through(server, "/server/muon/access/get", "GET", {}, HOME)
        assert err.value.status_code == 403

    def test_and_not_from_away(self):
        import ipaddress
        _access, server = printer_for(CASES[1])
        public = (HTTP, ipaddress.ip_address("203.0.113.9"),
                  UserInfo("_TRUSTED_USER_", ""))
        with pytest.raises(ServerError) as err:
            self._through(server, "/server/muon/access/request", "POST",
                          {"ask": {"kind": "join"}}, public)
        assert err.value.status_code == 403
        anonymous_gateway = (HTTP, SENTINEL, UserInfo("_TRUSTED_USER_", ""))
        with pytest.raises(ServerError):
            self._through(server, "/server/muon/access/request", "POST",
                          {"ask": {"kind": "join"}}, anonymous_gateway)

    def test_another_address_cannot_read_it(self):
        import ipaddress
        _access, server = printer_for(CASES[1])
        rid = call(server, "request", {"ask": {"kind": "join"}},
                   who=HOME)["requestId"]
        neighbour = (HTTP, ipaddress.ip_address("192.168.1.51"),
                     UserInfo("_TRUSTED_USER_", ""))
        assert call(server, "request_status", {"request_id": rid},
                    who=neighbour) == {"status": "expired"}
