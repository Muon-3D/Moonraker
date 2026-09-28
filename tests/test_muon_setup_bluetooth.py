"""muon_setup and setup over Bluetooth (KAN-436, ADR 0032 D4 and D7).

The contract, from ADR 0032's D7 table:

* **Caller class.** A request from muon-link's gateway with
  `X-Real-IP: 192.0.2.2` is `bluetooth`: the hotspot's rights and the driver
  kind `bluetooth` while setup is not complete, the rights of `remote` after.
  "From the gateway" is muon_gateway's user, whose one-shot token is bound to
  the address muon-link asked for; the address alone is nobody.
* **State.** `nearby` is `{"code": "F6QTDH"}` from the latest `bluetooth`
  request that carried a well-formed `X-Muon-Ble-Code`, and `null` 20 s after
  the last such request and once setup is complete.

`muon_floor`'s half ("treats it as remote") is in tests/test_muon_floor.py,
and the token binding in tests/test_muon_gateway.py.
"""

from __future__ import annotations

import asyncio
import copy
import ipaddress
from typing import Any, Dict, List

import pytest
from tornado.httputil import HTTPHeaders

from moonraker.common import RequestType, UserInfo, WebRequest
from moonraker.components import muon_setup as pkg
from moonraker.components.muon_setup import caller, clock, model
from moonraker.utils.exceptions import ServerError

from muon_setup_fakes import (
    GOOD_HEADERS, FakeWebsocket, Harness, request, run, state_with,
)
from test_muon_setup import ACCESS

BLUETOOTH_IP = ipaddress.ip_address("192.0.2.2")
CODE = "F6QTDH"


def in_setup() -> Dict[str, Any]:
    return state_with(language={"status": "done", "value": "en"})


def complete() -> Dict[str, Any]:
    doc = model.migrated_document(["transport_clips", "self_test",
                                   "load_filament"])
    doc["rev"] = 7
    return doc


def refused_as(info: Any, kind: str = "bluetooth") -> None:
    """The specific refusal, not any 403."""
    assert info.value.status_code == 403
    assert str(info.value) == f"muon_setup: not allowed from {kind}"


class Clock:
    """An injectable clock for `nearby`."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


async def with_clock(h: Harness) -> Clock:
    fake = Clock()
    h.setup.nearby_clock = fake
    return fake


def changes_since(h: Harness, mark: int) -> List[Dict[str, Any]]:
    return h.server.changes()[mark:]


# ==========================================================================
# The caller class
# ==========================================================================

class TestClassification:
    def test_the_bluetooth_address_from_the_gateway_is_bluetooth(self):
        web = request("bluetooth", "/server/muon/setup")
        assert web.get_ip_address() == BLUETOOTH_IP
        assert web.get_current_user().source == "muon_gateway"
        assert caller.caller_kind(web) == "bluetooth"

    @pytest.mark.parametrize("usr", [
        None,
        # What trusted_clients or a Moonraker login would hand a caller: not
        # muon_gateway's user, so not a token muon-link asked for.
        UserInfo("_TRUSTED_USER_", "", groups=["network"], source="moonraker"),
        UserInfo("someone", "", groups=["network"], source="ldap"),
    ])
    def test_the_same_address_from_anyone_else_is_nobody(self, usr: Any):
        """A peer that sets `X-Real-IP: 192.0.2.2` itself gets no token for
        it, so it is `other`: not `bluetooth`, and not even `remote`."""
        web = WebRequest("/server/muon/setup", {}, RequestType.GET, None,
                         BLUETOOTH_IP, usr, dict(GOOD_HEADERS))
        assert caller.caller_kind(web) == "other"

    def test_a_paired_sessions_token_is_remote_not_bluetooth(self):
        """The gateway's user at 192.0.2.1 is a paired session. Only the
        pair (gateway user, 192.0.2.2) is Bluetooth."""
        assert caller.caller_kind(request("remote", "/x")) == "remote"

    def test_the_address_is_the_floors_and_the_gateways(self):
        from moonraker import muon_floor
        from moonraker.components import muon_gateway
        assert caller.BLUETOOTH_SENTINEL == BLUETOOTH_IP
        assert caller.BLUETOOTH_SENTINEL == muon_floor.BLUETOOTH_SENTINEL
        assert caller.BLUETOOTH_SENTINEL == muon_gateway.BLUETOOTH_SENTINEL

    @pytest.mark.parametrize("state_complete,rights", [
        (False, "hotspot"), (True, "remote"),
    ])
    def test_bluetooth_has_the_hotspots_rights_then_remotes(
        self, state_complete: bool, rights: str
    ):
        assert caller.rights_of("bluetooth", state_complete) == rights
        for kind in ("panel", "hotspot", "lan", "remote", "other", "internal"):
            assert caller.rights_of(kind, state_complete) == kind


# ==========================================================================
# Rights before and after completion
# ==========================================================================

class TestRights:
    @pytest.mark.parametrize("endpoint,verb,body,allowed", ACCESS)
    def test_during_setup_bluetooth_may_do_what_the_hotspot_may(
        self, endpoint: str, verb: str, body: Any, allowed: set
    ):
        async def go():
            h = await Harness(stored=in_setup()).start()
            path = f"/server/muon/setup{endpoint}"
            if "hotspot" in allowed:
                result = await h.call("bluetooth", path, copy.deepcopy(body),
                                      method=verb)
                assert isinstance(result, dict)
                if "ok" in result:
                    assert result["ok"] is True, result
            else:
                rev = h.doc["rev"]
                with pytest.raises(ServerError) as info:
                    await h.call("bluetooth", path, copy.deepcopy(body),
                                 method=verb)
                refused_as(info)
                assert h.doc["rev"] == rev
        run(go())

    @pytest.mark.parametrize("endpoint,verb,body,allowed", ACCESS)
    def test_after_setup_bluetooth_may_do_what_remote_may(
        self, endpoint: str, verb: str, body: Any, allowed: set
    ):
        async def go():
            h = await Harness(stored=complete()).start()
            path = f"/server/muon/setup{endpoint}"
            args = dict(copy.deepcopy(body or {}))
            if "rev" in args:
                args["rev"] = 7
            if "remote" in allowed:
                result = await h.call("bluetooth", path, args, method=verb)
                assert result["state"] == "complete"
            else:
                before = copy.deepcopy(h.stored())
                with pytest.raises(ServerError) as info:
                    await h.call("bluetooth", path, args, method=verb)
                refused_as(info)
                assert h.stored() == before
        run(go())

    def test_during_setup_bluetooth_may_post_the_clock_like_the_hotspot(self):
        """02 §3: only the hotspot may post the clock. A phone over Bluetooth
        knows the owner's local time just as well, and has the hotspot's
        rights. Past the caller check, the handler answers on the merits: a
        time before the image was built is `invalid_clock`, not a 403."""
        async def go():
            h = await Harness(stored=in_setup()).start()
            result = await h.post("/clock", {"epoch_ms": 1}, kind="bluetooth")
            assert result["error"]["code"] == "invalid_clock"
        run(go())

    def test_after_setup_bluetooth_may_not_post_the_clock(self):
        async def go():
            h = await Harness(stored=complete()).start()
            with pytest.raises(ServerError) as info:
                await h.post("/clock", {"epoch_ms": 1_790_000_000_000},
                             kind="bluetooth")
            refused_as(info)
            assert h.aux.posted("/time") == []
            assert h.aux.posted("/time/zone") == []
        run(go())

    def test_the_clock_check_uses_the_same_rule(self):
        async def go():
            h = await Harness(stored=in_setup()).start()
            web = request("bluetooth", "/server/muon/setup/clock")
            assert h.setup.begin(web, clock.CLOCK_CALLERS) == "bluetooth"
        run(go())

    @pytest.mark.parametrize("action", ["start", "confirm"])
    def test_ready_actions_stay_panel_only(self, action: str):
        async def go():
            h = await Harness(stored=in_setup()).start()
            with pytest.raises(ServerError) as info:
                await h.post("/ready", {"rev": 5, "item": "self_test",
                                        "action": action}, kind="bluetooth")
            refused_as(info)
        run(go())

    def test_a_write_that_waited_while_setup_finished_is_refused(self):
        """Rights are read again under the lock: a Bluetooth write queued
        behind `finish` must not land with the hotspot's rights on a printer
        that is now complete."""
        async def go():
            h = await Harness(stored=in_setup()).start()
            await h.setup._lock.acquire()
            task = asyncio.ensure_future(h.post(
                "/card/dismiss", {"rev": 5}, kind="bluetooth"))
            for _ in range(5):
                await asyncio.sleep(0)
            h.setup.doc["state"] = "complete"
            h.setup._lock.release()
            with pytest.raises(ServerError) as info:
                await task
            refused_as(info)
            assert h.doc["card_dismissed"] is False
        run(go())

    def test_a_write_before_the_state_is_known_gets_the_narrower_rights(self):
        """Until the migration check decides, `bluetooth` is not given the
        hotspot's rights: nobody knows yet whether setup is complete."""
        async def go():
            h = Harness(stored=in_setup())
            assert h.setup.doc is None
            with pytest.raises(ServerError) as info:
                await h.post("/skip", {"rev": 5, "step": "network"},
                             kind="bluetooth")
            refused_as(info)
        run(go())


# ==========================================================================
# The driver kind
# ==========================================================================

class TestDriver:
    @pytest.mark.parametrize("named", ["phone", "web", "app", "bluetooth"])
    def test_a_bluetooth_claim_is_stored_as_bluetooth(self, named: str):
        async def go():
            h = await Harness(stored=in_setup()).start()
            result = await h.post("/driver", {"rev": 5, "kind": named,
                                              "client_id": "b1"},
                                  kind="bluetooth")
            driver = result["state"]["driver"]
            assert driver["kind"] == "bluetooth"
            assert driver["client_id"] == "b1"
            assert driver["lapsed"] is False
            assert result["state"]["rev"] == 5
            assert h.stored()["driver"]["kind"] == "bluetooth"
        run(go())

    def test_a_bluetooth_renewal_is_silent_and_keeps_rev(self):
        async def go():
            h = await Harness(stored=in_setup()).start()
            body = {"rev": 5, "kind": "app", "client_id": "b1"}
            first = await h.post("/driver", body, kind="bluetooth")
            mark = len(h.server.changes())
            renewed = await h.post("/driver", body, kind="bluetooth")
            assert renewed["state"]["driver"]["since"] == \
                first["state"]["driver"]["since"]
            assert renewed["state"]["rev"] == 5
            assert changes_since(h, mark) == []
        run(go())

    def test_a_bluetooth_claim_lapses_like_a_phones(self):
        doc = {"kind": "bluetooth", "client_id": "b1", "since": 100.0,
               "renewed": 100.0}
        assert model.driver_public(doc, 30., now=131.0)["lapsed"] is True

    def test_a_bluetooth_write_takes_the_driver_as_bluetooth(self):
        async def go():
            h = await Harness(stored=in_setup()).start()
            result = await h.post("/skip", {"rev": 5, "step": "network",
                                            "client_id": "b1"},
                                  kind="bluetooth")
            assert result["ok"] is True
            assert result["state"]["driver"]["kind"] == "bluetooth"
            assert result["state"]["driver"]["client_id"] == "b1"
            assert result["state"]["rev"] == 6
        run(go())

    def test_bluetooth_cannot_claim_the_panel(self):
        async def go():
            h = await Harness(stored=in_setup()).start()
            with pytest.raises(ServerError) as info:
                await h.post("/driver", {"rev": 5, "kind": "panel",
                                         "client_id": "b1"}, kind="bluetooth")
            assert info.value.status_code == 403
            assert str(info.value) == \
                "muon_setup: a bluetooth caller cannot drive as panel"
            assert h.doc["driver"] is None
        run(go())

    @pytest.mark.parametrize("kind", ["hotspot", "lan"])
    def test_no_other_caller_can_claim_bluetooth(self, kind: str):
        """The panel's "a phone over Bluetooth" must be true."""
        async def go():
            h = await Harness(stored=in_setup()).start()
            with pytest.raises(ServerError) as info:
                await h.post("/driver", {"rev": 5, "kind": "bluetooth",
                                         "client_id": "c1"}, kind=kind)
            assert info.value.status_code == 403
            assert str(info.value) == \
                f"muon_setup: a {kind} caller cannot drive as bluetooth"
            assert h.doc["driver"] is None
        run(go())

    def test_the_panel_cannot_claim_bluetooth(self):
        async def go():
            h = await Harness(stored=in_setup()).start()
            with pytest.raises(ServerError) as info:
                await h.post("/driver", {"rev": 5, "kind": "bluetooth",
                                         "client_id": "c1"})
            assert str(info.value) == \
                "muon_setup: a panel caller cannot drive as bluetooth"
        run(go())

    def test_after_setup_bluetooth_cannot_claim_at_all(self):
        async def go():
            h = await Harness(stored=complete()).start()
            with pytest.raises(ServerError) as info:
                await h.post("/driver", {"rev": 7, "kind": "app",
                                         "client_id": "b1"}, kind="bluetooth")
            refused_as(info)
            assert h.doc["driver"] is None
        run(go())


# ==========================================================================
# `nearby`
# ==========================================================================

class TestNearby:
    def test_nobody_nearby_is_null_and_the_key_is_after_driver(self):
        async def go():
            return (await Harness(stored=in_setup()).start()).setup.public_state()
        state = run(go())
        assert state["nearby"] is None
        keys = list(state)
        assert keys.index("nearby") == keys.index("driver") + 1

    def test_a_bluetooth_request_with_a_code_sets_it_and_announces_it(self):
        async def go():
            h = await Harness(stored=in_setup()).start()
            mark = len(h.server.changes())
            web = request("bluetooth", "/server/muon/setup", method="GET",
                          ble_code=CODE)
            state = await h.server.endpoints["/server/muon/setup"][1](web)
            assert state["nearby"] == {"code": CODE}
            announced = changes_since(h, mark)
            assert [c["nearby"] for c in announced] == [{"code": CODE}]
            # A computed field: announced with the same rev, never stored.
            assert announced[0]["rev"] == 5
            assert "nearby" not in h.stored()
        run(go())

    def test_every_setup_request_carries_it_writes_and_the_websocket_too(self):
        async def go():
            h = await Harness(stored=in_setup()).start()
            await h.post("/driver", {"rev": 5, "kind": "app", "client_id": "b1"},
                         kind="bluetooth", ble_code="0123AB")
            assert h.setup.public_state()["nearby"] == {"code": "0123AB"}
            await h.call("bluetooth", "/server/muon/setup/options",
                         method="GET", ble_code="0123AC")
            assert h.setup.public_state()["nearby"] == {"code": "0123AC"}
            await h.post("/skip", {"rev": 5, "step": "network"},
                         kind="bluetooth", ble_code="0123AD")
            assert h.setup.public_state()["nearby"] == {"code": "0123AD"}
            # JSON-RPC over the websocket reports the upgrade request's
            # headers, which is where the gateway put the code.
            web = request("bluetooth", "/server/muon/setup", method="GET",
                          websocket=True, ble_code="0123AE")
            assert isinstance(web.get_subscribable(), FakeWebsocket)
            await h.server.endpoints["/server/muon/setup"][1](web)
            assert h.setup.public_state()["nearby"] == {"code": "0123AE"}
        run(go())

    def test_a_new_code_replaces_the_old_and_a_repeat_is_not_announced(self):
        async def go():
            h = await Harness(stored=in_setup()).start()
            await h.call("bluetooth", "/server/muon/setup", method="GET",
                         ble_code=CODE)
            mark = len(h.server.changes())
            await h.call("bluetooth", "/server/muon/setup", method="GET",
                         ble_code=CODE)
            assert changes_since(h, mark) == []
            await h.call("bluetooth", "/server/muon/setup", method="GET",
                         ble_code="ZZZZ99")
            assert [c["nearby"] for c in changes_since(h, mark)] == [
                {"code": "ZZZZ99"}]
        run(go())

    @pytest.mark.parametrize("bad", [
        "f6qtdh",       # lower case: the gateway sends the symbols as shown
        "F6QTD",        # five
        "F6QTDHX",      # seven
        "F6Q TDH",      # the panel's grouping, not the header's
        "F6QTDI", "F6QTDL", "F6QTDO", "F6QTDU",  # not in Crockford's alphabet
        "F6QTD-", "",
        "F6QTDH\n",
        "Ｆ６ＱＴＤＨ",  # fullwidth F6QTDH
    ])
    def test_a_malformed_code_is_ignored(self, bad: str):
        async def go():
            h = await Harness(stored=in_setup()).start()
            await h.call("bluetooth", "/server/muon/setup", method="GET",
                         ble_code=CODE)
            mark = len(h.server.changes())
            await h.call("bluetooth", "/server/muon/setup", method="GET",
                         ble_code=bad)
            # Neither cleared nor replaced, and nothing announced.
            assert h.setup.public_state()["nearby"] == {"code": CODE}
            assert changes_since(h, mark) == []
        run(go())

    def test_a_malformed_code_alone_sets_nothing(self):
        async def go():
            h = await Harness(stored=in_setup()).start()
            await h.call("bluetooth", "/server/muon/setup", method="GET",
                         ble_code="F6QTDI")
            assert h.setup.public_state()["nearby"] is None
        run(go())

    def test_two_copies_of_the_header_are_malformed(self):
        async def go():
            h = await Harness(stored=in_setup()).start()
            headers = HTTPHeaders(GOOD_HEADERS)
            headers.add("X-Muon-Ble-Code", CODE)
            headers.add("X-Muon-Ble-Code", CODE)
            usr = UserInfo("muon-link:ab12", "", groups=["network"],
                           source="muon_gateway")
            web = WebRequest("/server/muon/setup", {}, RequestType.GET, None,
                             BLUETOOTH_IP, usr, headers)
            await h.server.endpoints["/server/muon/setup"][1](web)
            assert h.setup.public_state()["nearby"] is None
            one = HTTPHeaders(GOOD_HEADERS)
            one.add("X-Muon-Ble-Code", CODE)
            web = WebRequest("/server/muon/setup", {}, RequestType.GET, None,
                             BLUETOOTH_IP, usr, one)
            await h.server.endpoints["/server/muon/setup"][1](web)
            assert h.setup.public_state()["nearby"] == {"code": CODE}
        run(go())

    @pytest.mark.parametrize("kind", ["panel", "hotspot", "lan", "remote",
                                      "other"])
    def test_a_code_on_any_other_caller_is_ignored(self, kind: str):
        async def go():
            h = await Harness(stored=in_setup()).start()
            mark = len(h.server.changes())
            try:
                await h.call(kind, "/server/muon/setup", method="GET",
                             ble_code=CODE)
            except ServerError:
                pass  # `other` may not read; the code is ignored all the same
            assert h.setup.public_state()["nearby"] is None
            assert changes_since(h, mark) == []
        run(go())

    def test_a_code_from_the_bluetooth_address_without_the_token_is_ignored(
        self
    ):
        async def go():
            h = await Harness(stored=in_setup()).start()
            headers = dict(GOOD_HEADERS, **{"X-Muon-Ble-Code": CODE})
            web = WebRequest("/server/muon/setup", {}, RequestType.GET, None,
                             BLUETOOTH_IP, None, headers)
            with pytest.raises(ServerError) as info:
                await h.server.endpoints["/server/muon/setup"][1](web)
            refused_as(info, "other")
            assert h.setup.public_state()["nearby"] is None
        run(go())

    def test_it_expires_20_s_after_the_last_code_and_says_so(self):
        async def go():
            h = await Harness(stored=in_setup()).start()
            clk = await with_clock(h)
            await h.call("bluetooth", "/server/muon/setup", method="GET",
                         ble_code=CODE)
            assert h.setup._nearby_timer is not None
            clk.now += 10.0
            # A request 10 s in moves the 20 s on; not announced.
            await h.call("bluetooth", "/server/muon/setup", method="GET",
                         ble_code=CODE)
            mark = len(h.server.changes())
            clk.now += 19.9
            assert h.setup.public_state()["nearby"] == {"code": CODE}
            # The timer fires early (its 20 s ran from the first request):
            # nothing changes, and it waits out the rest.
            h.setup._on_nearby_timer()
            assert changes_since(h, mark) == []
            assert h.setup._nearby_timer is not None
            clk.now += 0.1
            assert h.setup.public_state()["nearby"] is None
            h.setup._on_nearby_timer()
            announced = changes_since(h, mark)
            assert len(announced) == 1
            assert announced[0]["nearby"] is None
            assert announced[0]["rev"] == 5
            # Once is enough.
            h.setup._on_nearby_timer()
            assert len(changes_since(h, mark)) == 1
        run(go())

    def test_the_timer_really_fires(self, monkeypatch):
        monkeypatch.setattr(pkg, "NEARBY_TTL", 0.05)

        async def go():
            h = await Harness(stored=in_setup()).start()
            await h.call("bluetooth", "/server/muon/setup", method="GET",
                         ble_code=CODE)
            mark = len(h.server.changes())
            await asyncio.sleep(0.4)
            announced = changes_since(h, mark)
            assert [c["nearby"] for c in announced] == [None]
        run(go())

    def test_a_request_without_a_code_does_not_keep_it_alive(self):
        async def go():
            h = await Harness(stored=in_setup()).start()
            clk = await with_clock(h)
            await h.call("bluetooth", "/server/muon/setup", method="GET",
                         ble_code=CODE)
            clk.now += 15.0
            await h.call("bluetooth", "/server/muon/setup", method="GET")
            clk.now += 5.0
            assert h.setup.public_state()["nearby"] is None
        run(go())

    def test_it_is_cleared_when_setup_completes(self):
        async def go():
            h = await Harness(stored=in_setup()).start()
            await h.call("bluetooth", "/server/muon/setup", method="GET",
                         ble_code=CODE)
            mark = len(h.server.changes())
            result = await h.post("/finish", {"rev": 5})
            assert result["state"]["state"] == "complete"
            assert result["state"]["nearby"] is None
            assert all(c["nearby"] is None for c in changes_since(h, mark))
            await h.setup.drain()
            assert h.setup._nearby is None
            assert h.setup._nearby_timer is None
            # A reset does not bring back the code from before it.
            await h.post("/reset", {})
            assert h.setup.public_state()["nearby"] is None
        run(go())

    def test_after_setup_a_code_sets_nothing(self):
        async def go():
            h = await Harness(stored=complete()).start()
            mark = len(h.server.changes())
            state = await h.call("bluetooth", "/server/muon/setup",
                                 method="GET", ble_code=CODE)
            assert state["nearby"] is None
            assert h.setup._nearby is None
            assert changes_since(h, mark) == []
        run(go())


# ==========================================================================
# Write hygiene over Bluetooth
# ==========================================================================

#: What muon-link-client's HTTP encoder always writes, and the gateway
#: forwards unchanged (crates/muon-link-client/src/http.rs).
CLIENT_HEADERS = {"Host": "printer", "Content-Type": "application/json"}
HOST_REFUSAL = "muon_setup: Host is not this printer"


class TestHygiene:
    def test_a_bluetooth_write_with_the_clients_host_succeeds(self):
        async def go():
            h = await Harness(stored=in_setup()).start()
            result = await h.post("/skip", {"rev": 5, "step": "network"},
                                  kind="bluetooth", headers=CLIENT_HEADERS)
            assert result["ok"] is True
            assert h.doc["steps"]["network"]["status"] == "skipped"
            claim = await h.post("/driver", {"rev": 6, "kind": "app",
                                             "client_id": "b1"},
                                 kind="bluetooth", headers=CLIENT_HEADERS)
            assert claim["state"]["driver"]["kind"] == "bluetooth"
        run(go())

    def test_a_bluetooth_write_over_the_websocket_with_that_host_succeeds(self):
        async def go():
            h = await Harness(stored=in_setup()).start()
            result = await h.post("/skip", {"rev": 5, "step": "network"},
                                  kind="bluetooth", headers=CLIENT_HEADERS,
                                  websocket=True)
            assert result["ok"] is True
        run(go())

    @pytest.mark.parametrize("kind", ["hotspot", "lan", "panel"])
    def test_the_same_host_from_any_other_caller_is_still_refused(
        self, kind: str
    ):
        async def go():
            h = await Harness(stored=in_setup()).start()
            with pytest.raises(ServerError) as info:
                await h.post("/skip", {"rev": 5, "step": "network"},
                             kind=kind, headers=CLIENT_HEADERS)
            assert info.value.status_code == 403
            assert str(info.value) == HOST_REFUSAL
            assert h.doc["steps"]["network"]["status"] == "pending"
            assert h.doc["rev"] == 5
        run(go())

    def test_the_bluetooth_address_without_the_token_gets_no_exemption(self):
        """Not `bluetooth`, so `other`: refused as a caller before the Host
        rule is reached, and nothing changes."""
        async def go():
            h = await Harness(stored=in_setup()).start()
            web = WebRequest("/server/muon/setup/skip",
                             {"rev": 5, "step": "network"}, RequestType.POST,
                             None, BLUETOOTH_IP, None, dict(CLIENT_HEADERS))
            with pytest.raises(ServerError) as info:
                await h.server.endpoints["/server/muon/setup/skip"][1](web)
            refused_as(info, "other")
            assert h.doc["rev"] == 5
        run(go())

    def test_the_host_rule_itself_is_unchanged_for_other_callers(self):
        """check_hygiene without the exemption: `printer` is refused with the
        existing message, as before KAN-436."""
        web = request("hotspot", "/server/muon/setup/skip", {"rev": 5},
                      headers=CLIENT_HEADERS)
        with pytest.raises(ServerError) as info:
            caller.check_hygiene(web, {"10.42.0.1"})
        assert str(info.value) == HOST_REFUSAL

    @pytest.mark.parametrize("state", ["in_setup", "complete"])
    def test_a_remote_caller_is_unchanged(self, state: str):
        """`remote` may not write, so it is refused as a caller, with or
        without the client's Host, before and after setup."""
        async def go():
            stored = in_setup() if state == "in_setup" else complete()
            h = await Harness(stored=stored).start()
            for headers in (CLIENT_HEADERS, GOOD_HEADERS):
                with pytest.raises(ServerError) as info:
                    await h.post("/skip", {"rev": stored["rev"],
                                           "step": "network"},
                                 kind="remote", headers=headers)
                refused_as(info, "remote")
            assert h.doc["rev"] == stored["rev"]
        run(go())

    def test_bluetooth_still_needs_a_json_content_type(self):
        async def go():
            h = await Harness(stored=in_setup()).start()
            with pytest.raises(ServerError) as info:
                await h.post("/skip", {"rev": 5, "step": "network"},
                             kind="bluetooth",
                             headers={"Host": "printer",
                                      "Content-Type": "text/plain"})
            assert info.value.status_code == 415
            assert str(info.value) == \
                "muon_setup: writes need Content-Type: application/json"
            assert h.doc["steps"]["network"]["status"] == "pending"
        run(go())

    def test_bluetooth_still_has_a_foreign_origin_refused(self):
        """Only the Host rule is lifted. The client sends no Origin; one that
        is sent must still name the printer."""
        async def go():
            h = await Harness(stored=in_setup()).start()
            with pytest.raises(ServerError) as info:
                await h.post("/skip", {"rev": 5, "step": "network"},
                             kind="bluetooth",
                             headers=dict(CLIENT_HEADERS,
                                          Origin="http://evil.example"))
            assert info.value.status_code == 403
            assert str(info.value) == "muon_setup: Origin is not this printer"
        run(go())

    def test_after_setup_the_exemption_opens_nothing(self):
        async def go():
            h = await Harness(stored=complete()).start()
            with pytest.raises(ServerError) as info:
                await h.post("/card/dismiss", {"rev": 7}, kind="bluetooth",
                             headers=CLIENT_HEADERS)
            refused_as(info)
        run(go())
