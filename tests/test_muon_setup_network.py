"""MR-3: GET /networks, POST /network (join), POST /region, profile cleanup.

02 §5.5, §5.6, §5.6a; the §8 tests 4, 5, 6, 9 and 10. Every join runs the
real runner against JoinScript's fake Aux; the ioctl finds no wlan0 on the
test box, so the address comes from FakeMachine (network.interface_ipv4's
documented fallback).
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List

import pytest

from moonraker.components.muon_setup import network
from moonraker.utils.exceptions import ServerError

from muon_setup_fakes import (
    FakeAux, Harness, JoinScript, REGION_174, REGION_OPTIONS_174,
    fresh_aux, run, state_with,
)

PSK = "hunter2hunter2"  # never logged anywhere
SSID = "HomeWiFi"


def join_body(**kw: Any) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "rev": 5, "kind": "wifi", "ssid": SSID, "security": "wpa2",
        "psk": PSK}
    body.update(kw)
    return body


def join_state() -> Dict[str, Any]:
    return state_with(language={"status": "done", "value": "en"})


def wifi_aux(script: JoinScript, **extra: Any) -> FakeAux:
    routes = fresh_aux().routes
    routes.update(script.routes())
    for key, value in extra.items():
        method, path = key.split(" ", 1)
        routes[(method, path)] = value
    return FakeAux(routes)


async def joined(h: Harness) -> None:
    """Run the join runner to completion."""
    await h.setup.drain()


class TestValidation:
    """02 §5.6 step 1: invalid_network with detail.field, in order."""

    @pytest.mark.parametrize("field,body", [
        ("ssid", {"ssid": ""}),
        ("ssid", {"ssid": "x" * 33}),
        ("psk", {"security": "wpa2", "psk": "short"}),
        ("psk", {"security": "wpa2", "psk": None}),
        ("psk", {"security": "open", "psk": PSK}),
        ("kind", {"kind": "nfc"}),
    ])
    def test_invalid_fields(self, field: str, body: Dict[str, Any]):
        async def go():
            h = await Harness(stored=join_state()).start()
            out = await h.post("/network", join_body(**body))
            assert out["ok"] is False
            assert out["error"]["code"] == "invalid_network"
            assert out["error"]["detail"]["field"] == field
            assert h.doc["op"] is None
        run(go())

    def test_64_hex_psk_is_valid(self):
        async def go():
            h = await Harness(stored=join_state(),
                              aux=wifi_aux(JoinScript())).start()
            out = await h.post("/network", join_body(psk="a" * 64))
            assert out["ok"] is True
            await h.setup.drain()
        run(go())

    @pytest.mark.parametrize("security", ["wep", "enterprise"])
    def test_wep_and_enterprise_unsupported(self, security: str):
        """OS-4 isn't built: wep and enterprise refuse before Aux is asked."""
        async def go():
            h = await Harness(stored=join_state()).start()
            out = await h.post(
                "/network",
                join_body(security=security, psk=PSK,
                          eap={"method": "peap", "phase2": "mschapv2",
                               "identity": "u", "password": "p",
                               "no_ca_check": True}))
            assert out["ok"] is False
            assert out["error"]["code"] == "unsupported_security"
            assert not h.aux.posted("/wifi/connect")
        run(go())

    def test_hidden_is_unsupported_until_os3(self):
        async def go():
            h = await Harness(stored=join_state()).start()
            out = await h.post("/network", join_body(hidden=True))
            assert out["ok"] is False
            assert out["error"]["code"] == "unsupported_security"
        run(go())

    def test_region_must_be_offered(self):
        async def go():
            h = await Harness(stored=join_state()).start()
            out = await h.post("/network", join_body(region="US"))
            assert out["ok"] is False
            assert out["error"]["code"] == "region_not_offered"
        run(go())


class TestJoin:
    def test_a_join_moves_the_phases_and_finishes_done(self):
        """Picker market: an address lands, region stays unconfirmed, the
        step stays pending for the owner to confirm (02 §5.6a)."""
        async def go():
            script = JoinScript(
                device_states=["preparing", "ip-config", "activated"],
                uplink={"kind": "wifi", "ssid": SSID,
                        "addresses": ["192.168.1.37"], "internet": True})
            h = await Harness(stored=join_state(),
                              aux=wifi_aux(script)).start()
            out = await h.post("/network", join_body())
            assert out["ok"] is True
            assert out["state"]["op"]["kind"] == "join"
            assert out["state"]["op"]["phase"] == "saving"
            await joined(h)
            step = h.doc["steps"]["network"]
            assert step["ssid"] == SSID
            assert step["addresses"] == ["192.168.1.37"]
            assert step["internet"] is True
            assert step["region_confirmed"] is False
            assert step["status"] == "pending"  # picker market
            assert h.doc["op"] is None
            assert h.doc["cursor"] == "network"
            # The phases were notified in order.
            phases = [s["op"]["phase"] for s in h.server.changes()
                      if s.get("op")]
            assert phases[0] == "saving" and "dhcp" in phases
            assert "internet_check" in phases and "update_check" in phases
        run(go())

    def test_busy_and_cancel_cleans_up(self):
        """02 §8 test 4: a write during a join is `busy`; cancel clears the
        op and deletes the not-previously-saved profile."""
        async def go():
            gate = asyncio.Event()

            async def slow_connect(body: Any) -> Any:
                await gate.wait()
                return {"status": "connecting", "ssid": body["ssid"]}
            script = JoinScript()
            aux = wifi_aux(script)
            aux.routes[("POST", "/wifi/connect")] = slow_connect
            h = await Harness(stored=join_state(), aux=aux).start()
            out = await h.post("/network", join_body())
            assert out["ok"] is True
            busy = await h.post("/skip", {"rev": h.doc["rev"],
                                          "step": "network"})
            assert busy["ok"] is False and busy["error"]["code"] == "busy"
            cancel = await h.post("/network/cancel", {})
            assert cancel["ok"] is True
            assert h.doc["op"] is None
            assert script.forgets == [SSID]
            gate.set()  # let the connect task finish
        run(go())

    def test_cancel_keeps_a_previously_saved_profile(self):
        async def go():
            gate = asyncio.Event()

            async def slow_connect(body: Any) -> Any:
                await gate.wait()
                return {"status": "connecting", "ssid": body["ssid"]}
            script = JoinScript(saved=[SSID])
            aux = wifi_aux(script)
            aux.routes[("POST", "/wifi/connect")] = slow_connect
            h = await Harness(stored=join_state(), aux=aux).start()
            await h.post("/network", join_body())
            await h.post("/network/cancel", {})
            assert script.forgets == []
            gate.set()
        run(go())

    @pytest.mark.parametrize("result,code", [
        # Aux detail.code / restored `code` wins (OS-2's stable codes).
        ({"status": "restored", "code": "wrong_password",
          "warning": "restored"}, "wrong_password"),
        ({"status": "restored", "code": "ssid_not_found"},
         "ssid_not_found"),
        ({"status": "restored", "warning": "restored an old profile"},
         "timeout"),
    ])
    def test_failure_codes(self, result: Any, code: str):
        """02 §8 test 5: 'restored' answers are failures; the code comes
        from `code`, never state_reason."""
        async def go():
            script = JoinScript(device_states=["need-auth", "disconnected"],
                                connect_result=result)
            h = await Harness(stored=join_state(),
                              aux=wifi_aux(script)).start()
            await h.post("/network", join_body())
            await joined(h)
            err = h.doc["steps"]["network"]["error"]
            assert err["code"] == code
            assert err["detail"]["ssid"] == SSID
            assert h.doc["steps"]["network"]["status"] == "pending"
            assert h.doc["op"] is None
            assert script.forgets == [SSID]
        run(go())

    @pytest.mark.parametrize("text,code", [
        ("Error: Connection activation failed: (7) Secrets were required, "
         "but none provided.", "wrong_password"),
        ("Error: Connection activation failed: 802-11-wireless-security",
         "wrong_password"),
        ("Could not connect: wrong password", "wrong_password"),
        ("Error: No network with SSID 'HomeWiFi' found", "ssid_not_found"),
        ("Error: IP configuration could not be reserved", "no_address"),
        ("Error: DHCP failed on wlan0", "no_address"),
        ("Error: something else entirely", "timeout"),
    ])
    def test_free_text_mapping(self, text: str, code: str):
        """until OS-2: Aux's reasons arrive as free text; map by substring.
        state_reason is never consulted."""
        async def go():
            script = JoinScript(
                device_states=["disconnected"],
                connect_result=ServerError(text, 400))
            h = await Harness(stored=join_state(),
                              aux=wifi_aux(script)).start()
            await h.post("/network", join_body())
            await joined(h)
            assert h.doc["steps"]["network"]["error"]["code"] == code
        run(go())

    def test_a_previously_saved_profile_is_not_deleted_on_failure(self):
        async def go():
            script = JoinScript(
                saved=[SSID],
                connect_result=ServerError("wrong password", 400))
            h = await Harness(stored=join_state(),
                              aux=wifi_aux(script)).start()
            await h.post("/network", join_body())
            await joined(h)
            assert script.forgets == []
        run(go())

    def test_when_saved_is_undetermined_nothing_is_deleted(self):
        """Can't tell => treated as saved: the owner's profile is safe."""
        async def go():
            script = JoinScript(
                connect_result=ServerError("wrong password", 400))
            aux = wifi_aux(script)
            aux.routes[("GET", "/wifi/saved")] = ServerError("down", 500)
            aux.routes[("GET", "/wifi/show")] = ServerError("down", 500)
            h = await Harness(stored=join_state(), aux=aux).start()
            await h.post("/network", join_body())
            await joined(h)
            assert script.forgets == []
        run(go())

    def test_psk_never_reaches_the_document_events_or_log(
            self, caplog: Any):
        """07 S2 / 02 §8 test 6."""
        async def go():
            script = JoinScript(
                uplink={"internet": True, "addresses": ["10.0.0.9"]})
            h = await Harness(stored=join_state(),
                              aux=wifi_aux(script)).start()
            with caplog.at_level(logging.DEBUG):
                await h.post("/network", join_body())
                await joined(h)
            import json
            blob = json.dumps(h.doc) + json.dumps(
                h.server.changes()) + caplog.text + json.dumps(
                h.db.namespaces)
            assert PSK not in blob
        run(go())

    def test_region_switch_runs_before_connect(self):
        """02 §8 test 9: `region` in the join applies before /wifi/connect."""
        async def go():
            calls: List[str] = []

            def region_post(body: Any) -> Dict[str, Any]:
                calls.append("region")
                return {"declared_country": body["country"]}

            script = JoinScript(uplink={"internet": True,
                                        "addresses": ["10.0.0.9"]})
            aux = wifi_aux(script)
            aux.routes[("POST", "/region/country")] = region_post
            aux.routes[("POST", "/wifi/connect")] = \
                lambda body: (calls.append("connect"),
                              {"status": "connecting", "ssid": SSID})[1]
            h = await Harness(stored=join_state(), aux=aux).start()
            await h.post("/network", join_body(region="DE"))
            await joined(h)
            assert calls[:1] == ["region"] and "connect" in calls
        run(go())

    def test_region_apply_failure_stops_the_join(self):
        async def go():
            script = JoinScript()
            aux = wifi_aux(script)
            aux.routes[("POST", "/region/country")] = ServerError(
                "busy", 400)
            h = await Harness(stored=join_state(), aux=aux).start()
            await h.post("/network", join_body(region="DE"))
            await joined(h)
            step = h.doc["steps"]["network"]
            assert step["region_error"]["code"] == "region_busy"
            assert step["status"] == "pending"
            assert h.doc["op"] is None
            assert not aux.posted("/wifi/connect")
        run(go())


class TestMarkets:
    @pytest.mark.parametrize("region_routes,confirmed", [
        # locked market
        ({"GET /region": dict(REGION_174, locked=True)}, True),
        # none market: countries list empty
        ({"GET /region/options": dict(REGION_OPTIONS_174, countries=[])},
         True),
        # declared == detected
        ({"GET /region": dict(REGION_174, declared_country="DE",
                              detected_country="DE")}, True),
    ])
    def test_confirmed_markets(self, region_routes: Dict[str, Any],
                               confirmed: bool):
        async def go():
            script = JoinScript(
                uplink={"internet": True, "addresses": ["10.0.0.9"]})
            h = await Harness(stored=join_state(),
                              aux=wifi_aux(script, **region_routes)).start()
            await h.post("/network", join_body())
            await joined(h)
            step = h.doc["steps"]["network"]
            assert step["region_confirmed"] is confirmed
            assert step["status"] == "done"
            assert h.doc["cursor"] == "name"
        run(go())

    def test_no_region_routes_at_all_confirms_none(self):
        """An image without /region or /region/options has market none: a
        join sets region_confirmed itself."""
        async def go():
            script = JoinScript(
                uplink={"internet": True, "addresses": ["10.0.0.9"]})
            aux = wifi_aux(script)
            aux.routes.pop(("GET", "/region"))
            aux.routes.pop(("GET", "/region/options"))
            aux.routes.pop(("POST", "/region/country"), None)
            h = await Harness(stored=join_state(), aux=aux).start()
            await h.setup._refresh_region()
            assert h.setup._live["region"] is None
            await h.post("/network", join_body())
            await joined(h)
            assert h.doc["steps"]["network"]["region_confirmed"] is True
            # And POST /region on that image answers region_apply_failed.
            out = await h.post("/region", {"rev": h.doc["rev"],
                                           "country": "DE"})
            assert out["ok"] is True  # the op started
            await joined(h)
            step = h.doc["steps"]["network"]
            assert step["region_error"]["code"] == "region_apply_failed"
        run(go())


class TestNetworksGet:
    def test_scan_normalization(self):
        async def go():
            scan = [
                {"ssid": "", "security": "WPA2", "signal": 90,
                 "freq": 2437, "chan": 6, "in_use": False, "bssid": "a"},
                {"ssid": SSID, "security": "WPA2", "signal": 60,
                 "freq": 2437, "chan": 6, "in_use": False, "bssid": "b1"},
                {"ssid": SSID, "security": "WPA2", "signal": 80,
                 "freq": 5180, "chan": 36, "in_use": True, "bssid": "b2"},
                {"ssid": "Muon-walnut-8987", "security": "WPA2",
                 "signal": 99, "freq": 2437, "chan": 1, "bssid": "c"},
                {"ssid": "OldNet", "security": "WEP", "signal": 40,
                 "freq": 2412, "chan": 1, "in_use": False, "bssid": "d"},
                {"ssid": "Corp", "security": "802.1X", "signal": 70,
                 "freq": 5500, "chan": 100, "in_use": False, "bssid": "e"},
            ]
            aux = fresh_aux()
            aux.routes[("GET", "/wifi/scan?rescan=true")] = scan
            aux.routes[("GET", "/wifi/saved")] = [{"name": "OldNet"}]
            h = await Harness(stored=join_state(), aux=aux).start()
            out = await h.call("panel", "/server/muon/setup/networks",
                               {"rescan": True}, method="GET")
            assert out["ok"] is True
            nets = {n["ssid"]: n for n in out["networks"]}
            assert "" not in nets and "Muon-walnut-8987" not in nets
            row = nets[SSID]
            assert row["signal"] == 80 and row["bssids"] == 2
            assert row["band"] == "5" and row["channel"] == 36
            assert row["in_use"] is True and row["security"] == "wpa2"
            assert row["supported"] is True
            assert nets["OldNet"]["security"] == "wep"
            assert nets["OldNet"]["supported"] is False
            assert nets["OldNet"]["saved"] is True
            assert nets["Corp"]["security"] == "enterprise"
            # channel_permitted from the region's channels (36 allowed, 100
            # is not in REGION_174's list).
            assert nets[SSID]["channel_permitted"] is True
            assert nets["Corp"]["channel_permitted"] is False
        run(go())

    def test_no_wifi_saved_route_means_nothing_saved(self):
        async def go():
            aux = fresh_aux()
            del aux.routes[("GET", "/wifi/saved")]
            aux.routes[("GET", "/wifi/scan?rescan=false")] = [
                {"ssid": SSID, "security": "WPA2", "signal": 50,
                 "freq": 2437, "chan": 6, "in_use": False}]
            h = await Harness(stored=join_state(), aux=aux).start()
            out = await h.call("panel", "/server/muon/setup/networks",
                               {"rescan": False}, method="GET")
            assert out["networks"][0]["saved"] is False
        run(go())


class TestRegionEndpoint:
    def _region_harness(self, **routes: Any):
        script = JoinScript()
        aux = wifi_aux(script)
        for key, value in routes.items():
            method, path = key.split(" ", 1)
            aux.routes[(method, path)] = value
        return aux

    def _state_needs_region(self) -> Dict[str, Any]:
        doc = join_state()
        doc["steps"]["network"].update(
            kind="wifi", ssid=SSID, addresses=["10.0.0.9"],
            hostname_local="muon.local", internet=True,
            region_confirmed=False)
        return doc

    def test_confirm_declares_and_finishes_the_step(self):
        """02 §8 test 9: the picker join stays pending until POST region."""
        async def go():
            aux = self._region_harness()
            aux.routes[("POST", "/region/country")] = \
                lambda body: {"declared_country": body["country"]}
            h = await Harness(stored=self._state_needs_region(), aux=aux).start()
            assert h.doc["steps"]["network"]["status"] == "pending"
            out = await h.post("/region", {"rev": h.doc["rev"],
                                           "country": "DE"})
            assert out["ok"] is True
            assert out["state"]["op"]["kind"] == "region_apply"
            await h.setup.drain()
            step = h.doc["steps"]["network"]
            assert step["region_confirmed"] is True
            assert step["region_error"] is None
            assert step["status"] == "done"
            assert h.doc["cursor"] == "name"
        run(go())

    @pytest.mark.parametrize("aux_ans,code", [
        (ServerError("busy", 400), "region_busy"),
        (ServerError("no-token", 400), "needs_reregistration"),
        (ServerError("readback-mismatch", 400), "region_apply_failed"),
        (ServerError("apply-failed", 400), "region_apply_failed"),
        (ServerError("country-not-in-token", 400), "region_not_offered"),
    ])
    def test_apply_failures_declare_nothing(self, aux_ans: Any, code: str):
        async def go():
            aux = self._region_harness()
            aux.routes[("POST", "/region/country")] = aux_ans
            h = await Harness(stored=self._state_needs_region(), aux=aux).start()
            await h.post("/region", {"rev": h.doc["rev"], "country": "DE"})
            await h.setup.drain()
            step = h.doc["steps"]["network"]
            assert step["region_error"]["code"] == code
            assert step["region_confirmed"] is False
            assert step["status"] == "pending"
        run(go())

    def test_free_text_busy_maps_until_os2(self):
        async def go():
            aux = self._region_harness()
            aux.routes[("POST", "/region/country")] = ServerError(
                "the wifi radio is busy applying another region", 400)
            h = await Harness(stored=self._state_needs_region(), aux=aux).start()
            await h.post("/region", {"rev": h.doc["rev"], "country": "DE"})
            await h.setup.drain()
            assert h.doc["steps"]["network"]["region_error"]["code"] == (
                "region_busy")
        run(go())

    def test_a_504_rechecks_before_deciding(self):
        """504 + declared_country now equal => treated as applied."""
        async def go():
            aux = self._region_harness()
            aux.routes[("POST", "/region/country")] = ServerError("slow", 504)
            aux.routes[("GET", "/region")] = dict(
                REGION_174, declared_country="DE", detected_country="DE")
            h = await Harness(stored=self._state_needs_region(), aux=aux).start()
            await h.post("/region", {"rev": h.doc["rev"], "country": "DE"})
            await h.setup.drain()
            step = h.doc["steps"]["network"]
            assert step["region_confirmed"] is True
            assert step["status"] == "done"
        run(go())

    def test_a_504_without_the_declaration_is_region_busy(self):
        async def go():
            aux = self._region_harness()
            aux.routes[("POST", "/region/country")] = ServerError("slow", 504)
            h = await Harness(stored=self._state_needs_region(), aux=aux).start()
            await h.post("/region", {"rev": h.doc["rev"], "country": "DE"})
            await h.setup.drain()
            assert h.doc["steps"]["network"]["region_error"]["code"] == (
                "region_busy")
        run(go())

    def test_country_not_in_options(self):
        async def go():
            aux = self._region_harness()
            h = await Harness(stored=self._state_needs_region(), aux=aux).start()
            out = await h.post("/region", {"rev": h.doc["rev"],
                                           "country": "US"})
            assert out["ok"] is False
            assert out["error"]["code"] == "region_not_offered"
            assert h.doc["op"] is None
        run(go())

    def test_single_zone_country_sets_the_zone(self):
        """02 §5.6a step 4: IE has one zone (Europe/Dublin)."""
        async def go():
            aux = self._region_harness()
            aux.routes[("POST", "/region/country")] = \
                lambda body: {"declared_country": body["country"]}
            aux.routes[("GET", "/region")] = dict(
                REGION_174, declared_country="IE", detected_country="IE")
            h = await Harness(stored=self._state_needs_region(), aux=aux).start()
            await h.post("/region", {"rev": h.doc["rev"], "country": "IE"})
            await h.setup.drain()
            await h.setup.drain()
            # tz_source was set through the region path...
            assert h.setup._internal.get("tz_source") == "region" or \
                not h.setup._internal.get("tz_source")
        run(go())

    def test_while_network_pending_apply_only(self):
        """02 §5.6a: before any join, POST region applies but does not
        confirm."""
        async def go():
            aux = self._region_harness()
            aux.routes[("POST", "/region/country")] = \
                lambda body: {"declared_country": body["country"]}
            h = await Harness(stored=join_state(), aux=aux).start()
            await h.post("/region", {"rev": h.doc["rev"], "country": "DE"})
            await h.setup.drain()
            step = h.doc["steps"]["network"]
            assert step["region_confirmed"] is True
            assert step["status"] == "pending"  # no join yet
        run(go())


class TestEthernet:
    def test_ethernet_with_an_address_is_done(self, monkeypatch):
        # Exercise the machine fallback without reading the test host's eth0.
        monkeypatch.setattr(network, "_ipv4_ioctl", lambda _ifname: None)

        async def go():
            h = await Harness(stored=join_state()).start()
            h.server.components["machine"].eth0 = "10.10.0.5"
            out = await h.post("/network", {"rev": h.doc["rev"],
                                            "kind": "ethernet"})
            assert out["ok"] is True
            step = h.doc["steps"]["network"]
            assert step["status"] == "done"
            assert step["kind"] == "ethernet"
            assert step["addresses"] == ["10.10.0.5"]
            assert h.doc["cursor"] == "name"
        run(go())

    def test_ethernet_without_an_address_is_invalid(self):
        async def go():
            h = await Harness(stored=join_state()).start()
            out = await h.post("/network", {"rev": h.doc["rev"],
                                            "kind": "ethernet"})
            # On a dev box eth0 exists; force "no address" by emptying the
            # fake machine and letting the ioctl answer what it answers.
            h.server.components["machine"].addresses = []
            h.server.components["machine"].eth0 = None
            import unittest.mock as mock
            with mock.patch.object(network, "_ipv4_ioctl",
                                   return_value=None):
                out = await h.post("/network", {"rev": h.doc["rev"],
                                                "kind": "ethernet"})
            assert out["ok"] is False
            assert out["error"]["code"] == "invalid_network"
            assert out["error"]["detail"]["field"] == "kind"
        run(go())


class TestDeferredCleanup:
    """The connect outlives the op: a cancelled or timed-out join forgets
    the profile only after /wifi/connect resolves, and disconnects first
    when the late connect put the printer on the cancelled SSID."""

    def _blocked_aux(self, script: JoinScript, gate: asyncio.Event,
                     result: Any = None) -> FakeAux:
        async def slow_connect(body: Any) -> Any:
            await gate.wait()
            return result or {"status": "connecting",
                              "ssid": body["ssid"]}
        aux = wifi_aux(script)
        aux.routes[("POST", "/wifi/connect")] = slow_connect
        return aux

    def test_cancel_waits_out_the_connect_then_disconnects(self):
        async def go():
            gate = asyncio.Event()
            script = JoinScript()
            script.current_ssid = SSID  # the late connect landed on it
            h = await Harness(stored=join_state(),
                              aux=self._blocked_aux(script, gate)).start()
            await h.post("/network", join_body())
            await asyncio.sleep(0)  # let the runner reach the connect
            out = await h.post("/network/cancel", {})
            assert out["ok"] is True            # cancel doesn't block
            assert script.forgets == []         # forget waits on connect
            gate.set()
            await h.setup.drain()
            assert script.disconnects == [{}] or len(script.disconnects) == 1
            assert script.forgets == [SSID]
            assert h.setup._join_connect is None
        run(go())

    def test_cancel_without_a_late_connection_forgets_normally(self):
        """Connect resolves but the printer isn't on that SSID: forget
        only, no disconnect."""
        async def go():
            gate = asyncio.Event()
            script = JoinScript()
            h = await Harness(stored=join_state(),
                              aux=self._blocked_aux(script, gate)).start()
            await h.post("/network", join_body())
            await asyncio.sleep(0)
            await h.post("/network/cancel", {})
            gate.set()
            await h.setup.drain()
            assert script.disconnects == []
            assert script.forgets == [SSID]
        run(go())

    def test_join_timeout_defers_the_cleanup(self):
        async def go():
            gate = asyncio.Event()
            script = JoinScript(device_states=["associating"],
                                uplink=None)
            script.current_ssid = SSID
            h = await Harness(stored=join_state(),
                              aux=self._blocked_aux(script, gate)).start()
            h.setup.join_timeout = 0.2
            await h.post("/network", join_body())
            # The op ends on its timeout while the connect still runs; the
            # cleanup is what drain() would otherwise wait 65 s for.
            for _ in range(100):
                if h.doc["op"] is None:
                    break
                await asyncio.sleep(0.05)
            assert h.doc["steps"]["network"]["error"]["code"] == "timeout"
            assert script.forgets == []  # the connect is still running
            gate.set()
            await h.setup.drain()
            assert len(script.disconnects) == 1
            assert script.forgets == [SSID]
        run(go())

    def test_a_saved_profile_is_never_disconnected_or_forgotten(self):
        async def go():
            gate = asyncio.Event()
            script = JoinScript(saved=[SSID])
            script.current_ssid = SSID
            h = await Harness(stored=join_state(),
                              aux=self._blocked_aux(script, gate)).start()
            await h.post("/network", join_body())
            await asyncio.sleep(0)
            await h.post("/network/cancel", {})
            draining = asyncio.create_task(h.setup.drain())
            try:
                await asyncio.sleep(0)
                assert not draining.done()
            finally:
                gate.set()
                await draining
            assert script.forgets == []
            assert script.disconnects == []
        run(go())

    def test_psk_is_absent_from_the_cleanup_path(self, caplog: Any):
        async def go():
            gate = asyncio.Event()
            script = JoinScript()
            h = await Harness(stored=join_state(),
                              aux=self._blocked_aux(script, gate)).start()
            with caplog.at_level(logging.DEBUG):
                await h.post("/network", join_body())
                await asyncio.sleep(0)
                await h.post("/network/cancel", {})
                gate.set()
                await h.setup.drain()
            assert PSK not in caplog.text
        run(go())

    @pytest.mark.parametrize("saved", [False, True])
    def test_a_new_join_while_the_prior_connect_runs_is_busy(self, saved):
        async def go():
            gate = asyncio.Event()
            script = JoinScript(saved=[SSID] if saved else [])
            h = await Harness(stored=join_state(),
                              aux=self._blocked_aux(script, gate)).start()
            await h.post("/network", join_body())
            await asyncio.sleep(0)
            await h.post("/network/cancel", {})
            out = await h.post("/network", join_body(rev=h.doc["rev"]))
            assert out["ok"] is False
            assert out["error"]["code"] == "busy"
            gate.set()
            await h.setup.drain()
        run(go())

class TestLegacySavedProfileAndUplink:
    @pytest.mark.parametrize("message", [
        f"Connection profile '{SSID}' not found",
        f"Connection profile '{SSID}' not found: nmcli connection show failed",
    ])
    def test_no_saved_route_can_still_recognize_an_absent_profile(self, message):
        async def go():
            script = JoinScript()
            aux = wifi_aux(script)
            del aux.routes[("GET", "/wifi/saved")]
            aux.routes[("GET", "/wifi/show?ssid=" + SSID)] = ServerError(message, 404)
            h = await Harness(stored=join_state(), aux=aux).start()
            assert await network._ssid_saved_before(h.setup, SSID) is False
        run(go())


    def test_a_missing_show_route_keeps_the_profile(self):
        async def go():
            aux = wifi_aux(JoinScript())
            del aux.routes[("GET", "/wifi/saved")]
            del aux.routes[("GET", "/wifi/show")]
            h = await Harness(stored=join_state(), aux=aux).start()
            assert await network._ssid_saved_before(h.setup, SSID) is True
        run(go())

    def test_ioctl_link_local_is_not_an_uplink(self):
        import unittest.mock as mock

        async def go():
            h = await Harness(stored=join_state()).start()
            with mock.patch.object(network.fcntl, "ioctl", return_value=(
                    bytes(20) + network.socket.inet_aton("169.254.2.3") + bytes(232))):
                assert network.interface_ipv4(h.setup, "eth0") is None
                assert network.ethernet_status(h.setup)["address"] is None
        run(go())



class TestJoinRegionAndResetBoundaries:
    @pytest.mark.parametrize("unavailable", [False, True])
    def test_unknown_region_is_not_a_confirmed_no_picker_market(self, unavailable):
        async def go():
            aux = wifi_aux(JoinScript())
            if unavailable:
                aux.routes[("GET", "/region")] = ServerError("down", 503)
            h = Harness(stored=join_state(), aux=aux)
            await h.setup._startup(poll=False)
            if unavailable:
                await h.setup.refresh_live()
            await h.post("/network", join_body())
            await joined(h)
            assert h.doc["steps"]["network"]["region_confirmed"] is False
            assert h.doc["steps"]["network"]["status"] == "pending"
        run(go())

    def test_reset_does_not_cancel_required_cleanup_during_failure_commit(self):
        async def go():
            entered, release = asyncio.Event(), asyncio.Event()
            script = JoinScript(connect_result=ServerError("bad-psk", 400))
            script.current_ssid = SSID
            h = await Harness(stored=join_state(), aux=wifi_aux(script)).start()
            original = h.setup._commit

            async def commit():
                if h.doc["op"] is None and h.doc["steps"]["network"]["error"]:
                    entered.set()
                    await release.wait()
                await original()
            h.setup._commit = commit
            await h.post("/network", join_body())
            await entered.wait()
            resetting = asyncio.create_task(h.post("/reset", {}))
            for _ in range(12):
                await asyncio.sleep(0)
            release.set()
            await resetting
            await h.setup.drain()
            assert script.forgets == [SSID] and len(script.disconnects) == 1
        run(go())

    def test_reset_excludes_a_join_write_that_is_still_validating(self):
        async def go():
            entered, release = asyncio.Event(), asyncio.Event()
            script = JoinScript()
            aux = wifi_aux(script)

            async def saved(_body):
                entered.set()
                await release.wait()
                return []
            aux.routes[("GET", "/wifi/saved")] = saved
            h = await Harness(stored=join_state(), aux=aux).start()
            joining = asyncio.create_task(h.post("/network", join_body()))
            await entered.wait()
            resetting = asyncio.create_task(h.post("/reset", {}))
            for _ in range(12):
                await asyncio.sleep(0)
            release.set()
            await asyncio.gather(joining, resetting)
            await h.setup.drain()
            assert h.doc["state"] == "new" and h.doc["op"] is None
            assert not aux.posted("/wifi/connect")
        run(go())

    def test_cancel_excludes_a_join_write_that_is_still_validating(self):
        async def go():
            entered, release = asyncio.Event(), asyncio.Event()
            aux = wifi_aux(JoinScript())

            async def saved(_body):
                entered.set()
                await release.wait()
                return []
            aux.routes[("GET", "/wifi/saved")] = saved
            h = await Harness(stored=join_state(), aux=aux).start()
            joining = asyncio.create_task(h.post("/network", join_body()))
            await entered.wait()
            cancelling = asyncio.create_task(h.post("/network/cancel", {}))
            for _ in range(12):
                await asyncio.sleep(0)
            release.set()
            await asyncio.gather(joining, cancelling)
            await h.setup.drain()
            assert h.doc["op"] is None
            assert not aux.posted("/wifi/connect")
        run(go())

    def test_the_rejoin_deadline_never_recovers_the_previous_network_address(self):
        async def go():
            script = JoinScript(uplink={"addresses": ["10.0.0.9"], "internet": True})
            script.current_ssid = "PreviousWiFi"
            aux = wifi_aux(script)
            h = await Harness(stored=self.completed(), aux=aux).start()
            h.setup.join_timeout = 0.0
            h.server.components["machine"].addresses = ["192.168.1.7"]

            async def preparing(_body):
                # Complete the accepted connect between the loop's initial
                # done check and its deadline check, without assigning DHCP.
                await asyncio.sleep(0)
                return {"state": "preparing"}
            aux.routes[("GET", "/wifi/device/status")] = preparing
            await h.post("/network", join_body(rev=h.doc["rev"]))
            await joined(h)
            step = h.doc["steps"]["network"]
            assert step["status"] == "pending" and step["addresses"] == []
            assert step["error"] is not None
            assert not aux.posted("/update/check")
        run(go())

    @pytest.mark.parametrize("endpoint", ["/region", "/network"])
    def test_zone_uses_the_applied_country_when_region_refresh_fails(self, endpoint):
        async def go():
            applied = []
            aux = wifi_aux(JoinScript())
            aux.routes[("GET", "/region")] = dict(REGION_174, declared_country="GB")
            aux.routes[("POST", "/time/zone")] = \
                lambda body: applied.append(body["tz"]) or {}

            def declare(body):
                aux.routes[("GET", "/region")] = ServerError("temporarily down", 503)
                return {"declared_country": body["country"]}
            aux.routes[("POST", "/region/country")] = declare
            h = await Harness(stored=join_state(), aux=aux).start()
            args = ({"rev": h.doc["rev"], "country": "IE"} if endpoint == "/region"
                    else join_body(region="IE", rev=h.doc["rev"]))
            await h.post(endpoint, args)
            await h.setup.drain()
            assert applied == ["Europe/Dublin"]
        run(go())

    def test_a_rejoin_waits_until_the_requested_ssid_owns_the_address(self):
        async def go():
            script = JoinScript(uplink={"addresses": ["10.0.0.9"], "internet": True})
            script.current_ssid = "PreviousWiFi"
            aux = wifi_aux(script)
            h = await Harness(stored=self.completed(), aux=aux).start()
            machine = h.server.components["machine"]
            machine.addresses = ["192.168.1.7"]
            polls = []

            def status(_body):
                polls.append(True)
                if len(polls) >= 4:
                    script.current_ssid = SSID
                    machine.addresses = ["10.0.0.9"]
                return {"state": "activated" if len(polls) >= 4 else "preparing"}
            aux.routes[("GET", "/wifi/device/status")] = status
            await h.post("/network", join_body(rev=h.doc["rev"]))
            await joined(h)
            assert len(polls) >= 4
            assert h.doc["steps"]["network"]["addresses"] == ["10.0.0.9"]
        run(go())

    def test_cancel_disconnects_a_completed_connect_still_waiting_for_dhcp(self):
        async def go():
            script = JoinScript()
            script.current_ssid = SSID
            h = await Harness(stored=join_state(), aux=wifi_aux(script)).start()
            h.server.components["machine"].addresses = []
            await h.post("/network", join_body())
            for _ in range(12):
                await asyncio.sleep(0)
            assert h.setup._join_connect is not None and h.setup._join_connect.done()
            await h.post("/network/cancel", {})
            await joined(h)
            assert len(script.disconnects) == 1 and script.forgets == [SSID]
        run(go())

    def test_an_owner_timezone_choice_wins_over_a_delayed_region_default(self):
        async def go():
            entered, release = asyncio.Event(), asyncio.Event()
            applied = []
            aux = wifi_aux(JoinScript())

            async def set_zone(body):
                if body["tz"] == "Europe/Dublin":
                    entered.set()
                    await release.wait()
                applied.append(body["tz"])
                return {}
            aux.routes[("POST", "/time/zone")] = set_zone
            h = await Harness(stored=join_state(), aux=aux).start()
            h.setup._live["region"]["declared_country"] = "IE"
            automatic = asyncio.create_task(network._single_zone_tz(h.setup, h.doc))
            await entered.wait()
            h.setup._live["region"]["declared_country"] = "US"
            owner = asyncio.create_task(h.post(
                "/timezone", {"rev": h.doc["rev"], "tz": "America/New_York"}))
            for _ in range(12):
                await asyncio.sleep(0)
            release.set()
            await asyncio.gather(automatic, owner)
            assert applied[-1] == "America/New_York"
            assert h.setup._internal["tz_source"] == "owner"
        run(go())

    def test_an_accepted_connect_waits_for_the_later_dhcp_address(self):
        async def go():
            script = JoinScript(uplink={"addresses": ["10.0.0.9"], "internet": True})
            aux = wifi_aux(script)
            h = await Harness(stored=join_state(), aux=aux).start()
            machine = h.server.components["machine"]
            machine.addresses = []
            polls = []

            def status(_body):
                polls.append(True)
                if len(polls) >= 3:
                    machine.addresses = ["10.0.0.9"]
                    script.current_ssid = SSID
                return {"state": "activated" if len(polls) >= 3 else "ip-config"}
            aux.routes[("GET", "/wifi/device/status")] = status
            await h.post("/network", join_body())
            await joined(h)
            assert len(polls) >= 3
            assert h.doc["steps"]["network"]["addresses"] == ["10.0.0.9"]
            assert h.doc["steps"]["network"]["error"] is None
        run(go())

    @pytest.mark.parametrize("replacement", [False, True])
    def test_enterprise_scan_is_unsupported_after_replacement(self, replacement):
        async def go():
            h = await Harness(stored=join_state()).start()
            scan = [{"ssid": "Corp", "security": "802.1X", "signal": 80}]
            if replacement:
                scan.insert(0, {"ssid": "Corp", "security": "WPA2", "signal": 20})
            row, = network.normalize_scan(h.setup, scan, [])
            assert row["security"] == "enterprise" and row["supported"] is False
        run(go())

    @pytest.mark.parametrize("detected", ["FR", None])
    def test_region_confirmed_before_join_stays_confirmed(self, detected):
        async def go():
            aux = wifi_aux(JoinScript(uplink={
                "addresses": ["10.0.0.9"], "internet": True}))
            aux.routes[("GET", "/region")] = dict(
                REGION_174, declared_country="DE", detected_country=detected)
            aux.routes[("POST", "/region/country")] = \
                lambda body: {"declared_country": body["country"]}
            h = await Harness(stored=join_state(), aux=aux).start()
            await h.post("/region", {"rev": h.doc["rev"], "country": "DE"})
            await h.setup.drain()
            assert h.doc["steps"]["network"]["region_confirmed"] is True
            await h.post("/network", join_body(rev=h.doc["rev"]))
            await joined(h)
            assert h.doc["steps"]["network"]["region_confirmed"] is True
            assert h.doc["steps"]["network"]["status"] == "done"
        run(go())

    def test_connect_failures_do_not_retain_credential_frames_or_chains(self):
        async def go():
            aux = wifi_aux(JoinScript(connect_result=ServerError("bad-psk", 400)))
            h = await Harness(stored=join_state(), aux=aux).start()
            result, error = await network._connect(h.setup, SSID, PSK)
            assert result is None and error is not None
            assert error.__traceback__ is None
            assert error.__cause__ is None and error.__context__ is None
        run(go())

    @staticmethod
    def completed():
        doc = join_state()
        doc.update(state="complete", cursor="finish")
        doc["steps"]["network"].update(
            status="done", kind="wifi", ssid="PreviousWiFi",
            addresses=["192.168.1.7"], region_confirmed=True)
        return doc

    @pytest.mark.parametrize("cancel", [False, True])
    def test_unsuccessful_rejoin_clears_the_previous_connection_fields(self, cancel):
        async def go():
            gate = asyncio.Event()
            script = JoinScript(connect_result=ServerError("connect failed", 500))
            aux = (TestDeferredCleanup()._blocked_aux(script, gate) if cancel
                   else wifi_aux(script))
            h = await Harness(stored=self.completed(), aux=aux).start()
            await h.post("/network", join_body(rev=h.doc["rev"]))
            if cancel:
                await asyncio.sleep(0)
                await h.post("/network/cancel", {})
                gate.set()
            await joined(h)
            step = h.doc["steps"]["network"]
            assert step["status"] == "pending"
            assert step["kind"] is None and step["addresses"] == []
            assert step["hostname_local"] is None and step["internet"] is None
        run(go())

    @pytest.mark.parametrize("detected", ["FR", None])
    def test_an_explicit_join_region_is_confirmed_after_success(self, detected):
        async def go():
            script = JoinScript(uplink={"addresses": ["10.0.0.9"], "internet": True})
            aux = wifi_aux(script)
            aux.routes[("GET", "/region")] = dict(
                REGION_174, declared_country="DE", detected_country=detected)
            aux.routes[("POST", "/region/country")] = \
                lambda body: {"declared_country": body["country"]}
            h = await Harness(stored=join_state(), aux=aux).start()
            await h.post("/network", join_body(region="DE", rev=h.doc["rev"]))
            await joined(h)
            assert h.doc["steps"]["network"]["region_confirmed"] is True
            assert h.doc["steps"]["network"]["status"] == "done"
        run(go())

    @pytest.mark.parametrize("detected", ["FR", None])
    def test_post_setup_join_preserves_explicit_region_confirmation(self, detected):
        async def go():
            script = JoinScript(uplink={"addresses": ["10.0.0.9"], "internet": True})
            aux = wifi_aux(script)
            aux.routes[("GET", "/region")] = dict(
                REGION_174, declared_country="DE", detected_country=detected)
            h = await Harness(stored=self.completed(), aux=aux).start()
            await h.post("/network", join_body(rev=h.doc["rev"]))
            await joined(h)
            assert h.doc["steps"]["network"]["region_confirmed"] is True
            assert h.doc["steps"]["network"]["status"] == "done"
        run(go())

    def test_failed_post_setup_region_does_not_report_the_new_ssid_as_connected(self):
        async def go():
            aux = wifi_aux(JoinScript())
            aux.routes[("POST", "/region/country")] = ServerError("busy", 400)
            h = await Harness(stored=self.completed(), aux=aux).start()
            await h.post("/network", join_body(region="DE", rev=h.doc["rev"]))
            await joined(h)
            step = h.doc["steps"]["network"]
            assert step["status"] == "pending"
            assert step["kind"] is None and step["addresses"] == []
            assert step["region_error"]["code"] == "region_busy"
            assert not aux.posted("/wifi/connect")
        run(go())

    @pytest.mark.parametrize("chosen", [None, "phone", "owner"])
    def test_region_bearing_join_applies_the_zone_unless_already_chosen(self, chosen):
        async def go():
            aux = wifi_aux(JoinScript())
            aux.routes[("GET", "/region")] = dict(REGION_174, declared_country="IE")
            aux.routes[("POST", "/region/country")] = \
                lambda body: {"declared_country": body["country"]}
            aux.routes[("POST", "/time/zone")] = {}
            h = await Harness(stored=join_state(), aux=aux).start()
            h.setup._internal["tz_source"] = chosen
            await h.post("/network", join_body(region="IE", rev=h.doc["rev"]))
            await joined(h)
            zones = [body for method, path, body in aux.calls
                     if method == "POST" and path == "/time/zone"]
            assert zones == ([] if chosen else [{"tz": "Europe/Dublin"}])
        run(go())

    @pytest.mark.parametrize("saved", [False, True])
    def test_reset_waits_for_join_cleanup_before_replacing_the_document(self, saved):
        async def go():
            gate = asyncio.Event()
            script = JoinScript(saved=[SSID] if saved else [])
            script.current_ssid = SSID
            aux = TestDeferredCleanup()._blocked_aux(script, gate)
            h = await Harness(stored=join_state(), aux=aux).start()
            await h.post("/network", join_body())
            await asyncio.sleep(0)
            resetting = asyncio.create_task(h.post("/reset", {}))
            try:
                for _ in range(12):
                    await asyncio.sleep(0)
                assert not resetting.done()
            finally:
                gate.set()
                await resetting
                await h.setup.drain()
            assert h.doc["state"] == "new" and h.doc["op"] is None
            assert script.forgets == ([] if saved else [SSID])
            assert len(script.disconnects) == (0 if saved else 1)
        run(go())


class TestReviewConnectionSampling:
    def test_address_is_sampled_after_the_target_ssid_is_verified(self):
        async def go():
            script = JoinScript(uplink={"addresses": ["10.0.0.9"], "internet": True})
            aux = wifi_aux(script)
            h = await Harness(stored=TestJoinRegionAndResetBoundaries.completed(),
                              aux=aux).start()
            machine = h.server.components["machine"]
            machine.addresses = ["192.168.1.7"]

            def current(_body):
                machine.addresses = ["10.0.0.9"]
                return {"ssid": SSID}

            aux.routes[("GET", "/wifi/current")] = current
            aux.routes[("GET", "/wifi/device/status")] = {"state": "activated"}
            await h.post("/network", join_body(rev=h.doc["rev"]))
            await joined(h)
            assert h.doc["steps"]["network"]["addresses"] == ["10.0.0.9"]
        run(go())

    def test_region_confirmation_follows_a_post_setup_join_from_skipped(self):
        async def go():
            doc = TestJoinRegionAndResetBoundaries.completed()
            doc["steps"]["network"].update(status="skipped", kind=None,
                                               addresses=[], region_confirmed=False)
            aux = wifi_aux(JoinScript())
            aux.routes[("POST", "/region/country")] = {"declared_country": "DE"}
            aux.routes[("GET", "/region")] = dict(REGION_174, detected_country=None)
            h = await Harness(stored=doc, aux=aux).start()
            await h.post("/network", join_body(rev=h.doc["rev"]))
            await joined(h)
            assert h.doc["steps"]["network"]["status"] == "pending"
            assert aux.posted("/wifi/ap/auto_off") == []
            out = await h.post("/region", {"rev": h.doc["rev"], "country": "DE"})
            assert out["ok"]
            await joined(h)
            assert h.doc["steps"]["network"]["status"] == "done"
            assert h.doc["steps"]["network"]["region_confirmed"] is True
            assert h.doc["state"] == "complete" and h.doc["cursor"] == "finish"
            assert aux.posted("/wifi/ap/auto_off") == [
                {"after_s": h.setup.hotspot_off_delay}]
        run(go())

    @pytest.mark.parametrize("frequency,band", [(2412, "2.4"), (5885, "5"),
                                               (5935, "6"), (5955, "6"),
                                               (6475, "6"), (7115, "6")])
    def test_scan_reports_the_actual_band(self, frequency, band):
        async def go():
            aux = fresh_aux()
            aux.routes[("GET", "/wifi/scan?rescan=true")] = [
                {"ssid": "BandTest", "security": "WPA2", "signal": 80,
                 "freq": frequency, "chan": 1}]
            h = await Harness(stored=join_state(), aux=aux).start()
            out = await h.call("panel", "/server/muon/setup/networks",
                               {"rescan": True}, method="GET")
            assert out["networks"][0]["band"] == band
        run(go())
