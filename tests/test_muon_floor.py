# Tests for the MUON floor (muon_floor.py).
#
# The floor had no tests at all before this file. That is the wrong shape for a
# security boundary whose contents are a deliberate product decision: the list
# is meant to be argued over, and an argument that nothing pins is one a later
# refactor settles by accident.
#
# These are pure unit tests. `check_floor` takes an endpoint, a transport and an
# address, and every branch it has is reachable without a Server, an event loop
# or a socket -- so none of the heavyweight fixtures in conftest are needed.

from __future__ import annotations

import ipaddress

import pytest

from moonraker import muon_floor
from moonraker.muon_floor import (
    FLOOR_PREFIXES,
    NETWORK_ROLE,
    PANEL_ROLE,
    check_floor,
    is_floor_endpoint,
    local_address,
    role_for_address,
)
from moonraker.utils.exceptions import ServerError


class _Transport:
    """Duck-typed stand-in. `_is_internal` reads transport.transport_type.name
    and nothing else, and imports nothing, deliberately, to avoid a cycle with
    common.py -- so a stub with the same shape exercises the real branch."""

    def __init__(self, name: str) -> None:
        self.transport_type = type("_T", (), {"name": name})()


INTERNAL = _Transport("INTERNAL")
HTTP = _Transport("HTTP")

LAN = ipaddress.ip_address("192.168.1.50")
LOOPBACK = ipaddress.ip_address("127.0.0.1")


class TestWhatIsOnTheFloor:
    """The membership of FLOOR_PREFIXES is the decision, so pin it directly.

    One reason now puts an entry here: **nothing else holds it.**
    ``require_bms_authority`` is an empty body (BMS-21) and ``trusted_clients``
    no longer answers 401 to a LAN caller, so for the mutating battery routes
    this tuple is the whole of their access control (KAN-350).

    The *other* reason -- SEC-2 flooring what an owner cannot consent away --
    used to put the developer-mode toggle here and no longer does. KAN-371 moved
    that gate to ``dev_mode_consent`` in the Aux API, which asks whether a person
    confirmed at the hardware rather than whether the packet came from 127.0.0.1.
    Keep the two reasons apart: an entry whose justification is physical presence
    does not belong on a check that any process on the device already satisfies.

    Everything else is governed by SEC-8's levels, which is policy rather than
    floor.

    The first-run setup entries follow the battery's reason, not presence.
    ``/server/muon/setup/reset`` (KAN-203, 07 S11) is refused by muon_setup to
    anything but the panel as well, so the floor is its second lock, the one
    that holds on every transport. ``/server/aux/setup``, ``/wifi/ap/auto_off``
    and ``/time`` (KAN-411/412/413) are driven only by muon_setup in-process,
    and nothing else holds them.
    """

    def test_the_floor_is_the_battery_commands_and_the_setup_entries(self):
        """Pinned as an exact tuple, so adding or dropping one is a failure here
        rather than a discovery in the field."""
        assert FLOOR_PREFIXES == (
            "/server/aux/bms/mode",
            "/server/aux/bms/charge",
            "/server/aux/bms/standby",
            "/server/aux/bms/fault",
            "/server/aux/bms/ship",
            "/server/muon/setup/reset",
            "/server/aux/setup",
            "/server/aux/wifi/ap/auto_off",
            "/server/aux/time",
        )

    def test_the_setup_reset_is_floored_and_nothing_else_of_setup_is(self):
        """07 S11: reset is panel-only. Every other setup route is reachable
        from the hotspot and the LAN, which is how the phone does setup, and
        muon_setup applies its own per-caller rules to them."""
        assert is_floor_endpoint("/server/muon/setup/reset")
        for endpoint in (
            "/server/muon/setup",
            "/server/muon/setup/options",
            "/server/muon/setup/driver",
            "/server/muon/setup/goto",
            "/server/muon/setup/skip",
            "/server/muon/setup/finish",
            "/server/muon/setup/card/dismiss",
            "/server/muon/setup/network/cancel",
        ):
            assert not is_floor_endpoint(endpoint), endpoint
        with pytest.raises(ServerError) as info:
            check_floor("/server/muon/setup/reset", HTTP, LAN)
        assert info.value.status_code == 403
        check_floor("/server/muon/setup/reset", HTTP, LOOPBACK)

    @pytest.mark.parametrize(
        "endpoint",
        [
            # The toggle itself. Enabling is gated by the waiver plus a redeemed
            # consent challenge in the Aux API; disabling is ungated on purpose,
            # because recovery must not depend on a working knob.
            "/server/aux/dev_mode",
            # The waiver text, so a client can show what it is asking consent to.
            "/server/aux/dev_mode/waiver",
            # The consent ceremony. Opening a challenge from the network is the
            # point of it: the network asks, the hardware confirms.
            "/server/aux/dev_mode/consent",
            "/server/aux/dev_mode/consent/abc123",
            # DEV-5: "restore safe configuration" is a single action, and these
            # are it. Flooring them put the recovery path out of reach of the
            # only interface that offers it.
            "/server/aux/dev_mode/refresh",
            "/server/aux/dev_mode/backup",
        ],
    )
    def test_every_developer_mode_route_is_reachable_from_the_network(
        self, endpoint: str
    ):
        """KAN-371. Spelled out as full endpoints rather than derived from
        FLOOR_PREFIXES, because deriving the expectation from the thing under
        test passes under any value of it.

        If this fails, the reported symptom is back: a printer already in
        developer mode, a dead toggle captioned "can only be changed at the
        printer", and no Restore/Backup actions -- on a machine whose panel
        carries no toggle to change it at.
        """
        assert not is_floor_endpoint(endpoint)

    @pytest.mark.parametrize(
        "endpoint",
        [
            "/server/aux/bms/mode",
            "/server/aux/bms/charge",
            # The one the `charge` entry has to cover by segment boundary. If
            # this fails, the power limit is reachable anonymously on the LAN
            # while the route beside it is not.
            "/server/aux/bms/charge/power",
            "/server/aux/bms/standby",
            "/server/aux/bms/fault/clear",
            "/server/aux/bms/ship",
        ],
    )
    def test_every_mutating_battery_route_is_floored(self, endpoint: str):
        """All six of the routes BMS_GUARD covers in the Aux API.

        This is the list from ``require_bms_authority``'s own docstring. It is
        spelled out as full endpoints rather than derived from FLOOR_PREFIXES,
        because deriving the expectation from the thing under test passes under
        any value of it.
        """
        assert is_floor_endpoint(endpoint)

    @pytest.mark.parametrize(
        "endpoint",
        [
            "/server/aux/bms/link",
            "/server/aux/bms/status",
            "/server/aux/bms/snapshot",
            "/server/aux/bms/capabilities",
        ],
    )
    def test_battery_telemetry_stays_open(self, endpoint: str):
        """Read-only pack state is not authority, and Fluidd needs it.

        The symptom if this breaks is subtler than a 403 in a console:
        ``/bms/link`` is what a UI polls to decide whether the battery exists,
        so flooring it makes a LAN client draw a printer with no battery.
        """
        assert not is_floor_endpoint(endpoint)

    @pytest.mark.parametrize(
        "endpoint",
        [
            "/server/aux/setup/complete",
            # Draft MuonOS#174's older marker, under the same prefix.
            "/server/aux/setup",
            "/server/aux/wifi/ap/auto_off",
            "/server/aux/time",
            "/server/aux/time/zone",
        ],
    )
    def test_the_first_run_setup_writes_are_floored(self, endpoint: str):
        """KAN-413 / KAN-411 / KAN-412. Only ``muon_setup`` writes these.

        From the network, marking setup complete would stop a new printer's
        setup and let its hotspot go off; clearing it would send a working
        printer back to its first screen; setting the clock would skip
        muon_setup's hotspot-only rule. Spelled out, not derived.
        """
        assert is_floor_endpoint(endpoint)

    @pytest.mark.parametrize(
        "endpoint",
        ["/server/aux/setupx", "/server/aux/timezone", "/server/aux/time_sync"],
    )
    def test_the_setup_and_time_entries_stop_at_a_segment(self, endpoint: str):
        """The prefixes are whole segments: a sibling route that merely starts
        with the same letters is not floored by them."""
        assert not is_floor_endpoint(endpoint)

    @pytest.mark.parametrize(
        "endpoint",
        [
            "/server/aux/wifi/ap/up",
            "/server/aux/wifi/ap/down",
            "/server/aux/wifi/ap/stations",
            "/server/aux/wifi/ap/show",
        ],
    )
    def test_the_owners_hotspot_controls_stay_open(self, endpoint: str):
        """The Fluidd hotspot card uses these (Level 0). A segment-boundary
        match on ``wifi/ap/auto_off`` must not take its siblings with it."""
        assert not is_floor_endpoint(endpoint)

    def test_the_bms_prefix_as_a_whole_is_not_floored(self):
        """The mistake this guards is one entry of ``/server/aux/bms``, which
        looks tidier and takes the telemetry with it."""
        assert "/server/aux/bms" not in FLOOR_PREFIXES
        assert not is_floor_endpoint("/server/aux/bms")

    @pytest.mark.parametrize(
        "endpoint",
        [
            "/server/aux/wifi/current",
            "/server/aux/wifi/connect",
            "/machine/update/status",
            "/machine/update/recover",
        ],
    )
    def test_the_surfaces_sec_8_governs_are_not_floored(self, endpoint: str):
        """These left the floor when SEC-2 narrowed. Open at Level 0.

        If this fails, either the narrowing was reverted or a prefix crept
        back -- and the visible symptom is Fluidd's wifi panel and update tab
        going dead over the LAN, with a 403 nothing in the UI explains.
        """
        assert not is_floor_endpoint(endpoint)

    def test_a_prefix_matches_on_a_segment_boundary_not_a_substring(self):
        """`/server/aux/bms/ship_status` is a different endpoint and must not be
        caught by ship mode's entry. The implementation checks equality or
        prefix + "/", which is what makes that true; assert it so a later
        `startswith` shortcut cannot silently widen the floor."""
        assert is_floor_endpoint("/server/aux/bms/ship")
        assert is_floor_endpoint("/server/aux/bms/ship/anything")
        assert not is_floor_endpoint("/server/aux/bms/ship_status")


class TestWhoIsAllowedThrough:
    def test_a_network_caller_is_denied_a_floor_surface(self):
        with pytest.raises(ServerError) as excinfo:
            check_floor("/server/aux/bms/mode", HTTP, LAN)
        assert excinfo.value.status_code == 403

    def test_the_panel_reaches_a_floor_surface(self):
        # Loopback is on-device: the MuonUI vhost listens on loopback only.
        check_floor("/server/aux/bms/mode", HTTP, LOOPBACK)

    def test_a_component_to_component_call_is_not_a_network_caller(self):
        # update_manager driving an OTA through aux_api_proxy, for instance.
        check_floor("/server/aux/bms/mode", INTERNAL, None)

    def test_a_network_caller_reaches_everything_off_the_floor(self):
        check_floor("/server/aux/wifi/current", HTTP, LAN)
        check_floor("/machine/update/status", HTTP, LAN)

    def test_a_lan_caller_can_leave_developer_mode(self):
        """KAN-371, and the half of it that is not a policy judgement.

        Disabling developer mode puts the OEM configuration back and blows
        nothing. ``set_dev_mode`` gates only the enable direction, in its own
        words, because "getting *out* of Developer Mode must not depend on a
        working knob, a reachable operator, or an attacker's cooperation". The
        floor used to contradict that by denying the route in both directions.
        """
        check_floor("/server/aux/dev_mode", HTTP, LAN)

    def test_a_lan_caller_can_restore_defaults_and_take_a_backup(self):
        """DEV-5. The single action, from the interface that offers it."""
        check_floor("/server/aux/dev_mode/refresh", HTTP, LAN)
        check_floor("/server/aux/dev_mode/backup", HTTP, LAN)

    @pytest.mark.parametrize(
        "endpoint",
        [
            "/server/aux/setup/complete",
            "/server/aux/wifi/ap/auto_off",
            "/server/aux/time",
            "/server/aux/time/zone",
        ],
    )
    def test_the_setup_writes_are_denied_to_a_lan_caller(self, endpoint: str):
        """KAN-413 / KAN-411 / KAN-412, through the check itself, not only the
        membership test."""
        with pytest.raises(ServerError) as excinfo:
            check_floor(endpoint, HTTP, LAN)
        assert excinfo.value.status_code == 403

    @pytest.mark.parametrize(
        "endpoint",
        [
            "/server/aux/setup/complete",
            "/server/aux/wifi/ap/auto_off",
            "/server/aux/time",
            "/server/aux/time/zone",
        ],
    )
    def test_the_setup_writes_are_denied_to_a_hotspot_caller(self, endpoint: str):
        """A phone on the hotspot is trusted by address (SEC-1) like the LAN,
        and is just as much a network caller here: only muon_setup, in-process,
        drives these (02 §1)."""
        hotspot = ipaddress.ip_address("10.42.0.23")
        with pytest.raises(ServerError) as excinfo:
            check_floor(endpoint, HTTP, hotspot)
        assert excinfo.value.status_code == 403

    @pytest.mark.parametrize(
        "endpoint",
        [
            "/server/aux/setup/complete",
            "/server/aux/wifi/ap/auto_off",
            "/server/aux/time",
            "/server/aux/time/zone",
        ],
    )
    def test_muon_setup_and_the_panel_still_reach_them(self, endpoint: str):
        """``muon_setup`` calls Aux in-process; the panel is on loopback."""
        check_floor(endpoint, INTERNAL, None)
        check_floor(endpoint, HTTP, LOOPBACK)

    def test_the_owners_hotspot_toggle_stays_open_to_the_lan(self):
        check_floor("/server/aux/wifi/ap/up", HTTP, LAN)
        check_floor("/server/aux/wifi/ap/down", HTTP, LAN)

    def test_ship_mode_is_denied_to_a_lan_caller(self):
        """The case KAN-350 exists for.

        Once ``trusted_clients`` covers the LAN, Moonraker no longer answers 401
        here, so this 403 is the only thing between a browser on the customer's
        network and a command that powers the battery down.
        """
        with pytest.raises(ServerError) as excinfo:
            check_floor("/server/aux/bms/ship", HTTP, LAN)
        assert excinfo.value.status_code == 403

    def test_a_lan_caller_still_reads_battery_telemetry(self):
        """Fluidd on the LAN draws the battery, so this must not be collateral
        damage from the entries above."""
        check_floor("/server/aux/bms/link", HTTP, LAN)
        check_floor("/server/aux/bms/status", HTTP, LAN)

    def test_the_panel_still_drives_the_battery(self):
        """The panel is the caller these routes are FOR. If this fails, the
        battery controls on the touchscreen go dead."""
        check_floor("/server/aux/bms/ship", HTTP, LOOPBACK)
        check_floor("/server/aux/bms/standby", HTTP, LOOPBACK)

    def test_an_addressless_transport_is_denied_not_waved_through(self):
        """Fail-closed. MQTT carries no address, and `None` must read as remote
        rather than as "no evidence it is remote"."""
        with pytest.raises(ServerError):
            check_floor("/server/aux/bms/ship", HTTP, None)


class TestAddressClassification:
    def test_v4_mapped_loopback_counts_as_loopback(self):
        """`IPv6Address.is_loopback` is False for ::ffff:127.0.0.1, so without
        the unwrap the panel is denied its own controls depending on how the
        socket was accepted."""
        assert local_address(ipaddress.ip_address("::ffff:127.0.0.1"))

    @pytest.mark.parametrize("addr", ["192.168.1.50", "10.0.0.1", "2a0d::1"])
    def test_routable_and_rfc1918_addresses_are_not_local(self, addr: str):
        assert not local_address(ipaddress.ip_address(addr))

    def test_roles_follow_the_address(self):
        assert role_for_address(LOOPBACK) == PANEL_ROLE
        assert role_for_address(LAN) == NETWORK_ROLE
        assert role_for_address(None) == NETWORK_ROLE


# ---------------------------------------------------------------------------
# SEC-8: the protection levels.
# ---------------------------------------------------------------------------

SENTINEL = ipaddress.ip_address("192.0.2.1")
HOTSPOT = ipaddress.ip_address("10.42.0.23")
LAN_V6 = ipaddress.ip_address("fd12:3456:789a::10")

WIFI = "/server/aux/wifi/connect"
UPGRADE = "/machine/update/upgrade"
check_protection = muon_floor.check_protection


class _User:
    """Duck-typed UserInfo. `has_identity` reads `.source` and nothing else."""

    def __init__(self, source: str) -> None:
        self.source = source


GATEWAY_USER = _User("muon_gateway")
# What trusted_clients hands a LAN browser, and what a Moonraker login is.
TRUSTED_USER = _User("moonraker")


@pytest.fixture
def protected():
    muon_floor.set_protection_level(muon_floor.LEVEL_PROTECTED)
    yield
    muon_floor.set_protection_level(muon_floor.LEVEL_OPEN)


@pytest.fixture(autouse=True)
def _level_is_reset_after_every_test():
    """The level is module state. A test that forgets to put it back would make
    every later test run at the wrong level, and pass or fail by ordering."""
    yield
    muon_floor.set_protection_level(muon_floor.LEVEL_OPEN)


class TestWhatLevelOneTakesBack:
    def test_the_protected_surfaces_are_the_two_sec_2_released(self):
        """SEC-8 names them: `/server/aux/*` and `/machine/update/*`. Pinned as
        exact tuples, because the list is the decision."""
        assert muon_floor.PROTECTED_PREFIXES == ("/server/aux", "/machine/update")
        assert muon_floor.PROTECTED_EXCLUSIONS == ("/server/aux/dev_mode",)

    @pytest.mark.parametrize(
        "endpoint",
        [
            "/server/aux/wifi/current",
            "/server/aux/wifi/connect",
            "/server/aux/wifi/ap/down",
            "/server/aux/proxy",
            "/server/aux/bms/link",
            "/server/aux/update/install",
            "/machine/update/status",
            "/machine/update/upgrade",
            "/machine/update/recover",
        ],
    )
    def test_every_route_under_the_two_prefixes_is_protected(self, endpoint):
        """Including `/server/aux/proxy`, the generic escape hatch: a Level 1
        that covered the named routes and not the proxy would cover nothing."""
        assert muon_floor.is_protected_endpoint(endpoint)

    @pytest.mark.parametrize(
        "endpoint",
        [
            "/server/aux/dev_mode",
            "/server/aux/dev_mode/waiver",
            "/server/aux/dev_mode/consent",
            "/server/aux/dev_mode/refresh",
            "/server/aux/dev_mode/backup",
        ],
    )
    def test_developer_mode_is_governed_elsewhere(self, endpoint):
        """SEC-8 excludes the toggle by name: `dev_mode_consent` gates enabling,
        and leaving must never depend on who is asking."""
        assert not muon_floor.is_protected_endpoint(endpoint)

    @pytest.mark.parametrize(
        "endpoint",
        [
            "/printer/print/start",
            "/server/files/upload",
            "/server/muon/identity",
            "/server/muon/protection",
            "/server/muon/dev_mode",
            "/machine/system_info",
            # A segment boundary, not a substring.
            "/server/auxiliary",
            "/machine/updates",
        ],
    )
    def test_printing_and_everything_else_stays_open(self, endpoint):
        """Level 1 is not a login wall. A LAN browser still prints, uploads and
        reads the printer's name."""
        assert not muon_floor.is_protected_endpoint(endpoint)


class TestWhoHasAnIdentity:
    def test_the_panel_does(self):
        assert muon_floor.has_identity(HTTP, LOOPBACK, TRUSTED_USER)

    def test_a_component_to_component_call_does(self):
        assert muon_floor.has_identity(INTERNAL, None, None)

    def test_a_paired_client_through_the_gateway_does(self):
        assert muon_floor.has_identity(HTTP, SENTINEL, GATEWAY_USER)

    @pytest.mark.parametrize("addr", [LAN, HOTSPOT, LAN_V6])
    def test_a_lan_or_hotspot_browser_does_not(self, addr):
        """trusted_clients authenticates it by address alone, which is exactly
        what Level 1 stops counting."""
        assert not muon_floor.has_identity(HTTP, addr, TRUSTED_USER)

    def test_the_sentinel_without_a_gateway_token_is_not_an_identity(self):
        """Any request muon-link forwards carries the sentinel. Only the token
        says the gateway admitted this client."""
        assert not muon_floor.has_identity(HTTP, SENTINEL, TRUSTED_USER)
        assert not muon_floor.has_identity(HTTP, SENTINEL, None)

    def test_a_gateway_user_off_the_sentinel_is_not_an_identity(self):
        """`_check_oneshot_token` binds the token to the sentinel, so this
        cannot happen through Moonraker. Asserted anyway, so the check does not
        quietly come to rest on the user alone."""
        assert not muon_floor.has_identity(HTTP, LAN, GATEWAY_USER)

    def test_an_addressless_transport_is_not_an_identity(self):
        assert not muon_floor.has_identity(HTTP, None, TRUSTED_USER)

    def test_the_sentinel_here_is_the_one_the_gateway_binds_tokens_to(self):
        """Two constants for one address. If they drift, every paired client is
        refused at Level 1 -- or, the other way round, the check reads an
        address nobody sends."""
        from moonraker.components import muon_gateway

        assert muon_floor.GATEWAY_SENTINEL == muon_gateway.SENTINEL


class TestLevelZeroIsOpen:
    def test_the_default_is_open(self):
        assert muon_floor.protection_level() == muon_floor.LEVEL_OPEN

    @pytest.mark.parametrize("addr", [LAN, HOTSPOT, LAN_V6])
    def test_a_lan_browser_reaches_wifi_and_updates(self, addr):
        """SEC-1. The shipped default is what makes Fluidd work with no sign-in."""
        check_protection(WIFI, HTTP, addr, TRUSTED_USER)
        check_protection(UPGRADE, HTTP, addr, TRUSTED_USER)


class TestLevelOneIsProtected:
    @pytest.mark.parametrize("addr", [LAN, HOTSPOT, LAN_V6])
    def test_a_lan_browser_is_refused_a_protected_surface(self, protected, addr):
        for endpoint in ("/server/aux/wifi/connect", "/machine/update/upgrade"):
            with pytest.raises(ServerError) as excinfo:
                muon_floor.check_protection(endpoint, HTTP, addr, TRUSTED_USER)
            assert excinfo.value.status_code == 403

    def test_the_panel_keeps_everything(self, protected):
        """SEC-8: an owner must not be able to lock themselves out."""
        check_protection(WIFI, HTTP, LOOPBACK, TRUSTED_USER)
        check_protection(UPGRADE, HTTP, LOOPBACK, TRUSTED_USER)

    def test_a_paired_client_keeps_everything(self, protected):
        check_protection(WIFI, HTTP, SENTINEL, GATEWAY_USER)
        check_protection(UPGRADE, HTTP, SENTINEL, GATEWAY_USER)

    def test_an_internal_call_keeps_everything(self, protected):
        """ota_deploy drives an install through aux_api_proxy this way."""
        muon_floor.check_protection("/server/aux/update/install", INTERNAL, None, None)

    def test_a_lan_browser_still_prints(self, protected):
        muon_floor.check_protection("/printer/print/start", HTTP, LAN, TRUSTED_USER)
        muon_floor.check_protection("/server/files/upload", HTTP, LAN, TRUSTED_USER)

    def test_a_lan_browser_can_still_leave_developer_mode(self, protected):
        muon_floor.check_protection("/server/aux/dev_mode", HTTP, LAN, TRUSTED_USER)

    def test_the_refusal_names_the_panel(self, protected):
        """A 403 the UI can explain, not a bare one."""
        with pytest.raises(ServerError) as excinfo:
            check_protection(WIFI, HTTP, LAN, TRUSTED_USER)
        assert "panel" in str(excinfo.value)

    def test_the_floor_is_unchanged_by_the_level(self, protected):
        """Level 1 adds to the floor and removes nothing from it: a paired
        client still cannot reach ship mode."""
        with pytest.raises(ServerError):
            check_floor("/server/aux/bms/ship", HTTP, SENTINEL)


class TestTheLevelSetter:
    @pytest.mark.parametrize("bad", [2, -1, "1", None, 1.5, 1.0, True, False])
    def test_an_unknown_level_is_refused(self, bad):
        with pytest.raises(ValueError):
            muon_floor.set_protection_level(bad)
        assert muon_floor.protection_level() == muon_floor.LEVEL_OPEN
