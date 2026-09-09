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

    SEC-2 as amended keeps only what an owner cannot consent away. Everything
    else is governed by SEC-8's levels, which is policy rather than floor.
    """

    def test_the_developer_mode_toggle_is_floored(self):
        # DEV-3: enabling blows a one-time-programmable fuse. Permanent in
        # hardware, so no setting may open it and no level may relax it.
        assert is_floor_endpoint("/server/aux/dev_mode")

    def test_the_floor_is_only_the_toggle(self):
        assert FLOOR_PREFIXES == ("/server/aux/dev_mode",)

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
        """`/server/aux/dev_mode_other` is a different endpoint and must not be
        caught by the toggle's entry. The implementation checks equality or
        prefix + "/", which is what makes that true; assert it so a later
        `startswith` shortcut cannot silently widen the floor."""
        assert is_floor_endpoint("/server/aux/dev_mode")
        assert is_floor_endpoint("/server/aux/dev_mode/anything")
        assert not is_floor_endpoint("/server/aux/dev_mode_other")


class TestWhoIsAllowedThrough:
    def test_a_network_caller_is_denied_a_floor_surface(self):
        with pytest.raises(ServerError) as excinfo:
            check_floor("/server/aux/dev_mode", HTTP, LAN)
        assert excinfo.value.status_code == 403

    def test_the_panel_reaches_the_toggle(self):
        # Loopback is the panel: the MuonUI vhost listens on loopback only.
        check_floor("/server/aux/dev_mode", HTTP, LOOPBACK)

    def test_a_component_to_component_call_is_not_a_network_caller(self):
        # update_manager driving an OTA through aux_api_proxy, for instance.
        check_floor("/server/aux/dev_mode", INTERNAL, None)

    def test_a_network_caller_reaches_everything_off_the_floor(self):
        check_floor("/server/aux/wifi/current", HTTP, LAN)
        check_floor("/machine/update/status", HTTP, LAN)

    def test_an_addressless_transport_is_denied_not_waved_through(self):
        """Fail-closed. MQTT carries no address, and `None` must read as remote
        rather than as "no evidence it is remote"."""
        with pytest.raises(ServerError):
            check_floor("/server/aux/dev_mode", HTTP, None)


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
