from __future__ import annotations

import configparser
import ipaddress
from pathlib import Path


TEMPLATE = Path(__file__).resolve().parents[1] / "core" / "M1" / "moonraker.core.conf.template"


def test_m1_image_opts_into_writes_for_the_developer_mode_config_root():
    """The live mode check remains the gate; this option only permits it to open."""
    config = configparser.ConfigParser(interpolation=None)
    config.read(TEMPLATE, encoding="utf-8")

    assert config.getboolean("file_manager", "enable_custom_config_write_access")


def test_m1_image_enables_the_gateway_token_component_for_root_only():
    """GATE-2: without it every request muon-link forwards is refused."""
    config = configparser.ConfigParser(interpolation=None)
    config.read(TEMPLATE, encoding="utf-8")

    assert config.has_section("muon_gateway")
    assert config.get("muon_gateway", "socket_path") == (
        "/home/printer_admin/comms/muon-gateway.sock"
    )
    # The default is uid 0 only; widening it must be a visible decision here.
    assert not config.has_option("muon_gateway", "allowed_uids")


def test_m1_image_trusts_the_lan_it_is_on_over_ipv6():
    """SEC-1: `.local` resolves to the printer's global IPv6 address, so without
    this a browser on the LAN gets 401 and a sign-in page on an open printer."""
    config = configparser.ConfigParser(interpolation=None)
    config.read(TEMPLATE, encoding="utf-8")

    assert config.getboolean("authorization", "trust_onlink_ipv6")
    # And no global range stands in for it in the static list.
    trusted = config.get("authorization", "trusted_clients").split()
    for entry in trusted:
        if ":" in entry:
            net = ipaddress.ip_network(entry, strict=False)
            assert net.is_private or net.is_link_local or net.is_loopback, entry
