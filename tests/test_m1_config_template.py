from __future__ import annotations

import configparser
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
