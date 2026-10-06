"""KAN-475 (MR-8): the port the records name, and the Muon TXT keys.

`ZeroconfRegistrar` is driven with hand-written fakes, and `AsyncRunner` is
replaced by a recorder: it is the only collaborator that opens a socket. The
config parsing, the record construction and the re-announce logic are the
real code.

MuonOS's `recipes/klipper_moonraker_fluidd/tests/test_mdns_address_record.py`
drives the same component with the shipped M1 template, which is where the
port-80 assertion against the real config lives.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import pytest

pytest.importorskip("zeroconf")

from moonraker.components import zeroconf as zc  # noqa: E402


class FakeConfig:
    def __init__(self, server: Any, values: Dict[str, str]) -> None:
        self.server = server
        self.values = values

    def get_server(self) -> Any:
        return self.server

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def getboolean(self, key: str, default: Any = None) -> Any:
        raw = self.values.get(key)
        return default if raw is None else raw.lower() in ("true", "1", "yes")

    def getint(self, key: str, default: Any = None, **_kw: Any) -> Any:
        raw = self.values.get(key)
        return default if raw is None else int(raw)


class FakeApp:
    route_prefix = ""

    def https_enabled(self) -> bool:
        return False


class FakeMachine:
    unit_name = "moonraker"
    public_ip = ""

    def get_provider_type(self) -> str:
        return "systemd_dbus"

    def get_moonraker_service_info(self) -> Dict[str, str]:
        return {"unit_name": "moonraker.service"}


class FakeSetup:
    def __init__(self, state: Optional[Dict[str, Any]]) -> None:
        # muon_setup's `doc` is None until it has decided what the printer is.
        self.doc = None if state is None else {"state": state["state"]}
        self.state = state

    def public_state(self) -> Dict[str, Any]:
        assert self.state is not None
        return self.state


class FakeServer:
    def __init__(self, setup: Optional[FakeSetup]) -> None:
        self.handlers: Dict[str, Any] = {}
        self.components: Dict[str, Any] = {
            "application": FakeApp(), "machine": FakeMachine()}
        if setup is not None:
            self.components["muon_setup"] = setup

    def get_host_info(self) -> Dict[str, Any]:
        return {"hostname": "Muon-walnut-8987", "address": "127.0.0.1",
                "port": 7125, "ssl_port": 7130}

    def get_app_args(self) -> Dict[str, Any]:
        return {"instance_uuid": "0" * 32, "software_version": "v0-test"}

    def lookup_component(self, name: str, default: Any = KeyError) -> Any:
        if name in self.components:
            return self.components[name]
        if default is KeyError:
            raise KeyError(name)
        return default

    def register_event_handler(self, event: str, callback: Any) -> None:
        self.handlers[event] = callback


class RecordingRunner:
    def __init__(self) -> None:
        self.registered: List[Any] = []
        self.updated: List[List[Any]] = []

    async def register_services(self, infos: List[Any], addresses: Any = None) -> None:
        self.registered = list(infos)

    async def update_services(self, infos: List[Any]) -> None:
        self.updated.append(list(infos))


def state(setup: str, name: str = "Walnut", display: str = "Walnut · 8987"
          ) -> Dict[str, Any]:
    return {
        "state": setup,
        "printer": {"name": name, "display": display},
        "steps": {"name": {"value": name}},
    }


def build(values: Dict[str, str], setup: Optional[FakeSetup]
          ) -> "tuple[zc.ZeroconfRegistrar, RecordingRunner, FakeServer]":
    server = FakeServer(setup)
    reg = zc.ZeroconfRegistrar(FakeConfig(server, values))
    runner = RecordingRunner()
    reg.runner = runner  # type: ignore[assignment]
    asyncio.run(reg.component_init())
    return reg, runner, server


M1 = {"octoprint_discovery": "True", "octoprint_addr_pref": "hostname",
      "advertised_port": "80"}


def txt(info: Any) -> Dict[str, Optional[str]]:
    return {k.decode(): None if v is None else v.decode()
            for k, v in info.properties.items()}


def test_both_records_name_the_advertised_port() -> None:
    _, runner, _ = build(M1, FakeSetup(state("complete")))
    assert [info.port for info in runner.registered] == [80, 80]


def test_without_the_option_the_server_port_is_kept() -> None:
    values = {k: v for k, v in M1.items() if k != "advertised_port"}
    _, runner, _ = build(values, None)
    assert [info.port for info in runner.registered] == [7125, 7125]


def test_the_octoprint_record_carries_name_and_setup() -> None:
    reg, runner, _ = build(M1, FakeSetup(state("new")))
    octo = txt(reg.octo_service_info)
    assert octo["name"] == "Walnut · 8987"
    assert octo["setup"] == "new"
    # Upstream's keys are untouched, and the Moonraker record gets no extras.
    assert octo["addr_pref"] == "hostname"
    assert "setup" not in txt(reg.service_info)


def test_no_keys_before_muon_setup_has_decided() -> None:
    # public_state() says "complete" while undecided; that must not leak out
    # as "Ready" for a printer that may be new.
    reg, _, _ = build(M1, FakeSetup(None))
    octo = txt(reg.octo_service_info)
    assert "setup" not in octo and "name" not in octo


def test_a_change_re_announces_the_record_under_the_same_name() -> None:
    reg, runner, server = build(M1, FakeSetup(state("in_progress")))
    before = reg.octo_service_info
    assert before is not None
    handler = server.handlers["muon_setup:muon_setup_changed"]
    asyncio.run(handler(state("complete")))
    assert len(runner.updated) == 1
    (after,) = runner.updated[0]
    assert txt(after)["setup"] == "complete"
    assert after.name == before.name and after.port == 80
    assert after.server == before.server
    assert reg.octo_service_info is after and after in reg.service_list
    assert before not in reg.service_list


def test_a_rename_re_announces_and_an_unchanged_state_does_not() -> None:
    reg, runner, server = build(M1, FakeSetup(state("complete")))
    handler = server.handlers["muon_setup:muon_setup_changed"]
    asyncio.run(handler(state("complete")))
    assert runner.updated == []
    asyncio.run(handler(state("complete", "Oak", "Oak · 8987")))
    assert txt(runner.updated[-1][0])["name"] == "Oak · 8987"


def test_a_change_before_registration_is_carried_into_it() -> None:
    server = FakeServer(FakeSetup(None))
    reg = zc.ZeroconfRegistrar(FakeConfig(server, M1))
    runner = RecordingRunner()
    reg.runner = runner  # type: ignore[assignment]
    asyncio.run(server.handlers["muon_setup:muon_setup_changed"](state("new")))
    assert runner.updated == []
    asyncio.run(reg.component_init())
    assert txt(reg.octo_service_info)["setup"] == "new"


def test_name_falls_back_and_unknown_states_are_left_out() -> None:
    assert zc._muon_txt({"state": "weird", "steps": {"name": {"value": "Elm"}}}
                        ) == {"name": "Elm"}
    assert zc._muon_txt({}) == {}
    long = zc._muon_txt({"printer": {"display": "x" * 400}})["name"]
    assert len(("name=" + long).encode()) <= 255
