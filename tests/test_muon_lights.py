# KAN-4767: tests for components/muon_lights.py, the host-side renderer and
# API for the M1's two 40-LED strips. No printer, no klippy, no sockets: the
# event loop is a virtual clock, and "klippy" is a recorder that stands in for
# the muon_lights_out webhook. Every cap is measured by counting what reaches
# that recorder, second by second, in each printer state.
#
# A negative control sits beside each check that could pass by doing nothing.
from __future__ import annotations

import base64
import json
import struct
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

import pytest

from moonraker.common import RequestType
from moonraker import muon_access_policy as policy
from moonraker.components import muon_lights as ml
from moonraker.components import websockets
from moonraker.utils.exceptions import ServerError

pytestmark = pytest.mark.asyncio

T0 = 1000.0


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class Handle:
    def __init__(self, when: float, cb: Any, args: Tuple[Any, ...]) -> None:
        self.when, self.cb, self.args = when, cb, args
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True


class Clock:
    """A virtual event loop: timers fire in time order as the test advances."""
    def __init__(self) -> None:
        self.t = T0
        self.timers: List[Handle] = []
        self.ready: List[Tuple[Any, Tuple[Any, ...]]] = []

    def get_loop_time(self) -> float:
        return self.t

    def delay_callback(self, delay: float, cb: Any, *args: Any) -> Handle:
        h = Handle(self.t + delay, cb, args)
        self.timers.append(h)
        return h

    def register_callback(self, cb: Any, *args: Any) -> None:
        self.ready.append((cb, args))

    async def _run(self, cb: Any, args: Tuple[Any, ...]) -> None:
        out = cb(*args)
        if hasattr(out, "__await__"):
            await out

    async def advance(self, seconds: float) -> None:
        end = self.t + seconds
        while True:
            if self.ready:
                cb, args = self.ready.pop(0)
                await self._run(cb, args)
                continue
            live = [h for h in self.timers if not h.cancelled]
            due = [h for h in live if h.when <= end + 1e-12]
            if not due:
                self.timers = live
                self.t = end
                return
            h = min(due, key=lambda x: x.when)
            self.timers.remove(h)
            self.t = max(self.t, h.when)
            await self._run(h.cb, h.args)


class FakeDB:
    def __init__(self) -> None:
        self.data: Dict[str, Any] = {}

    async def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    async def insert(self, key: str, value: Any) -> None:
        self.data[key] = json.loads(json.dumps(value))


class Apis:
    def __init__(self) -> None:
        self.gcode: List[Tuple[float, str]] = []
        self.clock: Optional[Clock] = None

    async def run_gcode(self, script: str, default: Any = None) -> str:
        assert self.clock is not None
        self.gcode.append((self.clock.t, script))
        return "ok"


class Server:
    error = ServerError

    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.endpoints: Dict[str, Any] = {}
        self.notifications: List[Tuple[str, str]] = []
        self.handlers: Dict[str, List[Any]] = {}
        self.events: List[Tuple[float, str, Any]] = []
        self.apis = Apis()
        self.apis.clock = clock
        self.db = FakeDB()
        self.components: Dict[str, Any] = {
            "klippy_apis": self.apis,
            "database": SimpleNamespace(
                register_local_namespace=lambda name: self.db),
        }

    def get_event_loop(self) -> Clock:
        return self.clock

    def register_endpoint(self, path: str, types: Any, cb: Any,
                          *args: Any, **kw: Any) -> None:
        self.endpoints[path] = (types, cb)

    def register_notification(self, event: str, name: str) -> None:
        self.notifications.append((event, name))

    def register_event_handler(self, event: str, cb: Any) -> None:
        self.handlers.setdefault(event, []).append(cb)

    def send_event(self, event: str, *args: Any) -> None:
        self.events.append((self.clock.t, event, args[0] if args else None))

    def lookup_component(self, name: str, default: Any = None) -> Any:
        return self.components.get(name, default)


class Config:
    def __init__(self, server: Server, **opts: Any) -> None:
        self.server = server
        self.opts = opts

    def get_server(self) -> Server:
        return self.server

    def getboolean(self, key: str, default: bool) -> bool:
        return bool(self.opts.get(key, default))

    def getfloat(self, key: str, default: float, **kw: Any) -> float:
        return float(self.opts.get(key, default))

    def getint(self, key: str, default: int, **kw: Any) -> int:
        return int(self.opts.get(key, default))


class Req:
    """The slice of WebRequest the component uses."""
    def __init__(self, args: Optional[Dict[str, Any]] = None,
                 rtype: RequestType = RequestType.POST,
                 conn: Optional[int] = None, ip: Optional[str] = None
                 ) -> None:
        self.args = args or {}
        self.rtype = rtype
        self.conn = conn
        self.ip = ip

    def get_args(self) -> Dict[str, Any]:
        return self.args

    def get_request_type(self) -> RequestType:
        return self.rtype

    def get_str(self, key: str, default: Any = None) -> Any:
        if key not in self.args:
            if default is None:
                raise ServerError(f"Missing Argument [{key}]", 400)
            return default
        return str(self.args[key])

    def get_client_connection(self) -> Any:
        return None if self.conn is None else SimpleNamespace(uid=self.conn)

    def get_ip_address(self) -> Optional[str]:
        return self.ip


class Rig:
    def __init__(self, **opts: Any) -> None:
        self.clock = Clock()
        self.server = Server(self.clock)
        self.lights = ml.MuonLights(Config(self.server, enabled=True, **opts))
        self.sent: List[Tuple[float, Dict[str, bytes]]] = []
        self.reply: Dict[str, Any] = {"ok": True}
        self.lights.send = self._send
        self.lights.db = self.server.db
        self.lights.klippy_ready = True
        self.status({"muon_lights_out": {
            "enabled": True, "blocked": None, "stop_count": 0,
            "idle_effect_on": False}})

    async def _send(self, params: Dict[str, Any]) -> Dict[str, Any]:
        frame = {k: base64.b64decode(v) for k, v in params.items()}
        self.sent.append((self.clock.t, frame))
        return dict(self.reply)

    def status(self, status: Dict[str, Any]) -> None:
        self.lights.on_status_update(status, self.clock.t)

    async def set(self, payload: Dict[str, Any], conn: int = 1) -> Any:
        return await self.lights._handle_set(Req(payload, conn=conn))

    async def preset(self, args: Dict[str, Any],
                     rtype: RequestType = RequestType.POST) -> Any:
        return await self.lights._handle_preset(Req(args, rtype, conn=1))

    async def start(self, conn: int = 1, **args: Any) -> Dict[str, Any]:
        return await self.lights._handle_stream_start(Req(args, conn=conn))

    async def frame(self, lease: str, seq: int, strip: str = "left",
                    start: int = 0, count: int = 40, value: int = 100,
                    conn: int = 1, raw: bool = False, rgb: Any = None
                    ) -> Any:
        data = rgb if rgb is not None else bytes([value]) * (3 * count)
        args = {"lease": lease, "seq": seq, "strip": strip, "start": start,
                "rgb": base64.b64encode(data).decode()}
        if raw:
            args["raw"] = True
        return await self.lights._handle_frame(Req(args, conn=conn))

    def per_second(self) -> List[int]:
        """Sends in each half-open one second window since T0."""
        counts: Dict[int, int] = {}
        for t, _ in self.sent:
            k = int(t - T0)
            counts[k] = counts.get(k, 0) + 1
        return [counts.get(i, 0) for i in range(max(counts, default=-1) + 1)]

    def max_in_any_second(self) -> int:
        times = [t for t, _ in self.sent]
        best = 0
        for i, t in enumerate(times):
            best = max(best, sum(1 for u in times[i:] if u < t + 1.0))
        return best


def ready_calls(r: "Rig") -> int:
    return sum(1 for _, g in r.server.apis.gcode if g == "LED_READY")


def stat_blocked(reason: Optional[str]) -> Dict[str, Any]:
    return {"muon_lights_out": {"blocked": reason}}


@pytest.fixture
def rig() -> Rig:
    return Rig()


async def settle(r: Rig, seconds: float = 0.2) -> None:
    await r.clock.advance(seconds)


# ---------------------------------------------------------------------------
# State and range checks
# ---------------------------------------------------------------------------

class TestState:
    async def test_state_has_the_documented_shape(self, rig: Rig) -> None:
        state = rig.lights.get_state()
        for key in ("on", "preset", "effect", "colors", "brightness", "speed",
                    "zones", "source", "stream", "limits", "effects",
                    "presets"):
            assert key in state
        assert state["effects"] == ["solid", "gradient", "rainbow", "breathe",
                                    "chase", "comet", "wave", "sparkle",
                                    "progress", "status", "off"]
        assert state["zones"] == {"left": None, "right": None}
        assert state["source"] == "user"
        assert state["stream"]["active"] is False
        limits = state["limits"]
        assert limits["fps_out"] == 30 and limits["fps_in_max"] == 60
        assert limits["leds"] == {"left": 40, "right": 40}
        assert limits["max_brightness"] == 80
        assert any(p["id"] == "aurora" and p["builtin"]
                   for p in state["presets"])

    async def test_disabled_component_registers_nothing(self) -> None:
        clock = Clock()
        server = Server(clock)
        comp = ml.MuonLights(Config(server, enabled=False))
        assert server.endpoints == {} and server.handlers == {}
        assert comp.enabled is False

    async def test_endpoints_and_notification_are_registered(
            self, rig: Rig) -> None:
        paths = set(rig.server.endpoints)
        assert {"/server/lights", "/server/lights/set",
                "/server/lights/preset", "/server/lights/stream/start",
                "/server/lights/stream/stop",
                "/server/lights/frame"} <= paths
        assert ("muon_lights:update", "lights_update") in \
            rig.server.notifications

    BAD = [
        {"brightness": 101}, {"brightness": -1}, {"brightness": "70"},
        {"brightness": True}, {"brightness": float("nan")},
        {"speed": 101}, {"speed": -0.5}, {"speed": None},
        {"colors": []}, {"colors": ["#000000"] * 5}, {"colors": ["red"]},
        {"colors": ["#12345"]}, {"colors": "#ffffff"}, {"colors": [5]},
        {"effect": "disco"}, {"effect": 3}, {"on": "yes"}, {"on": 1},
        {"zones": {"middle": {}}}, {"zones": {"left": {"x": 1}}},
        {"zones": {"left": {"brightness": 500}}}, {"zones": []},
        {"zones": {"left": 5}}, {"preset": "aurora"}, {"bogus": 1},
    ]

    @pytest.mark.parametrize("bad", BAD)
    async def test_bad_value_is_a_400_and_applies_nothing(
            self, rig: Rig, bad: Dict[str, Any]) -> None:
        before = json.dumps(rig.lights.get_state(), sort_keys=True)
        good = {"effect": "comet", "colors": ["#ff7a00"], "brightness": 33}
        with pytest.raises(ServerError) as e:
            await rig.set({**good, **bad})        # good fields ride along
        assert e.value.status_code == 400
        assert list(bad)[0] in str(e.value)       # it names the field
        assert json.dumps(rig.lights.get_state(), sort_keys=True) == before

    async def test_control_the_same_good_fields_do_apply(
            self, rig: Rig) -> None:
        good = {"effect": "comet", "colors": ["#ff7a00"], "brightness": 33,
                "zones": {"right": {"effect": "solid",
                                    "colors": ["#ffffff"]}}}
        state = await rig.set(good)
        assert state["effect"] == "comet" and state["brightness"] == 33
        assert state["zones"]["right"] == {"effect": "solid",
                                           "colors": ["#ffffff"]}
        assert state["zones"]["left"] is None and state["preset"] is None

    async def test_short_hex_and_case_are_normalised(self, rig: Rig) -> None:
        state = await rig.set({"colors": ["#F0a", "#36C5F0"]})
        assert state["colors"] == ["#ff00aa", "#36c5f0"]

    async def test_zone_null_clears_the_override(self, rig: Rig) -> None:
        await rig.set({"zones": {"left": {"brightness": 10}}})
        state = await rig.set({"zones": {"left": None}})
        assert state["zones"]["left"] is None

    async def test_sets_over_20_per_second_keep_the_latest(
            self, rig: Rig) -> None:
        for i in range(50):
            await rig.set({"brightness": i})
        # 20 were applied at once, the rest held; the latest wins shortly.
        assert rig.lights.state["brightness"] == 19
        await rig.clock.advance(1.5)
        assert rig.lights.state["brightness"] == 49

    async def test_control_20_sets_in_a_second_are_all_applied(
            self, rig: Rig) -> None:
        for i in range(20):
            await rig.set({"brightness": i})
        assert rig.lights.state["brightness"] == 19
        assert not rig.lights._pending_set


# ---------------------------------------------------------------------------
# Presets
# ---------------------------------------------------------------------------

class TestPresets:
    async def test_apply_a_builtin(self, rig: Rig) -> None:
        state = await rig.preset({"apply": "aurora"})
        assert state["preset"] == "aurora" and state["effect"] == "gradient"
        assert state["colors"] == ["#36c5f0", "#7a5cff"]

    async def test_a_manual_change_clears_the_preset_name(
            self, rig: Rig) -> None:
        await rig.preset({"apply": "aurora"})
        assert (await rig.set({"brightness": 12}))["preset"] is None

    async def test_save_apply_delete_a_user_preset(self, rig: Rig) -> None:
        await rig.set({"effect": "solid", "colors": ["#ffaa55"],
                       "brightness": 55})
        state = await rig.preset({"save": {"name": "Desk warm"}})
        mine = [p for p in state["presets"] if not p["builtin"]]
        assert len(mine) == 1 and mine[0]["name"] == "Desk warm"
        pid = mine[0]["id"]
        assert pid.startswith("u_")
        assert rig.server.db.data["presets"][pid]["colors"] == ["#ffaa55"]
        await rig.preset({"apply": "aurora"})
        await rig.preset({"apply": pid})
        assert rig.lights.state["colors"] == ["#ffaa55"]
        state = await rig.preset({"id": pid}, RequestType.DELETE)
        assert not [p for p in state["presets"] if not p["builtin"]]
        assert rig.server.db.data["presets"] == {}

    async def test_user_presets_are_stored_in_the_database_and_reloaded(
            self, rig: Rig) -> None:
        await rig.preset({"save": {"name": "One"}})
        data = rig.server.db.data["presets"]
        again = Rig()
        again.server.db.data["presets"] = data
        await again.lights.component_init()
        assert [p["name"] for p in again.lights.get_state()["presets"]
                if not p["builtin"]] == ["One"]

    async def test_at_most_16_user_presets(self, rig: Rig) -> None:
        for i in range(16):
            await rig.preset({"save": {"name": f"P{i}"}})
        with pytest.raises(ServerError) as e:
            await rig.preset({"save": {"name": "one too many"}})
        assert e.value.status_code == 400
        assert len(rig.lights.user_presets) == 16
        # control: deleting one makes room again
        pid = next(iter(rig.lights.user_presets))
        await rig.preset({"id": pid}, RequestType.DELETE)
        await rig.preset({"save": {"name": "fits now"}})

    async def test_builtins_cannot_be_deleted(self, rig: Rig) -> None:
        with pytest.raises(ServerError) as e:
            await rig.preset({"id": "aurora"}, RequestType.DELETE)
        assert e.value.status_code == 400
        assert "aurora" in {p["id"] for p in rig.lights.get_state()["presets"]}

    @pytest.mark.parametrize("args", [
        {}, {"apply": "aurora", "save": {"name": "x"}}, {"save": "x"},
        {"save": {"name": ""}}, {"save": {"name": "x" * 33}},
        {"save": {"name": 5}}, {"save": {"name": "ok", "extra": 1}},
        {"zap": 1}])
    async def test_bad_preset_requests_are_400(
            self, rig: Rig, args: Dict[str, Any]) -> None:
        with pytest.raises(ServerError) as e:
            await rig.preset(args)
        assert e.value.status_code == 400
        assert rig.lights.user_presets == {}

    async def test_unknown_preset_is_404(self, rig: Rig) -> None:
        with pytest.raises(ServerError) as e:
            await rig.preset({"apply": "nope"})
        assert e.value.status_code == 404
        with pytest.raises(ServerError) as e:
            await rig.preset({"id": "u_zzzz"}, RequestType.DELETE)
        assert e.value.status_code == 404


# ---------------------------------------------------------------------------
# The stream lease
# ---------------------------------------------------------------------------

class TestLease:
    async def test_start_returns_a_lease_and_expiry(self, rig: Rig) -> None:
        out = await rig.start(strips=["left", "right"], fps=30)
        assert out["fps_out"] == 30 and out["expires_in"] == 2.0
        assert out["lease"] and rig.lights.get_state()["stream"]["active"]

    async def test_it_ends_after_2s_without_a_frame(self, rig: Rig) -> None:
        lease = (await rig.start())["lease"]
        await rig.clock.advance(1.9)
        assert rig.lights.lease is not None
        await rig.clock.advance(0.3)
        assert rig.lights.lease is None
        with pytest.raises(ServerError) as e:
            await rig.frame(lease, 1)
        assert e.value.status_code == 409

    async def test_frames_keep_it_alive(self, rig: Rig) -> None:
        lease = (await rig.start())["lease"]
        for i in range(1, 8):
            await rig.clock.advance(1.0)
            await rig.frame(lease, i)
        assert rig.lights.lease is not None          # 7 s of 1 s frames

    async def test_only_one_lease_and_takeover_when_idle(
            self, rig: Rig) -> None:
        first = (await rig.start(conn=1))["lease"]
        with pytest.raises(ServerError) as e:
            await rig.start(conn=2)
        assert e.value.status_code == 409
        await rig.frame(first, 1, conn=1)
        await rig.clock.advance(1.0)
        with pytest.raises(ServerError):
            await rig.start(conn=2)                  # still fresh
        # Make it idle without the sweeper having run yet.
        rig.lights.lease.last = rig.clock.t - 2.5    # type: ignore
        second = (await rig.start(conn=2))["lease"]
        assert second != first
        assert rig.lights.lease.client == "ws:2"     # type: ignore
        with pytest.raises(ServerError):
            await rig.frame(first, 2, conn=1)        # the old holder is out

    async def test_same_client_may_restart(self, rig: Rig) -> None:
        a = (await rig.start(conn=1))["lease"]
        b = (await rig.start(conn=1))["lease"]
        assert a != b and rig.lights.lease.id == b   # type: ignore

    async def test_another_client_cannot_use_the_lease(
            self, rig: Rig) -> None:
        lease = (await rig.start(conn=1))["lease"]
        with pytest.raises(ServerError) as e:
            await rig.frame(lease, 1, conn=2)
        assert e.value.status_code == 409

    async def test_stop_and_disconnect_end_it(self, rig: Rig) -> None:
        lease = (await rig.start(conn=1))["lease"]
        out = await rig.lights._handle_stream_stop(
            Req({"lease": lease}, conn=1))
        assert out == {"stopped": True} and rig.lights.lease is None
        lease = (await rig.start(conn=1))["lease"]
        with pytest.raises(ServerError):
            await rig.lights._handle_stream_stop(
                Req({"lease": "wrong"}, conn=1))
        assert rig.lights.lease is not None
        rig.lights._on_client_removed(SimpleNamespace(uid=1))
        assert rig.lights.lease is None
        # control: another connection closing does not
        lease = (await rig.start(conn=1))["lease"]
        rig.lights._on_client_removed(SimpleNamespace(uid=99))
        assert rig.lights.lease is not None and lease

    async def test_a_user_preset_ends_the_lease_at_once(
            self, rig: Rig) -> None:
        lease = (await rig.start())["lease"]
        await rig.frame(lease, 1)
        await rig.preset({"apply": "aurora"})
        assert rig.lights.lease is None
        assert rig.lights.get_state()["stream"]["active"] is False
        with pytest.raises(ServerError):
            await rig.frame(lease, 2)

    async def test_control_a_plain_set_does_not_end_it(self, rig: Rig) -> None:
        await rig.start()
        await rig.set({"brightness": 20})
        assert rig.lights.lease is not None

    async def test_lease_validation(self, rig: Rig) -> None:
        for strips in ([], ["middle"], "left", ["left", "left"]):
            with pytest.raises(ServerError) as e:
                await rig.start(strips=strips)
            assert e.value.status_code == 400
        with pytest.raises(ServerError):
            await rig.start(fps=0)
        with pytest.raises(ServerError):
            await rig.start(fps=500)
        assert rig.lights.lease is None

    async def test_lease_fps_is_never_above_the_output_cap(
            self, rig: Rig) -> None:
        out = await rig.start(fps=60)
        assert out["fps_out"] == 30


class TestFrames:
    async def test_seq_only_increases(self, rig: Rig) -> None:
        lease = (await rig.start())["lease"]
        assert (await rig.frame(lease, 10))["status"] == "ok"
        assert (await rig.frame(lease, 10))["status"] == "seq"   # duplicate
        assert (await rig.frame(lease, 9))["status"] == "seq"    # late
        assert (await rig.frame(lease, 11))["status"] == "ok"
        assert rig.lights.get_state()["stream"]["seq_dropped"] == 2

    async def test_n_limits(self, rig: Rig) -> None:
        lease = (await rig.start())["lease"]
        assert (await rig.frame(lease, 1, "left", 0, 40))["ok"]
        assert (await rig.frame(lease, 2, "both", 0, 80))["ok"]
        for strip, start, count in (("left", 0, 41), ("left", 1, 40),
                                    ("both", 0, 81), ("both", 1, 80),
                                    ("right", 39, 2)):
            with pytest.raises(ServerError) as e:
                await rig.frame(lease, 3, strip, start, count)
            assert e.value.status_code == 400

    @pytest.mark.parametrize("args", [
        {"strip": "middle"}, {"start": -1}, {"seq": -1}, {"seq": "1"},
        {"rgb": "not base64!"}, {"rgb": base64.b64encode(b"ab").decode()},
        {"rgb": ""}, {"raw": "yes"}, {"zzz": 1}])
    async def test_bad_frames_are_400(self, rig: Rig,
                                      args: Dict[str, Any]) -> None:
        lease = (await rig.start())["lease"]
        good = {"lease": lease, "seq": 1, "strip": "left", "start": 0,
                "rgb": base64.b64encode(bytes(3)).decode()}
        with pytest.raises(ServerError) as e:
            await rig.lights._handle_frame(Req({**good, **args}, conn=1))
        assert e.value.status_code == 400
        # control: the unmodified frame is fine
        assert (await rig.lights._handle_frame(Req(good, conn=1)))["ok"]

    async def test_both_strips_index_left_first(self, rig: Rig) -> None:
        lease = (await rig.start())["lease"]
        data = bytes([10, 20, 30]) * 40 + bytes([40, 50, 60]) * 40
        await rig.frame(lease, 1, "both", 0, 80, rgb=data, raw=True)
        await settle(rig)
        assert rig.sent[-1][1]["left"][:3] == bytes([10, 20, 30])
        assert rig.sent[-1][1]["right"][:3] == bytes([40, 50, 60])

    async def test_partial_frame_updates_only_its_leds(
            self, rig: Rig) -> None:
        lease = (await rig.start(strips=["left"]))["lease"]
        await rig.frame(lease, 1, "left", 5, 2, value=200, raw=True)
        await settle(rig)
        left = rig.sent[-1][1]["left"]
        assert left[:15] == bytes(15) and left[15:21] == bytes([200] * 6)
        assert left[21:] == bytes(len(left) - 21)

    async def test_input_rate_over_60_per_second_is_dropped(
            self, rig: Rig) -> None:
        lease = (await rig.start())["lease"]
        # 300 frames in the same instant: the 120 burst passes, rest drop.
        for i in range(300):
            await rig.frame(lease, i + 1, value=i % 255)
        assert rig.lights.stream_dropped == 180
        # control: 60/s spread over a second is fine
        await rig.clock.advance(5)
        before = rig.lights.stream_dropped
        lease = (await rig.start())["lease"]
        for i in range(60):
            await rig.frame(lease, i + 1, value=i)
            await rig.clock.advance(1 / 60)
        assert rig.lights.stream_dropped == before

    async def test_coalescing_latest_wins(self, rig: Rig) -> None:
        lease = (await rig.start())["lease"]
        for i in range(1, 101):                      # 100 frames at once
            await rig.frame(lease, i, value=i, raw=True)
        await settle(rig, 0.1)
        assert len(rig.sent) == 1                    # not one per frame
        assert rig.sent[0][1]["left"][:3] == bytes([100] * 3)

    async def test_brightness_cap_is_80_percent_even_raw(
            self, rig: Rig) -> None:
        lease = (await rig.start())["lease"]
        await rig.frame(lease, 1, "both", 0, 80, value=255, raw=True)
        await settle(rig)
        assert max(rig.sent[-1][1]["left"]) <= 204   # 80% of 255
        assert max(rig.sent[-1][1]["right"]) <= 204
        assert max(rig.sent[-1][1]["left"]) == 204   # and it did reach it
        await rig.frame(lease, 2, "left", 0, 40, value=255)   # with gamma
        await settle(rig)
        assert max(rig.sent[-1][1]["left"]) <= 204

    async def test_cap_keeps_the_colour(self, rig: Rig) -> None:
        lease = (await rig.start())["lease"]
        await rig.frame(lease, 1, "left", 0, 1, rgb=bytes([255, 128, 0]),
                        raw=True)
        await settle(rig)
        r, g, b = rig.sent[-1][1]["left"][:3]
        assert (r, b) == (204, 0) and abs(g - 102) <= 1

    async def test_cap_is_configurable_and_a_control_without_it(self) -> None:
        low = Rig(max_brightness=50)
        lease = (await low.start())["lease"]
        await low.frame(lease, 1, value=255, raw=True)
        await settle(low)
        assert max(low.sent[-1][1]["left"]) == 127
        full = Rig(max_brightness=100)
        lease = (await full.start())["lease"]
        await full.frame(lease, 1, value=255, raw=True)
        await settle(full)
        assert max(full.sent[-1][1]["left"]) == 255

    async def test_user_effects_are_capped_too(self, rig: Rig) -> None:
        await rig.set({"effect": "solid", "colors": ["#ffffff"],
                       "brightness": 100})
        await settle(rig)
        assert max(rig.sent[-1][1]["left"]) == 204


class TestBinary:
    def packet(self, strip: int, start: int, seq: int, rgb: bytes) -> bytes:
        return struct.pack(">BBHI", 0x4C, strip, start, seq) + rgb

    async def test_accepted_only_from_the_lease_holders_connection(
            self, rig: Rig) -> None:
        await rig.start(conn=7)
        rig.lights.handle_binary(7, self.packet(2, 0, 1, bytes([90]) * 240))
        await settle(rig)
        assert rig.sent and rig.sent[-1][1]["left"][:3] == bytes([
            rig.lights.gamma_lut[90]] * 3)
        n = len(rig.sent)
        rig.lights.handle_binary(8, self.packet(2, 0, 2, bytes([10]) * 240))
        await settle(rig)
        assert len(rig.sent) == n and rig.lights.stream_rejected == 1

    async def test_no_lease_no_frames(self, rig: Rig) -> None:
        rig.lights.handle_binary(7, self.packet(0, 0, 1, bytes(120)))
        await settle(rig)
        assert not rig.sent and rig.lights.stream_rejected == 1

    async def test_bad_packets_are_rejected_and_seq_applies(
            self, rig: Rig) -> None:
        await rig.start(conn=7)
        rig.lights.handle_binary(7, b"\x4c\x00")                    # short
        rig.lights.handle_binary(7, b"\x00" * 20)                   # magic
        rig.lights.handle_binary(7, self.packet(5, 0, 1, bytes(3)))  # strip
        assert rig.lights.stream_rejected == 3
        rig.lights.handle_binary(7, self.packet(0, 0, 5, bytes(3)))
        rig.lights.handle_binary(7, self.packet(0, 0, 5, bytes(3)))
        assert rig.lights.stream_seq_dropped == 1

    async def test_the_websocket_routes_binary_to_the_component(self) -> None:
        got: List[Tuple[int, bytes]] = []
        lights = SimpleNamespace(
            handle_binary=lambda uid, msg: got.append((uid, msg)))
        queued: List[Any] = []
        fake = SimpleNamespace(
            uid=42, server=SimpleNamespace(
                lookup_component=lambda name, default=None: lights),
            eventloop=SimpleNamespace(
                register_callback=lambda *a: queued.append(a)),
            _process_message=lambda m: None)
        websockets.WebSocket.on_message(fake, b"L\x00\x00\x00")   # type: ignore
        assert got == [(42, b"L\x00\x00\x00")] and not queued
        # control: text and JSON bytes still go to the RPC handler
        websockets.WebSocket.on_message(fake, '{"id":1}')         # type: ignore
        websockets.WebSocket.on_message(fake, b'{"id":1}')        # type: ignore
        assert len(got) == 1 and len(queued) == 2


# ---------------------------------------------------------------------------
# Output: what reaches the MCU
# ---------------------------------------------------------------------------

class TestOutputBudget:
    async def _run(self, rig: Rig, seconds: float) -> None:
        await rig.clock.advance(seconds)

    async def test_idle_animation_is_capped_at_30_fps(self, rig: Rig) -> None:
        await rig.set({"effect": "rainbow", "speed": 100})
        await self._run(rig, 6)
        counts = rig.per_second()
        assert max(counts) <= 30 and min(counts[1:-1]) >= 28
        assert rig.max_in_any_second() <= 30 + 1       # incl. the closed end

    async def test_the_measurement_sees_a_higher_rate_if_there_is_one(
            self) -> None:
        # Control for the test above: raise the ceiling and the same
        # counter reads higher, so it is measuring the real output.
        rig = Rig()
        rig.lights.idle_fps = 60.
        await rig.set({"effect": "rainbow", "speed": 100})
        await self._run(rig, 4)
        assert max(rig.per_second()) > 40

    async def test_config_cannot_raise_the_ceiling(self) -> None:
        rig = Rig(idle_fps=240, print_fps=120)
        assert rig.lights.idle_fps == 30 and rig.lights.print_fps == 6

    async def test_printing_is_capped_at_6_fps(self, rig: Rig) -> None:
        await rig.set({"effect": "rainbow", "speed": 100})
        rig.status({"print_stats": {"state": "printing"}})
        await self._run(rig, 6)
        counts = rig.per_second()
        assert 0 < max(counts) <= 6 and rig.max_in_any_second() <= 6
        assert rig.lights.get_state()["limits"]["fps_out"] == 6

    async def test_paused_is_capped_too_and_idle_resumes(
            self, rig: Rig) -> None:
        await rig.set({"effect": "rainbow", "speed": 100})
        rig.status({"print_stats": {"state": "paused"}})
        await self._run(rig, 3)
        assert rig.max_in_any_second() <= 6
        rig.sent.clear()
        rig.status({"print_stats": {"state": "standby"}})
        t = rig.clock.t
        await self._run(rig, 2)
        assert sum(1 for s, _ in rig.sent if s >= t) > 40

    async def test_homing_probing_and_mesh_send_nothing(
            self, rig: Rig) -> None:
        await rig.set({"effect": "rainbow", "speed": 100})
        await self._run(rig, 1)
        rig.status(stat_blocked("busy"))
        rig.sent.clear()
        await self._run(rig, 5)
        assert rig.sent == []                          # 0 fps, 0 attempts
        rig.status(stat_blocked(None))
        await self._run(rig, 1)
        assert rig.sent                                # and it comes back

    async def test_fault_and_print_effects_hold_it_too(self, rig: Rig) -> None:
        await rig.set({"effect": "rainbow"})
        for reason in ("fault", "print"):
            rig.status(stat_blocked(reason))
            rig.sent.clear()
            await self._run(rig, 3)
            assert rig.sent == [] and rig.lights.source() == reason
            rig.status(stat_blocked(None))
            await self._run(rig, 0.5)
            assert rig.sent and rig.lights.source() == "user"

    async def test_unchanged_frames_are_never_sent(self, rig: Rig) -> None:
        await rig.set({"effect": "solid", "colors": ["#336699"]})
        await self._run(rig, 10)
        assert len(rig.sent) == 1                      # once, then silence
        await rig.set({"brightness": 40})
        await self._run(rig, 2)
        assert len(rig.sent) == 2
        for a, b in zip(rig.sent, rig.sent[1:]):
            assert a[1] != b[1]

    async def test_a_repeated_identical_stream_frame_is_not_resent(
            self, rig: Rig) -> None:
        lease = (await rig.start())["lease"]
        for i in range(1, 60):
            await rig.frame(lease, i, value=77, raw=True)
            await rig.clock.advance(1 / 30)
        assert len(rig.sent) == 1
        # control: a frame that changes IS sent
        await rig.frame(lease, 100, value=78, raw=True)
        await self._run(rig, 0.2)
        assert len(rig.sent) == 2

    async def test_only_the_changed_strip_is_sent(self, rig: Rig) -> None:
        await rig.set({"effect": "solid", "colors": ["#ffffff"]})
        await self._run(rig, 1)
        assert set(rig.sent[-1][1]) == {"left", "right"}
        await rig.set({"zones": {"right": {"colors": ["#ff0000"]}}})
        await self._run(rig, 1)
        assert set(rig.sent[-1][1]) == {"right"}

    async def test_a_streamed_burst_costs_one_send_per_tick(
            self, rig: Rig) -> None:
        lease = (await rig.start())["lease"]
        t = 0
        for step in range(2 * 60):                    # 60 fps in for 2 s
            await rig.frame(lease, step + 1, "both", 0, 80,
                            value=(step * 7) % 250, raw=True)
            await rig.clock.advance(1 / 60)
            t += 1
        counts = rig.per_second()
        assert max(counts) <= 30 and rig.max_in_any_second() <= 31
        assert rig.max_in_any_second() >= 25           # it is streaming

    async def test_nothing_is_sent_before_klippy_is_ready(self) -> None:
        rig = Rig()
        rig.lights.klippy_ready = False
        await rig.set({"effect": "rainbow"})
        await rig.clock.advance(3)
        assert rig.sent == []
        rig.lights.klippy_ready = True
        rig.lights._kick()
        await rig.clock.advance(1)
        assert rig.sent

    async def test_nothing_is_sent_while_klippy_has_the_output_off(
            self) -> None:
        rig = Rig()
        rig.status({"muon_lights_out": {"enabled": False}})
        await rig.set({"effect": "rainbow"})
        await rig.clock.advance(3)
        assert rig.sent == []
        assert rig.lights.get_state()["output"]["available"] is False

    async def test_status_effect_sends_nothing_and_idle_costs_no_timers(
            self, rig: Rig) -> None:
        await rig.clock.advance(5)
        assert rig.sent == []
        live = [h for h in rig.clock.timers if not h.cancelled]
        assert live == []                              # no polling at rest

    async def test_a_static_user_look_leaves_no_timer_running(
            self, rig: Rig) -> None:
        await rig.set({"effect": "solid", "colors": ["#00ff00"]})
        await rig.clock.advance(1)
        live = [h for h in rig.clock.timers if not h.cancelled]
        assert live == []


class TestMcuBackoff:
    async def test_rising_retransmits_hold_output_then_it_resumes(
            self, rig: Rig) -> None:
        await rig.set({"effect": "rainbow", "speed": 100})
        rig.status({"mcu": {"last_stats": {"bytes_retransmit": 100}}})
        await rig.clock.advance(2)
        assert rig.sent
        rig.status({"mcu": {"last_stats": {"bytes_retransmit": 140}}})
        rig.sent.clear()
        t = rig.clock.t
        await rig.clock.advance(9)
        assert rig.sent == []                           # 0 fps
        await rig.clock.advance(3)                      # 10 s have passed
        assert [s for s, _ in rig.sent if s > t + 10]

    async def test_flat_retransmits_do_not_back_off(self, rig: Rig) -> None:
        await rig.set({"effect": "rainbow", "speed": 100})
        for _ in range(4):
            rig.status({"mcu": {"last_stats": {"bytes_retransmit": 100}}})
            await rig.clock.advance(1)
        assert rig.per_second()[1] >= 28

    async def test_lights_off_baseline_retransmits_do_not_count(
            self, rig: Rig) -> None:
        # No frame was sent in the interval, so the rise is not ours.
        rig.status({"mcu": {"last_stats": {"bytes_retransmit": 100}}})
        rig.status({"mcu": {"last_stats": {"bytes_retransmit": 500}}})
        await rig.set({"effect": "rainbow"})
        await rig.clock.advance(2)
        assert rig.sent


class TestKlippyAnswers:
    async def test_a_dropped_frame_is_counted_and_sent_again(
            self, rig: Rig) -> None:
        rig.reply = {"ok": False, "reason": "failed"}
        await rig.set({"effect": "solid", "colors": ["#123456"]})
        await rig.clock.advance(3)
        first = len(rig.sent)
        assert first >= 1
        assert rig.lights.stats["failed"] == first
        rig.reply = {"ok": True}
        await rig.clock.advance(3)
        assert len(rig.sent) > first
        sent_ok = len(rig.sent)
        await rig.clock.advance(5)
        assert len(rig.sent) == sent_ok                # now it is quiet

    async def test_fault_reply_marks_the_source_and_retries_slowly(
            self, rig: Rig) -> None:
        lease = (await rig.start())["lease"]
        rig.reply = {"ok": False, "reason": "fault"}
        seq = 0
        for _ in range(10):                  # a client sending for 5 s
            seq += 1
            await rig.frame(lease, seq, value=50)
            await rig.clock.advance(0.5)
        assert rig.lights.source() == "fault"
        assert len(rig.sent) <= 6                      # about 1 look a second
        rig.reply = {"ok": True}
        for _ in range(6):
            seq += 1
            await rig.frame(lease, seq, value=50)
            await rig.clock.advance(0.5)
        assert rig.lights.source() == "stream"

    async def test_a_stale_fault_does_not_outlive_the_stream(
            self, rig: Rig) -> None:
        lease = (await rig.start())["lease"]
        rig.reply = {"ok": False, "reason": "fault"}
        await rig.frame(lease, 1, value=50)
        await rig.clock.advance(4)                     # lease ran out
        assert rig.lights.lease is None
        assert rig.lights.source() == "user"

    async def test_faults_win_over_a_stream(self, rig: Rig) -> None:
        lease = (await rig.start())["lease"]
        rig.status(stat_blocked("fault"))
        for i in range(1, 100):
            await rig.frame(lease, i, value=i, raw=True)
            await rig.clock.advance(1 / 60)
        assert rig.sent == []                          # not a byte went out
        assert rig.lights.get_state()["source"] == "fault"
        rig.status(stat_blocked(None))
        await rig.frame(lease, 500, value=9, raw=True)
        await rig.clock.advance(0.2)
        assert rig.sent and rig.lights.get_state()["source"] == "stream"

    async def test_a_release_hands_back_to_the_printer_once(
            self, rig: Rig) -> None:
        await rig.set({"effect": "solid", "colors": ["#00ff00"]})
        await rig.clock.advance(1)
        assert rig.lights.owning
        await rig.set({"effect": "status"})
        await rig.clock.advance(2)
        assert ready_calls(rig) == 1
        assert not rig.lights.owning
        await rig.clock.advance(3)
        assert ready_calls(rig) == 1                   # and only once

    async def test_no_release_gcode_in_a_print(self, rig: Rig) -> None:
        await rig.set({"effect": "solid", "colors": ["#00ff00"]})
        await rig.clock.advance(1)
        rig.status({"print_stats": {"state": "printing"}})
        await rig.set({"effect": "status"})
        await rig.clock.advance(2)
        assert ready_calls(rig) == 0

    async def test_klippys_own_look_coming_back_is_taken_over(
            self, rig: Rig) -> None:
        await rig.set({"effect": "solid", "colors": ["#00ff00"]})
        await rig.clock.advance(1)
        n = len(rig.sent)
        rig.status({"muon_lights_out": {"idle_effect_on": True}})
        await rig.clock.advance(1)
        assert len(rig.sent) == n + 1                  # one full resend
        rig.status({"muon_lights_out": {"idle_effect_on": True}})
        await rig.clock.advance(1)
        assert len(rig.sent) == n + 1                  # but not a loop

    async def test_stop_led_effects_blanks_until_the_user_acts(
            self, rig: Rig) -> None:
        await rig.set({"effect": "solid", "colors": ["#00ff00"]})
        await rig.clock.advance(1)
        rig.status({"muon_lights_out": {"stop_count": 1}})
        await rig.clock.advance(1)
        assert set(rig.sent[-1][1]["left"]) == {0}
        await rig.set({"brightness": 50})
        await rig.clock.advance(1)
        assert max(rig.sent[-1][1]["left"]) > 0


# ---------------------------------------------------------------------------
# Persistence, restore, notifications
# ---------------------------------------------------------------------------

class TestPersistence:
    def saves(self, rig: Rig) -> List[Tuple[float, str]]:
        return [(t, g) for t, g in rig.server.apis.gcode
                if g.startswith("SAVE_VARIABLE")]

    async def test_at_most_one_save_every_5_seconds(self, rig: Rig) -> None:
        for i in range(200):                           # 20 sets/s for 10 s
            await rig.set({"brightness": i % 100})
            await rig.clock.advance(0.05)
        await rig.clock.advance(6)
        saves = self.saves(rig)
        assert 1 <= len(saves) <= 3
        for (a, _), (b, _) in zip(saves, saves[1:]):
            assert b - a >= 5.0 - 1e-6
        last = json.loads(saves[-1][1].split("VALUE='")[1][:-1])
        assert last["brightness"] == rig.lights.state["brightness"]

    async def test_nothing_is_saved_without_a_change(self, rig: Rig) -> None:
        await rig.clock.advance(30)
        assert self.saves(rig) == []

    async def test_stream_frames_never_save(self, rig: Rig) -> None:
        lease = (await rig.start())["lease"]
        for i in range(1, 200):
            await rig.frame(lease, i, value=i % 200)
            await rig.clock.advance(1 / 60)
        await rig.clock.advance(10)
        assert self.saves(rig) == []

    async def test_no_save_while_printing_it_waits(self, rig: Rig) -> None:
        rig.status({"print_stats": {"state": "printing"}})
        await rig.set({"brightness": 11})
        await rig.clock.advance(20)
        assert self.saves(rig) == []
        rig.status({"print_stats": {"state": "complete"}})
        await rig.clock.advance(6)
        assert len(self.saves(rig)) == 1

    async def test_the_saved_state_comes_back_and_survives_a_bad_one(
            self, rig: Rig) -> None:
        await rig.set({"effect": "comet", "colors": ["#ff7a00"],
                       "brightness": 61, "speed": 22,
                       "zones": {"left": {"effect": "solid"}}})
        await rig.clock.advance(6)
        saved = json.loads(self.saves(rig)[-1][1].split("VALUE='")[1][:-1])
        fresh = Rig()
        fresh.lights._restore(saved)
        assert fresh.lights.state["effect"] == "comet"
        assert fresh.lights.state["zones"]["left"] == {"effect": "solid"}
        broken = Rig()
        broken.lights._restore({"brightness": 900})
        broken.lights._restore("junk")
        assert broken.lights.state["brightness"] == 70   # default kept


class TestNotifications:
    async def test_a_change_is_announced_and_coalesced(self, rig: Rig) -> None:
        for i in range(30):
            await rig.set({"brightness": i})
        await rig.clock.advance(0.5)
        events = [e for e in rig.server.events
                  if e[1] == "muon_lights:update"]
        assert 1 <= len(events) <= 5                   # 30 sets, not 30
        assert events[-1][2]["brightness"] == rig.lights.state["brightness"]

    async def test_at_most_10_a_second(self, rig: Rig) -> None:
        for i in range(60):
            await rig.set({"brightness": i % 100})
            await rig.clock.advance(0.02)
        times = [t for t, e, _ in rig.server.events
                 if e == "muon_lights:update"]
        assert times
        assert all(b - a >= 0.1 - 1e-6 for a, b in zip(times, times[1:]))

    async def test_lease_changes_are_announced(self, rig: Rig) -> None:
        await rig.start()
        await rig.clock.advance(0.2)
        last = [e for e in rig.server.events
                if e[1] == "muon_lights:update"][-1][2]
        assert last["stream"]["active"] is True


class TestLedModeShim:
    def macro(self, **kw: Any) -> Dict[str, Any]:
        base = {"mode": "status", "h": 0, "h2": 180, "bright": 60,
                "speed": 50}
        base.update(kw)
        return {"gcode_macro LED_MODE": base}

    async def ready(self, rig: Rig) -> None:
        rig.lights.ready_at = rig.clock.t
        rig.lights.on_status_update(self.macro(), rig.clock.t, adopt=False)

    async def test_a_led_mode_call_becomes_the_user_state(
            self, rig: Rig) -> None:
        await self.ready(rig)
        await rig.clock.advance(20)
        rig.status(self.macro(mode="gradient", h=120, h2=240, bright=40,
                              speed=70))
        s = rig.lights.state
        assert s["effect"] == "gradient" and s["brightness"] == 40
        assert s["speed"] == 70 and s["on"] is True
        assert s["colors"] == [ml.hue_to_hex(120), ml.hue_to_hex(240)]
        await rig.clock.advance(1)
        assert rig.sent                                # rendered here

    async def test_partial_updates_are_merged(self, rig: Rig) -> None:
        await self.ready(rig)
        await rig.clock.advance(20)
        rig.status({"gcode_macro LED_MODE": {"mode": "solid"}})
        rig.status({"gcode_macro LED_MODE": {"bright": 25}})
        assert rig.lights.state["effect"] == "solid"
        assert rig.lights.state["brightness"] == 25
        assert rig.lights.state["colors"][0] == ml.hue_to_hex(0)

    async def test_off_turns_it_off_and_status_hands_back(
            self, rig: Rig) -> None:
        await self.ready(rig)
        await rig.clock.advance(20)
        rig.status(self.macro(mode="solid"))
        rig.status(self.macro(mode="off"))
        assert rig.lights.state["on"] is False
        rig.status(self.macro(mode="status"))
        assert rig.lights.state["effect"] == "status"

    async def test_the_boot_restore_is_ignored_during_the_settle_window(
            self, rig: Rig) -> None:
        await self.ready(rig)
        rig.lights._restore({"effect": "comet", "brightness": 33})
        await rig.clock.advance(3)       # _LED_MODE_RESTORE runs at +2 s
        rig.status(self.macro(mode="solid", bright=99))
        assert rig.lights.state["effect"] == "comet"
        assert rig.lights.state["brightness"] == 33
        # control: after the window the same call is adopted
        await rig.clock.advance(20)
        rig.status(self.macro(mode="gradient", bright=44))
        assert rig.lights.state["effect"] == "gradient"

    async def test_an_unchanged_macro_changes_nothing(self, rig: Rig) -> None:
        await self.ready(rig)
        await rig.clock.advance(20)
        before = json.dumps(rig.lights.state, sort_keys=True)
        rig.status(self.macro())
        rig.status(self.macro())
        assert json.dumps(rig.lights.state, sort_keys=True) == before

    async def test_led_mode_ends_a_stream_it_replaced(self, rig: Rig) -> None:
        await self.ready(rig)
        await rig.start()
        await rig.clock.advance(20)
        await rig.start()
        rig.status(self.macro(mode="rainbow"))
        assert rig.lights.lease is None

    async def test_the_hue_matches_the_macro(self) -> None:
        # led_modes.cfg: HSL(h, 85%, 55%)
        assert ml.hue_to_hex(0) == "#ee2b2b"
        assert ml.hue_to_hex(120) == "#2bee2b"
        assert ml.hue_to_hex(240) == "#2b2bee"
        assert ml.hue_to_hex(360) == ml.hue_to_hex(0)


class TestRenderers:
    @pytest.mark.parametrize("effect", [e for e in ml.EFFECTS])
    async def test_every_effect_renders_40_valid_pixels(self, effect: str) -> None:
        for t in (0., 0.3, 7.7):
            pix = ml.render(effect, ["#36c5f0", "#7a5cff"], 50., t, 40, 0.5)
            assert len(pix) == 40
            assert all(0. <= c <= 1.0001 for p in pix for c in p)

    @pytest.mark.parametrize("effect", sorted(ml.ANIMATED))
    async def test_animated_effects_move(self, effect: str) -> None:
        a = ml.render(effect, ["#36c5f0", "#7a5cff"], 80., 0., 40)
        b = ml.render(effect, ["#36c5f0", "#7a5cff"], 80., 0.77, 40)
        assert a != b

    @pytest.mark.parametrize("effect", ["solid", "gradient", "off"])
    async def test_static_effects_do_not(self, effect: str) -> None:
        a = ml.render(effect, ["#36c5f0", "#7a5cff"], 80., 0., 40)
        assert a == ml.render(effect, ["#36c5f0", "#7a5cff"], 80., 9., 40)

    async def test_progress_fills_in_proportion(self) -> None:
        pix = ml.render("progress", ["#ffffff"], 50., 0., 40, 0.5)
        assert sum(1 for p in pix if p[0] > 0.5) == 20

    async def test_gradient_ends_are_the_colours(self) -> None:
        pix = ml.render("gradient", ["#ff0000", "#0000ff"], 0., 0., 40)
        assert pix[0] == (1., 0., 0.) and pix[-1] == (0., 0., 1.)


# ---------------------------------------------------------------------------
# Who may call it (BRIEF 6)
# ---------------------------------------------------------------------------

class TestAccess:
    async def test_writes_are_the_lights_action_and_reads_are_reads(self) -> None:
        post = RequestType.POST
        for path in ("/server/lights", "/server/lights/set",
                     "/server/lights/preset", "/server/lights/stream/start",
                     "/server/lights/stream/stop", "/server/lights/frame"):
            assert [a.name for a in policy.classify(path, post, {})] == \
                ["lights"]
        assert [a.name for a in policy.classify(
            "/server/lights/preset", RequestType.DELETE, {"id": "x"})] == \
            ["lights"]
        assert [a.name for a in policy.classify(
            "/server/lights", RequestType.GET, {})] == ["read"]

    async def test_open_by_default_and_the_owner_when_protected(self) -> None:
        row = policy.ACTIONS["lights"]
        assert row.relaxed == policy.SIGNED_OUT_GUEST   # D-166: open
        assert row.standard == policy.ADMIN
        assert row.strict == policy.ADMIN
        # control: it is not the fail-closed fallback by accident
        assert policy.ACTIONS["system"] is not row

    async def test_a_negative_control_unlisted_writes_stay_system(self) -> None:
        names = [a.name for a in policy.classify(
            "/server/lightsout", RequestType.POST, {})]
        assert names == ["system"]
