# MUON, KAN-4767: lighting for the M1's two 40-LED strips.
#
# THE HARD RULE: the lights never cost the printer. The strips share the main
# RP2040 with motion, so the priority is Klipper, then Moonraker, then the
# panel and the lights. Everything that costs anything happens HERE, on the
# host, outside klippy:
#
#   * every effect and every stream is rendered in this component;
#   * klippy gets finished bytes through ONE webhooks endpoint,
#     muon_lights_out/frame (klippy/extras/muon_lights_out.py), never G-code;
#   * output obeys one budget (below), enforced here and again in the extra.
#
# Enable it in moonraker.conf (it does nothing unless it is on):
#     [muon_lights]
#     enabled: True
#
# OUTPUT BUDGET (frames to the MCU, both strips counted as one)
#     idle                      at most 30 fps
#     printing or paused        at most  6 fps  (bench proof sets the final)
#     homing, probing, mesh,
#     Z_POWER work              0 fps (the extra gates this itself)
#     MCU stressed              0 fps while mcu bytes_retransmit is rising
#   An unchanged strip is never sent. Callers may send faster than the
#   output; the latest frame wins (coalescing).
#
# LAYERS, highest first: fault, print state, live stream, user preset, off.
# Faults and the print state are still rendered by led_effect in klippy, so
# the extra drops this component's frames while one is active (one writer).
#
# API (BRIEF 3-5). HTTP and websocket, JSON-RPC names in brackets:
#   GET  /server/lights                 state
#   POST /server/lights                 set any subset of the fields
#   POST /server/lights/set             same        [server.lights.set]
#   POST /server/lights/preset          {"apply": id} | {"save": {"name"}}
#   DELETE /server/lights/preset?id=
#   POST /server/lights/stream/start    [server.lights.stream.start]
#   POST /server/lights/stream/stop     [server.lights.stream.stop]
#   POST /server/lights/frame           [server.lights.frame]
#   notification: notify_lights_update
# Binary websocket frames: [0x4C][u8 strip][u16 start][u32 seq][RGB...], big
# endian, strip 0 left, 1 right, 2 both. They carry no lease, so they are
# taken only from the connection that holds it.
#
# LED_MODE shim: the macro is left exactly as it is. This component watches
# the gcode_macro LED_MODE variables and adopts a change as the user state,
# so the panel and macros that call LED_MODE keep working and are then
# rendered here instead of by led_effect. See _on_led_mode.
from __future__ import annotations

import base64
import binascii
import colorsys
import json
import logging
import math
import re
import struct
import uuid
from collections import deque
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Deque,
    Dict,
    List,
    Optional,
    Tuple,
)

from ..common import RequestType
from ..utils.exceptions import ServerError

if TYPE_CHECKING:
    from ..common import WebRequest
    from ..confighelper import ConfigHelper

STRIPS = ("left", "right")
EFFECTS = ["solid", "gradient", "rainbow", "breathe", "chase", "comet",
           "wave", "sparkle", "progress", "status", "off"]
HEX_RE = re.compile(r"^#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})$")
MAGIC = 0x4C
LEDS_PER_STRIP = 40
MAX_PRESETS = 16
MAX_NAME = 32
SETS_PER_SECOND = 20
FRAMES_PER_SECOND = 60
FRAME_BURST = 120
LEASE_IDLE = 2.0
PERSIST_INTERVAL = 5.0
NOTIFY_INTERVAL = 0.1
SETTLE_AFTER_READY = 10.0
BLOCKED_RETRY = 1.0
SAVE_KEY = "muon_lights"
DB_NAMESPACE = "muon_lights"
SET_FIELDS = ("on", "effect", "colors", "brightness", "speed", "zones")
ZONE_FIELDS = ("effect", "colors", "brightness", "speed")

Rgb = Tuple[float, float, float]
Sender = Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]

BUILTIN_PRESETS: Dict[str, Dict[str, Any]] = {
    "aurora": {"name": "Aurora", "effect": "gradient",
               "colors": ["#36c5f0", "#7a5cff"], "brightness": 70,
               "speed": 40},
    "sunset": {"name": "Sunset", "effect": "gradient",
               "colors": ["#ff7a00", "#ff2d6f"], "brightness": 65,
               "speed": 30},
    "ocean": {"name": "Ocean", "effect": "wave",
              "colors": ["#0077ff", "#00e0c0"], "brightness": 60,
              "speed": 35},
    "forest": {"name": "Forest", "effect": "gradient",
               "colors": ["#1fa84a", "#c6e23b"], "brightness": 60,
               "speed": 30},
    "ember": {"name": "Ember", "effect": "comet", "colors": ["#ff5a1f"],
              "brightness": 70, "speed": 45},
    "candy": {"name": "Candy", "effect": "chase",
              "colors": ["#ff4fa3", "#4fd0ff"], "brightness": 70,
              "speed": 50},
    "daylight": {"name": "Daylight", "effect": "solid",
                 "colors": ["#fff4e0"], "brightness": 80, "speed": 50},
    "focus": {"name": "Focus", "effect": "solid", "colors": ["#cfe8ff"],
              "brightness": 90, "speed": 50},
    "party": {"name": "Party", "effect": "rainbow", "colors": ["#ff0000"],
              "brightness": 80, "speed": 70},
    "calm": {"name": "Calm", "effect": "breathe", "colors": ["#7a9cff"],
             "brightness": 50, "speed": 20},
}


# ---------------------------------------------------------------------------
# Validation. Everything is checked before anything is applied.
# ---------------------------------------------------------------------------

def bad(field: str, why: str) -> ServerError:
    return ServerError(f"{field}: {why}", 400)


def check_number(field: str, value: Any, lo: float, hi: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise bad(field, f"must be a number from {lo:g} to {hi:g}")
    if not (lo <= value <= hi) or math.isnan(value):
        raise bad(field, f"must be from {lo:g} to {hi:g}")
    return value


def check_colors(field: str, value: Any) -> List[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 4:
        raise bad(field, "must be a list of 1 to 4 hex colours")
    out: List[str] = []
    for item in value:
        if not isinstance(item, str) or HEX_RE.match(item) is None:
            raise bad(field, f"{item!r} is not a hex colour like #36c5f0")
        item = item.lower()
        if len(item) == 4:
            item = "#" + "".join(c * 2 for c in item[1:])
        out.append(item)
    return out


def check_effect(field: str, value: Any) -> str:
    if not isinstance(value, str) or value not in EFFECTS:
        raise bad(field, f"must be one of {', '.join(EFFECTS)}")
    return value


def check_look(prefix: str, src: Dict[str, Any],
               fields: Tuple[str, ...]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key in fields:
        if key not in src:
            continue
        name = prefix + key
        value = src[key]
        if key == "effect":
            out[key] = check_effect(name, value)
        elif key == "colors":
            out[key] = check_colors(name, value)
        else:
            out[key] = check_number(name, value, 0, 100)
    return out


def validate_set(payload: Any) -> Dict[str, Any]:
    """Return the normalised change, or raise a 400 that names the field."""
    if not isinstance(payload, dict):
        raise bad("body", "must be a JSON object")
    for key in payload:
        if key not in SET_FIELDS:
            raise bad(str(key), "is not a field that can be set")
    out = check_look("", payload, ("effect", "colors", "brightness", "speed"))
    if "on" in payload:
        if not isinstance(payload["on"], bool):
            raise bad("on", "must be true or false")
        out["on"] = payload["on"]
    if "zones" in payload:
        zones = payload["zones"]
        if not isinstance(zones, dict):
            raise bad("zones", "must be an object")
        checked: Dict[str, Any] = {}
        for strip, zone in zones.items():
            if strip not in STRIPS:
                raise bad(f"zones.{strip}", "is not a strip (left or right)")
            if zone is None:
                checked[strip] = None
                continue
            if not isinstance(zone, dict):
                raise bad(f"zones.{strip}", "must be an object or null")
            for key in zone:
                if key not in ZONE_FIELDS:
                    raise bad(f"zones.{strip}.{key}", "is not a zone field")
            checked[strip] = check_look(f"zones.{strip}.", zone, ZONE_FIELDS)
        out["zones"] = checked
    return out


# ---------------------------------------------------------------------------
# Rendering. Pure functions of time; the output is 0..1 floats per LED.
# ---------------------------------------------------------------------------

def hex_to_rgb(value: str) -> Rgb:
    return (int(value[1:3], 16) / 255., int(value[3:5], 16) / 255.,
            int(value[5:7], 16) / 255.)


def hue_to_hex(hue: float) -> str:
    """The same colour LED_MODE's macro makes: HSL(h, 85%, 55%)."""
    r, g, b = colorsys.hls_to_rgb((hue % 360.) / 360., 0.55, 0.85)
    return "#%02x%02x%02x" % (round(r * 255), round(g * 255), round(b * 255))


def _mix(a: Rgb, b: Rgb, f: float) -> Rgb:
    return (a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f,
            a[2] + (b[2] - a[2]) * f)


def _scale(c: Rgb, f: float) -> Rgb:
    return (c[0] * f, c[1] * f, c[2] * f)


def _palette(colors: List[Rgb], f: float) -> Rgb:
    if len(colors) == 1:
        return colors[0]
    f = min(max(f, 0.), 1.) * (len(colors) - 1)
    i = min(int(f), len(colors) - 2)
    return _mix(colors[i], colors[i + 1], f - i)


def _noise(i: int, step: int) -> float:
    h = (i * 2654435761 ^ step * 40503 ^ 0x9E3779B9) & 0xFFFFFFFF
    h = (h ^ (h >> 15)) * 2246822519 & 0xFFFFFFFF
    return ((h ^ (h >> 13)) & 0xFFFF) / 65535.


ANIMATED = frozenset(("rainbow", "breathe", "chase", "comet", "wave",
                      "sparkle"))
BLACK: Rgb = (0., 0., 0.)


def render(effect: str, colors: List[str], speed: float, t: float, n: int,
           progress: float = 0.) -> List[Rgb]:
    """One strip of n LEDs at time t, before brightness, gamma and the cap."""
    pal = [hex_to_rgb(c) for c in colors] or [BLACK]
    if effect == "solid":
        return [pal[0]] * n
    if effect == "gradient":
        return [_palette(pal, i / max(n - 1, 1)) for i in range(n)]
    if effect == "rainbow":
        rate = 0.05 + speed / 100. * 0.45
        return [colorsys.hsv_to_rgb((i / n + t * rate) % 1., 1., 1.)
                for i in range(n)]
    if effect == "breathe":
        period = (105. - speed) / 20.
        f = 0.5 - 0.5 * math.cos(2 * math.pi * t / max(period, 0.2))
        return [_scale(pal[0], f)] * n
    if effect == "chase":
        rate = 0.1 + speed / 100. * 1.4          # laps per second
        block = max(3, n // 5)
        head = (t * rate * n) % n
        out = [BLACK] * n
        for k in range(block):
            out[int(head + k) % n] = pal[(k * len(pal)) // block]
        return out
    if effect == "comet":
        rate = 0.1 + speed / 100. * 1.2
        head = (t * rate * n) % n
        out = [BLACK] * n
        for k in range(n):
            behind = (head - k) % n
            out[k] = _scale(pal[0], 0.82 ** behind) if behind < n else BLACK
        return out
    if effect == "wave":
        rate = 0.1 + speed / 100. * 0.9
        return [_scale(_palette(pal, i / max(n - 1, 1)),
                       0.5 + 0.5 * math.sin(2 * math.pi
                                            * (i / n * 2 - t * rate)))
                for i in range(n)]
    if effect == "sparkle":
        rate = 2. + speed / 100. * 10.
        step = int(t * rate)
        spark = pal[-1]
        return [spark if _noise(i, step) > 0.9 else _scale(pal[0], 0.15)
                for i in range(n)]
    if effect == "progress":
        lit = progress * n
        return [pal[0] if i + 1 <= lit else _scale(pal[0], 0.08)
                for i in range(n)]
    return [BLACK] * n                                   # off / status


# ---------------------------------------------------------------------------
# The component
# ---------------------------------------------------------------------------

class Lease:
    def __init__(self, lease_id: str, client: str, conn: Optional[int],
                 strips: List[str], fps: float, now: float) -> None:
        self.id = lease_id
        self.client = client
        self.conn = conn
        self.strips = strips
        self.fps = fps
        self.last = now
        self.seq = -1
        self.buffers: Dict[str, List[Rgb]] = {
            s: [BLACK] * LEDS_PER_STRIP for s in strips}
        self.raw: Dict[str, bool] = {s: False for s in strips}
        self.tokens: Dict[str, float] = {
            s: float(FRAME_BURST) for s in strips}
        self.token_time = now


class MuonLights:
    def __init__(self, config: ConfigHelper) -> None:
        self.server = config.get_server()
        self.enabled = config.getboolean("enabled", False)
        self.max_brightness = config.getfloat("max_brightness", 80.,
                                              minval=1., maxval=100.)
        # Hard ceilings, whatever the config says: BRIEF 2.
        self.idle_fps = min(30., config.getfloat("idle_fps", 30., minval=0.))
        self.print_fps = min(6., config.getfloat("print_fps", 6., minval=0.))
        self.gamma = config.getfloat("gamma", 2.2, above=0.)
        self.backoff_seconds = config.getfloat("backoff_seconds", 10.,
                                               minval=1.)
        self.leds = {"left": config.getint("left_leds", LEDS_PER_STRIP,
                                           minval=1, maxval=LEDS_PER_STRIP),
                     "right": config.getint("right_leds", LEDS_PER_STRIP,
                                            minval=1, maxval=LEDS_PER_STRIP)}
        self.loop = self.server.get_event_loop()
        self.cap_byte = int(255 * self.max_brightness / 100.)
        self.gamma_lut = [round(255 * (i / 255.) ** self.gamma)
                          for i in range(256)]
        # state
        self.state: Dict[str, Any] = {
            "on": True, "preset": None, "effect": "status",
            "colors": ["#36c5f0", "#7a5cff"], "brightness": 70,
            "speed": 40, "zones": {"left": None, "right": None}}
        self.user_presets: Dict[str, Dict[str, Any]] = {}
        self.lease: Optional[Lease] = None
        self.stream_dropped = 0
        self.stream_seq_dropped = 0
        self.stream_rejected = 0
        # output
        self.send: Sender = self._klippy_send
        self.klippy_ready = False
        self.ready_at = 0.
        self.output = {"available": False, "blocked": None}
        self.printing = False
        self.progress = 0.
        self.last_retransmit: Optional[int] = None
        self.stress_until = 0.
        self.tx_since_stats = 0
        self.last_tx = -1e9
        self.last_sent: Dict[str, Optional[bytes]] = {s: None
                                                      for s in STRIPS}
        self.owning = False
        self.blanked = False
        self.stop_count: Optional[int] = None
        self.idle_effect_on = False
        self.blocked_reason: Optional[str] = None
        self.stats = {"frames_out": 0, "sends": 0, "failed": 0,
                      "dropped_by_klippy": 0, "unchanged_skipped": 0}
        self.led_mode_seen: Optional[Tuple[Any, ...]] = None
        self.led_macro: Dict[str, Any] = {}
        self.out_status: Dict[str, Any] = {}
        # timers
        self._timer: Optional[Any] = None
        self._lease_timer: Optional[Any] = None
        self._in_step = False
        self._timer_due = 0.
        self._tx_times: Deque[float] = deque()
        self._dirty = True
        self._persist_dirty = False
        self._persist_timer: Optional[Any] = None
        self._last_persist = -1e9
        self._notify_timer: Optional[Any] = None
        self._notify_due = False
        self._last_notify = -1e9
        self._set_times: Dict[str, List[float]] = {}
        self._pending_set: Dict[str, Dict[str, Any]] = {}
        self._pending_timer: Dict[str, Any] = {}
        self.db: Any = None
        if not self.enabled:
            logging.info("muon_lights: disabled ([muon_lights] enabled: False)")
            return
        self.server.register_endpoint(
            "/server/lights", RequestType.GET | RequestType.POST,
            self._handle_root)
        self.server.register_endpoint(
            "/server/lights/set", RequestType.POST, self._handle_set)
        self.server.register_endpoint(
            "/server/lights/preset", RequestType.POST | RequestType.DELETE,
            self._handle_preset)
        self.server.register_endpoint(
            "/server/lights/stream/start", RequestType.POST,
            self._handle_stream_start)
        self.server.register_endpoint(
            "/server/lights/stream/stop", RequestType.POST,
            self._handle_stream_stop)
        self.server.register_endpoint(
            "/server/lights/frame", RequestType.POST, self._handle_frame)
        self.server.register_notification("muon_lights:update",
                                          "lights_update")
        self.server.register_event_handler(
            "server:klippy_ready", self._on_klippy_ready)
        self.server.register_event_handler(
            "server:klippy_disconnect", self._on_klippy_down)
        self.server.register_event_handler(
            "server:klippy_shutdown", self._on_klippy_down)
        self.server.register_event_handler(
            "websockets:client_removed", self._on_client_removed)

    async def component_init(self) -> None:
        if not self.enabled:
            return
        database = self.server.lookup_component("database")
        self.db = database.register_local_namespace(DB_NAMESPACE)
        saved = await self.db.get("presets", {})
        if isinstance(saved, dict):
            for pid, preset in saved.items():
                try:
                    self.user_presets[str(pid)] = self._clean_preset(preset)
                except ServerError:
                    logging.warning("muon_lights: dropped bad preset %s", pid)

    # -- time ---------------------------------------------------------------
    def now(self) -> float:
        return self.loop.get_loop_time()

    # -- state --------------------------------------------------------------
    def _clean_preset(self, preset: Any) -> Dict[str, Any]:
        if not isinstance(preset, dict):
            raise bad("preset", "must be an object")
        name = preset.get("name")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= MAX_NAME:
            raise bad("name", f"must be 1 to {MAX_NAME} characters")
        body = validate_set({k: v for k, v in preset.items()
                             if k in ("effect", "colors", "brightness",
                                      "speed", "zones")})
        out: Dict[str, Any] = {"name": name.strip()}
        for key in ("effect", "colors", "brightness", "speed"):
            out[key] = body.get(key, self.state[key])
        out["zones"] = {s: (body.get("zones") or {}).get(s)
                        for s in STRIPS}
        return out

    def _preset_list(self) -> List[Dict[str, Any]]:
        rows = [{"id": pid, "name": p["name"], "builtin": True}
                for pid, p in BUILTIN_PRESETS.items()]
        rows += [{"id": pid, "name": p["name"], "builtin": False}
                 for pid, p in self.user_presets.items()]
        return rows

    def source(self) -> str:
        if self.blocked_reason in ("fault", "print"):
            return self.blocked_reason
        if self.lease is not None:
            return "stream"
        return "user"

    def get_state(self) -> Dict[str, Any]:
        s = self.state
        lease = self.lease
        return {
            "on": s["on"], "preset": s["preset"], "effect": s["effect"],
            "colors": list(s["colors"]), "brightness": s["brightness"],
            "speed": s["speed"],
            "zones": {k: (dict(v) if v else None)
                      for k, v in s["zones"].items()},
            "source": self.source(),
            "stream": {"active": lease is not None,
                       "client": lease.client if lease else None,
                       "dropped": self.stream_dropped,
                       "seq_dropped": self.stream_seq_dropped},
            "limits": {
                "fps_out": self._nominal_fps(),
                "fps_in_max": FRAMES_PER_SECOND,
                "leds": dict(self.leds),
                "fps_out_idle": self.idle_fps,
                "fps_out_print": self.print_fps,
                "max_brightness": self.max_brightness,
                "frame_burst": FRAME_BURST,
                "sets_per_s": SETS_PER_SECOND,
                "lease_idle_s": LEASE_IDLE,
                "user_presets_max": MAX_PRESETS,
            },
            "output": {"available": self.output["available"],
                       "blocked": self.blocked_reason, **self.stats},
            "effects": list(EFFECTS),
            "presets": self._preset_list(),
        }

    def _apply(self, change: Dict[str, Any]) -> None:
        """Commit an already validated change. Nothing here can fail."""
        s = self.state
        for key in ("on", "effect", "colors", "brightness", "speed"):
            if key in change:
                s[key] = change[key]
        for strip, zone in change.get("zones", {}).items():
            if zone is None:
                s["zones"][strip] = None
            else:
                merged = dict(s["zones"].get(strip) or {})
                merged.update(zone)
                s["zones"][strip] = merged or None
        if any(k in change for k in ("effect", "colors", "brightness",
                                     "speed", "zones")):
            s["preset"] = None
        if change.get("on") or "effect" in change:
            self.blanked = False

    def _changed(self, persist: bool = True) -> None:
        self.blanked = False
        self._dirty = True
        if persist:
            self._persist_dirty = True
            self._arm_persist()
        self._notify()
        self._kick()

    # -- the handlers --------------------------------------------------------
    async def _handle_root(self, web_request: WebRequest) -> Dict[str, Any]:
        if web_request.get_request_type() == RequestType.GET:
            return self.get_state()
        return await self._handle_set(web_request)

    def _client_id(self, web_request: WebRequest) -> str:
        conn = web_request.get_client_connection()
        if conn is not None:
            return f"ws:{conn.uid}"
        ip = web_request.get_ip_address()
        return f"http:{ip}" if ip is not None else "internal"

    async def _handle_set(self, web_request: WebRequest) -> Dict[str, Any]:
        args = dict(web_request.get_args())
        change = validate_set(args)           # 400 before anything applies
        client = self._client_id(web_request)
        now = self.now()
        stamps = [t for t in self._set_times.get(client, [])
                  if now - t < 1.0]
        if len(stamps) >= SETS_PER_SECOND:
            # Over 20 per second from this client: the latest wins. Hold it
            # (merged with anything already held) and apply it shortly.
            held = self._pending_set.setdefault(client, {})
            held.update({k: v for k, v in change.items() if k != "zones"})
            if "zones" in change:
                zones = held.setdefault("zones", {})
                zones.update(change["zones"])
            self._set_times[client] = stamps
            if client not in self._pending_timer:
                delay = max(0.01, 1.0 - (now - stamps[0]))
                self._pending_timer[client] = self.loop.delay_callback(
                    delay, self._flush_pending, client)
            state = self.get_state()
            state["queued"] = True
            return state
        stamps.append(now)
        self._set_times[client] = stamps
        self._apply(change)
        self._changed()
        return self.get_state()

    def _flush_pending(self, client: str) -> None:
        self._pending_timer.pop(client, None)
        held = self._pending_set.pop(client, None)
        if held:
            stamps = self._set_times.setdefault(client, [])
            stamps.append(self.now())
            self._apply(held)
            self._changed()

    async def _handle_preset(self, web_request: WebRequest) -> Dict[str, Any]:
        if web_request.get_request_type() == RequestType.DELETE:
            pid = web_request.get_str("id")
            if pid in BUILTIN_PRESETS:
                raise bad("id", "a built-in preset cannot be deleted")
            if pid not in self.user_presets:
                raise ServerError(f"Preset '{pid}' not found", 404)
            del self.user_presets[pid]
            await self._store_presets()
            self._notify()
            return self.get_state()
        args = web_request.get_args()
        has_apply, has_save = "apply" in args, "save" in args
        for key in args:
            if key not in ("apply", "save"):
                raise bad(str(key), "is not a preset field")
        if has_apply == has_save:
            raise bad("body", 'send exactly one of "apply" or "save"')
        if has_apply:
            pid = args["apply"]
            preset = BUILTIN_PRESETS.get(pid) if isinstance(pid, str) else None
            if preset is None and isinstance(pid, str):
                preset = self.user_presets.get(pid)
            if preset is None:
                raise ServerError(f"Preset '{pid}' not found", 404)
            self._end_lease("preset")
            self.state.update(
                {"on": True, "preset": pid, "effect": preset["effect"],
                 "colors": list(preset["colors"]),
                 "brightness": preset["brightness"],
                 "speed": preset["speed"],
                 "zones": {s: (dict(preset["zones"][s])
                               if preset.get("zones", {}).get(s) else None)
                           for s in STRIPS}})
            self._changed()
            return self.get_state()
        spec = args["save"]
        if not isinstance(spec, dict):
            raise bad("save", "must be an object with a name")
        for key in spec:
            if key != "name":
                raise bad(f"save.{key}", "is not a field (only name)")
        if len(self.user_presets) >= MAX_PRESETS:
            raise bad("save", f"at most {MAX_PRESETS} user presets")
        s = self.state
        fresh = self._clean_preset({
            "name": spec.get("name"), "effect": s["effect"],
            "colors": s["colors"], "brightness": s["brightness"],
            "speed": s["speed"], "zones": {
                k: v for k, v in s["zones"].items() if v}})
        pid = "u_" + uuid.uuid4().hex[:4]
        while pid in self.user_presets:
            pid = "u_" + uuid.uuid4().hex[:4]
        self.user_presets[pid] = fresh
        self.state["preset"] = pid
        await self._store_presets()
        self._changed()
        return self.get_state()

    async def _store_presets(self) -> None:
        if self.db is not None:
            await self.db.insert("presets", dict(self.user_presets))

    # -- stream lease -------------------------------------------------------
    async def _handle_stream_start(
        self, web_request: WebRequest
    ) -> Dict[str, Any]:
        args = web_request.get_args()
        strips = args.get("strips", list(STRIPS))
        if (not isinstance(strips, list) or not strips
                or any(s not in STRIPS for s in strips)
                or len(set(strips)) != len(strips)):
            raise bad("strips", "must be a list of left and/or right")
        fps = args.get("fps", self.idle_fps)
        fps = check_number("fps", fps, 1, FRAMES_PER_SECOND)
        client = self._client_id(web_request)
        conn = web_request.get_client_connection()
        now = self.now()
        cur = self.lease
        if cur is not None and cur.client != client:
            if now - cur.last < LEASE_IDLE:
                raise ServerError(
                    f"The stream is held by {cur.client}", 409)
            self._end_lease("takeover")                    # it went idle
        elif cur is not None:
            self._end_lease("restart")
        out_fps = min(float(fps), self.idle_fps)
        self.lease = Lease(uuid.uuid4().hex[:12], client,
                           conn.uid if conn is not None else None,
                           [s for s in STRIPS if s in strips], out_fps, now)
        self._arm_lease_timer()
        self.blanked = False
        self._changed(persist=False)
        return {"lease": self.lease.id, "fps_out": out_fps,
                "expires_in": LEASE_IDLE}

    async def _handle_stream_stop(
        self, web_request: WebRequest
    ) -> Dict[str, Any]:
        lease_id = web_request.get_str("lease")
        cur = self.lease
        if cur is None:
            return {"stopped": False}
        if cur.id != lease_id:
            raise ServerError("That is not the active lease", 409)
        self._end_lease("stop")
        self._changed(persist=False)
        return {"stopped": True}

    def _end_lease(self, why: str) -> None:
        if self.lease is None:
            return
        logging.debug("muon_lights: lease %s ended: %s", self.lease.id, why)
        self.lease = None
        self.last_sent = {s: None for s in STRIPS}
        self._dirty = True

    def _on_client_removed(self, connection: Any) -> None:
        cur = self.lease
        if cur is not None and cur.conn == getattr(connection, "uid", None):
            self._end_lease("disconnect")
            self._changed(persist=False)

    def _arm_lease_timer(self) -> None:
        if self._lease_timer is None and self.lease is not None:
            wait = max(0.05, self.lease.last + LEASE_IDLE - self.now())
            self._lease_timer = self.loop.delay_callback(
                wait, self._check_lease)

    def _check_lease(self) -> None:
        self._lease_timer = None
        cur = self.lease
        if cur is None:
            return
        if self.now() - cur.last >= LEASE_IDLE - 1e-9:
            self._end_lease("idle")
            self._changed(persist=False)
        else:
            self._arm_lease_timer()

    async def _handle_frame(self, web_request: WebRequest) -> Dict[str, Any]:
        args = web_request.get_args()
        for key in args:
            if key not in ("lease", "seq", "strip", "start", "rgb", "raw"):
                raise bad(str(key), "is not a frame field")
        lease_id = args.get("lease")
        cur = self.lease
        if cur is None or lease_id != cur.id:
            raise ServerError("No such lease (it may have expired)", 409)
        client = self._client_id(web_request)
        if client != cur.client:
            raise ServerError("The lease belongs to another client", 409)
        seq = args.get("seq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise bad("seq", "must be a non-negative integer")
        strip = args.get("strip")
        if strip not in ("left", "right", "both"):
            raise bad("strip", "must be left, right or both")
        start = args.get("start", 0)
        if isinstance(start, bool) or not isinstance(start, int) or start < 0:
            raise bad("start", "must be a non-negative integer")
        raw = args.get("raw", False)
        if not isinstance(raw, bool):
            raise bad("raw", "must be true or false")
        try:
            data = base64.b64decode(args.get("rgb", ""), validate=True)
        except (binascii.Error, ValueError, TypeError):
            raise bad("rgb", "must be base64") from None
        status = self._take_frame(cur, strip, start, seq, data, raw)
        return {"ok": status == "ok", "status": status}

    def handle_binary(self, conn_uid: int, message: bytes) -> None:
        """Binary websocket frame: [0x4C][u8 strip][u16 start][u32 seq][RGB]."""
        cur = self.lease
        if cur is None or cur.conn is None or cur.conn != conn_uid:
            self.stream_rejected += 1          # no lease on this connection
            return
        if len(message) < 8 or message[0] != MAGIC:
            self.stream_rejected += 1
            return
        _, strip_id, start, seq = struct.unpack(">BBHI", message[:8])
        if strip_id > 2:
            self.stream_rejected += 1
            return
        strip = ("left", "right", "both")[strip_id]
        self._take_frame(cur, strip, start, seq, bytes(message[8:]), False)

    def _take_frame(self, cur: Lease, strip: str, start: int, seq: int,
                    data: bytes, raw: bool) -> str:
        """The hot path: validate, rate limit, store. No rendering here."""
        count, rem = divmod(len(data), 3)
        if rem or count == 0:
            raise bad("rgb", "must be 3 bytes per LED")
        targets = list(cur.strips) if strip == "both" else [strip]
        if strip != "both" and strip not in cur.strips:
            raise bad("strip", "is not part of the lease")
        if strip == "both" and cur.strips != list(STRIPS):
            raise bad("strip", "both needs a lease on both strips")
        limit = (self.leds["left"] + self.leds["right"]
                 if strip == "both" else self.leds[strip])
        if count > (80 if strip == "both" else 40) or start + count > limit:
            raise bad("rgb", f"at most {limit} LEDs from index {start}")
        now = self.now()
        cur.last = now
        if seq <= cur.seq:
            self.stream_seq_dropped += 1
            return "seq"
        cur.tokens = {s: min(float(FRAME_BURST),
                             t + (now - cur.token_time) * FRAMES_PER_SECOND)
                      for s, t in cur.tokens.items()}
        cur.token_time = now
        if any(cur.tokens[s] < 1. for s in targets):
            self.stream_dropped += 1                 # coalesced: latest wins
            return "rate"
        for s in targets:
            cur.tokens[s] -= 1.
        cur.seq = seq
        nleft = self.leds["left"]
        for i in range(count):
            rgb = (data[3 * i] / 255., data[3 * i + 1] / 255.,
                   data[3 * i + 2] / 255.)
            pos = start + i
            if strip == "both":
                target, index = (("left", pos) if pos < nleft
                                 else ("right", pos - nleft))
            else:
                target, index = strip, pos
            buf = cur.buffers.get(target)
            if buf is not None and index < len(buf):
                buf[index] = rgb
        for s in targets:
            cur.raw[s] = raw
        self._dirty = True
        self._kick()
        return "ok"

    # -- composing a frame ----------------------------------------------------
    def _look(self, strip: str) -> Dict[str, Any]:
        look = {k: self.state[k] for k in ZONE_FIELDS}
        zone = self.state["zones"].get(strip)
        if zone:
            look.update(zone)
        return look

    def _bytes(self, pixels: List[Rgb], brightness: float,
               apply_gamma: bool) -> bytes:
        """Brightness, gamma, then the safety cap on the wire values."""
        out = bytearray()
        k = brightness / 100.
        lut = self.gamma_lut
        cap = self.cap_byte
        for r, g, b in pixels:
            vals = [lut[min(255, max(0, round(c * k * 255.)))]
                    if apply_gamma else
                    min(255, max(0, round(c * k * 255.)))
                    for c in (r, g, b)]
            top = max(vals)
            if top > cap:
                vals = [v * cap // top for v in vals]
            out += bytes(vals)
        return bytes(out)

    def compose(self, now: float) -> Optional[Dict[str, bytes]]:
        """Both strips' finished bytes, or None when the printer's own state
        lights (effect 'status') and this component stays out of it."""
        lease = self.lease
        out: Dict[str, bytes] = {}
        user_off = (not self.state["on"]) or self.blanked
        for strip in STRIPS:
            n = self.leds[strip]
            if lease is not None and strip in lease.strips:
                buf = lease.buffers[strip][:n]
                out[strip] = self._bytes(buf, 100., not lease.raw[strip])
                continue
            look = self._look(strip)
            if user_off or look["effect"] == "off":
                out[strip] = bytes(3 * n)
                continue
            if look["effect"] == "status":
                continue                  # the printer's own look
            pixels = render(look["effect"], look["colors"], look["speed"],
                            now, n, self.progress)
            out[strip] = self._bytes(pixels, look["brightness"], True)
        return out or None

    def _animated(self) -> bool:
        if self.lease is not None:
            return False                     # frames drive it, via _kick
        if not self.state["on"] or self.blanked:
            return False
        return any(self._look(s)["effect"] in ANIMATED
                   or self._look(s)["effect"] == "progress" and self.printing
                   for s in STRIPS)

    # -- the budget -----------------------------------------------------------
    def _nominal_fps(self) -> float:
        fps = self.print_fps if self.printing else self.idle_fps
        if self.lease is not None:
            fps = min(fps, self.lease.fps)
        return fps

    def _budget(self, now: float) -> float:
        if not self.klippy_ready or not self.output["available"]:
            return 0.
        if now < self.stress_until:
            return 0.
        if self.out_status.get("blocked") is not None:
            return 0.          # klippy said homing, a fault or the print
        return self._nominal_fps()

    # -- the pump ---------------------------------------------------------------
    def _interval(self, now: float) -> float:
        fps = self._budget(now)
        return 1. / fps if fps > 0 else BLOCKED_RETRY

    def _earliest(self, now: float) -> float:
        """The first moment the budget allows another transmit. Spacing of
        1/fps AND at most int(fps) transmits in any one second, so the cap
        holds for every window, not only on average."""
        fps = self._budget(now)
        if fps <= 0.:
            return now + BLOCKED_RETRY
        at = self.last_tx + 1. / fps
        cap = max(1, int(fps))
        while self._tx_times and now - self._tx_times[0] >= 1.0:
            self._tx_times.popleft()
        if len(self._tx_times) >= cap:
            at = max(at, self._tx_times[0] + 1.0)
        if self.blocked_reason is not None:
            at = max(at, self.last_tx + BLOCKED_RETRY)
        return at

    def _arm(self, wait: float) -> None:
        """One pump timer; an earlier request replaces a later one."""
        due = self.now() + wait
        if self._timer is not None:
            if self._timer_due <= due + 1e-3:
                return
            self._timer.cancel()
        self._timer_due = due
        self._timer = self.loop.delay_callback(wait, self._timer_fired)

    def _kick(self) -> None:
        if not self.enabled or self._in_step:
            return
        now = self.now()
        self._arm(max(0., self._earliest(now) - now) + 1e-6)

    def _timer_fired(self) -> None:
        self._timer = None
        self.loop.register_callback(self._pump)

    async def _pump(self) -> None:
        self._in_step = True
        try:
            await self.step(self.now())
        except Exception:
            logging.exception("muon_lights: step failed")
        finally:
            self._in_step = False
        if self._animated() or self._dirty or self.blocked_reason is not None:
            now = self.now()
            wait = self._earliest(now) - now
            if wait <= 0.:
                wait = self._interval(now)     # nothing went out: never spin
            self._arm(wait + 1e-6)

    async def step(self, now: float) -> bool:
        """One output decision. Returns True when a frame was transmitted."""
        fps = self._budget(now)
        if fps <= 0.:
            return False                       # held: homing, stress, off
        if now < self._earliest(now):
            return False
        frames = self.compose(now)
        if frames is None:
            self.blocked_reason = self.out_status.get("blocked")
            await self._release()
            self._dirty = False
            return False
        changed = {s: b for s, b in frames.items()
                   if b != self.last_sent.get(s)}
        if not changed:
            self.stats["unchanged_skipped"] += 1
            self._dirty = False
            return False
        self._dirty = False
        self.last_tx = now
        self._tx_times.append(now)
        self.owning = True
        self.tx_since_stats += 1
        self.stats["sends"] += 1
        self.stats["frames_out"] += 1
        params = {s: base64.b64encode(b).decode() for s, b in changed.items()}
        try:
            reply = await self.send(params)
        except ServerError as e:
            logging.info("muon_lights: send failed: %s", e)
            reply = {"ok": False, "reason": "failed"}
        if reply.get("ok"):
            self.last_sent.update(changed)
            if self.blocked_reason is not None:
                self.blocked_reason = None
                self._notify()
            return True
        reason = reply.get("reason", "failed")
        self.stats["dropped_by_klippy"] += 1
        if reason == "failed":
            self.stats["failed"] += 1
        for s in changed:                 # not applied: send it again
            self.last_sent[s] = None
        self._dirty = True
        new = reason if reason in ("fault", "print", "busy") else None
        if new != self.blocked_reason:
            self.blocked_reason = new
            self._notify()
        return False

    async def _release(self) -> None:
        """Effect 'status': hand the strips back to the printer's state."""
        if not self.owning:
            return
        self.owning = False
        self.last_sent = {s: None for s in STRIPS}
        if self.printing:
            return
        apis = self.server.lookup_component("klippy_apis", None)
        if apis is not None and self.klippy_ready:
            await apis.run_gcode("LED_READY", None)

    async def _klippy_send(self, params: Dict[str, Any]) -> Dict[str, Any]:
        apis = self.server.lookup_component("klippy_apis")
        result = await apis._send_klippy_request(
            "muon_lights_out/frame", params)
        return result if isinstance(result, dict) else {"ok": False}

    # -- klippy state -----------------------------------------------------------
    async def _on_klippy_ready(self) -> None:
        apis = self.server.lookup_component("klippy_apis")
        try:
            listing = await apis.get_object_list()
            wanted: Dict[str, Optional[List[str]]] = {
                "print_stats": ["state"], "virtual_sdcard": ["progress"],
                "mcu": ["last_stats"], "muon_lights_out": None,
                "gcode_macro LED_MODE": None}
            objects = {k: v for k, v in wanted.items() if k in listing}
            status = await apis.subscribe_objects(
                objects, self.on_status_update, {})
            saved = await apis.query_objects(
                {"save_variables": ["variables"]}, {})
        except ServerError as e:
            logging.info("muon_lights: klippy setup failed: %s", e)
            return
        self.klippy_ready = True
        self.ready_at = self.now()
        self._restore((saved.get("save_variables") or {})
                      .get("variables", {}).get(SAVE_KEY))
        self.on_status_update(status, self.ready_at, adopt=False)
        self._dirty = True
        if self._persist_dirty:
            self._arm_persist()
        self._kick()

    def _on_klippy_down(self, *args: Any) -> None:
        self.klippy_ready = False
        self.output["available"] = False
        self.last_sent = {s: None for s in STRIPS}
        self.owning = False

    def _restore(self, saved: Any) -> None:
        if not isinstance(saved, dict):
            return
        try:
            change = validate_set({k: v for k, v in saved.items()
                                   if k in SET_FIELDS})
        except ServerError:
            logging.warning("muon_lights: saved state is invalid; ignored")
            return
        self._apply(change)
        preset = saved.get("preset")
        if isinstance(preset, str) and (preset in BUILTIN_PRESETS
                                        or preset in self.user_presets):
            self.state["preset"] = preset

    def on_status_update(self, status: Dict[str, Any], eventtime: float,
                         adopt: bool = True) -> None:
        now = self.now()
        ps = status.get("print_stats")
        if isinstance(ps, dict) and "state" in ps:
            was = self.printing
            self.printing = ps["state"] in ("printing", "paused")
            if was != self.printing:
                self._dirty = True
        vs = status.get("virtual_sdcard")
        if isinstance(vs, dict) and "progress" in vs:
            self.progress = float(vs["progress"] or 0.)
        mcu = status.get("mcu")
        if isinstance(mcu, dict):
            stats = mcu.get("last_stats")
            if isinstance(stats, dict) and "bytes_retransmit" in stats:
                self._on_retransmit(int(stats["bytes_retransmit"]), now)
        out = status.get("muon_lights_out")
        if isinstance(out, dict):
            # Subscriptions send only what changed: keep the whole.
            self.out_status.update(out)
            self._on_output_status(self.out_status, now)
        macro = status.get("gcode_macro LED_MODE")
        if isinstance(macro, dict):
            self.led_macro.update(macro)
            self._on_led_mode(self.led_macro, now, adopt)
        self._kick()

    def _on_retransmit(self, value: int, now: float) -> None:
        prev, self.last_retransmit = self.last_retransmit, value
        sent, self.tx_since_stats = self.tx_since_stats, 0
        # Back off only when the count rose AND we were transmitting, so a
        # lights-off baseline of retransmits never throttles anything.
        if prev is not None and value > prev and sent > 0:
            self.stress_until = now + self.backoff_seconds
            logging.info("muon_lights: mcu retransmits rising; output held "
                         "for %.0f s", self.backoff_seconds)

    def _on_output_status(self, out: Dict[str, Any], now: float) -> None:
        was = self.output["available"]
        self.output["available"] = bool(out.get("enabled"))
        blocked = out.get("blocked")
        if blocked != self.blocked_reason and blocked in (
                None, "fault", "print", "busy"):
            if blocked is None and self.blocked_reason is not None:
                self.last_sent = {s: None for s in STRIPS}
                self._dirty = True
            self.blocked_reason = blocked
            self._notify()
        stop = out.get("stop_count")
        if isinstance(stop, int):
            if (self.stop_count is not None and stop > self.stop_count
                    and self.owning):
                self.blanked = True            # LED timeout / STOP_LED_EFFECTS
                self._dirty = True
            self.stop_count = stop
        idle_on = bool(out.get("idle_effect_on"))
        if idle_on and not self.idle_effect_on:
            # LED_READY or LED_MODE re-lit klippy's own look: take it back.
            self.blanked = False
            self.last_sent = {s: None for s in STRIPS}
            self._dirty = True
        self.idle_effect_on = idle_on
        if was != self.output["available"]:
            self._dirty = True

    # -- the LED_MODE shim --------------------------------------------------------
    def _on_led_mode(self, macro: Dict[str, Any], now: float,
                     adopt: bool = True) -> None:
        """Adopt a change of the LED_MODE macro's variables as the user
        state. The macro is untouched, so every old caller keeps working;
        what changes is who draws it. Ignored for SETTLE_AFTER_READY after
        klippy starts: the macro's own boot restore (_LED_MODE_RESTORE, which
        reads the older muon_led value) must not overwrite what was saved
        here."""
        key = tuple(macro.get(k, 0) for k in ("mode", "h", "h2", "bright",
                                              "speed"))
        if self.led_mode_seen is None:
            self.led_mode_seen = key
            return
        if key == self.led_mode_seen:
            return
        self.led_mode_seen = key
        if not adopt or now - self.ready_at < SETTLE_AFTER_READY:
            return
        mode, h, h2, bright, speed = key
        try:
            if mode not in EFFECTS:
                return
            colors = [hue_to_hex(float(h)), hue_to_hex(float(h2))]
            change = validate_set({
                "effect": mode if mode != "off" else self.state["effect"],
                "colors": colors,
                "brightness": min(100., max(0., float(bright))),
                "speed": min(100., max(0., float(speed))),
                "on": mode != "off"})
        except (ServerError, TypeError, ValueError):
            return
        self._end_lease("led_mode")
        self._apply(change)
        self._changed()

    # -- persistence and notifications -------------------------------------------
    def _arm_persist(self) -> None:
        if self._persist_timer is not None or not self.klippy_ready:
            return
        wait = max(0., self._last_persist + PERSIST_INTERVAL - self.now())
        self._persist_timer = self.loop.delay_callback(
            wait, self._persist_fired)

    def _persist_fired(self) -> None:
        self._persist_timer = None
        self.loop.register_callback(self._persist)

    async def _persist(self) -> None:
        if not self._persist_dirty:
            return
        if self.printing:
            # Writing the variables file runs on klippy. Wait for the print.
            self._persist_timer = self.loop.delay_callback(
                PERSIST_INTERVAL, self._persist_fired)
            return
        self._persist_dirty = False
        self._last_persist = self.now()
        value = json.dumps({k: self.state[k] for k in
                            ("on", "preset", "effect", "colors",
                             "brightness", "speed", "zones")},
                           separators=(",", ":"))
        apis = self.server.lookup_component("klippy_apis", None)
        if apis is None:
            return
        await apis.run_gcode(
            f"SAVE_VARIABLE VARIABLE={SAVE_KEY} VALUE='{value}'", None)

    def _notify(self) -> None:
        self._notify_due = True
        if self._notify_timer is not None:
            return
        wait = max(0., self._last_notify + NOTIFY_INTERVAL - self.now())
        self._notify_timer = self.loop.delay_callback(wait, self._notify_now)

    def _notify_now(self) -> None:
        self._notify_timer = None
        if not self._notify_due:
            return
        self._notify_due = False
        self._last_notify = self.now()
        self.server.send_event("muon_lights:update", self.get_state())

    def close(self) -> None:
        for timer in (self._timer, self._lease_timer, self._persist_timer,
                      self._notify_timer):
            if timer is not None:
                timer.cancel()


def load_component(config: ConfigHelper) -> MuonLights:
    return MuonLights(config)
