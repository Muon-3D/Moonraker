"""B9-MR-1: the MUTP toolpath, its reader, and GET /server/muon/toolpath.

The three sample files are in tests/assets/muon_toolpath (see its README):
a real M1 OrcaSlicer slice, trimmed, and two written in PrusaSlicer's and
Cura's conventions. `*.app.json` beside each is the app's own parser's output
on it, so the parity test compares against that program, not against this
reader's idea of it.
"""
from __future__ import annotations

import asyncio
import io
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from moonraker import muon_toolpath_format as fmt
from moonraker.common import RequestType, TransportType, WebRequest
from moonraker.components import muon_toolpath as component
from moonraker.components.gcode_preprocessor import (
    MARKER_RE,
    GCodePreprocessorComponent,
)
from moonraker.utils.exceptions import ServerError

ASSETS = Path(__file__).resolve().parent / "assets" / "muon_toolpath"
SAMPLES = ("orcaslicer", "prusaslicer", "cura")


def raw(name: str) -> bytes:
    return (ASSETS / f"{name}.gcode").read_bytes()


def toolpath(gcode: bytes, **kw: Any) -> Dict[str, Any]:
    return fmt.decode(fmt.build(io.BytesIO(gcode), **kw))


def line_ending_at(data: bytes, end: int) -> bytes:
    """The line whose newline is the byte before `end`."""
    assert data[end - 1:end] == b"\n", f"offset {end} is not a line end"
    start = data.rfind(b"\n", 0, end - 1) + 1
    return data[start:end]


# -- the format, on the three sample files -------------------------------------

#: z and height of each layer, read off the files by hand. Layer 0 is the start
#: G-code's purge, before the first layer comment.
LAYERS = {
    "orcaslicer": [(0.15, 0.15), (0.2, 0.2), (0.4, 0.2), (0.6, 0.2)],
    "prusaslicer": [(0.2, 0.2), (0.2, 0.2), (0.4, 0.2), (0.6, 0.2)],
    # Cura writes no ;Z: or ;HEIGHT:, so both come from the moves; the first
    # layer shares the purge's Z and still measures 0.3 from the bed.
    "cura": [(0.3, 0.3), (0.3, 0.3), (0.5, 0.2), (0.7, 0.2)],
}

#: The types each layer must contain, besides travel.
LAYER_TYPES = {
    "orcaslicer": [
        {fmt.PURGE},
        {fmt.PURGE, fmt.OUTER_WALL, fmt.INNER_WALL, fmt.INFILL},
        {fmt.OUTER_WALL, fmt.INNER_WALL, fmt.INFILL},
        {fmt.OUTER_WALL, fmt.INNER_WALL, fmt.INFILL},
    ],
    "prusaslicer": [
        {fmt.PURGE},
        {fmt.PURGE, fmt.OUTER_WALL, fmt.INNER_WALL, fmt.INFILL},
        {fmt.OUTER_WALL, fmt.INNER_WALL, fmt.INFILL, fmt.SUPPORT,
         fmt.SUPPORT_INTERFACE},
        {fmt.OUTER_WALL, fmt.INFILL},
    ],
    "cura": [
        {fmt.PURGE},
        {fmt.PURGE, fmt.OUTER_WALL, fmt.INNER_WALL, fmt.INFILL},
        {fmt.OUTER_WALL, fmt.INNER_WALL, fmt.INFILL, fmt.SUPPORT,
         fmt.SUPPORT_INTERFACE},
        {fmt.OUTER_WALL, fmt.INFILL},
    ],
}


@pytest.mark.parametrize("name", SAMPLES)
def test_header_says_what_the_file_is(name: str) -> None:
    data = fmt.build(io.BytesIO(raw(name)))
    assert data[:4] == b"MUTP"
    assert int.from_bytes(data[4:6], "little") == 1
    path = fmt.decode(data)
    assert path["flags"] == 0
    assert path["scale"] == pytest.approx(0.01)
    for s in path["segments"]:
        assert path["min"][0] - 1e-4 <= s["x"] <= path["max"][0] + 1e-4
        assert path["min"][1] - 1e-4 <= s["y"] <= path["max"][1] + 1e-4
        assert path["min"][2] <= s["z"] <= path["max"][2]
    # Well under the G-code: the plan budgets about an eighth on real files,
    # and these samples are short lines.
    assert len(data) * 3 < len(raw(name))


@pytest.mark.parametrize("name", SAMPLES)
def test_layers_carry_z_and_height(name: str) -> None:
    layers = toolpath(raw(name))["layers"]
    got = [(round(layer["z"], 4), round(layer["height"], 4)) for layer in layers]
    assert got == LAYERS[name]


@pytest.mark.parametrize("name", SAMPLES)
def test_each_layer_has_the_slicers_feature_types(name: str) -> None:
    path = toolpath(raw(name))
    for index, expected in enumerate(LAYER_TYPES[name]):
        kinds = {
            s["type"] for s in path["segments"]
            if s["layer"] == index and s["type"] != fmt.TRAVEL
        }
        assert kinds == expected, f"layer {index}"


def test_widths_come_from_width_comments() -> None:
    path = toolpath(raw("prusaslicer"))
    by_type: Dict[int, set] = {}
    for s in path["segments"]:
        by_type.setdefault(s["type"], set()).add(round(s["width"], 2))
    # ;WIDTH:0.5 skirt, 0.45 walls, 0.35 support, 0.4 top infill; travel 0.
    assert by_type[fmt.TRAVEL] == {0.0}
    assert by_type[fmt.OUTER_WALL] == {0.45}
    assert by_type[fmt.INNER_WALL] == {0.45}
    assert by_type[fmt.SUPPORT] == {0.35}
    assert by_type[fmt.SUPPORT_INTERFACE] == {0.35}
    assert by_type[fmt.INFILL] == {0.5, 0.45, 0.4}
    # Cura writes none, so every width is 0 ("not given").
    assert {s["width"] for s in toolpath(raw("cura"))["segments"]} == {0.0}
    # The real Orca slice: first layer 0.48/0.49, then its walls and infill.
    orca = {round(s["width"], 2) for s in toolpath(raw("orcaslicer"))["segments"]}
    assert orca == {0.0, 0.4, 0.44, 0.48, 0.49}


@pytest.mark.parametrize("name", SAMPLES)
def test_offsets_are_the_byte_after_each_moves_line(name: str) -> None:
    data = raw(name)
    path = toolpath(data)
    ends = [s["end"] for s in path["segments"]]
    assert ends == sorted(ends)
    for s in path["segments"]:
        line = line_ending_at(data, s["end"]).split(b";")[0].split()
        assert line[0] in (b"G0", b"G1"), line
    first = 0
    for layer in path["layers"]:
        seg = path["segments"][first]
        # The layer's offset is where its first segment's line starts.
        assert data[layer["offset"] - 1:layer["offset"]] == b"\n"
        assert line_ending_at(data, seg["end"]) == data[layer["offset"]:seg["end"]]
        first += layer["count"]
    assert first == len(path["segments"])


@pytest.mark.parametrize("name", SAMPLES)
def test_the_apps_parser_draws_the_same_part(name: str) -> None:
    """The app's segments are this file's non-travel segments, one for one:
    the same end points, the same file offsets, at the layer's z."""
    app = json.loads((ASSETS / f"{name}.app.json").read_text())
    ours = [s for s in toolpath(raw(name))["segments"] if s["type"] != fmt.TRAVEL]
    assert len(ours) == app["count"] == len(app["segments"])
    for i, (s, (x, y, z, end)) in enumerate(zip(ours, app["segments"])):
        assert s["end"] == end, i
        assert s["x"] == pytest.approx(x, abs=0.006), i
        assert s["y"] == pytest.approx(y, abs=0.006), i
        assert s["z"] == pytest.approx(z, abs=1e-4), i


# -- the reader, on small cases -------------------------------------------------

def kinds(gcode: str) -> List[int]:
    return [s["type"] for s in toolpath(gcode.encode())["segments"]]


def test_e_is_relative_under_m83_even_after_g90_as_in_klipper() -> None:
    # The app's parser resets E to absolute on G90; Klipper does not, so the
    # second move extrudes on the printer and is drawn as plastic here.
    assert kinds("M83\nG90\nG1 X10 E1\nG1 X20 E1\n") == [fmt.OTHER, fmt.OTHER]
    assert kinds("M82\nG90\nG1 X10 E1\nG1 X20 E1\n") == [fmt.OTHER, fmt.TRAVEL]


def test_g92_resets_e_and_offsets_axes() -> None:
    assert kinds("M82\nG1 X10 E5\nG92 E0\nG1 X20 E1\n") == [fmt.OTHER, fmt.OTHER]
    path = toolpath(b"G1 X50 Y5\nG92 X0\nG1 X10\n")
    assert [round(s["x"], 2) for s in path["segments"]] == [50.0, 60.0]


def test_a_retracting_wipe_and_a_plain_move_are_travel() -> None:
    assert kinds("M83\nG1 X10 E1\nG1 X12 E-0.5\nG1 X20\nG1 E1\nG1 Z1\n") == [
        fmt.OTHER, fmt.TRAVEL, fmt.TRAVEL,
    ]


def test_without_layer_comments_a_layer_starts_where_extrusion_changes_z() -> None:
    path = toolpath(
        b"M83\nG1 Z0.2\nG1 X10 E1\n"
        b"G1 Z0.6\nG1 X0 Y5\nG1 Z0.2\nG1 X10 Y5 E1\n"   # a hop: same layer
        b"G1 Z0.4\nG1 X0 E1\n"                           # a new layer
    )
    assert [(round(layer["z"], 3), layer["count"]) for layer in path["layers"]] == [
        (0.2, 3), (0.4, 1),
    ]


def test_a_layer_comment_holds_through_z_changes() -> None:
    # Vase mode: Z rises on every move, and the slicer's comments still decide.
    path = toolpath(
        b";LAYER_CHANGE\n;Z:0.2\nM83\nG1 X1 Z0.21 E1\nG1 X2 Z0.22 E1\n"
        b";LAYER_CHANGE\n;Z:0.4\n;HEIGHT:0.2\nG1 X3 Z0.41 E1\n"
    )
    assert [(round(layer["z"], 3), layer["count"]) for layer in path["layers"]] == [
        (0.2, 2), (0.4, 1),
    ]


def test_cura_layers_take_z_from_their_first_extrusion() -> None:
    path = toolpath(
        b"M82\n;LAYER:0\nG0 X5 Y5 Z0.3\n;TYPE:WALL-OUTER\nG1 X10 E1\n"
        b";LAYER:1\nG0 X5 Y5 Z0.5\nG1 X10 E2\n;LAYER:2\n"
    )
    assert [round(layer["z"], 3) for layer in path["layers"]] == [0.3, 0.5]
    assert kinds("M82\n;LAYER:0\nG0 X5 Z0.3\n;TYPE:WALL-OUTER\nG1 X10 E1\n") == [
        fmt.TRAVEL, fmt.OUTER_WALL,
    ]


def test_type_names_of_all_three_slicers() -> None:
    for name, kind in (
        ("Outer wall", fmt.OUTER_WALL), ("External perimeter", fmt.OUTER_WALL),
        ("WALL-OUTER", fmt.OUTER_WALL), ("Inner wall", fmt.INNER_WALL),
        ("Perimeter", fmt.INNER_WALL), ("WALL-INNER", fmt.INNER_WALL),
        ("Sparse infill", fmt.INFILL), ("Internal infill", fmt.INFILL),
        ("FILL", fmt.INFILL), ("SKIN", fmt.INFILL),
        ("Support", fmt.SUPPORT), ("Support material", fmt.SUPPORT),
        ("SUPPORT", fmt.SUPPORT), ("Support interface", fmt.SUPPORT_INTERFACE),
        ("Support material interface", fmt.SUPPORT_INTERFACE),
        ("SUPPORT-INTERFACE", fmt.SUPPORT_INTERFACE),
        ("Skirt", fmt.PURGE), ("Skirt/Brim", fmt.PURGE), ("SKIRT", fmt.PURGE),
        ("Custom", fmt.PURGE), ("Wipe tower", fmt.PURGE),
        ("Something new", fmt.OTHER),
    ):
        assert fmt.feature_type(name) == kind, name
    # Orca's Bambu-style tags are read like the Prusa-style ones.
    path = toolpath(
        b"; CHANGE_LAYER\n; Z_HEIGHT: 0.2\n; LAYER_HEIGHT: 0.2\n"
        b"; FEATURE: Outer wall\n; LINE_WIDTH: 0.42\nM83\nG1 X5 E1\n"
    )
    (s,) = path["segments"]
    assert (s["type"], round(s["width"], 2), round(s["z"], 2)) == (
        fmt.OUTER_WALL, 0.42, 0.2,
    )


def test_arcs_are_followed_as_chords_ending_on_the_arcs_line() -> None:
    gcode = b"M83\nG1 X10 Y0\nG3 X0 Y10 I-10 J0 E5\n"
    path = toolpath(gcode)
    arc = path["segments"][1:]
    # A quarter circle of radius 10 is 15.7 mm: 16 chords of at most 1 mm.
    assert len(arc) == 16
    assert {s["end"] for s in arc} == {len(gcode)}
    assert {s["type"] for s in arc} == {fmt.OTHER}
    for s in arc:
        assert (s["x"] ** 2 + s["y"] ** 2) ** 0.5 == pytest.approx(10, abs=0.01)
    assert (round(arc[-1]["x"], 2), round(arc[-1]["y"], 2)) == (0.0, 10.0)
    # Clockwise from the same start is the other three quarters.
    assert len(toolpath(b"M83\nG1 X10 Y0\nG2 X0 Y10 I-10 J0 E5\n")["segments"]) == 49


def test_crlf_offsets_count_both_bytes() -> None:
    gcode = b"M83\r\nG1 X10 E1\r\nG1 X20 E1\r\n"
    assert [s["end"] for s in toolpath(gcode)["segments"]] == [16, 27]


def test_a_wide_part_widens_the_scale() -> None:
    path = toolpath(b"M83\nG1 X1 Y1\nG1 X0 Y0\nG1 X500 E1\n")
    assert path["scale"] > 500 / 32767 - 1e-9
    assert path["segments"][-1]["x"] == pytest.approx(500, abs=path["scale"])


def test_too_many_moves_are_cut_off_and_flagged() -> None:
    path = toolpath(b"G1 X1\nG1 X2\nG1 X3\nG1 X4\n", max_segments=3)
    assert path["flags"] & fmt.FLAG_TRUNCATED
    assert len(path["segments"]) == 3


def test_an_empty_file_is_a_valid_toolpath() -> None:
    path = toolpath(b"; nothing\nM104 S0\n")
    assert path["layers"] == [] and path["segments"] == []


def test_decode_refuses_what_is_not_mutp() -> None:
    with pytest.raises(ValueError):
        fmt.decode(b"GCODE" + bytes(60))
    good = fmt.build(io.BytesIO(raw("cura")))
    with pytest.raises(ValueError):
        fmt.decode(good[:-1])


def test_the_reader_runs_as_its_own_process(tmp_path: Path) -> None:
    out = tmp_path / "x.mutp"
    import subprocess
    with open(ASSETS / "cura.gcode", "rb") as source:
        subprocess.run(
            [sys.executable, "-I", component.FORMAT_SCRIPT, str(out)],
            stdin=source, check=True, timeout=60,
        )
    assert out.read_bytes() == fmt.build(io.BytesIO(raw("cura")))
    assert os.listdir(tmp_path) == ["x.mutp"]


# -- the component ----------------------------------------------------------------

class _EventLoop:
    def run_in_thread(self, callback: Any, *args: Any) -> Any:
        return asyncio.get_running_loop().run_in_executor(None, callback, *args)


class _FileManager:
    def __init__(self, root: str) -> None:
        self.root = root

    def get_directory(self, name: str) -> str:
        return self.root if name == "gcodes" else ""


class _Server:
    def __init__(self, data_path: str, gcodes: str) -> None:
        self.data_path = data_path
        self.components: Dict[str, Any] = {"file_manager": _FileManager(gcodes)}
        self.endpoints: Dict[str, Dict[str, Any]] = {}

    def register_endpoint(self, path: str, request_types: Any, callback: Any,
                          **kwargs: Any) -> None:
        self.endpoints[path] = dict(kwargs, request_types=request_types,
                                    callback=callback)

    def lookup_component(self, name: str, default: Any = None) -> Any:
        return self.components.get(name, default)

    def get_event_loop(self) -> _EventLoop:
        return _EventLoop()

    def get_app_args(self) -> Dict[str, Any]:
        return {"data_path": self.data_path}

    def error(self, message: str, status: int = 400) -> ServerError:
        return ServerError(message, status)


class _Config:
    def __init__(self, server: _Server, values: Dict[str, Any]) -> None:
        self.server = server
        self.values = values

    def get_server(self) -> _Server:
        return self.server

    def get(self, name: str, default: Any = None) -> Any:
        return self.values.get(name, default)

    def getfloat(self, name: str, default: float) -> float:
        return float(self.values.get(name, default))


@pytest.fixture
def printer(tmp_path: Path):
    gcodes = tmp_path / "gcodes"
    gcodes.mkdir()
    data = tmp_path / "data"
    data.mkdir()

    def make(**values: Any) -> component.MuonToolpath:
        server = _Server(str(data), str(gcodes))
        values.setdefault("request_wait", 60)
        tp = component.MuonToolpath(_Config(server, values))  # type: ignore
        server.components["muon_toolpath"] = tp
        return tp

    make.gcodes = gcodes  # type: ignore[attr-defined]
    make.cache = data / "muon_toolpath"  # type: ignore[attr-defined]
    return make


async def get(tp: component.MuonToolpath, filename: Optional[str]) -> bytes:
    args = {} if filename is None else {"filename": filename}
    return await tp._handle_toolpath(
        WebRequest(component.ENDPOINT, args, RequestType.GET))


async def settle(tp: component.MuonToolpath) -> None:
    while tp._builds:
        await asyncio.gather(*tp._builds.values(), return_exceptions=True)


def status_of(coro: Any) -> int:
    with pytest.raises(ServerError) as err:
        asyncio.run(coro)
    return err.value.status_code


def test_the_route_is_an_http_get_answering_octet_stream(printer: Any) -> None:
    tp = printer()
    ep = tp.server.endpoints[component.ENDPOINT]
    assert ep["request_types"] == RequestType.GET
    assert ep["transports"] == TransportType.HTTP
    assert ep["wrap_result"] is False
    assert ep["content_type"] == "application/octet-stream"


def test_bad_requests(printer: Any) -> None:
    tp = printer()
    (printer.gcodes / "notes.txt").write_text("hi")
    assert status_of(get(tp, None)) == 400
    assert status_of(get(tp, "../data/x.gcode")) == 400
    assert status_of(get(tp, "notes.txt")) == 400
    assert status_of(get(tp, "missing.gcode")) == 404
    assert status_of(get(tp, "sub/missing.gcode")) == 404


def test_first_request_makes_the_toolpath_and_answers_it(printer: Any) -> None:
    tp = printer()
    (printer.gcodes / "sub").mkdir()
    target = printer.gcodes / "sub" / "part.gcode"
    target.write_bytes(raw("prusaslicer"))
    data = asyncio.run(get(tp, "sub/part.gcode"))
    assert data == fmt.build(io.BytesIO(raw("prusaslicer")))
    st = target.stat()
    assert os.listdir(printer.cache) == [f"{st.st_size}-{st.st_mtime_ns}.mutp"]
    # Moonraker's own spelling of a gcodes path is accepted too.
    assert asyncio.run(get(tp, "gcodes/sub/part.gcode")) == data


def test_409_while_the_toolpath_is_being_made(printer: Any) -> None:
    tp = printer(request_wait=0)
    (printer.gcodes / "part.gcode").write_bytes(raw("orcaslicer"))

    async def go() -> None:
        with pytest.raises(ServerError) as err:
            await get(tp, "part.gcode")
        assert err.value.status_code == 409
        with pytest.raises(ServerError) as err:
            await get(tp, "part.gcode")
        assert err.value.status_code == 409
        assert len(tp._builds) == 1    # the second request did not start another
        await settle(tp)
        assert await get(tp, "part.gcode") == fmt.build(io.BytesIO(raw("orcaslicer")))

    asyncio.run(go())


def test_the_cache_follows_size_and_mtime_not_the_name(printer: Any) -> None:
    tp = printer()
    part = printer.gcodes / "part.gcode"
    part.write_bytes(raw("cura"))
    first = asyncio.run(get(tp, "part.gcode"))

    # Renamed, same bytes and mtime: served from the cache, no new process.
    os.replace(part, printer.gcodes / "renamed.gcode")

    async def no_process(*_: Any) -> Optional[str]:
        raise AssertionError("a cached toolpath was made again")

    real_run = tp._run
    tp._run = no_process  # type: ignore[method-assign]
    assert asyncio.run(get(tp, "renamed.gcode")) == first

    # Changed: a new key, a new toolpath.
    tp._run = real_run  # type: ignore[method-assign]
    with open(printer.gcodes / "renamed.gcode", "ab") as f:
        f.write(b"G1 X50 Y50\n")
    second = asyncio.run(get(tp, "renamed.gcode"))
    assert second != first
    assert len(os.listdir(printer.cache)) == 2


def test_a_failed_build_answers_500_and_is_not_retried(printer: Any, monkeypatch: Any) -> None:
    tp = printer()
    (printer.gcodes / "part.gcode").write_bytes(raw("cura"))
    monkeypatch.setattr(component, "FORMAT_SCRIPT", str(printer.cache / "nope.py"))
    assert status_of(get(tp, "part.gcode")) == 500
    calls = []

    async def counted(*args: Any) -> Optional[str]:
        calls.append(args)
        return None

    tp._run = counted  # type: ignore[method-assign]
    assert status_of(get(tp, "part.gcode")) == 500
    assert calls == []


def test_the_oldest_toolpaths_go_past_the_cache_size(printer: Any) -> None:
    tp = printer(cache_size=0.001)   # about 1 KB: one toolpath at a time
    for name in ("a", "b"):
        (printer.gcodes / f"{name}.gcode").write_bytes(raw("prusaslicer") + name.encode() * 3)
    asyncio.run(get(tp, "a.gcode"))
    asyncio.run(get(tp, "b.gcode"))
    st = (printer.gcodes / "b.gcode").stat()
    assert os.listdir(printer.cache) == [f"{st.st_size}-{st.st_mtime_ns}.mutp"]


def test_build_soon_never_raises(printer: Any) -> None:
    tp = printer()

    async def go() -> None:
        tp.build_soon(str(printer.gcodes / "missing.gcode"))
        assert tp._builds == {}

    asyncio.run(go())


def test_a_staged_upload_is_drawn_for_the_name_it_is_moved_to(
    printer: Any, tmp_path: Path
) -> None:
    """gcode_preprocessor hands over the staged file; file_manager then moves
    it into the gcodes root, keeping size and mtime."""
    tp = printer()
    staged = tmp_path / "upload.tmp"
    staged.write_bytes(raw("orcaslicer"))

    async def go() -> None:
        tp.build_soon(str(staged))
        await settle(tp)
        os.replace(staged, printer.gcodes / "part.gcode")
        tp._run = None  # type: ignore[assignment]   # must not build again
        assert await get(tp, "part.gcode") == fmt.build(io.BytesIO(raw("orcaslicer")))

    asyncio.run(go())


@pytest.mark.skipif(sys.platform == "win32",
                    reason="Windows cannot rename a file another handle holds open")
def test_the_upload_build_reads_the_bytes_it_opened_even_after_the_move(
    printer: Any, tmp_path: Path
) -> None:
    tp = printer()
    staged = tmp_path / "upload.tmp"
    staged.write_bytes(raw("orcaslicer"))

    async def go() -> None:
        tp.build_soon(str(staged))
        os.replace(staged, printer.gcodes / "part.gcode")   # before it finishes
        await settle(tp)
        assert await get(tp, "part.gcode") == fmt.build(io.BytesIO(raw("orcaslicer")))

    asyncio.run(go())


# -- the hook in gcode_preprocessor ---------------------------------------------

class _PreConfig:
    def __init__(self, server: _Server, key_path: str) -> None:
        self.server = server
        self.values = {"binary": "/usr/bin/avoid_excluded_zone",
                       "marker_key_path": key_path}

    def get_server(self) -> _Server:
        return self.server

    def get(self, name: str, default: Any = None) -> Any:
        return self.values.get(name, default)

    def getfloat(self, name: str, default: float) -> float:
        return default


def test_preprocessor_hands_over_the_file_after_the_safety_pass(
    printer: Any, tmp_path: Path
) -> None:
    tp = printer()
    server = tp.server
    pre = GCodePreprocessorComponent(
        _PreConfig(server, str(tmp_path / "key")))  # type: ignore[arg-type]
    order: List[str] = []

    async def excluded_zone_pass(path: str) -> None:
        order.append("pass")

    pre._invoke_preprocessor = excluded_zone_pass  # type: ignore[method-assign]
    pre._binary_digest = "0" * 64
    seen: List[bytes] = []

    class _Recorder:
        def build_soon(self, path: str) -> None:
            order.append("toolpath")
            seen.append(Path(path).read_bytes())

    server.components["muon_toolpath"] = _Recorder()
    staged = tmp_path / "upload.tmp"
    staged.write_bytes(raw("cura"))
    asyncio.run(pre.process_path(str(staged)))
    assert order == ["pass", "toolpath"]
    last = seen[0].rstrip(b"\n").rsplit(b"\n", 1)[-1]
    assert MARKER_RE.match(last), "the toolpath must be made after the marker"

    # Without the component the safety pass is unchanged.
    del server.components["muon_toolpath"]
    asyncio.run(pre.process_path(str(staged)))
    assert order == ["pass", "toolpath", "pass"]
