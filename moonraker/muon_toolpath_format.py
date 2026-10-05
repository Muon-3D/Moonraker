# moonraker/muon_toolpath_format.py
#
# B9-MR-1: the MUTP toolpath format, and the G-code reader that makes it.
#
# The app and Fluidd draw the part a printer is making from the G-code file
# itself, and today each downloads the whole file to do it (muon3d-app
# docs/plans/live-printer-viewer.md, section 2). A MUTP file is the same
# drawing in about a quarter of the bytes, made once on the printer.
#
# This module is the standard library only, on purpose: the muon_toolpath
# component runs it as its own process (`python -I muon_toolpath_format.py OUT
# < file.gcode`), niced, so a 40 MB file is read without holding Moonraker's
# event loop or its GIL.
#
# THE FORMAT, little-endian, version 1
#
#   header   magic "MUTP", u16 version, u16 flags,
#            f32 bounds min[3], f32 bounds max[3], f32 xy scale (mm per unit),
#            u32 layer count
#   layers   per layer: f32 z, f32 height, u32 segment count,
#            u32 file offset of its first segment
#   segments per segment, every layer's in order: i16 x, i16 y, u8 type,
#            u8 width (0.01 mm), u32 end file offset
#
# A segment is one XY move, travel included, so the segments form one chain:
# a segment starts where the one before it ended, and the first segment's
# start is not recorded. Its end point is `min + (x, y) * scale`, at its
# layer's z. `scale` is 0.01 mm unless the moves span more than 327.67 mm, in
# which case it grows to fit them into 0..32767.
#
# Every "file offset" is a byte offset into the G-code file as it is on disk,
# the same count as Klipper's `virtual_sdcard.file_position`:
#
#   - a segment's end file offset is the byte after its line's newline, so a
#     segment has been read once `file_position` reaches it;
#   - a layer's file offset is where its first segment's line starts, so the
#     layer has begun once `file_position` passes it.
#
# Bounds cover every segment's end point and every layer's z. Type is one of
# the constants below; width is 0 for travel and where the slicer gave none
# (Cura writes no widths). Flag bit 0 says the file had more than
# MAX_SEGMENTS moves and the toolpath stops there.
#
# HOW THE G-CODE IS READ
#
# Moves follow Klipper (klippy/extras/gcode_move.py), not the app's parser,
# where the two differ: E is relative under G91 *or* M83, so a G90 after M83
# leaves E relative; G92 sets any axis; G2/G3 arcs are followed as chords of
# at most 1 mm (the app's parser skips arcs). A move extrudes when E
# increases, as in the app's parser (packages/moonraker-client/src/
# toolpath.ts), so on a file without those three the non-travel segments here
# and the app's segments are the same list; tests/test_muon_toolpath.py holds
# the two to that on all three sample files.
#
# Comments: `;TYPE:` (OrcaSlicer, PrusaSlicer and Cura alike) for the type,
# `;WIDTH:` for the width, `;LAYER_CHANGE` (Orca, Prusa) and `;LAYER:<n>`
# (Cura) for layers, `;Z:` and `;HEIGHT:` for a layer's z and height. Orca's
# Bambu-style spellings (`; FEATURE:`, `; LINE_WIDTH:`, `; CHANGE_LAYER`,
# `; Z_HEIGHT:`, `; LAYER_HEIGHT:`) are read too. Until the first layer
# comment -- the start G-code, or a file from a slicer that writes none -- a
# new layer starts when the head extrudes at a new Z, so a Z hop on a travel
# never makes one; in a file that has layer comments, untyped extrusion before
# the first one is the start G-code's purge, and typed 7. A layer's z is its
# `;Z:`, else the Z of its first extrusion; its height is its `;HEIGHT:`, else
# its z less the highest layer under it (or the bed).

from __future__ import annotations

import math
import os
import struct
import sys
from array import array
from typing import Any, BinaryIO, Dict, List, Optional

MAGIC = b"MUTP"
VERSION = 1
FLAG_TRUNCATED = 0x0001

XY_SCALE = 0.01
I16_MAX = 32767
WIDTH_UNIT = 0.01
MAX_SEGMENTS = 2_000_000
ARC_CHORD_MM = 1.0
ARC_MAX_CHORDS = 720

HEADER = struct.Struct("<4sHH6ffI")
LAYER = struct.Struct("<ffII")
SEGMENT = struct.Struct("<hhBBI")

OTHER = 0
OUTER_WALL = 1
INNER_WALL = 2
INFILL = 3
SUPPORT = 4
SUPPORT_INTERFACE = 5
TRAVEL = 6
PURGE = 7

_TYPE_NAMES = {
    OUTER_WALL: (
        "Outer wall", "Overhang wall",                      # OrcaSlicer
        "External perimeter", "Overhang perimeter",         # PrusaSlicer
        "WALL-OUTER",                                       # Cura
    ),
    INNER_WALL: ("Inner wall", "Perimeter", "WALL-INNER"),
    INFILL: (
        "Sparse infill", "Internal solid infill", "Top surface",
        "Bottom surface", "Bridge", "Internal Bridge", "Gap infill", "Ironing",
        "Internal infill", "Solid infill", "Top solid infill", "Bridge infill",
        "Gap fill",
        "FILL", "SKIN", "BRIDGE",
    ),
    SUPPORT: (
        "Support", "Support transition", "Support material",
        "SUPPORT", "SUPPORT-INFILL",
    ),
    SUPPORT_INTERFACE: (
        "Support interface", "Support material interface", "SUPPORT-INTERFACE",
    ),
    # The start G-code's purge line is typed Custom by Orca and Prusa.
    PURGE: (
        "Skirt", "Brim", "Custom", "Prime tower", "Wipe tower",
        "Skirt/Brim",
        "SKIRT", "PRIME-TOWER",
    ),
}
FEATURE_TYPES: Dict[str, int] = {
    name.lower(): kind for kind, names in _TYPE_NAMES.items() for name in names
}

_TYPE_TAGS = ("TYPE:", "FEATURE:")
_WIDTH_TAGS = ("WIDTH:", "LINE_WIDTH:")
_Z_TAGS = ("Z:", "Z_HEIGHT:")
_HEIGHT_TAGS = ("HEIGHT:", "LAYER_HEIGHT:")
_LAYER_TAGS = ("LAYER_CHANGE", "CHANGE_LAYER")

_F32 = struct.Struct("<f")


def feature_type(name: str) -> int:
    return FEATURE_TYPES.get(name.strip().lower(), OTHER)


def _f32(value: float) -> float:
    return float(_F32.unpack(_F32.pack(value))[0])


def _number(text: str) -> Optional[float]:
    """A G-code word's value, or None. Leading-dot forms (`Z.6`) are valid."""
    try:
        value = float(text)
    except ValueError:
        return None
    return value if math.isfinite(value) else None


def _tag_value(comment: str, tags: tuple) -> Optional[str]:
    for tag in tags:
        if comment.startswith(tag):
            return comment[len(tag):].strip()
    return None


class _Layer:
    __slots__ = ("z_tag", "z_extrude", "z_open", "height", "first", "offset")

    def __init__(self, z_open: float, first: int, offset: int) -> None:
        self.z_tag: Optional[float] = None
        self.z_extrude: Optional[float] = None
        self.z_open = z_open
        self.height: Optional[float] = None
        self.first = first
        self.offset = offset

    @property
    def z(self) -> float:
        if self.z_tag is not None:
            return self.z_tag
        if self.z_extrude is not None:
            return self.z_extrude
        return self.z_open


class ToolpathBuilder:
    """Feed it G-code a line at a time with `feed`, then call `encode`."""

    def __init__(self, max_segments: int = MAX_SEGMENTS) -> None:
        self.max_segments = max_segments
        self.truncated = False
        # Klipper's gcode_move state: positions are the toolhead's, `base` is
        # what G92 has offset them by.
        self.pos = [0.0, 0.0, 0.0]
        self.base = [0.0, 0.0, 0.0]
        self.e = 0.0
        self.absolute_coord = True
        self.absolute_extrude = True
        self.kind = OTHER
        self.width = 0
        self.xs = array("d")
        self.ys = array("d")
        self.kinds = array("B")
        self.widths = array("B")
        self.ends = array("L")
        self.layers: List[_Layer] = []
        # Set by a layer comment, and opened as a layer by the next segment,
        # so a comment with no moves after it (the end G-code's) adds nothing.
        self.pending: Optional[_Layer] = None
        self.tagged = False
        self.offset = 0

    # -- reading ----------------------------------------------------------

    def feed(self, raw: bytes) -> bool:
        """Read one line, newline included. False once the toolpath is full."""
        start = self.offset
        self.offset = end = start + len(raw)
        if self.truncated:
            return False
        line = raw.decode("latin-1").strip()
        if not line:
            return True
        if line[0] == ";":
            self._comment(line[1:].strip(), start)
            return True
        semi = line.find(";")
        if semi >= 0:
            line = line[:semi].rstrip()
            if not line:
                return True
        c0 = line[0]
        if c0 != "G" and c0 != "M":
            return True
        parts = line.split()
        cmd = parts[0].upper()
        if cmd in ("G1", "G0", "G01", "G00"):
            self._linear(parts, start, end)
        elif cmd in ("G2", "G3", "G02", "G03"):
            self._arc(parts, cmd in ("G2", "G02"), start, end)
        elif cmd == "G90":
            self.absolute_coord = True
        elif cmd == "G91":
            self.absolute_coord = False
        elif cmd == "M82":
            self.absolute_extrude = True
        elif cmd == "M83":
            self.absolute_extrude = False
        elif cmd == "G92":
            self._set_position(parts)
        return not self.truncated

    def read(self, stream: BinaryIO) -> "ToolpathBuilder":
        for raw in stream:
            if not self.feed(raw):
                break
        return self

    def _comment(self, comment: str, start: int) -> None:
        value = _tag_value(comment, _TYPE_TAGS)
        if value is not None:
            self.kind = feature_type(value)
            return
        value = _tag_value(comment, _WIDTH_TAGS)
        if value is not None:
            width = _number(value)
            if width is not None:
                self.width = max(0, min(255, round(width / WIDTH_UNIT)))
            return
        if comment in _LAYER_TAGS or (
            comment.startswith("LAYER:")
            and comment[6:].strip().lstrip("-").isdigit()
        ):
            if not self.tagged:
                # Everything before the first layer comment is the start
                # G-code. Orca and Prusa type its purge Custom; Cura types
                # nothing, so its untyped extrusion there is the purge too.
                for i, kind in enumerate(self.kinds):
                    if kind == OTHER:
                        self.kinds[i] = PURGE
            self.tagged = True
            self.pending = _Layer(self.pos[2], len(self.xs), start)
            return
        target = self.pending
        if target is None and self.layers:
            target = self.layers[-1]
        if target is None:
            return
        value = _tag_value(comment, _Z_TAGS)
        if value is not None:
            target.z_tag = _number(value)
            return
        value = _tag_value(comment, _HEIGHT_TAGS)
        if value is not None:
            target.height = _number(value)

    def _words(self, parts: List[str]) -> Dict[str, float]:
        words: Dict[str, float] = {}
        for part in parts[1:]:
            value = _number(part[1:])
            if value is not None:
                words[part[0].upper()] = value
        return words

    def _target(self, words: Dict[str, float]) -> List[float]:
        new = list(self.pos)
        for i, axis in enumerate("XYZ"):
            if axis in words:
                if self.absolute_coord:
                    new[i] = words[axis] + self.base[i]
                else:
                    new[i] += words[axis]
        return new

    def _extrudes(self, words: Dict[str, float]) -> bool:
        if "E" not in words:
            return False
        if self.absolute_coord and self.absolute_extrude:
            e = words["E"]
        else:
            e = self.e + words["E"]
        extruding = e > self.e + 1e-5
        self.e = e
        return extruding

    def _linear(self, parts: List[str], start: int, end: int) -> None:
        words = self._words(parts)
        new = self._target(words)
        extruding = self._extrudes(words)
        if new[0] != self.pos[0] or new[1] != self.pos[1]:
            self._segment(new[0], new[1], new[2], extruding, start, end)
        self.pos = new

    def _arc(self, parts: List[str], clockwise: bool, start: int, end: int) -> None:
        words = self._words(parts)
        new = self._target(words)
        extruding = self._extrudes(words)
        x0, y0 = self.pos[0], self.pos[1]
        cx = x0 + words.get("I", 0.0)
        cy = y0 + words.get("J", 0.0)
        radius = math.hypot(x0 - cx, y0 - cy)
        a0 = math.atan2(y0 - cy, x0 - cx)
        a1 = math.atan2(new[1] - cy, new[0] - cx)
        sweep = a1 - a0
        if clockwise:
            if sweep >= -1e-9:
                sweep -= 2 * math.pi
        elif sweep <= 1e-9:
            sweep += 2 * math.pi
        chords = 1
        if radius > 0:
            chords = math.ceil(abs(sweep) * radius / ARC_CHORD_MM)
            chords = max(1, min(ARC_MAX_CHORDS, chords))
        z0 = self.pos[2]
        for i in range(1, chords + 1):
            if i == chords:
                x, y = new[0], new[1]
            else:
                angle = a0 + sweep * i / chords
                x = cx + radius * math.cos(angle)
                y = cy + radius * math.sin(angle)
            z = z0 + (new[2] - z0) * i / chords
            self._segment(x, y, z, extruding, start, end)
            if self.truncated:
                break
            self.pos = [x, y, z]
        self.pos = new

    def _set_position(self, parts: List[str]) -> None:
        words = self._words(parts)
        if not words:
            words = {"X": 0.0, "Y": 0.0, "Z": 0.0, "E": 0.0}
        for i, axis in enumerate("XYZ"):
            if axis in words:
                self.base[i] = self.pos[i] - words[axis]
        if "E" in words:
            self.e = words["E"]

    # -- segments and layers ----------------------------------------------

    def _segment(
        self, x: float, y: float, z: float, extruding: bool, start: int, end: int
    ) -> None:
        if len(self.xs) >= self.max_segments:
            self.truncated = True
            return
        layer = self._layer_for(z, extruding, start)
        if extruding and layer.z_extrude is None:
            layer.z_extrude = z
        self.xs.append(x)
        self.ys.append(y)
        self.kinds.append(self.kind if extruding else TRAVEL)
        self.widths.append(self.width if extruding else 0)
        self.ends.append(end)

    def _layer_for(self, z: float, extruding: bool, start: int) -> _Layer:
        index = len(self.xs)
        if self.pending is not None:
            layer, self.pending = self.pending, None
            layer.first, layer.offset = index, start
            self.layers.append(layer)
            return layer
        if not self.layers:
            layer = _Layer(z, index, start)
            self.layers.append(layer)
            return layer
        layer = self.layers[-1]
        if (
            not self.tagged
            and extruding
            and layer.z_extrude is not None
            and abs(z - layer.z_extrude) > 1e-4
        ):
            layer = _Layer(z, index, start)
            self.layers.append(layer)
        return layer

    # -- writing ----------------------------------------------------------

    def encode(self) -> bytes:
        count = len(self.xs)
        layers = self.layers
        zs = [_f32(layer.z) for layer in layers]
        if count:
            lo = [min(self.xs), min(self.ys), min(zs)]
            hi = [max(self.xs), max(self.ys), max(zs)]
        else:
            lo = [0.0, 0.0, 0.0]
            hi = [0.0, 0.0, 0.0]
        lo = [_f32(v) for v in lo]
        hi = [_f32(v) for v in hi]
        span = max(hi[0] - lo[0], hi[1] - lo[1])
        scale = _f32(XY_SCALE)
        while span / scale > I16_MAX:
            scale = _f32(max(scale * 1.0001, span / I16_MAX))
        flags = FLAG_TRUNCATED if self.truncated else 0

        out = bytearray(HEADER.size + LAYER.size * len(layers) + SEGMENT.size * count)
        HEADER.pack_into(out, 0, MAGIC, VERSION, flags, *lo, *hi, scale, len(layers))
        pos = HEADER.size
        for i, layer in enumerate(layers):
            last = layers[i + 1].first if i + 1 < len(layers) else count
            height = layer.height
            if height is None:
                # Down to the highest layer under this one, or to the bed: the
                # start G-code's purge can share the first layer's Z.
                under = [z for z in zs[:i] if z < zs[i] - 1e-6]
                height = zs[i] - max(under) if under else max(0.0, zs[i])
            LAYER.pack_into(out, pos, zs[i], height, last - layer.first, layer.offset)
            pos += LAYER.size
        x0, y0 = lo[0], lo[1]
        xs, ys, kinds = self.xs, self.ys, self.kinds
        widths, ends = self.widths, self.ends
        pack = SEGMENT.pack_into
        step = SEGMENT.size
        for i in range(count):
            qx = round((xs[i] - x0) / scale)
            qy = round((ys[i] - y0) / scale)
            pack(
                out, pos,
                0 if qx < 0 else I16_MAX if qx > I16_MAX else qx,
                0 if qy < 0 else I16_MAX if qy > I16_MAX else qy,
                kinds[i], widths[i], ends[i],
            )
            pos += step
        return bytes(out)


def build(stream: BinaryIO, max_segments: int = MAX_SEGMENTS) -> bytes:
    """The MUTP bytes of the G-code read from `stream`."""
    return ToolpathBuilder(max_segments).read(stream).encode()


def decode(data: bytes) -> Dict[str, Any]:
    """The reference reader: a MUTP file as plain values, end points in mm."""
    if len(data) < HEADER.size:
        raise ValueError("too short for a MUTP header")
    magic, version, flags, *rest = HEADER.unpack_from(data, 0)
    if magic != MAGIC:
        raise ValueError("not a MUTP file")
    if version != VERSION:
        raise ValueError(f"MUTP version {version} is not supported")
    lo, hi, scale, layer_count = rest[0:3], rest[3:6], rest[6], rest[7]
    pos = HEADER.size
    layers = []
    for _ in range(layer_count):
        z, height, count, offset = LAYER.unpack_from(data, pos)
        layers.append(
            {"z": z, "height": height, "count": count, "offset": offset}
        )
        pos += LAYER.size
    total = sum(layer["count"] for layer in layers)
    if len(data) != pos + total * SEGMENT.size:
        raise ValueError("MUTP length does not match its layer table")
    segments = []
    for index, layer in enumerate(layers):
        for _ in range(layer["count"]):
            qx, qy, kind, width, end = SEGMENT.unpack_from(data, pos)
            segments.append({
                "x": lo[0] + qx * scale,
                "y": lo[1] + qy * scale,
                "z": layer["z"],
                "layer": index,
                "type": kind,
                "width": width * WIDTH_UNIT,
                "end": end,
            })
            pos += SEGMENT.size
    return {
        "version": version,
        "flags": flags,
        "min": list(lo),
        "max": list(hi),
        "scale": scale,
        "layers": layers,
        "segments": segments,
    }


def main(argv: List[str]) -> int:
    """`muon_toolpath_format.py OUT`: G-code on stdin, MUTP written to OUT.

    OUT appears whole or not at all: the bytes go to a sibling file first and
    are renamed over it, so a reader never sees half a toolpath.
    """
    if len(argv) != 2:
        print("usage: muon_toolpath_format.py OUT < file.gcode", file=sys.stderr)
        return 2
    if hasattr(os, "nice"):
        try:
            os.nice(10)
        except OSError:
            pass
    out = argv[1]
    data = build(sys.stdin.buffer)
    part = f"{out}.part-{os.getpid()}"
    try:
        with open(part, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(part, out)
    except BaseException:
        try:
            os.remove(part)
        except OSError:
            pass
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
