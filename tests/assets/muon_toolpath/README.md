# Toolpath samples (B9-MR-1)

One small file per slicer, for `tests/test_muon_toolpath.py`. These files are
checked out byte for byte (`.gitattributes`), because a toolpath's offsets are
byte offsets into them.

| File | What it is |
|---|---|
| `orcaslicer.gcode` | A real M1 slice: OrcaSlicer 2.5.0-dev, a 10 mm cube, 1 October 2026. Trimmed to the start G-code, the first three layers and the end G-code; nothing else is changed. |
| `prusaslicer.gcode` | Written in PrusaSlicer 2.8's conventions, not sliced: `;TYPE:`/`;WIDTH:`/`;LAYER_CHANGE`/`;Z:`/`;HEIGHT:`, relative E, numbers without a leading zero (`E.466`, `Z.6`), retract-and-wipe and Z-hop travel, support and support interface. |
| `cura.gcode` | Written in Cura 5.8's conventions (Marlin flavour), not sliced: `;LAYER:<n>`, upper-case `;TYPE:` names, no widths, absolute E with a retract and prime around each travel, `G0` travel, and Cura's `G91` end G-code. |

`<name>.app.json` is what the app's parser makes of each file:
`parseToolpath` from muon3d-app `packages/moonraker-client/src/toolpath.ts`,
run under Node (`node --experimental-strip-types`), each segment's end point
rounded to 0.1 µm, with its file offset. `made_by` names the app commit. The
parity test holds the toolpath's non-travel segments to that list.
