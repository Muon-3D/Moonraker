# MUON USB printing

The M1 template enables `[muon_usb]`. `rejected_path` optionally overrides
`/run/muon-usb/rejected` (primarily for tests). MuonOS owns the read-only mounts
under `<data_path>/usb/<label-or-uuid>` and rejection records; Moonraker never
mounts, repairs or writes a USB filesystem. The root is registered read-only
when present and checked again on USB requests, including `/server/files/list`.
No recursive watchers, content reads or metadata extraction run during listing.

## API

Responses below are the result objects, inside Moonraker's usual HTTP
`{"result": ...}` envelope. All paths are relative, start with `usb/`, and use
the mount directory name exactly as supplied by MuonOS. Hidden names, traversal,
absolute paths, control characters, backslashes and **all** symlinks (including
internal links) are refused or
omitted. Not following any symlinks also makes traversal cycle-safe.

* `GET /server/muon/usb/status`
  ```json
  {"sticks":[{"name":"Demo","path":"usb/Demo"}],"rejected":[{"name":"sdb1","fstype":"ntfs","label":"Photos"}]}
  ```
  Missing directories mean empty lists. Malformed/incomplete rejected JSON
  records are ignored until the next request. Rejected records are reduced to
  these three string fields; Moonraker does not expose device nodes or UUIDs.
* `GET /server/muon/usb/list?path=usb/Demo`
  ```json
  {"path":"usb/Demo","dirs":[{"name":"Parts","path":"usb/Demo/Parts","modified":1700000000.0}],"files":[{"name":"part.gcode","path":"usb/Demo/part.gcode","size":1234,"modified":1700000001.0}]}
  ```
  Files use `file_manager.VALID_GCODE_EXTS`, case-insensitively. Files and
  directories are independently sorted newest first, then by name. Four
  directory levels **below usb** are permitted: `usb/Demo/a/b/c/file.gcode`
  is valid; `usb/Demo/a/b/c/d/file.gcode` is not. At the deepest directory no
  deeper directories are advertised.
* `GET /server/files/list?root=usb` returns the standard flat file list:
  ```json
  [{"path":"Demo/part.gcode","size":1234,"modified":1700000001.0,"permissions":"r"}]
  ```
  The same depth/hidden/symlink rules apply. The walk runs in a worker thread.
* `GET /server/muon/usb/metadata?path=usb/Demo/part.gcode`
  ```json
  {"estimated_time":3723.0,"slicer":"PrusaSlicer","filament_type":"PLA"}
  ```
  `estimated_time` is seconds or null; `slicer` is a detected PrusaSlicer,
  OrcaSlicer, BambuStudio, Cura or Muon name, or null. `filament_type` is
  optional. Only 64 KiB at each end are read. Prusa/Orca/Bambu duration comments
  and Cura `;TIME:` are supported. No separate Muon-specific duration format
  is known; Muon exports with these comments use the same parser.
* `POST /server/muon/usb/print` with `{"path":"usb/Demo/part.gcode"}`
  returns `{"filename":"usb-import/part.gcode"}`. A worker copies to a hidden
  temporary file in `gcodes/usb-import`, checks the source still exists and is
  unchanged, then atomically replaces `part.gcode`. On failure it removes the
  temporary file. A successful import replaces an earlier import with the same
  basename. Calls are serialized and readiness is checked before and after
  copying. The component calls `klippy_apis.start_print`, preserving its
  `gcode_preprocessor.ensure_verified` safety gate. Once copied, unplugging the
  stick cannot interrupt the print. Complete imports remain after print failure.

USB reads and downloads have the usual read classification (not account-drive
filtering). The print endpoint has the `print` action. Uploads and mutations
targeting USB are refused even for an administrator.

## Errors for clients

* 400 `Invalid USB path.`
* 400 `USB directory depth exceeds 4.`
* 400 `The USB path is not a G-code file.`
* 400 `The USB path is not a regular file.`
* 403 `USB symlinks are not allowed.`
* 403 `The USB root is read-only.`
* 403 `The USB import directory is not safe.`
* 404 `The USB stick or path is no longer available.`
* 404 `The USB directory is no longer available.`
* 404 `The USB stick was removed while copying. Nothing was printed.`
* 404 `The G-code directory is not available.`
* 409 `Klippy is not ready. Nothing was printed.`
* 409 `The printer is busy. Nothing was printed.`
* 500 `Could not create the USB import directory.`

Normal access-policy errors and safety-preprocessor/start-print errors are
propagated unchanged. These APIs do not bypass printer authorization.
