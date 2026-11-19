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
  {"path":"usb/Demo","dirs":[{"name":"Parts","path":"usb/Demo/Parts","modified":1700000000.0}],"files":[{"name":"part.gcode","path":"usb/Demo/part.gcode","size":1234,"modified":1700000001.0}],"truncated":false}
  ```
  Files use `file_manager.VALID_GCODE_EXTS`, case-insensitively. Files and
  directories are independently sorted newest first, then by name. Four
  directory levels **below usb** are permitted: `usb/Demo/a/b/c/file.gcode`
  is valid; `usb/Demo/a/b/c/d/file.gcode` is not. At the deepest directory no
  deeper directories are advertised.
  A folder lists at most 2000 entries (`truncated` is true when more exist);
  the flat `/server/files/list` stops at 10000 files. Only real mountpoints
  count as sticks. Printing needs free space of file size plus 256 MB on the
  printer, otherwise HTTP 507 "Not enough space on the printer". Leftover
  `.usb-*` temporary copies are removed at startup.
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

## File management (KAN-4814, spec v1.2)

Paths use the `usb/<stick>/<dir...>/<file>` form everywhere. Copy `items` for
`to_usb` are relative to `gcodes/` (`<dir>/<file>`). "Copy all" is
`items: ["usb/<stick>"]` for `to_printer` and `items: ["/"]` for `to_usb`.
A folder item expands to its printable files, recursively, to depth 4.

* `GET /server/muon/usb/status` gains, per stick, `dev`, `unit`
  (`muon-usb-mount@<dev>.service`), `fs`, `free_bytes`, `total_bytes`,
  `writable` (true only during a `to_usb` job) and `read_only` (never
  writable: write-protect switch, unsupported filesystem, or a failed rw
  remount until the stick is replugged). Top level: `job` and
  `ejected: [{name, at}]` (ejected, still plugged in: "Safe to remove").
* `GET /server/muon/usb/list?path=&offset=&limit=` keeps the `dirs`/`files`
  split. Files carry `size` and `modified`, dirs `modified`. Entries are sorted
  (folders first, then newest first) before the 2000 cap. `limit` defaults to
  500, maximum 2000. `total` is the real entry count; `truncated` means the
  page does not reach the end of the folder.
* `GET /server/muon/usb/file?path=` streams a printable file: `Content-Length`,
  `Accept-Ranges: bytes`, one `Range` (206), `Content-Disposition:
  attachment; filename*=UTF-8''<name>`, an `ETag` from mtime and size
  (`If-None-Match` gives 304). Anything that is not exactly one satisfiable
  range (malformed, reversed, past the end, multi-range) is 416 with
  `Content-Range: bytes */<size>`. Read in 256 KiB chunks at ionice idle class.
* `POST /server/muon/usb/copy {direction, stick, items, dest?, on_conflict?}`
  returns `{job_id}`; 409 while another job runs; 400 for bad paths. One job at
  a time, run in its own thread at ionice idle class, limited to about 8 MB/s
  while the printer prints or is paused. Each file goes to a hidden `.usb-<uuid>`
  name, is fsynced, renamed, and the folder is fsynced; a source that changed
  while copying is `source_changed`. Cancel removes the in-flight temp file and
  keeps finished files.
  * `to_usb` first starts the root unit `muon-usb-rw@<dev>.service` (remount
    rw), and always stops it again in a `finally` block (remount ro, sync). A
    stick that cannot be remounted fails the job at once with `read_only`.
  * Skipped (job continues): `name_invalid` (FAT-illegal characters
    `<>:"\|?*`, over 255 UTF-16 units, trailing dot or space, deeper than 4
    folders), `too_large` (over 4 GiB on vfat), `exists` (`on_conflict: skip`),
    `folder_full` (the destination folder already has 2000 entries).
  * Per-file errors (job continues): `read_error`, `write_error`,
    `source_changed`. Job-ending: `no_space`, `stick_removed`, `read_only`.
* `GET /server/muon/usb/job` is the current or last job, with `items`.
  Notification `notify_muon_usb_job` carries the job object at most twice a
  second plus once at the end; past 200 items it carries `item` (the one that
  changed) and the totals instead of `items`.
* `POST /server/muon/usb/job/cancel {job_id}`; the job ends as `cancelled`.
* `POST /server/muon/usb/eject {stick}`: sync, then stop
  `muon-usb-mount@<dev>.service`. 409 `{reason: "job_running", job_id}` (in the
  HTTP error object, and as `extra` over WebSocket) while a job runs.

Access: reads (`status list metadata job file`) are Operator/OpenGuest reads;
`copy`, `job/cancel`, `eject` and `print` are the `print` action. `to_usb` also
reads gcodes (checked per item in account mode). Moonraker uses its systemd
D-Bus connection (`machine.do_service_action`); MuonOS ships the polkit rule
that lets the `moonraker` user start and stop only `muon-usb-rw@*` and
`muon-usb-mount@*`.
