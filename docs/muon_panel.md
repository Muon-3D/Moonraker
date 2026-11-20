# muon_panel

`GET|HEAD /server/muon/panel/index.html` serves the touch-panel page
(`[muon_panel] path`, default `/usr/share/muon-panel/index.html`, one
self-contained HTML file, at most 8 MB) for Control over Bluetooth or the
relay, where the gateway reaches only Moonraker.

- Headers: `Content-Type: text/html; charset=utf-8`, strong `ETag`
  (sha256, first 32 hex), `X-Muon-Panel-Version` (first 12 hex),
  `Cache-Control: no-cache`, `X-Content-Type-Options: nosniff`,
  `Vary: Accept-Encoding`. No CSP: the file carries its own.
- `If-None-Match` matching gives 304 with no body.
- `Accept-Encoding: gzip` gives a gzip copy, compressed once and cached by
  the file's mtime and size. Reading, hashing and compressing run in an
  executor.
- A symlink, a non-regular file or one over 8 MB is refused (500, JSON
  error); a missing file is 404. Other methods are 405. Query strings are
  ignored.
- Access: a read (Viewer and up, guests on Open printers included).
