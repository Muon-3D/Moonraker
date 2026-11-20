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

## Live state and remote navigation (KAN-4812, KAN-4949)

Code: `moonraker/components/muon_panel_nav.py`, loaded by `muon_panel`.

**The panel connection.** One connection: local (a peer at 127.0.0.1 or
::1, or the unix socket) that called `server.connection.identify` with
`client_name` `muon-panel`, of any client type (the panel is a `display`).
Nothing is registered. The latest one to identify wins; when it
disconnects the state is `{connected: false}` and every pending navigation
fails with 503.

The client name `muon-panel` is refused (403) at identify to every
non-local connection, whatever its type, so a guest cannot be taken for the
panel or lock it out. A navigation is sent to the panel connection directly,
as the JSON-RPC notification `muon_panel_navigate`, and never through
Klippy's remote methods, where a G-code macro could call it with a forged
`caller_is_owner`. So `connection.register_remote_method` refuses the name
`muon_panel_navigate` (403, reserved) from every connection.

| Method | HTTP | Who |
| --- | --- | --- |
| `server.muon.panel.publish` `{state}` | `POST /server/muon/panel/publish` | the panel connection only; anyone else 403 |
| `server.muon.panel.state` | `GET /server/muon/panel/state` | a read: Viewer and up |
| `server.muon.panel.navigate` `{screen, params?, if_seq?}` | `POST /server/muon/panel/navigate` | a write: Operator and up |
| `server.muon.panel.navigate_result` `{req_id, ok, status?, reason?, seq?}` | `POST /server/muon/panel/navigate_result` | the panel connection only |

`publish` and `navigate_result` are never reachable by a remote principal,
the owner included: the level table's `panel_only` row (fixed, above every
level) refuses them, and the component checks the connection again.

**State.** `state = {seq, screen, params, modal, busy, updated_at,
owner_only_routes}`. Moonraker assigns its own `seq` (last + 1) when the
panel's is not greater than the last one; `publish` answers `{seq}`.
`GET state` answers `{connected: true, ...state}`, `{connected: true}`
before the first publish, or `{connected: false}`. The notification
`notify_muon_panel_state` carries the same body as its one parameter, at
most 10 a second (the latest is always delivered), and is never sent to the
panel connection.

**Navigate.** Errors carry `{reason}` beside the usual `error` object (and
as `error.data` over JSON-RPC):

- 503 `panel_offline`: no panel connection, or it has not published yet
- 403 `owner_only`: `screen` is in the last published `owner_only_routes`
  and the caller is not the printer owner (the admin level, or the panel
  itself); returned before the panel is contacted. Both sides are compared
  lower case with leading and trailing `/` removed
- 429 `rate_limited`: one caller (the muon access principal; local callers
  are exempt) has two navigations waiting, or started two in the last
  second
- 409 `stale_seq` `{seq}`: `if_seq` is not the current `seq`
- 429: eight navigations are already waiting
- otherwise the panel is called with
  `muon_panel_navigate {req_id, screen, params, caller_role,
  caller_is_owner, caller_level}` (`caller_level` is the access level name,
  `panel` for local callers) and has 2.0 s to answer with `navigate_result`.
  `ok` gives 200 `{seq}`, Moonraker's current seq, not the panel's; not `ok`
  gives its `status` (400, 403, 409 or 423, anything else is 409) with
  `{reason}`; no answer gives 504 `panel_timeout`.

A `navigate_result` that is late, for an unknown `req_id`, or from any
connection but the panel is dropped (debug log; 403 for a foreign
connection, `{accepted: false}` otherwise).

**The panel enforces owner-only too.** Moonraker's check is the first gate
only: the panel must refuse an owner-only screen itself when
`caller_is_owner` is false, including sub-pages opened through `params`.
Published `seq` values are 0 to 2^53-1; Moonraker's own count never goes
back, across panel reconnects too.

**Who is sent the notification.** `notify_muon_panel_state` goes only to
connections whose principal may read the state by GET (the `read` row). That
is every admitted client, so the panel must never put secrets in `params`
or `modal`.
