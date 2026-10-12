# muon_bridge (KAN-527)

`muon_bridge` lets a browser on the printer's LAN drive another printer that
the browser can't reach directly. The M1 makes the connection on its behalf:

- **Bambu Lab printers in LAN mode.** The M1 uses MQTT over TLS on port 8883,
  FTPS on port 990 for uploads, and, on the A1 and P1 series, the camera on
  port 6000.
- **PrusaLink printers.** The M1 proxies `/api/v1` and does the HTTP Digest
  authentication itself. This means the browser never runs into PrusaLink's
  missing CORS headers.

The bridge is a separate surface from this M1's own Klipper. Its methods live
only under `server.muon_bridge.*`. Its notifications are
`notify_muon_bridge_status`, and each one goes only to the websocket that
opened the session. Every answer carries `"bridged": true`, along with the
session id, the kind of printer and its address. The bridge refuses to target
this printer's own addresses.

## Configuration

```ini
[muon_bridge]
enabled: False
#   Off by default. While it is off, the component registers no methods.
max_sessions: 2
#   How many bridge sessions can be open at once (1-8).
max_upload_mb: 32
#   The largest file one upload may carry, in MiB (1-36). Files are sent
#   base64-encoded. Moonraker caps an HTTP body at 50 MiB, and Tornado caps a
#   websocket message at 10 MiB, so a file over about 7 MiB has to go by HTTP
#   POST to /server/muon_bridge/upload.
status_interval: 5
#   How often a PrusaLink printer is polled for its status, in seconds.
prusalink_storage: usb
#   The PrusaLink storage that uploads go to and prints start from.
```

## Who may use it

Only the owner may use the bridge. Access is the `bridge` row of
`muon_access_policy`:

- It requires the admin level (the owner's level) from the home network,
  under every preset.
- The row is fixed, so presets and overrides cannot change it.
- If the printer has no owner, only the panel may use the bridge.
- Viewers are refused, and so are callers from away.

`check_access` applies this row to every `/server/muon_bridge/*` endpoint,
reads included. The component then checks it again on its own. If the printer
has no `[muon_access]` section, only the panel may use the bridge.

Each session belongs to the principal that opened it. Other callers can't
see or drive it.

## Targets

`host` must be an IP literal in RFC 1918 (`10/8`, `172.16/12`, `192.168/16`)
or ULA (`fc00::/7`) space. The bridge refuses everything else:

- public addresses, CGNAT, loopback, link-local, multicast and unspecified
  addresses;
- this printer's own addresses;
- host names, because a name can resolve somewhere else on the next lookup.

The ports are fixed. A caller can't choose them.

## Credentials

Credentials arrive in `open_session`'s `credentials` object:

- Bambu: `{"access_code": ...}`
- PrusaLink: `{"username": ..., "password": ...}`. The username defaults to
  `maker`.

The component removes the credentials from the request's arguments straight
away. It holds them in RAM only, in a `Secret` (a `bytearray` that is never
shown in a `repr`). The `Secret` is overwritten with zeros in all of these
cases:

- `close_session` is called;
- the websocket that opened the session goes away;
- the printer drops the connection, or PrusaLink stops answering;
- a session fails to open;
- Moonraker shuts down.

`credentials` and `access_code` are among `utils/redact.py`'s sensitive
fields, so Moonraker's request logging never writes them. The Digest code
does not cache HA1, because HA1 works as well as the password. It is computed
again from the `Secret` for each request.

## Limits

- Opening sessions: a burst of 4, then 1 every 15 s, across all callers.
- Commands and PrusaLink requests: a burst of 10, then 1 per second, per
  session.
- Uploads: a burst of 2, then 1 every 30 s, per session.
- Camera frames: a burst of 4, then 2 per second, per session.
- Only one session per target address.

When a limit is hit, the call is refused with a 429.

## API

All of these methods are JSON-RPC (and HTTP under `/server/muon_bridge/`).
`open_session` has to come over the websocket, because a session ends when
its websocket closes.

| Method | Arguments | Notes |
|---|---|---|
| `server.muon_bridge.open_session` | `kind` (`bambu`/`prusalink`), `host`, `serial` (Bambu), `storage` (PrusaLink, optional), `credentials` | Returns the session and the first status |
| `server.muon_bridge.status` | `session_id` (optional) | Without `session_id`, lists the caller's sessions |
| `server.muon_bridge.upload` | `session_id`, `filename`, `data` (base64) | Bambu: `.3mf`/`.gcode` over FTPS. PrusaLink: `.gcode`/`.bgcode`, `PUT /api/v1/files/{storage}/{name}` |
| `server.muon_bridge.start` | `session_id`, `filename`, `options` | Bambu: `print.project_file` (`options.plate`, `timelapse`, `bed_levelling`, `flow_cali`, `vibration_cali`, `layer_inspect`, `use_ams`) or `print.gcode_file`. PrusaLink: `POST /api/v1/files/{storage}/{name}` |
| `server.muon_bridge.pause` / `resume` / `stop` | `session_id` | Bambu: `print.pause`/`resume`/`stop`. PrusaLink: the current job |
| `server.muon_bridge.close_session` | `session_id` | |
| `server.muon_bridge.camera` | `session_id` | One JPEG from an A1/P1 camera, base64-encoded. 404 where the printer has no camera on port 6000 |
| `server.muon_bridge.prusalink` | `session_id`, `method`, `path` (under `/api/v1/`), `body` (JSON) | The `/api/v1` proxy. Answers with `status_code`, the `headers` that are safe to pass on, and `body` |

Status notifications look like this:

```json
{"jsonrpc": "2.0", "method": "notify_muon_bridge_status", "params": [{
  "bridged": true, "session_id": "mb-…", "kind": "bambu",
  "host": "192.168.1.20", "serial": "01S00A…", "connected": true,
  "opened": 1760000000.0,
  "status": {"gcode_state": "RUNNING", "mc_percent": 12}}]}
```

`status` carries only what has changed. Changes are gathered for 0.5 s before
a notification is sent. When a session ends, the last notification has
`"connected": false` and a `reason`.

## Bambu Lab: TLS

The printer's MQTT, FTPS and camera servers present a certificate issued by
Bambu Lab's CA, with the serial number as the certificate's name.
`moonraker/assets/muon_bridge_bambu_ca.pem` holds the public BBL CA and BBL
CA2 roots, and the bridge trusts nothing else. It sends the serial as SNI and
checks the certificate name against it. The one relaxed check is
`VERIFY_X509_STRICT`: the roots lack extensions that this flag demands. An
FTPS data channel resumes the control channel's TLS session, as the printer
requires.

## Sources

The protocols come from public write-ups. No client code was copied:

- OpenBambuAPI (documentation under GFDL-1.3), at commit
  `cc383a2c96576a9f53391c879acfb8dca5c534e4`:
  [mqtt.md](https://github.com/Doridian/OpenBambuAPI/blob/cc383a2c96576a9f53391c879acfb8dca5c534e4/mqtt.md),
  [tls.md](https://github.com/Doridian/OpenBambuAPI/blob/cc383a2c96576a9f53391c879acfb8dca5c534e4/tls.md),
  [ftp.md](https://github.com/Doridian/OpenBambuAPI/blob/cc383a2c96576a9f53391c879acfb8dca5c534e4/ftp.md),
  [video.md](https://github.com/Doridian/OpenBambuAPI/blob/cc383a2c96576a9f53391c879acfb8dca5c534e4/video.md).
  The CA certificates come from its `examples/ca_cert.pem`. They are public
  keys.
- The OASIS MQTT 3.1.1 standard
  (<http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html>).
  The bridge has its own small client for it, built on `asyncio` and `ssl`.
- PrusaLink's OpenAPI description
  ([prusa3d/Prusa-Link-Web, spec/openapi.yaml](https://github.com/prusa3d/Prusa-Link-Web/blob/master/spec/openapi.yaml)).
- RFC 7616 and RFC 2617 (HTTP Digest).

## Dependencies

The bridge uses the standard library only, plus Tornado, which Moonraker
already has. It does not use `paho-mqtt`. The MuonOS image needs to add
nothing. Enabling the bridge on an M1 takes a `[muon_bridge] enabled: True`
section, and `[muon_access]` has to be loaded too (Moonraker#40). Without it,
only the panel can use the bridge.

## Tests

`tests/test_muon_bridge.py` uses fake servers on loopback: an MQTT broker, an
FTPS server and a camera in front of Bambu-style certificates, made with the
`openssl` command; and a PrusaLink HTTP server that checks Digest answers
independently.
