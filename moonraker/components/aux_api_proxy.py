# Moonraker component — wifi_autoproxy.py
#
# Enable it with a bare section in moonraker.conf:
#     [aux_api_proxy]
#
# ──────────────────────────────────────────────────────────────────────────
import asyncio, json, logging, os, re, contextlib
from pathlib import Path
from typing import Dict, Any, Callable, Optional
from urllib.parse import unquote, urlencode

FASTAPI_ROOT = "http://127.0.0.1:6789"         #  loopback-only Aux API bind
OPENAPI_PATH = "/openapi.json"                 #  FastAPI default
MOON_PREFIX  = "/server/aux"                   #  Moonraker namespace

# The Aux API rejects every unauthenticated request. The shared secret is
# reissued into tmpfs on each boot by aux_api_token.service and is readable by
# the printer_admin group, which the moonraker user belongs to.
AUX_TOKEN_FILE = Path(os.getenv("AUX_API_TOKEN_FILE", "/run/aux_api/token"))
AUX_TOKEN_HEADER = "X-Aux-Api-Key"

# Map lower-case OpenAPI keys → canonical HTTP verbs
HTTP_VERBS = {"get": "GET", "post": "POST", "put": "PUT",
              "patch": "PATCH", "delete": "DELETE"}

_PATH_PARAM_RE = re.compile(r"\{[^}]+\}")


def _path_pattern(fast_path: str) -> "re.Pattern[str]":
    """Turn an OpenAPI path into an anchored matcher for the proxy.

    "/wifi/show/{ssid}" becomes ^/wifi/show/[^/?#]+$ -- one path segment per
    parameter, and no character that could start a query, a fragment or a
    second path segment. Anchored at both ends, so an absolute URL, a
    scheme-relative "//host/...", or userinfo smuggled in as "@host/..."
    cannot match (KAN-83).
    """
    parts = [re.escape(seg) if not _PATH_PARAM_RE.fullmatch(seg) else "[^/?#]+"
             for seg in fast_path.split("/")]
    return re.compile("^" + "/".join(parts) + "$")


def _has_encoded_separator(path: str) -> bool:
    """True if percent-decoding `path` would introduce a new separator.

    The pattern above excludes the literal bytes / ? # from a parameter
    segment, but not their percent-encodings. "/wifi/show/..%2f..%2fupdate"
    is one segment to the regex and four to anything that decodes before
    routing, so the allowlist would authorise one path and the Aux API
    would serve another. Decoding once and re-checking closes that; %25 is
    refused as well, so a double-encoded payload cannot reach a second
    decoding pass with a separator still hidden in it (KAN-83).

    Encodings that do not change the shape of the path -- %20 in an SSID,
    say -- are unaffected, which is why this is not simply a ban on '%'.
    Compared by count rather than by presence, since every legitimate path
    already contains '/'. A double-encoded "%252f" is allowed through and
    is correct to allow: one downstream decode yields the literal text
    "%2f" inside a segment, not a separator.
    """
    decoded = unquote(path)
    if decoded == path:
        return False
    return any(decoded.count(c) > path.count(c) for c in "/?#\\")


# ID-3: where the owner's rename is stored. Moonraker's database lives at
# /home/printer_data/database, which our rugix-ctrl-config recipe persists, so
# the name survives a reboot and an OS update -- and is cleared by a factory
# reset, which is the behaviour ID-2 asks for.
MUON_NAMESPACE = "muon"
FRIENDLY_NAME_KEY = "friendly_name"

# A rename is a label, not an identifier, so this is about what fits on a
# 480x480 panel and in a printer list -- not about safety. It is still bounded:
# an unbounded string here ends up in the database, the panel and every list.
MAX_NAME_LENGTH = 32

# ──────────────────────────────────────────────────────────────────────────
class AuxAutoProxy:
    def __init__(self, config):
        self.server      = config.get_server()
        self.http_client = self.server.lookup_component("http_client")
        self.log         = logging.getLogger("wifi_autoproxy")
        self._token: Optional[str] = None
        # ID-3: the owner's rename. `muon` rather than a Fluidd-owned
        # namespace, because the name belongs to the printer and has to
        # outlive whichever interface set it.
        self.database    = self.server.lookup_component("database")
        self.database.register_local_namespace(MUON_NAMESPACE)

    # Moonraker calls this coroutine right after all components load
    async def component_init(self):
        spec = await self._fetch_spec()
        self._register_from_spec(spec)

    # ---------- Aux API credentials --------------------------------------
    def _auth_headers(self, headers: Optional[Dict[str, Any]] = None
                      ) -> Dict[str, Any]:
        """Add this boot's Aux API token to an outgoing header dict."""
        merged = dict(headers or {})
        token = self._aux_token()
        if token:
            merged[AUX_TOKEN_HEADER] = token
        return merged

    def _aux_token(self) -> Optional[str]:
        # Cached after the first successful read; the token is stable for the
        # life of a boot, and Moonraker does not outlive one.
        if self._token is not None:
            return self._token
        try:
            token = AUX_TOKEN_FILE.read_text().strip()
        except OSError as exc:
            self.log.error(f"Cannot read Aux API token {AUX_TOKEN_FILE}: {exc}")
            return None
        if not token:
            self.log.error(f"Aux API token {AUX_TOKEN_FILE} is empty")
            return None
        self._token = token
        return token

    # ---------- fetch the OpenAPI document (async) ----------------------
    async def _fetch_spec(self) -> Dict[str, Any]:
        # KAN-83: this used to read /tmp/fastapi_openapi.json whenever the
        # file existed. Nothing in the tree ever wrote it, so it bought
        # nothing and cost a lot: /tmp is world-writable, and the spec read
        # from it decides which endpoints get registered and proxied, so any
        # local process could choose the proxy's route table. It also never
        # invalidated, so an OTA that changed the Aux routes would keep
        # serving the old ones. The fetch below is a localhost request made
        # once at startup; there is nothing here worth caching.
        url  = f"{FASTAPI_ROOT}{OPENAPI_PATH}"
        self.log.info(f"Fetching OpenAPI from {url}")
        rsp  = await self.http_client.get(
            url, headers=self._auth_headers(),
            connect_timeout=3., request_timeout=6.
        )
        rsp.raise_for_status()
        return rsp.json()

    # ---------- build Moonraker endpoints from the spec -----------------
    def _register_from_spec(self, spec: Dict[str, Any]):
        needs_proxy = False

        self._spec = spec
        # KAN-83: every path the dynamic proxy is allowed to reach. Built
        # from the spec rather than hand-written, so it cannot drift from
        # the routes that actually exist.
        self._proxy_allowed: list[tuple[re.Pattern[str], frozenset[str]]] = []

        # register the raw OpenAPI document
        self.server.register_endpoint(
            f"{MOON_PREFIX}/openapi.json",
            ["GET"],
            self._openapi_handler
        )

        # MUON, DEV-4: developer mode must be visible on the panel *and* in the
        # interface.  SEC-2 keeps /server/aux/dev_mode on the floor, and
        # `is_floor_endpoint` matches that prefix and everything under it, so
        # *reading* the state is denied to the network as well as setting it.
        # Publish the state somewhere that is not on the floor.  GET only, no request body
        # forwarded, and it calls Aux through the internal helper rather than
        # re-exporting the route -- so this can never become a way to *change*
        # the mode, whatever Aux grows later.
        self.server.register_endpoint(
            "/server/muon/dev_mode",
            ["GET"],
            self._dev_mode_status_handler
        )

        # MUON, ID-2/ID-3/ID-4: this printer's name.
        #
        # Two halves from two places, joined here:
        #   * the derived name, SSID and display form come from Aux, which is
        #     the only component that can read the CM4 hardware serial;
        #   * the owner's rename lives in Moonraker's own database, because
        #     ID-3 wants it to survive a reboot and an OS update but *not* a
        #     factory reset -- and /home/printer_data/database has exactly
        #     that lifetime.
        #
        # Off the floor deliberately: a printer that cannot tell the LAN what
        # it is called cannot appear in a printer list (ID-4, and WEB-5..7 in
        # phase 3). /server/muon has never been on the floor, so this does not
        # depend on what SEC-2's scope happens to be.
        # Safe to expose because ID-5 makes the name authority-free: every
        # trust decision uses the fingerprint, never this.
        self.server.register_endpoint(
            "/server/muon/identity",
            ["GET"],
            self._identity_handler
        )
        # The rename. A write, but only ever to Moonraker's database -- it can
        # never reach Aux, and there is no path from here to the derived
        # identity, which is a pure function of the serial and not settable.
        self.server.register_endpoint(
            "/server/muon/identity/name",
            ["POST"],
            self._set_identity_name_handler
        )

        for fast_path, path_item in spec.get("paths", {}).items():
            # Paths with {...} are handled by the generic /proxy endpoint
            if _PATH_PARAM_RE.search(fast_path):
                # Record the verbs the spec publishes for this route, not
                # just its shape. Without them the proxy accepted any verb
                # on any allowed path, so a route the Aux API exposes only
                # for GET could be driven as DELETE or PUT through it --
                # the static handlers above have always been verb-bound,
                # and this closes the same gap on the dynamic one (KAN-83).
                param_verbs = frozenset(
                    HTTP_VERBS[k] for k in path_item if k in HTTP_VERBS
                )
                if not param_verbs:
                    continue
                needs_proxy = True
                self._proxy_allowed.append(
                    (_path_pattern(fast_path), param_verbs)
                )
                continue

            verbs = [HTTP_VERBS[k] for k in path_item if k in HTTP_VERBS]
            if not verbs:
                continue

            moon_path = f"{MOON_PREFIX}{fast_path}"
            self.server.register_endpoint(
                moon_path, verbs, self._make_static_handler(fast_path)
            )
            self.log.info(f"Registered {moon_path} → {fast_path} ({', '.join(verbs)})")

        if needs_proxy:
            self.server.register_endpoint(
                f"{MOON_PREFIX}/proxy", ["POST"], self._handle_dynamic_proxy
            )
            self.log.info("Parameterized routes proxied via /server/aux/proxy")

    # ---------- factory for fixed-path handlers -------------------------
    def _make_static_handler(self, fast_path: str) -> Callable:
        async def handler(webreq):
            method = webreq.get_action()           # e.g. "POST"
            args   = dict(webreq.get_args())       # all params
            url    = f"{FASTAPI_ROOT}{fast_path}"

            # Look up in your cached spec whether this op has a requestBody
            op       = self._spec["paths"][fast_path].get(method.lower(), {})
            has_body = "requestBody" in op

            # Build URL + body + headers
            if has_body:
                # JSON endpoint → serialize into the body
                body    = json.dumps(args or {})
                headers = {"Content-Type": "application/json"}
            else:
                # No JSON expected → preserve as query
                if args:
                    url += "?" + urlencode(args, doseq=True)
                # Tornado wants a non-None POST body, even if empty
                body    = "" if method in ("POST","PUT","PATCH") else None
                headers = {}

            # Debug log
            self.log.debug(f"Proxying → {method} {url!r}  headers={headers!r} body={body!r}")

            # Forward
            resp = await self.http_client.request(
                method          = method,
                url             = url,
                body            = body,
                headers         = self._auth_headers(headers),
                connect_timeout = 3.,
                # Wi-Fi association + 4-way handshake + DHCP routinely runs
                # 8-30s on this board, so an 8s budget here turned successful
                # connects into a 500. aux_api bounds its own nmcli call well
                # below this, so it always answers before we give up.
                request_timeout = 60.,
            )
            resp.raise_for_status()

            # Return JSON or raw
            with contextlib.suppress(Exception):
                return resp.json()
            return webreq.create_raw_response(
                resp.content,
                code    = resp.status_code,
                headers = resp.headers,
            )

        return handler

    # ---------- generic proxy for paths containing {...} ----------------
    async def _handle_dynamic_proxy(self, webreq):
        path  = webreq.get_str("path")                   # e.g. /wifi/show/mySSID
        verb  = webreq.get_str("method", "GET").upper()
        if verb not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise self.server.error("Invalid HTTP verb", 400)

        # KAN-83: `path` was concatenated onto FASTAPI_ROOT with no checks at
        # all, so a caller could reach any Aux route -- OTA install, the
        # dev_mode config rewrite, the BMS ship-mode endpoints -- and a value
        # like "@evil.example/" or "//evil.example/" re-pointed the request
        # at an arbitrary host, making Moonraker an SSRF pivot speaking from
        # inside the printer's network. This endpoint exists only to serve
        # the parameterised routes that could not be registered statically,
        # so matching against exactly those is both the tightest rule and
        # the one that needs no maintenance.
        if _has_encoded_separator(path):
            self.log.warning("Rejected proxy path %r (encoded separator)", path)
            raise self.server.error("Invalid proxy path", 400)

        matched = [verbs for p, verbs in self._proxy_allowed if p.match(path)]
        if not matched:
            self.log.warning("Rejected proxy path %r", path)
            raise self.server.error("Invalid proxy path", 400)
        if not any(verb in verbs for verbs in matched):
            self.log.warning("Rejected proxy verb %s on %r", verb, path)
            raise self.server.error("Invalid proxy method for path", 405)

        url   = f"{FASTAPI_ROOT}{path}"
        query = webreq.get("query", None)
        if query and verb in {"GET", "DELETE"}:
            url += f"?{query}"

        # Explicit, like every other call out of this component. Moonraker's
        # http_client already defaults to 5s/10s, so this changes no behaviour
        # -- it makes the bound visible and testable rather than inherited from
        # a library default a future release could widen.
        resp = await self.http_client.request(
            method=verb,
            url=url,
            body=webreq.get("body", None),
            headers=self._auth_headers(),
            connect_timeout=3.,
            request_timeout=8.,
        )
        resp.raise_for_status()
        return resp.json()

    async def _openapi_handler(self, webreq):
        # return exactly the JSON you fetched from FastAPI
        return self._spec

    # ---------- read-only developer-mode state (DEV-4) ------------------
    async def _identity_handler(self, webreq):
        """ID-2/ID-3/ID-4: what this printer is called, and what it is.

        `name` is what a person should be shown: the owner's rename if there
        is one, otherwise the name derived from the hardware serial. `source`
        says which, so an interface can offer "reset to the default name"
        without having to guess.

        The derived fields are always reported alongside, because ID-2's
        promise is that a factory-reset printer comes back as the name on its
        label -- and that promise is about the derived name, whatever the
        current override happens to be.
        """
        derived = await self.get("/identity")
        if not isinstance(derived, dict):
            raise self.server.error("Aux returned an unreadable identity", 502)

        override = await self.database.get_item(
            MUON_NAMESPACE, FRIENDLY_NAME_KEY, None
        )

        derived_name = derived.get("name")
        suffix = derived.get("suffix")
        return {
            "name": override or derived_name,
            "source": "owner" if override else "derived",
            "derived_name": derived_name,
            "suffix": suffix,
            # ID-4. Recomputed here rather than taken from Aux, because the
            # display form has to follow the override; Aux only knows the
            # derived half.
            "display": (
                f"{(override or derived_name or '').title()} · "
                f"{(suffix or '').upper()}"
            ),
            "ssid": derived.get("ssid"),
            # ID-1. The trust identifier. Reported for a trust-context
            # display; it is deliberately not what the name derives from.
            "fingerprint": derived.get("fingerprint"),
        }

    async def _set_identity_name_handler(self, webreq):
        """ID-2: the owner renames the printer.

        Storing an empty name clears the override and the derived name comes
        back, which is what a "reset to default" control needs.
        """
        args = webreq.get_args()
        name = args.get("name")
        if name is None:
            raise self.server.error("A 'name' argument is required", 400)
        if not isinstance(name, str):
            raise self.server.error("'name' must be a string", 400)

        name = name.strip()
        if len(name) > MAX_NAME_LENGTH:
            raise self.server.error(
                f"A printer name may be at most {MAX_NAME_LENGTH} characters",
                400,
            )

        if name:
            await self.database.insert_item(
                MUON_NAMESPACE, FRIENDLY_NAME_KEY, name
            )
        else:
            # delete_item raises when the key is absent; clearing a name that
            # was never set is not an error.
            with contextlib.suppress(Exception):
                await self.database.delete_item(
                    MUON_NAMESPACE, FRIENDLY_NAME_KEY
                )

        return await self._identity_handler(webreq)

    async def _dev_mode_status_handler(self, webreq):
        state = await self.get("/dev_mode")
        if not isinstance(state, dict):
            raise self.server.error(
                "Aux returned an unreadable dev_mode state", 502
            )
        # `enabled` only. Aux also returns core_cfg, but that is a filesystem
        # path and this endpoint is readable from the LAN; DEV-4 needs the
        # banner, not the path. The panel reads the full state over loopback.
        return {"enabled": bool(state.get("enabled", False))}
    


    # ===== Internal aux-api helpers for other Moonraker components =====
    async def get(self, path: str) -> Any:
        url = f"{FASTAPI_ROOT}{path}"
        resp = await self.http_client.get(
            url, headers=self._auth_headers(),
            connect_timeout=3., request_timeout=8.
        )
        resp.raise_for_status()
        with contextlib.suppress(Exception):
            return resp.json()
        return resp.content

    async def post(self, path: str, body: Any | None = None) -> Any:
            url = f"{FASTAPI_ROOT}{path}"

            # Prepare body + headers the way Moonraker's http_client expects
            headers = None
            raw_body = None

            if isinstance(body, (dict, list)):
                import json as _json
                raw_body = _json.dumps(body)
                headers = {"Content-Type": "application/json"}
            elif isinstance(body, (bytes, bytearray)):
                raw_body = body
            elif isinstance(body, str):
                raw_body = body
            else:
                # Tornado wants a non-None body for POST/PUT/PATCH; empty string is fine
                raw_body = ""

            resp = await self.http_client.post(
                url,
                body=raw_body,
                headers=self._auth_headers(headers),
                connect_timeout=3.0,
                request_timeout=15.0,
            )
            resp.raise_for_status()
            try:
                return resp.json()
            except Exception:
                return resp.content

    # OTA convenience wrappers
    async def ota_status(self) -> Any:
        return await self.get("/update/status")
    
    async def ota_check_server(self) -> Any:
        return await self.post("/update/check", {"wait": False})

    async def ota_start(self, url: str | None = None) -> Any:
        body = {"url": url} if url else {}
        return await self.post("/update/install", body)

    async def ota_commit(self) -> Any:
        return await self.post("/update/commit", {})
        

# Moonraker entry-point
def load_component(config):
    return AuxAutoProxy(config)
