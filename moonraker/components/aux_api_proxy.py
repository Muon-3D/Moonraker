# Moonraker component — wifi_autoproxy.py
#
# Enable it with a bare section in moonraker.conf:
#     [aux_api_proxy]
#
# ──────────────────────────────────────────────────────────────────────────
import json
import logging
import os
import re
import contextlib
import unicodedata
from pathlib import Path
from typing import Dict, Any, Callable, Optional
from urllib.parse import unquote, urlencode

from tornado.httpclient import HTTPClientError

from .. import muon_access_policy as policy
from ..utils import ServerError
from ..utils import redact

FASTAPI_ROOT = "http://127.0.0.1:6789"  # loopback-only Aux API bind
OPENAPI_PATH = "/openapi.json"  # FastAPI default
MOON_PREFIX = "/server/aux"  # Moonraker namespace

# The Aux API rejects every unauthenticated request. The shared secret is
# reissued into tmpfs on each boot by aux_api_token.service and is readable by
# the printer_admin group, which the moonraker user belongs to.
AUX_TOKEN_FILE = Path(os.getenv("AUX_API_TOKEN_FILE", "/run/aux_api/token"))
AUX_TOKEN_HEADER = "X-Aux-Api-Key"

# KAN-4297: the HTTP client's address, for the Aux API to tell a device on
# the printer's own hotspot from anyone else (MuonOS #554). The Aux API trusts
# it only from a loopback peer, which Moonraker is.
CLIENT_IP_HEADER = "X-Muon-Client-Ip"

# Map lower-case OpenAPI keys → canonical HTTP verbs
HTTP_VERBS = {"get": "GET", "post": "POST", "put": "PUT",
              "patch": "PATCH", "delete": "DELETE"}

_PATH_PARAM_RE = re.compile(r"\{[^}]+\}")

# KAN-3604: Aux routes that only Moonraker's own handlers may call, through
# the internal helper. They are never mirrored under /server/aux. The `dev_mode`
# access row is delegated to Aux, so a mirror of /dev_mode/request would let any
# admitted client skip the owner rule that guards /server/muon/dev_mode/request.
INTERNAL_ONLY_AUX_PATHS = frozenset({"/dev_mode/request"})

# KAN-3603: the Aux API's own ZONE_NAME (time_routes.py), copied. Aux still
# checks that tzdata carries the zone; this keeps junk from being forwarded.
ZONE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$")

# KAN-4351: a challenge id as the Aux API makes them (Control checks the same
# shape before it sends one). Anything else is never put into an Aux path.
CHALLENGE_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
# The longest waiver version forwarded to Aux.
MAX_WAIVER_VERSION = 64
# A refusal code Control can read: `dev-mode:<code>: <why>`.
REFUSAL_CODE = re.compile(r"^[a-z_]+$")
# What the Aux API says with a bare status and no code of its own.
REFUSAL_CODE_BY_STATUS = {428: "consent_required", 429: "throttled"}


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


def _aux_error_message(resp: Any) -> Optional[str]:
    """The Aux API's own explanation of a failed response, if it gave one.

    Every error on the Aux API's OTA routes is shaped by
    `update_routes._http_error` as

        {"detail": {"code": "invalid_state", "message": "<why>"}}

    and `raise_for_status()` with no argument throws all of that away: Tornado's
    HTTPError carries only the reason phrase, so a refusal the Aux API took
    care to explain reaches Fluidd as the bare word "Conflict". That is
    unfixable in a client, because the client is never sent the body.

    The body has not gone anywhere -- http_client fetches with
    `raise_error=False` and keeps `resp.body` whatever the status -- so this is
    a read of something already in hand, not a second request.

    Returns None when there is nothing better to say, which leaves
    `raise_for_status()`'s own message in place. Three shapes are handled
    because the Aux API uses all three: FastAPI's own validation errors are a
    LIST of detail objects, `HTTPException(detail="...")` is a plain string,
    and the Muon routes use the dict above.
    """
    try:
        payload = resp.json()
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    detail = payload.get("detail")
    if isinstance(detail, str):
        return detail.strip() or None
    if isinstance(detail, dict):
        message = detail.get("message")
        return message.strip() or None if isinstance(message, str) else None
    if isinstance(detail, list):
        # FastAPI validation errors: take the first one that names itself.
        for item in detail:
            if isinstance(item, dict) and isinstance(item.get("msg"), str):
                return item["msg"].strip() or None
    return None


def _aux_error_code(resp: Any) -> Optional[str]:
    """The Aux API's `detail.code`, e.g. `printer_busy` on a refused install.

    Kept so a caller can branch on the code rather than the English message
    (KAN-203: muon_setup maps 409s and 422s by it).
    """
    try:
        payload = resp.json()
    except Exception:
        return None
    detail = payload.get("detail") if isinstance(payload, dict) else None
    code = detail.get("code") if isinstance(detail, dict) else None
    return code if isinstance(code, str) and code else None


def _aux_error_detail(resp: Any) -> Optional[dict]:
    """The Aux API's `detail` when it is an object, else None. KAN-3358: a
    failed Wi-Fi join's detail carries `restored` and `restore_detail` beside
    the code, and the caller reads them from here."""
    try:
        payload = resp.json()
    except Exception:
        return None
    detail = payload.get("detail") if isinstance(payload, dict) else None
    return dict(detail) if isinstance(detail, dict) else None


def _raise_for_aux_status(resp: Any) -> None:
    """raise_for_status with the Aux API's own message, and its `detail.code`
    attached to the ServerError as `aux_code`."""
    try:
        resp.raise_for_status(_aux_error_message(resp))
    except Exception as exc:
        setattr(exc, "aux_code", _aux_error_code(resp))
        setattr(exc, "aux_detail", _aux_error_detail(resp))
        raise


def _not_answering(exc: ServerError) -> bool:
    """A timeout (599), or a 500 that no HTTP response stands behind."""
    if exc.status_code == 599:
        return True
    return exc.status_code == 500 and not isinstance(
        exc.__cause__, HTTPClientError)


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
        self.server = config.get_server()
        self.http_client = self.server.lookup_component("http_client")
        self.log = logging.getLogger("wifi_autoproxy")
        self._token: Optional[str] = None
        # ID-3: the owner's rename. `muon` rather than a Fluidd-owned
        # namespace, because the name belongs to the printer and has to
        # outlive whichever interface set it.
        self.database = self.server.lookup_component("database")
        self.database.register_local_namespace(MUON_NAMESPACE)
        # MR-9 (KAN-203): the Muon endpoints below are served by the helpers,
        # not mirrored from the spec, so they do not need the spec to exist.
        # They used to be registered only after _fetch_spec() succeeded, so an
        # Aux API that was late at boot made component_init raise and left
        # them missing until Moonraker restarted: a printer that could not
        # say its own name. Registered here, they answer 503 until Aux does.
        self._register_muon_endpoints()

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

    def _client_ip_headers(self, webreq: Any,
                           headers: Optional[Dict[str, Any]] = None
                           ) -> Dict[str, Any]:
        """Set X-Muon-Client-Ip from the address Moonraker resolved for this
        request (WebRequest.get_ip_address(): tornado's remote_ip, which takes
        X-Real-IP from the trusted local nginx and is validated by
        validate_real_ip_header). Any value the caller supplied is dropped
        first. Omitted unless the request is plain HTTP from a client:
        websocket/JSON-RPC, unix-socket, MQTT and internal calls get none."""
        merged = {k: v for k, v in (headers or {}).items()
                  if k.lower() != CLIENT_IP_HEADER.lower()}
        is_http = getattr(webreq, "is_plain_http", None)
        get_ip = getattr(webreq, "get_ip_address", None)
        if is_http is None or get_ip is None or not is_http():
            return merged
        ip = get_ip()
        if ip is not None:
            merged[CLIENT_IP_HEADER] = str(ip)
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
        url = f"{FASTAPI_ROOT}{OPENAPI_PATH}"
        self.log.info(f"Fetching OpenAPI from {url}")
        rsp = await self.http_client.get(
            url, headers=self._auth_headers(),
            connect_timeout=3., request_timeout=6.
        )
        rsp.raise_for_status()
        return rsp.json()

    # ---------- Muon endpoints served by the helpers --------------------
    def _register_muon_endpoints(self) -> None:
        # MUON, DEV-4: developer mode must be visible on the panel *and* in the
        # interface.  SEC-2 keeps /server/aux/dev_mode on the floor, and
        # `is_floor_endpoint` matches that prefix and everything under it, so
        # *reading* the state is denied to the network as well as setting it.
        # Publish the state somewhere that is not on the floor. GET only, with no
        # request body
        # forwarded, and it calls Aux through the internal helper rather than
        # re-exporting the route -- so this can never become a way to *change*
        # the mode, whatever Aux grows later.
        self.server.register_endpoint(
            "/server/muon/dev_mode",
            ["GET"],
            self._dev_mode_status_handler
        )
        # KAN-3604 / KAN-4351 (Jack, 17 Nov): Control asks for developer mode
        # on or off through this one route, and only ever to Aux's
        # /dev_mode/request, /dev_mode/waiver, /dev_mode/consent/<id> and
        # /dev_mode through the internal helper below -- never a pass-through
        # of /server/aux, which stays the panel's under the `dev_mode` row.
        #   GET                  who may ask, and the waiver turning on agrees to
        #   GET ?challenge_id    has the person at the printer answered
        #   POST {enabled}       ask: a panel challenge, or applied at once
        #   POST {enabled, challenge_id, waiver_*}   make the confirmed change
        # Who may ask is decided centrally (muon_access_policy's
        # `dev_mode_request` row, on the POSTs: anyone on an open printer with
        # no owner, the owning account on a linked one, the Protected entry
        # respected). A GET is a read, so a client that may not ask can still
        # be told who may. Off the floor like the GET above.
        self.server.register_endpoint(
            "/server/muon/dev_mode/request",
            ["GET", "POST"],
            self._dev_mode_request_handler
        )

        # KAN-3603 (Jack, 17 Nov): the time zone from Control after set-up.
        # GET reads Aux's /time, POST sets it through Aux's /time/zone (the
        # existing timedatectl set-timezone path; sudoers is not widened).
        # Who may do either is muon_access_policy's `timezone` row, the same
        # for both. Never a pass-through of /server/aux.
        self.server.register_endpoint(
            "/server/muon/timezone",
            ["GET", "POST"],
            self._timezone_handler
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

            if fast_path in INTERNAL_ONLY_AUX_PATHS:
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
            method = webreq.get_action()  # e.g. "POST"
            args = dict(webreq.get_args())  # all params
            url = f"{FASTAPI_ROOT}{fast_path}"

            # Look up in your cached spec whether this op has a requestBody
            op = self._spec["paths"][fast_path].get(method.lower(), {})
            has_body = "requestBody" in op

            # Build URL + body + headers
            if has_body:
                # JSON endpoint → serialize into the body
                body = json.dumps(args or {})
                headers = {"Content-Type": "application/json"}
            else:
                # No JSON expected → preserve as query
                if args:
                    url += "?" + urlencode(args, doseq=True)
                # Tornado wants a non-None POST body, even if empty
                body = "" if method in ("POST", "PUT", "PATCH") else None
                headers = {}

            # Debug log. Redacted: a body or query can carry a password, a
            # hotspot key or the waiver signer's name (utils/redact.py).
            self.log.debug(
                f"Proxying → {method} {redact.redact_url(url)!r} "
                f"headers={headers!r} body={redact.redact_json_text(body)!r}"
            )

            # Forward
            resp = await self.http_client.request(
                method=method,
                url=url,
                body=body,
                headers=self._auth_headers(
                    self._client_ip_headers(webreq, headers)),
                connect_timeout=3.,
                # Wi-Fi association + 4-way handshake + DHCP routinely runs
                # 8-30s on this board, so an 8s budget here turned successful
                # connects into a 500. aux_api bounds its own nmcli call well
                # below this, so it always answers before we give up.
                request_timeout=60.,
            )
            resp.raise_for_status(_aux_error_message(resp))

            # Return JSON or raw
            with contextlib.suppress(Exception):
                return resp.json()
            return webreq.create_raw_response(
                resp.content,
                code=resp.status_code,
                headers=resp.headers,
            )

        return handler

    # ---------- generic proxy for paths containing {...} ----------------
    async def _handle_dynamic_proxy(self, webreq):
        path = webreq.get_str("path")  # e.g. /wifi/show/mySSID
        verb = webreq.get_str("method", "GET").upper()
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

        url = f"{FASTAPI_ROOT}{path}"
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
            headers=self._auth_headers(self._client_ip_headers(webreq)),
            connect_timeout=3.,
            request_timeout=8.,
        )
        resp.raise_for_status(_aux_error_message(resp))
        return resp.json()

    async def _openapi_handler(self, webreq):
        # return exactly the JSON you fetched from FastAPI
        return self._spec

    # ---------- the printer's name (ID-2/ID-3/ID-4) ---------------------
    async def _identity_handler(self, webreq):
        return await self.get_identity()

    async def get_identity(self) -> Dict[str, Any]:
        """ID-2/ID-3/ID-4: what this printer is called, and what it is.

        Public so muon_setup reads the same answer as GET
        /server/muon/identity (KAN-203, spec 02 §5.7).

        `name` is what a person should be shown: the owner's rename if there
        is one, otherwise the name derived from the hardware serial. `source`
        says which, so an interface can offer "reset to the default name"
        without having to guess.

        The derived fields are always reported alongside, because ID-2's
        promise is that a factory-reset printer comes back as the name on its
        label -- and that promise is about the derived name, whatever the
        current override happens to be.
        """
        derived = await self._get_or_unavailable("/identity")
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
            # KAN-403. The Iroh EndpointId muon-link publishes, or None before
            # it has run or from an Aux that predates the field. Public by
            # design (PRIV-6): a client matches a printer found on the LAN to
            # the one in its account with it. A match key, not a trust
            # decision; the Iroh handshake proves the key.
            "endpoint_id": derived.get("endpoint_id"),
            # ID-1. The trust identifier. Reported for a trust-context
            # display; it is deliberately not what the name derives from.
            "fingerprint": derived.get("fingerprint"),
            # KAN-203 (spec 02 §7): whether this printer still needs setting
            # up, so an app that finds it can route it (06 §1).
            "setup": self._setup_state(),
            # KAN-3993: open | protected, the same value muon-link's GET
            # /pairing reports. Lets a client hide "Ask for access" on an
            # Open printer. Read-only; fails closed to "protected".
            "entry": self._entry(),
        }

    @staticmethod
    def _entry() -> str:
        """open iff the protection level is Open (muon_floor, the same level
        muon-link reads for GET /pairing); anything else, or any error,
        is protected."""
        try:
            from .. import muon_floor
            if muon_floor.protection_level() == muon_floor.LEVEL_OPEN:
                return "open"
        except Exception:
            logging.exception("Could not read the protection level")
        return "protected"

    def _setup_state(self) -> Optional[str]:
        """new | in_progress | complete, from muon_setup, or None when it is
        not configured on this printer."""
        setup = self.server.lookup_component("muon_setup", None)
        if setup is None:
            return None
        state = setup.public_state().get("state")
        return state if isinstance(state, str) else None

    async def _get_or_unavailable(self, path: str) -> Any:
        """GET from Aux for the Muon endpoints registered in __init__.

        While Aux is not answering -- late at boot, or restarting -- they say
        503, which a client should retry, instead of the 500 a refused
        connection turns into, which reads as a fault (02 §7).

        Only "not answering" becomes 503. http_client reports a timeout as 599
        and a failed connection as 500 with no HTTP error behind it; a 500
        that Aux really answered carries Tornado's HTTPClientError as its
        cause, and keeps its status.
        """
        try:
            return await self.get(path)
        except ServerError as exc:
            if _not_answering(exc):
                raise self.server.error(
                    f"The Aux API is not answering yet ({path})", 503
                ) from exc
            raise

    async def _set_identity_name_handler(self, webreq):
        """ID-2: the owner renames the printer.

        Storing an empty name clears the override and the derived name comes
        back, which is what a "reset to default" control needs.
        """
        args = webreq.get_args()
        name = args.get("name")
        if name is None:
            raise self.server.error("A 'name' argument is required", 400)
        return await self.set_friendly_name(name)

    async def set_friendly_name(self, name: Any) -> Dict[str, Any]:
        """Store the owner's rename, or clear it with an empty name, and
        return the identity. Public so muon_setup's name step applies the
        same rules as POST /server/muon/identity/name (spec 02 §5.7)."""
        # Settings' rename answers with the identity, so ask Aux first: a
        # 503 after the write would report a failure for a rename that
        # happened. muon_setup's name step uses store_friendly_name(), which
        # works with Aux down (02 §5.7).
        await self._get_or_unavailable("/identity")
        await self.store_friendly_name(name)
        return await self.get_identity()

    async def store_friendly_name(self, name: Any) -> str:
        """The rename alone, with no Aux call: it lives in Moonraker's
        database, so it can be saved while Aux is down. Returns the name as
        stored, stripped; "" means the override was cleared."""
        if not isinstance(name, str):
            raise self.server.error("'name' must be a string", 400)

        name = name.strip()
        # 02 §5.7: no control characters (C0, C1, newlines), and the length
        # is counted in code points, which is what len() of a str counts.
        if any(unicodedata.category(ch) == "Cc" for ch in name):
            raise self.server.error(
                "A printer name may not contain control characters", 400)
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
        return name

    async def _dev_mode_status_handler(self, webreq):
        state = await self._get_or_unavailable("/dev_mode")
        if not isinstance(state, dict):
            raise self.server.error(
                "Aux returned an unreadable dev_mode state", 502
            )
        # `enabled` only. Aux also returns core_cfg, but that is a filesystem
        # path and this endpoint is readable from the LAN; DEV-4 needs the
        # banner, not the path. The panel reads the full state over loopback.
        return {"enabled": bool(state.get("enabled", False))}


    def _dev_mode_refusal(self, exc: ServerError, path: str,
                          gone_code: Optional[str] = None) -> Exception:
        """What a failed Aux call means to Control: `dev-mode:<code>: <why>`
        with the Aux API's own words, or the plain 503 while it is not
        answering. An error with no code to name is returned as it was."""
        if _not_answering(exc):
            return self.server.error(
                f"The Aux API is not answering yet ({path})", 503)
        detail = getattr(exc, "aux_detail", None) or {}
        code = getattr(exc, "aux_code", None) or detail.get("error")
        status = exc.status_code
        if not isinstance(code, str):
            code = REFUSAL_CODE_BY_STATUS.get(status)
            if code is None and status == 404:
                code = gone_code
        if not isinstance(code, str) or not REFUSAL_CODE.match(code):
            return exc
        return self.server.error(f"dev-mode:{code}: {exc}", status)

    async def _dev_mode_waiver(self) -> Optional[Dict[str, str]]:
        """The waiver turning developer mode on agrees to, from Aux's
        GET /dev_mode/waiver, or None when Aux cannot say (an older Aux, or
        not answering): the caller then has no waiver to show."""
        try:
            waiver = await self.get("/dev_mode/waiver")
        except ServerError:
            return None
        if (isinstance(waiver, dict)
                and isinstance(waiver.get("version"), str)
                and isinstance(waiver.get("text"), str)):
            return {"version": waiver["version"], "text": waiver["text"]}
        return None

    async def _dev_mode_request_handler(self, webreq):
        args = webreq.get_args()
        if webreq.get_action() == "GET":
            if "challenge_id" in args:
                return await self._dev_mode_answer(args["challenge_id"])
            return await self._dev_mode_who_may_ask(webreq)
        enabled = args.get("enabled")
        if not isinstance(enabled, bool):
            raise self.server.error("'enabled' must be true or false", 400)
        if args.get("challenge_id") is not None:
            return await self._dev_mode_complete(enabled, args)
        return await self._dev_mode_ask(enabled)

    async def _dev_mode_who_may_ask(self, webreq) -> Dict[str, Any]:
        """GET with nothing: whether this connection is the printer's owner,
        who owns it, whether this connection may ask, and the waiver."""
        state = policy.state()
        principal = None
        if state is not None:
            get_user = getattr(webreq, "get_current_user", None)
            principal = policy.resolve_principal(
                getattr(webreq, "transport", None),
                webreq.get_ip_address(),
                get_user() if callable(get_user) else None,
                state.entry,
                state.home,
            )
        as_owner = principal is not None and principal.level >= policy.ADMIN
        may_ask = state is not None and policy.decide_action(
            policy.ACTIONS["dev_mode_request"], principal, state).allowed
        linked: Optional[bool] = None
        if state is not None:
            if state.owner == policy.OWNER_NONE:
                linked = False
            elif state.owner != policy.OWNER_UNKNOWN:
                linked = True
        account = None
        if linked:
            access = self.server.lookup_component("muon_access", None)
            email = getattr(access, "owner_email", None)
            if isinstance(email, str) and email:
                # Anyone who can read may GET this, and everyone is shown the
                # whole address so a guest knows who to ask (D-176).
                account = email
        return {
            "as_owner": as_owner,
            "may_ask": may_ask,
            "owner": {"linked": linked, "account": account},
            "waiver": await self._dev_mode_waiver(),
        }

    async def _dev_mode_answer(self, challenge_id: Any) -> Dict[str, Any]:
        """GET ?challenge_id: has the person at the printer answered. Aux's
        GET /dev_mode/consent/<id> only reads; it advances nothing."""
        if (not isinstance(challenge_id, str)
                or not CHALLENGE_ID.match(challenge_id)):
            raise self.server.error("'challenge_id' is not a challenge id", 400)
        try:
            state = await self.get(f"/dev_mode/consent/{challenge_id}")
        except ServerError as exc:
            raise self._dev_mode_refusal(
                exc, "/dev_mode/consent", "unknown_challenge") from exc
        if not isinstance(state, dict) or not isinstance(
                state.get("confirmed"), bool):
            raise self.server.error(
                "Aux returned an unreadable dev_mode answer", 502)
        return {
            "confirmed": state["confirmed"],
            "refused": state.get("refused") is True,
        }

    async def _dev_mode_ask(self, enabled: bool) -> Dict[str, Any]:
        """POST {enabled}: Aux either opens a challenge on the panel (the
        first release of the warranty) or applies the change at once. Its
        answer is passed through as it is: Control follows what it says."""
        try:
            result = await self.post("/dev_mode/request", {"enabled": enabled})
        except ServerError as exc:
            raise self._dev_mode_refusal(exc, "/dev_mode/request") from exc
        if not isinstance(result, dict):
            raise self.server.error(
                "Aux returned an unreadable dev_mode answer", 502)
        if result.get("challenge_id"):
            challenge: Dict[str, Any] = {
                "challenge_id": result["challenge_id"],
                "enabled": (result["enabled"]
                            if isinstance(result.get("enabled"), bool)
                            else enabled),
            }
            for key in ("expires_in_seconds", "instruction"):
                if result.get(key) is not None:
                    challenge[key] = result[key]
            # Turning on is what the waiver is for.
            if enabled:
                challenge["waiver"] = await self._dev_mode_waiver()
            return challenge
        return {"enabled": bool(result.get("enabled", False))}

    async def _dev_mode_complete(self, enabled: bool,
                                 args: Dict[str, Any]) -> Dict[str, Any]:
        """POST {enabled, challenge_id, waiver_acknowledged, waiver_version}:
        make the change the person at the printer confirmed, through Aux's
        POST /dev_mode. Only those four fields are forwarded."""
        challenge_id = args["challenge_id"]
        if (not isinstance(challenge_id, str)
                or not CHALLENGE_ID.match(challenge_id)):
            raise self.server.error("'challenge_id' is not a challenge id", 400)
        body: Dict[str, Any] = {"enabled": enabled,
                                "challenge_id": challenge_id}
        if enabled:
            body["waiver_acknowledged"] = (
                args.get("waiver_acknowledged") is True)
            version = args.get("waiver_version")
            if isinstance(version, str) and version:
                if len(version) > MAX_WAIVER_VERSION:
                    raise self.server.error(
                        "dev-mode:bad_request: 'waiver_version' is too long",
                        400)
                body["waiver_version"] = version
        try:
            # Turning on restarts Klipper: Aux takes its time over it.
            result = await self.post("/dev_mode", body, timeout=60.0)
        except ServerError as exc:
            raise self._dev_mode_refusal(exc, "/dev_mode") from exc
        if not isinstance(result, dict):
            raise self.server.error(
                "Aux returned an unreadable dev_mode answer", 502)
        return {"enabled": bool(result.get("enabled", False))}

    async def _timezone_handler(self, webreq):
        if webreq.get_action() == "GET":
            state = await self._get_or_unavailable("/time")
            if not isinstance(state, dict) or not isinstance(
                    state.get("tz"), str):
                raise self.server.error(
                    "Aux returned an unreadable time state", 502)
            return {"zone": state["tz"]}
        zone = webreq.get_args().get("zone")
        if (not isinstance(zone, str) or not ZONE_NAME.match(zone)
                or ".." in zone):
            raise self.server.error("'zone' must be an IANA zone name", 400)
        try:
            state = await self.post("/time/zone", {"tz": zone})
        except ServerError as exc:
            if getattr(exc, "aux_code", None) == "invalid_timezone":
                raise self.server.error(
                    f"{zone!r} is not a time zone this printer knows", 400
                ) from exc
            if _not_answering(exc):
                raise self.server.error(
                    "The Aux API is not answering yet (/time/zone)", 503
                ) from exc
            raise
        if not isinstance(state, dict) or not isinstance(state.get("tz"), str):
            raise self.server.error("Aux returned an unreadable time state", 502)
        return {"zone": state["tz"]}

    # ===== Internal aux-api helpers for other Moonraker components =====
    async def get(self, path: str) -> Any:
        url = f"{FASTAPI_ROOT}{path}"
        resp = await self.http_client.get(
            url, headers=self._auth_headers(),
            connect_timeout=3., request_timeout=8.
        )
        _raise_for_aux_status(resp)
        with contextlib.suppress(Exception):
            return resp.json()
        return resp.content

    async def post(self, path: str, body: Any | None = None,
                   timeout: float = 15.0) -> Any:
        # `timeout` is for the few calls that legitimately run long: the
        # region apply (~8 s, 60 s limit) and a waited update check (KAN-203).
        url = f"{FASTAPI_ROOT}{path}"

        # Prepare body + headers the way Moonraker's http_client expects.
        headers = None
        raw_body: str | bytes | bytearray | None = None

        if isinstance(body, (dict, list)):
            raw_body = json.dumps(body)
            headers = {"Content-Type": "application/json"}
        elif isinstance(body, (bytes, bytearray)):
            raw_body = body
        elif isinstance(body, str):
            raw_body = body
        else:
            # Tornado wants a non-None body for POST/PUT/PATCH; empty string is fine.
            raw_body = ""

        resp = await self.http_client.post(
            url,
            body=raw_body,
            headers=self._auth_headers(headers),
            connect_timeout=3.0,
            request_timeout=timeout,
        )
        _raise_for_aux_status(resp)
        try:
            return resp.json()
        except Exception:
            return resp.content

    async def delete(self, path: str) -> Any:
        """DELETE, for muon_setup's development reset of the setup marker
        (KAN-203; DELETE /setup/complete, MuonOS OS-7). Same bounds as get()."""
        resp = await self.http_client.request(
            method="DELETE",
            url=f"{FASTAPI_ROOT}{path}",
            headers=self._auth_headers(),
            connect_timeout=3.,
            request_timeout=8.,
        )
        _raise_for_aux_status(resp)
        with contextlib.suppress(Exception):
            return resp.json()
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
