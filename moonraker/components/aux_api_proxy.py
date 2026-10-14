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
from typing import Dict, Any, Callable, Optional, Tuple
from urllib.parse import unquote, urlencode

from tornado.httpclient import HTTPClientError

from .. import muon_floor
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


def _raise_for_aux_status(resp: Any) -> None:
    """raise_for_status with the Aux API's own message, and its `detail.code`
    attached to the ServerError as `aux_code`."""
    try:
        resp.raise_for_status(_aux_error_message(resp))
    except Exception as exc:
        setattr(exc, "aux_code", _aux_error_code(resp))
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
# KAN-547: a developer-mode request, and who it is from.
#
# Jack's rule (2026-10-09, "no exceptions" 2026-10-14): every developer-mode
# change, on and off, is confirmed at the printer's panel. A printer nobody
# owns takes a request from anyone; a linked printer only from its owning
# account, from anywhere. The Aux API enforces that (dev_mode_owner, MuonOS
# #378). What it cannot do is tell who is asking: it never sees a client.
# Moonraker can, so this route is the one place that vouches for the owner.
#
# Who is the owner here: a request through muon-link's gateway (the sentinel
# address and a token muon_gateway minted) whose token names the admin level
# explicitly, with the Operator role. Admin is the level of the owner's
# enrolled devices (ACC-20, ADR 0037), and no grant carries it (NET-11).
# Nothing else is the owner:
#
#   * NOT a token that names no level. muon_access_policy._gateway_principal
#     reads such a token as admin, so that a muon-link from before the
#     principal existed keeps working; here that default would make every
#     remote session the owner, app.muon3d.com's Operator sessions included.
#     Only the level the token states counts.
#   * NOT the panel or anything else on loopback. On a linked printer the
#     panel confirms the owner's request and cannot make one, and any process
#     on the device is loopback too.
#   * NOT a LAN browser, signed in with the printer password or not. The
#     password is the printer's, not the account's.
#
# Everyone may still use the route: on a printer nobody owns, Aux takes their
# request; on a linked one, Aux answers owner_required and names the account.
# The decision stays in one place, and this route only adds what is true.
#
# The headers cannot be forged through the rest of this component. Every
# other call out builds its upstream headers from scratch and forwards none
# of the caller's (_make_static_handler, _handle_dynamic_proxy, get/post).
DEV_MODE_REQUEST_ENDPOINT = "/server/muon/dev_mode/request"
OWNER_LEVEL_HEADER = "X-Muon-Access-Level"
OWNER_PRINCIPAL_HEADER = "X-Muon-Principal"
#: muon_access_policy's name for the owner's level (ACC-7, ACC-9).
OWNER_LEVEL = "admin"
#: Only an Operator changes anything; a Viewer watches (ACC-11).
OWNER_ROLE = "operator"
# As muon_gateway checks a principal, and as Aux re-checks the header.
_PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9._:@+-]{1,128}$")
# Aux mints challenge ids with secrets.token_urlsafe(24): 32 URL-safe
# characters. A path segment, so nothing that could start another one.
_CHALLENGE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
# The redeem's optional fields, and their types. Nothing else is forwarded.
_REDEEM_FIELDS = {
    "waiver_acknowledged": bool,
    "waiver_version": str,
    "signer_name": str,
    "reentry_token": str,
}
# Open and poll are quick. A redeem backs up and clones the developer tree and
# restarts Klipper, which Aux waits up to 60 s for.
DEV_MODE_OPEN_TIMEOUT = 8.
DEV_MODE_REDEEM_TIMEOUT = 120.
# muon-link's LinkPhase, as Aux's dev_mode_owner reads it: `linked` names the
# owner, every other known phase is a printer nobody owns, and a phase this
# code does not know is no answer.
LINKED_PHASE = "linked"
UNOWNED_PHASES = frozenset(
    ("unavailable", "unlinked", "connecting", "code", "offer", "failed"))


def owner_headers(ip_addr: Any, user: Any) -> Dict[str, str]:
    """The headers that tell Aux a request is the owner's, or {}.

    See the block above for who that is. Reads the token's own fields and
    never muon_access_policy.resolve_principal, whose default for a token that
    names nothing is admin.
    """
    if not muon_floor._is_gateway_address(ip_addr):
        return {}
    if user is None or getattr(
            user, "source", None) != muon_floor.GATEWAY_USER_SOURCE:
        return {}
    if getattr(user, "access_level", None) != OWNER_LEVEL:
        return {}
    if getattr(user, "access_role", None) != OWNER_ROLE:
        return {}
    headers = {OWNER_LEVEL_HEADER: OWNER_LEVEL}
    name = getattr(user, "principal", "") or getattr(user, "username", "")
    if isinstance(name, str) and _PRINCIPAL_RE.match(name):
        headers[OWNER_PRINCIPAL_HEADER] = name
    return headers


def _boolean_arg(value: Any, name: str) -> bool:
    """A JSON boolean, or "true"/"false" from a query string."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    raise ServerError(f"'{name}' must be true or false", 400)


def _has_json_detail(resp: Any) -> bool:
    try:
        payload = resp.json()
    except Exception:
        return False
    return isinstance(payload, dict) and "detail" in payload


def _dev_mode_refusal(resp: Any) -> Tuple[str, str]:
    """(code, message) for a developer-mode answer Aux refused.

    Aux's own refusals are {"detail": {"error": <code>, "message": <why>}}
    (owner_required, owner_unknown, no_change, waiver_required,
    waiver_out_of_date). The rest carry a string detail, so their code is
    named from the status.
    """
    try:
        payload = resp.json()
    except Exception:
        payload = None
    detail = payload.get("detail") if isinstance(payload, dict) else None
    if isinstance(detail, dict) and isinstance(detail.get("error"), str):
        message = detail.get("message")
        return detail["error"], (
            message.strip() if isinstance(message, str) else detail["error"])
    message = _aux_error_message(resp) or "The printer refused the request."
    code = {
        404: "challenge_not_found",
        428: "confirmation_required",
        429: "throttled",
        503: "unavailable",
    }.get(resp.status_code, "refused")
    return code, message


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
        # KAN-547: ask for a developer-mode change, follow the answer at the
        # panel, and complete it. The one route that can say a request is
        # the owner's; see owner_headers. muon-link admits it, and no other
        # Aux route (/server/aux/ stays closed to every remote session).
        self.server.register_endpoint(
            DEV_MODE_REQUEST_ENDPOINT,
            ["GET", "POST"],
            self._dev_mode_request_handler
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
                headers=self._auth_headers(headers),
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
            headers=self._auth_headers(),
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
        }

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

    # ---------- KAN-547: a developer-mode request -----------------------
    async def _dev_mode_request_handler(self, webreq):
        """Ask for a developer-mode change, poll it, or complete it.

        GET
            Who may ask, for a client deciding whether to offer the switch:
            {"as_owner", "owner": {"linked", "account"}, "may_ask",
            "waiver"}. Advisory; Aux decides when asked.
        POST {"enabled": bool}
            Opens a challenge for that direction (Aux POST /dev_mode/consent).
            The printer's panel asks the person there. For turning on, the
            answer carries the waiver the redeem has to acknowledge.
        GET {"challenge_id": str}
            Whether the person at the printer has answered (Aux GET
            /dev_mode/consent/{id}). Read-only.
        POST {"enabled": bool, "challenge_id": str, ...}
            Completes it once confirmed (Aux POST /dev_mode). For turning on,
            also waiver_acknowledged and waiver_version, or a reentry_token;
            signer_name is optional.

        A refusal is a ServerError whose message starts with the Aux code,
        "dev-mode:<code>: <why>", so a client can branch without parsing the
        sentence: owner_required, owner_unknown, no_change, waiver_required,
        waiver_out_of_date, confirmation_required, challenge_not_found,
        throttled, unavailable.
        """
        args = webreq.get_args()
        owner = owner_headers(
            webreq.get_ip_address(), webreq.get_current_user())
        if webreq.get_action() == "GET":
            challenge_id = self._challenge_id_arg(args.get("challenge_id"))
            if challenge_id is None:
                return await self._dev_mode_request_probe(owner)
            state = await self._dev_mode_call(
                "GET", f"/dev_mode/consent/{challenge_id}", None, {},
                DEV_MODE_OPEN_TIMEOUT)
            return {
                key: state.get(key) for key in (
                    "challenge_id", "confirmed", "refused", "expires_at",
                    "enabled")
            }
        if "enabled" not in args:
            raise self.server.error("'enabled' is required", 400)
        enabled = _boolean_arg(args.get("enabled"), "enabled")
        challenge_id = self._challenge_id_arg(args.get("challenge_id"))
        if challenge_id is None:
            return await self._open_dev_mode_request(enabled, owner)
        body: Dict[str, Any] = {
            "enabled": enabled, "challenge_id": challenge_id}
        for name, kind in _REDEEM_FIELDS.items():
            value = args.get(name)
            if value is None:
                continue
            if kind is bool:
                value = _boolean_arg(value, name)
            elif not isinstance(value, kind):
                raise self.server.error(f"'{name}' must be a string", 400)
            body[name] = value
        status = await self._dev_mode_call(
            "POST", "/dev_mode", body, owner, DEV_MODE_REDEEM_TIMEOUT)
        # Not core_cfg: a filesystem path, as for GET /server/muon/dev_mode.
        # The re-entry token is the one chance to read it (KAN-466); it goes
        # to the caller that completed the change and is never logged.
        answer: Dict[str, Any] = {
            "enabled": bool(status.get("enabled", False)),
            "released": bool(status.get("released", False)),
        }
        if isinstance(status.get("reentry_token"), str):
            answer["reentry_token"] = status["reentry_token"]
        return answer

    async def _dev_mode_request_probe(
        self, owner: Dict[str, str]
    ) -> Dict[str, Any]:
        """What a client needs to decide whether to offer the switch.

        `owner` is the link as muon-link reports it: linked or not, and the
        account, never the link code (APP-38). Aux reads the same answer when
        it decides, and names the account in owner_required anyway, so this
        says nothing a request would not. `may_ask` follows #378's rule: the
        owner, or anyone while nobody owns the printer; an unknown link is
        the owner's alone. `waiver` is what turning on will ask to
        acknowledge, or null if Aux could not say.
        """
        link = await self._link_owner()
        try:
            found = await self._dev_mode_call(
                "GET", "/dev_mode/waiver", None, {}, DEV_MODE_OPEN_TIMEOUT)
            waiver: Optional[Dict[str, Any]] = {
                "version": found.get("version"), "text": found.get("text")}
        except ServerError:
            waiver = None
        return {
            "as_owner": bool(owner),
            "owner": link,
            "may_ask": bool(owner) or link["linked"] is False,
            "waiver": waiver,
        }

    async def _link_owner(self) -> Dict[str, Any]:
        """{"linked": True | False | None, "account": str | None}."""
        unknown: Dict[str, Any] = {"linked": None, "account": None}
        link = self.server.lookup_component("muon_link", None)
        if link is None:
            return unknown
        try:
            status = await link.status()
        except Exception:
            return unknown
        phase = status.get("phase") if isinstance(status, dict) else None
        if phase == LINKED_PHASE:
            account = status.get("account")
            return {"linked": True,
                    "account": account if isinstance(account, str)
                    and account else None}
        if phase in UNOWNED_PHASES:
            return {"linked": False, "account": None}
        return unknown

    def _challenge_id_arg(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str) or not _CHALLENGE_ID_RE.match(value):
            raise self.server.error("'challenge_id' is not a challenge id", 400)
        return value

    async def _open_dev_mode_request(
        self, enabled: bool, owner: Dict[str, str]
    ) -> Dict[str, Any]:
        waiver: Optional[Dict[str, Any]] = None
        if enabled:
            # Before the challenge, so a printer that cannot say what is
            # being agreed to puts nothing on its panel. A remote session has
            # no other way to read it: /server/aux/ is closed to it.
            found = await self._dev_mode_call(
                "GET", "/dev_mode/waiver", None, {}, DEV_MODE_OPEN_TIMEOUT)
            waiver = {"version": found.get("version"),
                      "text": found.get("text")}
        challenge = await self._dev_mode_call(
            "POST", "/dev_mode/consent", {"enabled": enabled}, owner,
            DEV_MODE_OPEN_TIMEOUT)
        self.log.info(
            "Developer mode %s requested%s; waiting at the printer",
            "on" if enabled else "off", " by the owner" if owner else "")
        answer = {
            key: challenge.get(key) for key in (
                "challenge_id", "expires_at", "expires_in_seconds",
                "instruction", "enabled")
        }
        answer["as_owner"] = bool(owner)
        if waiver is not None:
            answer["waiver"] = waiver
        return answer

    async def _dev_mode_call(
        self, method: str, path: str, body: Optional[Dict[str, Any]],
        owner: Dict[str, str], timeout: float,
    ) -> Dict[str, Any]:
        headers: Dict[str, Any] = dict(owner)
        raw_body: Optional[str] = None
        if body is not None:
            raw_body = json.dumps(body)
            headers["Content-Type"] = "application/json"
        resp = await self.http_client.request(
            method=method,
            url=f"{FASTAPI_ROOT}{path}",
            body=raw_body,
            headers=self._auth_headers(headers),
            connect_timeout=3.,
            request_timeout=timeout,
        )
        status = resp.status_code
        # http_client answers a refused connection or a timeout with a 500 (or
        # 599) and no body: Aux did not answer, which a client should retry.
        # A 500 that Aux really sent carries its JSON detail and keeps it.
        if status == 599 or (status >= 500 and not _has_json_detail(resp)):
            raise self.server.error(
                "dev-mode:unavailable: The printer's Aux API is not "
                "answering yet.", 503)
        if status >= 400:
            code, message = _dev_mode_refusal(resp)
            raise self.server.error(f"dev-mode:{code}: {message}", status)
        try:
            answer = resp.json()
        except Exception:
            answer = None
        if not isinstance(answer, dict):
            raise self.server.error(
                "Aux returned an unreadable developer-mode answer", 502)
        return answer


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
