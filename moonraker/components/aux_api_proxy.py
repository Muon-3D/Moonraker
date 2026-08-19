# Moonraker component — wifi_autoproxy.py
#
# Enable it with a bare section in moonraker.conf:
#     [aux_api_proxy]
#
# ──────────────────────────────────────────────────────────────────────────
import asyncio, json, logging, os, re, contextlib
from pathlib import Path
from typing import Dict, Any, Callable, Optional
from urllib.parse import urlencode

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

# ──────────────────────────────────────────────────────────────────────────
class AuxAutoProxy:
    def __init__(self, config):
        self.server      = config.get_server()
        self.http_client = self.server.lookup_component("http_client")
        self.log         = logging.getLogger("wifi_autoproxy")
        self._token: Optional[str] = None

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
        cache = Path("/tmp/fastapi_openapi.json")
        if cache.exists():
            self.log.info(f"Loading OpenAPI from {cache}")
            return json.loads(cache.read_text())

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

        # register the raw OpenAPI document
        self.server.register_endpoint(
            f"{MOON_PREFIX}/openapi.json",
            ["GET"],
            self._openapi_handler
        )

        for fast_path, path_item in spec.get("paths", {}).items():
            # Paths with {...} are handled by the generic /proxy endpoint
            if _PATH_PARAM_RE.search(fast_path):
                needs_proxy = True
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
                request_timeout = 8.,
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

        url   = f"{FASTAPI_ROOT}{path}"
        query = webreq.get("query", None)
        if query and verb in {"GET", "DELETE"}:
            url += f"?{query}"

        resp = await self.http_client.request(
            method=verb,
            url=url,
            body=webreq.get("body", None),
            headers=self._auth_headers()
        )
        resp.raise_for_status()
        return resp.json()

    async def _openapi_handler(self, webreq):
        # return exactly the JSON you fetched from FastAPI
        return self._spec
    


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
