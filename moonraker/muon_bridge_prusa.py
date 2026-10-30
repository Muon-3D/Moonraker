# MUON, KAN-527 -- a PrusaLink printer, through this M1, so the browser never
# meets PrusaLink's missing CORS headers or its Digest challenge.
#
# PrusaLink's API is /api/v1 (prusa3d/Prusa-Link-Web, spec/openapi.yaml):
#   GET /api/v1/status, GET /api/v1/job, PUT /api/v1/job/{id}/pause|resume,
#   DELETE /api/v1/job/{id}, PUT /api/v1/files/{storage}/{name} (upload),
#   POST /api/v1/files/{storage}/{name} (print it).
# HTTP Digest is RFC 7616 (and RFC 2617 without qop, which PrusaLink sends),
# implemented here on hashlib.

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote

from tornado.httpclient import AsyncHTTPClient, HTTPRequest

from .muon_bridge_common import (
    BridgeError, Dialer, IPAddress, Secret, check_filename, direct, url_host
)

API_PREFIX = "/api/v1/"
HTTP_PORT = 80
UPLOAD_EXTENSIONS = (".gcode", ".bgcode")
PROXY_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD")
#: What a proxied answer may carry back; never Set-Cookie or the challenge.
PASS_HEADERS = ("Content-Type", "ETag", "Last-Modified", "Location")
MAX_ANSWER = 4 << 20

_PARAM = re.compile(r'(\w+)\s*=\s*("((?:[^"\\]|\\.)*)"|[^\s,]+)')
_PATH = re.compile(r"^[A-Za-z0-9._~!$&'()*+,;=:@%/\-]*$")
_HASHES = {
    "MD5": hashlib.md5, "MD5-SESS": hashlib.md5,
    "SHA-256": hashlib.sha256, "SHA-256-SESS": hashlib.sha256,
}


def parse_challenge(header: str) -> Dict[str, str]:
    scheme, _, rest = header.strip().partition(" ")
    if scheme.lower() != "digest":
        raise BridgeError("PrusaLink did not ask for Digest authentication",
                          502)
    params: Dict[str, str] = {}
    for match in _PARAM.finditer(rest):
        quoted = match.group(3)
        params[match.group(1).lower()] = (
            re.sub(r"\\(.)", r"\1", quoted) if quoted is not None
            else match.group(2))
    if "nonce" not in params or "realm" not in params:
        raise BridgeError("PrusaLink sent a malformed Digest challenge", 502)
    return params


class DigestAuth:
    """Answers one server's Digest challenges. Keeps the nonce, never the
    password or HA1 (which is as good as the password): they are worked out
    from the Secret for each request."""

    def __init__(self, username: Secret, password: Secret) -> None:
        self.username = username
        self.password = password
        self.challenge: Optional[Dict[str, str]] = None
        self.count = 0

    def learn(self, header: str) -> bool:
        """Take a new challenge; False when the old one was answered and
        refused (a wrong password, not a stale nonce)."""
        params = parse_challenge(header)
        algorithm = params.get("algorithm", "MD5").upper()
        if algorithm not in _HASHES:
            raise BridgeError(
                f"PrusaLink asked for unsupported Digest {algorithm}", 502)
        retry = (self.challenge is None
                 or params.get("stale", "").lower() == "true"
                 or params["nonce"] != self.challenge["nonce"])
        self.challenge = params
        self.count = 0
        return retry

    def header(self, method: str, uri: str) -> str:
        assert self.challenge is not None
        chal = self.challenge
        algorithm = chal.get("algorithm", "MD5").upper()
        hasher = _HASHES[algorithm]

        def digest(data: bytes) -> str:
            return hasher(data).hexdigest()

        user = self.username.reveal()
        realm, nonce = chal["realm"].encode(), chal["nonce"].encode()
        ha1 = digest(user + b":" + realm + b":" + self.password.reveal())
        cnonce = os.urandom(8).hex()
        if algorithm.endswith("-SESS"):
            ha1 = digest(f"{ha1}:{chal['nonce']}:{cnonce}".encode())
        ha2 = digest(f"{method}:{uri}".encode())
        qops = [q.strip() for q in chal.get("qop", "").split(",") if q.strip()]
        fields = [
            f'username="{user.decode()}"', f'realm="{chal["realm"]}"',
            f'nonce="{chal["nonce"]}"', f'uri="{uri}"',
        ]
        if "auth" in qops:
            self.count += 1
            nc = f"{self.count:08x}"
            response = digest(
                f"{ha1}:{chal['nonce']}:{nc}:{cnonce}:auth:{ha2}".encode())
            fields += ["qop=auth", f"nc={nc}", f'cnonce="{cnonce}"']
        elif qops:
            raise BridgeError("PrusaLink asked for an unsupported Digest qop",
                              502)
        else:
            response = digest(f"{ha1}:{nonce.decode()}:{ha2}".encode())
        fields.append(f'response="{response}"')
        if "algorithm" in chal:
            fields.append(f"algorithm={chal['algorithm']}")
        if "opaque" in chal:
            fields.append(f'opaque="{chal["opaque"]}"')
        return "Digest " + ", ".join(fields)


def check_api_path(path: Any) -> str:
    """A path under /api/v1, with no way out of it."""
    if not isinstance(path, str) or not path.startswith(API_PREFIX):
        raise BridgeError(f"'path' must start with {API_PREFIX}", 400)
    route, _, query = path.partition("?")
    segments = route.split("/")
    if (
        not _PATH.match(route) or ".." in segments or "." in segments
        or "//" in route or len(path) > 512
        or "%2f" in route.lower() or "%2e" in route.lower()
        or any(ch in query for ch in "\r\n #")
    ):
        raise BridgeError("'path' is not a plain PrusaLink API path", 400)
    return path


class PrusaPrinter:
    kind = "prusalink"

    def __init__(self, ip: IPAddress, username: Secret, password: Secret,
                 storage: str = "usb", dialer: Dialer = direct,
                 client: Optional[AsyncHTTPClient] = None) -> None:
        if storage not in ("usb", "local", "sdcard"):
            raise BridgeError("'storage' must be usb, local or sdcard", 400)
        self.ip = ip
        self.storage = storage
        self.dialer = dialer
        self.auth = DigestAuth(username, password)
        self.secrets = (username, password)
        self.client = client or AsyncHTTPClient()
        self.last_status: Dict[str, Any] = {}

    def _url(self, path: str) -> str:
        host, port = self.dialer(str(self.ip), HTTP_PORT)
        try:
            from ipaddress import ip_address
            host = url_host(ip_address(host))
        except ValueError:
            pass
        return f"http://{host}:{port}{path}"

    async def request(
        self, method: str, path: Any, body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None, timeout: float = 30.0
    ) -> Tuple[int, Dict[str, str], bytes]:
        method = method.upper()
        if method not in PROXY_METHODS:
            raise BridgeError(f"'method' must be one of {list(PROXY_METHODS)}",
                              400)
        check_api_path(path)
        if any(s.wiped for s in self.secrets):
            raise BridgeError("the session's credentials have been dropped",
                              410)
        for _ in range(3):
            send = dict(headers or {})
            if self.auth.challenge is not None:
                send["Authorization"] = self.auth.header(method, path)
            request = HTTPRequest(
                self._url(path), method=method, headers=send,
                body=body if body is not None else (
                    b"" if method in ("POST", "PUT", "PATCH") else None),
                follow_redirects=False, connect_timeout=5.0,
                request_timeout=timeout, decompress_response=True,
            )
            try:
                response = await self.client.fetch(request, raise_error=False)
            except OSError as exc:
                raise BridgeError(
                    f"cannot reach PrusaLink: {type(exc).__name__}", 504
                ) from None
            send.pop("Authorization", None)
            if response.code == 599:
                raise BridgeError("cannot reach PrusaLink", 504)
            if response.code == 401:
                challenge = response.headers.get("WWW-Authenticate")
                if challenge and self.auth.learn(challenge):
                    continue
                # 403, not 401: Moonraker's JSON-RPC reports 401 as
                # "invalid params" (common.py).
                raise BridgeError("PrusaLink refused the user name or "
                                  "password", 403)
            answer = response.body or b""
            if len(answer) > MAX_ANSWER:
                raise BridgeError("PrusaLink's answer is too large", 502)
            kept = {name: response.headers[name] for name in PASS_HEADERS
                    if name in response.headers}
            return response.code, kept, answer
        raise BridgeError("PrusaLink kept refusing the Digest answer", 403)

    async def proxy(self, method: str, path: Any, body: Any = None
                    ) -> Dict[str, Any]:
        data: Optional[bytes] = None
        headers: Dict[str, str] = {}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        code, kept, answer = await self.request(method, path, data, headers)
        result: Dict[str, Any] = {"status_code": code, "headers": kept}
        if "json" in kept.get("Content-Type", "") and answer:
            try:
                result["body"] = json.loads(answer)
                return result
            except ValueError:
                pass
        result["body"] = answer.decode("utf-8", "replace")
        return result

    async def _json(self, method: str, path: str) -> Any:
        code, kept, answer = await self.request(method, path)
        if code >= 400:
            raise BridgeError(f"PrusaLink answered {code} to {method} {path}",
                              502 if code >= 500 else 409)
        if not answer:
            return None
        try:
            return json.loads(answer)
        except ValueError:
            raise BridgeError("PrusaLink sent something that is not JSON",
                              502) from None

    async def open(self) -> None:
        await self.refresh()

    async def refresh(self) -> Dict[str, Any]:
        status = await self._json("GET", "/api/v1/status")
        self.last_status = status if isinstance(status, dict) else {}
        return self.status()

    def status(self) -> Dict[str, Any]:
        printer = self.last_status.get("printer") or {}
        job = self.last_status.get("job") or {}
        keep = ("state", "temp_nozzle", "target_nozzle", "temp_bed",
                "target_bed", "axis_z", "speed", "flow")
        out: Dict[str, Any] = {k: printer[k] for k in keep if k in printer}
        if job:
            out["job"] = {k: job[k] for k in
                          ("id", "progress", "time_remaining", "time_printing")
                          if k in job}
        return out

    async def _job_id(self) -> int:
        await self.refresh()
        job = self.last_status.get("job") or {}
        if not isinstance(job.get("id"), int):
            raise BridgeError("PrusaLink has no job running", 409)
        return job["id"]

    async def pause(self) -> None:
        await self._json("PUT", f"/api/v1/job/{await self._job_id()}/pause")

    async def resume(self) -> None:
        await self._json("PUT", f"/api/v1/job/{await self._job_id()}/resume")

    async def stop(self) -> None:
        await self._json("DELETE", f"/api/v1/job/{await self._job_id()}")

    async def start(self, filename: Any, options: Dict[str, Any]) -> None:
        check_filename(filename, UPLOAD_EXTENSIONS)
        await self._json("POST", f"/api/v1/files/{self.storage}/{quote(filename)}")

    async def upload(self, filename: Any, data: bytes) -> None:
        check_filename(filename, UPLOAD_EXTENSIONS)
        code, _, _ = await self.request(
            "PUT", f"/api/v1/files/{self.storage}/{quote(filename)}", data,
            {"Content-Type": "application/octet-stream",
             "Overwrite": "?1", "Print-After-Upload": "?0"},
            timeout=600.0)
        if code >= 400:
            raise BridgeError(f"PrusaLink refused the upload ({code})",
                              409 if code < 500 else 502)

    async def close(self) -> None:
        for secret in self.secrets:
            secret.wipe()
        self.auth.challenge = None
