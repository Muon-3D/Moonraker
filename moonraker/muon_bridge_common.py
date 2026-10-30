# MUON, KAN-527 -- what every muon_bridge transport shares: the target rule,
# credentials held in RAM, rate limits and file names.
#
# See components/muon_bridge.py for the component and the rules it keeps.

from __future__ import annotations

import ipaddress
import re
import time
from typing import Any, Callable, Iterable, Optional, Tuple, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

#: RFC 1918 and RFC 4193 (ULA). Nothing else is a bridge target.
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(net) for net in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
))

#: A dial override: (host, port) -> (host, port). The identity in production;
#: tests point it at their fake servers on loopback.
Dialer = Callable[[str, int], Tuple[str, int]]


def direct(host: str, port: int) -> Tuple[str, int]:
    return host, port


class BridgeError(Exception):
    """A refusal or a failure to report to the caller, with an HTTP status.
    The message never carries a credential."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


def parse_target(
    host: Any, own_addresses: Iterable[Any] = ()
) -> IPAddress:
    """The target's address, if it is a private LAN address and not this
    printer. Only IP literals: a name could resolve anywhere, and resolve
    differently the next time (DNS rebinding)."""
    if not isinstance(host, str) or not host:
        raise BridgeError("'host' must be the printer's IP address", 400)
    text = host.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        raise BridgeError(
            "'host' must be an IP address on this network, not a name", 400
        ) from None
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if isinstance(ip, ipaddress.IPv6Address) and ip.scope_id:
        raise BridgeError("'host' must not carry a zone index", 400)
    if not any(ip.version == net.version and ip in net
               for net in PRIVATE_NETWORKS):
        raise BridgeError(
            f"{ip} is not a private LAN address (RFC 1918 or ULA); "
            "muon_bridge reaches printers on this network only", 403
        )
    for own in own_addresses:
        try:
            other = ipaddress.ip_address(str(own))
        except ValueError:
            continue
        other_mapped = getattr(other, "ipv4_mapped", None)
        if (other_mapped or other) == ip:
            raise BridgeError(
                f"{ip} is this printer; muon_bridge drives other printers "
                "only", 403
            )
    return ip


def url_host(ip: IPAddress) -> str:
    return f"[{ip}]" if ip.version == 6 else str(ip)


class Secret:
    """A credential in RAM only. Kept in a bytearray so that close() can
    overwrite it; repr() never shows it. Copies a library insists on (ftplib
    takes a str) are made per call and not kept."""

    __slots__ = ("_buf",)

    def __init__(self, value: str) -> None:
        self._buf = bytearray(value.encode("utf-8"))

    def __repr__(self) -> str:
        return "Secret(<redacted>)"

    __str__ = __repr__

    def __len__(self) -> int:
        return len(self._buf)

    @property
    def wiped(self) -> bool:
        return not any(self._buf)

    def reveal(self) -> bytes:
        if self.wiped:
            raise BridgeError("the session's credentials have been dropped", 410)
        return bytes(self._buf)

    def reveal_str(self) -> str:
        return self.reveal().decode("utf-8")

    def wipe(self) -> None:
        for index in range(len(self._buf)):
            self._buf[index] = 0


def take_secret(args: dict, name: str, max_len: int = 128) -> Secret:
    """Remove a credential from a request's arguments, so the request does
    not keep it, and hold it as a Secret."""
    value = args.pop(name, None)
    if not isinstance(value, str) or not value:
        raise BridgeError(f"'{name}' is required", 400)
    if len(value) > max_len or any(ch in value for ch in "\r\n\x00"):
        raise BridgeError(f"'{name}' is not valid", 400)
    return Secret(value)


class RateLimit:
    """A token bucket: `burst` at once, refilled at `per_second`."""

    def __init__(self, burst: float, per_second: float,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.burst = float(burst)
        self.per_second = float(per_second)
        self.clock = clock
        self.tokens = float(burst)
        self.stamp = clock()

    def take(self, what: str) -> None:
        now = self.clock()
        self.tokens = min(
            self.burst, self.tokens + (now - self.stamp) * self.per_second
        )
        self.stamp = now
        if self.tokens < 1.0:
            raise BridgeError(f"too many {what}; try again shortly", 429)
        self.tokens -= 1.0


_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()+\-]{0,126}$")


def check_filename(name: Any, extensions: Iterable[str]) -> str:
    """A bare file name that is safe in an FTP command and a URL path."""
    if not isinstance(name, str) or not _FILENAME.match(name) or ".." in name:
        raise BridgeError(
            "'filename' must be a plain file name (letters, digits, space, "
            "._()+-), up to 127 characters", 400
        )
    allowed = tuple(ext.lower() for ext in extensions)
    if not name.lower().endswith(allowed):
        raise BridgeError(
            f"'filename' must end with one of {list(allowed)}", 400
        )
    return name


def optional_str(value: Any, name: str, max_len: int = 64) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > max_len:
        raise BridgeError(f"'{name}' must be a string", 400)
    return value
