# MUON, KAN-203 -- who is calling muon_setup, and whether they may.
#
# Spec 02 §3 (specs/m1-first-run-setup in Muon-3D/OrcaSlicer) and 07 S5/S6.
# Classified once per request, from the address Moonraker already resolved
# (nginx's X-Real-IP, validated by utils/real_ip.py) and the user
# authorization.py stamped. The floor still applies on top: `reset` is in
# muon_floor.FLOOR_PREFIXES, so a network caller never reaches the handler.

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING, Any, Iterable, Mapping, Optional, Set
from urllib.parse import urlsplit

from ... import muon_floor
from ...common import TransportType
from ...utils.exceptions import ServerError

if TYPE_CHECKING:
    from ...common import WebRequest

PANEL = "panel"
HOTSPOT = "hotspot"
LAN = "lan"
REMOTE = "remote"
INTERNAL = "internal"
OTHER = "other"

#: muon-link's forwarded requests carry this address (GATE-2(b)).
GATEWAY_SENTINEL = ipaddress.ip_address("192.0.2.1")
GATEWAY_USER_SOURCE = "muon_gateway"
#: The hotspot's subnet: NetworkManager's shared mode on ap0.
HOTSPOT_NET = ipaddress.ip_network("10.42.0.0/24")
HOTSPOT_ADDRESS = "10.42.0.1"

# What each kind of caller may do (02 §3). `internal` is another component in
# this process, so it is treated as the panel.
READ_STATE = frozenset({PANEL, HOTSPOT, LAN, REMOTE, INTERNAL})
READ = frozenset({PANEL, HOTSPOT, LAN, INTERNAL})
WRITE = frozenset({PANEL, HOTSPOT, LAN, INTERNAL})
PANEL_ONLY = frozenset({PANEL, INTERNAL})

#: Which driver surface a write from each kind of caller claims (01 §3).
SURFACE_FOR_KIND = {PANEL: "panel", HOTSPOT: "phone", LAN: "web"}


def caller_kind(webreq: WebRequest) -> str:
    transport = webreq.get_subscribable()
    if getattr(transport, "transport_type", None) == TransportType.INTERNAL:
        return INTERNAL
    user = webreq.get_current_user()
    if user is not None and getattr(user, "source", None) == GATEWAY_USER_SOURCE:
        return REMOTE
    ip = webreq.get_ip_address()
    if ip is None:
        # MQTT and the like: no address, so nothing to trust.
        return OTHER
    if _same_address(ip, GATEWAY_SENTINEL):
        return REMOTE
    if muon_floor.local_address(ip):
        return PANEL
    if _in_network(ip, HOTSPOT_NET):
        return HOTSPOT
    if user is not None and muon_floor.NETWORK_ROLE in getattr(user, "groups", []):
        return LAN
    return OTHER


def require(kind: str, allowed: Iterable[str]) -> None:
    if kind not in allowed:
        raise ServerError(f"muon_setup: not allowed from {kind}", 403)


def _same_address(ip: Any, other: Any) -> bool:
    try:
        return ipaddress.ip_address(str(ip)) == other
    except ValueError:
        return False


def _in_network(ip: Any, net: Any) -> bool:
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    try:
        return ipaddress.ip_address(str(ip)) in net
    except ValueError:
        return False


# --------------------------------------------------------------------------
# HTTP write hygiene (02 §3, 07 S6): CSRF and DNS rebinding.
#
# At Level 0 a browser on the owner's LAN is trusted by address alone, so any
# web page that browser visits could otherwise post a setup write to the
# printer. Two things stop it:
#
#   * `Content-Type: application/json`. A cross-origin form cannot send it,
#     and a cross-origin fetch that sets it needs a CORS preflight Moonraker
#     does not grant.
#   * a Host (and Origin, when present) that names this printer. A rebinding
#     page is same-origin with itself, so the only thing it cannot control is
#     that its Host header is its own domain, not the printer's.
#
# The websocket gets the Host check too, which 02 §3 does not ask for. The
# spec leans on Moonraker's websocket origin check, but Tornado's default
# check_origin compares the Origin's host with the Host header, and under DNS
# rebinding both are the attacker's domain, so it passes. The upgrade
# request's Host is still the attacker's domain, though, and a browser that
# really is talking to the printer always names the printer there.
# --------------------------------------------------------------------------

_PORT_RE = re.compile(r":\d+$")


def bare_host(value: Optional[str]) -> Optional[str]:
    """Lower-cased host without port, brackets or IPv6 zone."""
    if not value:
        return None
    host = value.strip().lower()
    if host.startswith("["):
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:
        host = _PORT_RE.sub("", host)
    host = host.split("%", 1)[0]
    return host.rstrip(".") or None


def origin_host(origin: Optional[str]) -> Optional[str]:
    if not origin:
        return None
    try:
        parts = urlsplit(origin.strip())
    except ValueError:
        return None
    if parts.scheme not in ("http", "https"):
        return None
    return bare_host(parts.netloc.rsplit("@", 1)[-1])


def allowed_hosts(hostname: Optional[str], addresses: Iterable[str]) -> Set[str]:
    """The names a browser can legitimately use to reach this printer.

    02 §3 lists `localhost:100` for the panel. The MuonUI vhost forwards
    `Host $host`, which drops the port, so the panel's requests arrive as
    `localhost`; ports are ignored throughout, since a rebinding page controls
    the port as freely as the path. Only the name matters.
    """
    hosts = {HOTSPOT_ADDRESS, "muon3d.local", "localhost", "127.0.0.1", "::1"}
    if hostname:
        name = hostname.strip().lower()
        hosts.update({name, f"{name}.local"})
    for addr in addresses:
        host = bare_host(addr)
        if host:
            hosts.add(host)
    return hosts


def check_hygiene(webreq: WebRequest, hosts: Set[str]) -> None:
    """Raise 415/403 for a setup write that fails 02 §3's rules.

    Only a request that arrived over HTTP (plain, or JSON-RPC over HTTP) or a
    websocket has headers to check. An internal call has none and is not a
    browser.
    """
    headers: Optional[Mapping[str, str]] = webreq.get_http_headers()
    if headers is None:
        return
    transport = webreq.get_subscribable()
    is_websocket = (
        not webreq.is_plain_http()
        and getattr(transport, "transport_type", None) == TransportType.WEBSOCKET
    )
    if webreq.is_plain_http():
        ctype = (headers.get("Content-Type") or "").strip().lower()
        if not ctype.startswith("application/json"):
            raise ServerError(
                "muon_setup: writes need Content-Type: application/json", 415
            )
    host = bare_host(headers.get("Host"))
    if host is None or host not in hosts:
        raise ServerError("muon_setup: Host is not this printer", 403)
    if is_websocket:
        return
    origin = headers.get("Origin")
    if origin is not None and origin_host(origin) not in hosts:
        raise ServerError("muon_setup: Origin is not this printer", 403)
