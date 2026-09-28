# MUON, KAN-203 -- who is calling muon_setup, and whether they may.
#
# Spec 02 §3 (specs/m1-first-run-setup in Muon-3D/OrcaSlicer) and 07 S5/S6.
# Classified once per request, from the address Moonraker already resolved
# (nginx's X-Real-IP, validated by utils/real_ip.py) and the user
# authorization.py stamped. The floor still applies on top: `reset` is in
# muon_floor.FLOOR_PREFIXES, so a network caller never reaches the handler.
#
# KAN-436 adds `bluetooth` (ADR 0032 D4 and D7, in Muon_Internal_Documentation
# 40-audits/decisions/0032-iroh-ble-on-the-m1.md): a phone on muon-link's
# Bluetooth transport. Its rights follow `state`, so every check here takes
# whether setup is complete (rights_of).

from __future__ import annotations

import ipaddress
import re
import socket
from typing import (
    TYPE_CHECKING, AbstractSet, Any, Iterable, List, Mapping, Optional, Set
)
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
#: KAN-436, ADR 0032 D4: a phone on muon-link's Bluetooth transport.
BLUETOOTH = "bluetooth"
INTERNAL = "internal"
OTHER = "other"

#: muon-link's forwarded requests carry this address (GATE-2(b)).
GATEWAY_SENTINEL = muon_floor.GATEWAY_SENTINEL
#: ...and this one when the connection started on the Bluetooth transport
#: (ADR 0032 D4 rule 3). muon_gateway binds a token to it only when muon-link
#: asks for a Bluetooth one.
BLUETOOTH_SENTINEL = muon_floor.BLUETOOTH_SENTINEL
GATEWAY_USER_SOURCE = muon_floor.GATEWAY_USER_SOURCE
#: The hotspot's subnet: NetworkManager's shared mode on ap0.
HOTSPOT_NET = ipaddress.ip_network("10.42.0.0/24")
HOTSPOT_ADDRESS = "10.42.0.1"

# What each kind of caller may do (02 §3). `internal` is another component in
# this process, so it is treated as the panel.
READ_STATE = frozenset({PANEL, HOTSPOT, LAN, REMOTE, INTERNAL})
READ = frozenset({PANEL, HOTSPOT, LAN, INTERNAL})
WRITE = frozenset({PANEL, HOTSPOT, LAN, INTERNAL})
PANEL_ONLY = frozenset({PANEL, INTERNAL})
#: 02 §3: `reset` is the one thing another component may not do.
RESET = frozenset({PANEL})

#: Which driver surface a write from each kind of caller claims (01 §3). A
#: Bluetooth caller's claim is always `bluetooth`, whatever kind it names
#: (ADR 0032 D7 "Caller class"): the panel's words come from the transport.
SURFACE_FOR_KIND = {PANEL: "panel", HOTSPOT: "phone", LAN: "web",
                    BLUETOOTH: "bluetooth"}


def caller_kind(webreq: WebRequest) -> str:
    transport = webreq.get_subscribable()
    if getattr(transport, "transport_type", None) == TransportType.INTERNAL:
        return INTERNAL
    user = webreq.get_current_user()
    ip = webreq.get_ip_address()
    if user is not None and getattr(user, "source", None) == GATEWAY_USER_SOURCE:
        # The user is muon_gateway's: its one-shot token came over the uid-0
        # socket and is bound to the address muon-link asked for, so a token
        # minted for Bluetooth arrives only with 192.0.2.2 and one minted for
        # a paired session only with 192.0.2.1 (Authorization's
        # _check_oneshot_token compares them). Both halves are needed.
        if _same_address(ip, BLUETOOTH_SENTINEL):
            return BLUETOOTH
        return REMOTE
    if ip is None:
        # MQTT and the like: no address, so nothing to trust.
        return OTHER
    if _same_address(ip, GATEWAY_SENTINEL):
        return REMOTE
    if _same_address(ip, BLUETOOTH_SENTINEL):
        # The Bluetooth address without the gateway's token is not the
        # gateway: muon-link never forwards it unauthenticated. Unlike
        # `remote`, it grants hotspot rights, so an address alone must never
        # reach them (ADR 0032 D4).
        return OTHER
    if muon_floor.local_address(ip):
        return PANEL
    if _in_network(ip, HOTSPOT_NET):
        return HOTSPOT
    if user is not None and muon_floor.NETWORK_ROLE in getattr(user, "groups", []):
        return LAN
    return OTHER


def rights_of(kind: str, complete: bool) -> str:
    """The kind whose rights a caller has (ADR 0032 D4 rule 4).

    `bluetooth` has the hotspot's rights while setup is not complete and the
    rights of `remote` after. Every other kind is its own. Pass
    `complete=True` whenever the state is not known yet: the narrower rights.
    """
    if kind == BLUETOOTH:
        return REMOTE if complete else HOTSPOT
    return kind


def require(kind: str, allowed: Iterable[str], complete: bool = True) -> None:
    """403 unless this caller's rights are among `allowed`. The message names
    the caller's own kind, `bluetooth` included."""
    if rights_of(kind, complete) not in allowed:
        raise ServerError(f"muon_setup: not allowed from {kind}", 403)


# --------------------------------------------------------------------------
# The code a Bluetooth phone shows (ADR 0032 D7 "State").
#
# The gateway sends the SEC-7 comparison value of the Bluetooth connection as
# `X-Muon-Ble-Code: F6QTDH`, and drops whatever header the client sent. It is
# six symbols of Crockford's base32 alphabet, upper case, no separator:
# muon_link_crypto's `Sas` (pairing.rs, SAS_SYMBOLS = 6) drawn from
# base32.rs's ALPHABET, "0123456789ABCDEFGHJKMNPQRSTVWXYZ" -- no I, L, O or U.
# The panel shows it as `F6Q TDH`; that grouping is the panel's, not ours.
# --------------------------------------------------------------------------

BLE_CODE_HEADER = "X-Muon-Ble-Code"
BLE_CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_BLE_CODE_RE = re.compile(r"[0-9A-HJKMNP-TV-Z]{6}")


def ble_code(webreq: WebRequest) -> Optional[str]:
    """The well-formed code this request carries, else None.

    Only a header from the gateway is read, so call it for a `bluetooth`
    caller only. A second copy of the header is malformed, not a choice.
    """
    headers = webreq.get_http_headers()
    if headers is None:
        return None
    get_list = getattr(headers, "get_list", None)
    if get_list is not None:
        values = get_list(BLE_CODE_HEADER)
        if len(values) != 1:
            return None
        value: Optional[str] = values[0]
    else:
        value = headers.get(BLE_CODE_HEADER)
    if not isinstance(value, str) or not _BLE_CODE_RE.fullmatch(value):
        return None
    return value


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


def printer_hosts(server: Any) -> Set[str]:
    """allowed_hosts() for this printer: its hostname, and every address the
    machine component reports for its network interfaces."""
    addresses: List[str] = []
    machine = server.lookup_component("machine", None)
    if machine is not None:
        network = machine.get_system_info().get("network", {})
        for info in network.values():
            for addr in info.get("ip_addresses", []):
                if isinstance(addr.get("address"), str):
                    addresses.append(addr["address"])
    return allowed_hosts(socket.gethostname(), addresses)


def check_hygiene(
    webreq: WebRequest,
    hosts: Set[str],
    component: str = "muon_setup",
    extra_origins: AbstractSet[str] = frozenset(),
) -> None:
    """Raise 415/403 for a write that fails 02 §3's rules.

    Only a request that arrived over HTTP (plain, or JSON-RPC over HTTP) or a
    websocket has headers to check. An internal call has none and is not a
    browser. `component` names the refusing component in the error, since
    muon_link applies the same rules to its writes. `extra_origins` are whole
    Origin values accepted besides the printer's own names, compared exactly;
    muon_setup passes none.
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
                f"{component}: writes need Content-Type: application/json", 415
            )
    host = bare_host(headers.get("Host"))
    if host is None or host not in hosts:
        raise ServerError(f"{component}: Host is not this printer", 403)
    if is_websocket:
        return
    origin = headers.get("Origin")
    if origin is None or origin in extra_origins:
        return
    if origin_host(origin) not in hosts:
        raise ServerError(f"{component}: Origin is not this printer", 403)
