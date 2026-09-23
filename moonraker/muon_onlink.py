# MUON -- trust the printer's own on-link IPv6 prefixes.
#
# Why this exists
# ---------------
# `SEC-1` says an open printer answers Fluidd on the LAN with no sign-in. The
# M1 template implements that by listing private space in `trusted_clients`:
# RFC1918, link-local and the ULA block. It deliberately lists no global IPv6
# range, because nginx listens on [::]:80 and the printer holds a globally
# routable address with no NAT in front of it -- a global range in that list
# would open the printer to the internet.
#
# The gap: `<host>.local` resolves over mDNS to the printer's *global* IPv6
# address too, browsers prefer IPv6, and a home network that hands out no ULA
# (most of them) leaves the browser talking from its own global address. That
# address is in no listed range, so Moonraker answers 401 and Fluidd shows a
# sign-in page on a printer that has no accounts. Measured on boxwood and
# walnut on 2026-09-22: direct IPv4 returned 200, `.local` over IPv6 returned
# 401. The bench mitigation was to add the LAN's current /64 by hand, which an
# OTA or a prefix change from the ISP silently undoes.
#
# What this does instead
# ----------------------
# It reads the kernel's IPv6 routing table and trusts a caller whose address
# falls inside a prefix the printer has *directly on-link* -- a route with no
# gateway, on a real interface. That is the definition of "on the same LAN",
# and it follows the network: when the prefix changes, the route changes, and
# the next refresh picks it up.
#
# Why that is not "trust the internet"
# ------------------------------------
# A host on the internet cannot talk TCP to the printer from inside the
# printer's own on-link prefix. It can forge a SYN with such a source address,
# but the SYN-ACK goes to that address on the LAN, not back to the attacker, so
# the handshake never completes and no HTTP request is ever read. Every request
# Moonraker authorises is on an established connection.
#
# The guards, each of which removes one way this could widen:
#   * IPv6 only. IPv4 LAN space is already covered by the RFC1918 entries, and
#     skipping IPv4 keeps muon-link's `192.0.2.1` sentinel (`GATE-2(g)`) out of
#     reach even on a network that routes TEST-NET-1 on-link.
#   * Prefix length >= MIN_PREFIXLEN. A default route or a short on-link route
#     would otherwise trust half the address space.
#   * Never a route with a next hop, never `lo`, never multicast.
#   * The floor (muon_floor.py) is untouched: it keys on loopback, not on this,
#     so a trusted LAN caller is still refused the floored surfaces.
from __future__ import annotations

import ipaddress
import logging
import time
from typing import Iterable, List, Optional, Union

IPv6Network = ipaddress.IPv6Network
IPAddr = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

ROUTE_TABLE = "/proc/net/ipv6_route"

#: A /48 is a whole site. Anything shorter is not a LAN.
MIN_PREFIXLEN = 48

#: How long a read of the routing table is reused. A prefix change reaches
#: Moonraker within this long; a lookup per request would read /proc per
#: request.
REFRESH_S = 30.0

_RTF_UP = 0x0001
_RTF_GATEWAY = 0x0002
_ZERO = "0" * 32


def _hex_to_v6(value: str) -> ipaddress.IPv6Address:
    return ipaddress.IPv6Address(int(value, 16))


def parse_ipv6_routes(lines: Iterable[str]) -> List[IPv6Network]:
    """The on-link LAN prefixes in the text of /proc/net/ipv6_route.

    Each line is: dest dest_plen src src_plen next_hop metric refcnt use
    flags ifname, the addresses as 32 hex digits and the lengths and flags in
    hex.
    """
    found: List[IPv6Network] = []
    for line in lines:
        fields = line.split()
        if len(fields) != 10:
            continue
        dest, plen, _src, _splen, nexthop, _m, _r, _u, flags, ifname = fields
        try:
            prefixlen = int(plen, 16)
            flag_bits = int(flags, 16)
            net = IPv6Network((_hex_to_v6(dest), prefixlen))
        except ValueError:
            continue
        if ifname == "lo":
            continue
        if not flag_bits & _RTF_UP or flag_bits & _RTF_GATEWAY:
            continue
        if nexthop != _ZERO:
            continue
        if prefixlen < MIN_PREFIXLEN or prefixlen == 128:
            continue
        if net.is_multicast or net.is_link_local or net.is_loopback:
            continue
        if net not in found:
            found.append(net)
    return found


class OnlinkPrefixes:
    """A cached view of the on-link prefixes, re-read every REFRESH_S."""

    def __init__(
        self, route_table: str = ROUTE_TABLE, refresh_s: float = REFRESH_S
    ) -> None:
        self.route_table = route_table
        self.refresh_s = refresh_s
        self._prefixes: List[IPv6Network] = []
        self._read_at: Optional[float] = None

    def _refresh(self, now: float) -> None:
        try:
            with open(self.route_table, encoding="ascii") as f:
                prefixes = parse_ipv6_routes(f)
        except OSError:
            # No IPv6 on this host, or /proc is not mounted. Trust nothing
            # extra rather than keep a stale list.
            prefixes = []
        if prefixes != self._prefixes:
            logging.info(
                "On-link IPv6 prefixes trusted: %s",
                ", ".join(str(p) for p in prefixes) or "none")
        self._prefixes = prefixes
        self._read_at = now

    def prefixes(self, now: Optional[float] = None) -> List[IPv6Network]:
        now = time.monotonic() if now is None else now
        if self._read_at is None or now - self._read_at >= self.refresh_s:
            self._refresh(now)
        return list(self._prefixes)

    def contains(self, ip: IPAddr, now: Optional[float] = None) -> bool:
        if not isinstance(ip, ipaddress.IPv6Address):
            return False
        if ip.ipv4_mapped is not None:
            return False
        return any(ip in net for net in self.prefixes(now))
