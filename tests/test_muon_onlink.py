from __future__ import annotations

import ipaddress

from moonraker.muon_onlink import OnlinkPrefixes, parse_ipv6_routes

ZERO = "0" * 32


def _route(net: str, flags: int = 0x1, nexthop: str = ZERO,
           ifname: str = "wlan0") -> str:
    n = ipaddress.IPv6Network(net)
    dest = f"{int(n.network_address):032x}"
    return (f"{dest} {n.prefixlen:02x} {ZERO} 00 {nexthop} "
            f"00000100 00000001 00000000 {flags:08x} {ifname:>8}")


# A real walnut table on 2026-09-22, rebuilt: the LAN /64 from the RA, the
# default route via the router, link-local, the host's own /128, multicast and
# loopback.
WALNUT = [
    _route("2a0d:3344:5920:fd0d::/64"),
    _route("::/0", flags=0x3, nexthop="fe80000000000000021122fffe334455"),
    _route("fe80::/64"),
    _route("2a0d:3344:5920:fd0d:1234:5678:9abc:def0/128", flags=0x80200001),
    _route("ff00::/8"),
    _route("::1/128", ifname="lo"),
]


def test_only_the_lan_prefix_is_on_link():
    assert parse_ipv6_routes(WALNUT) == [
        ipaddress.IPv6Network("2a0d:3344:5920:fd0d::/64")]


def test_a_route_through_a_gateway_is_never_on_link():
    via_router = _route("2001:db8:1::/64", flags=0x3,
                        nexthop="fe80000000000000021122fffe334455")
    assert parse_ipv6_routes([via_router]) == []


def test_a_nexthop_without_the_gateway_flag_is_still_refused():
    odd = _route("2001:db8:1::/64", nexthop="fe80000000000000021122fffe334455")
    assert parse_ipv6_routes([odd]) == []


def test_a_short_on_link_route_is_refused():
    # An on-link /32 or a default route marked on-link would trust a
    # continent; nothing shorter than a site (/48) counts as the LAN.
    assert parse_ipv6_routes([_route("2001:db8::/32"), _route("::/0")]) == []
    assert parse_ipv6_routes([_route("2001:db8:1::/48")]) == [
        ipaddress.IPv6Network("2001:db8:1::/48")]


def test_a_route_that_is_not_up_is_refused():
    assert parse_ipv6_routes([_route("2001:db8:1::/64", flags=0x0)]) == []


def test_garbage_lines_are_skipped():
    assert parse_ipv6_routes(["", "not a route", "zz " * 10]) == []


def _prefixes(tmp_path, lines, refresh_s=30.0):
    table = tmp_path / "ipv6_route"
    table.write_text("\n".join(lines) + "\n", encoding="ascii")
    return table, OnlinkPrefixes(str(table), refresh_s=refresh_s)


def test_a_lan_browser_on_its_global_address_is_trusted(tmp_path):
    _, p = _prefixes(tmp_path, WALNUT)
    assert p.contains(ipaddress.ip_address("2a0d:3344:5920:fd0d::abcd"), now=0)


def test_the_internet_is_not(tmp_path):
    _, p = _prefixes(tmp_path, WALNUT)
    assert not p.contains(ipaddress.ip_address("2a0d:3344:5920:fd0e::1"), now=0)
    assert not p.contains(ipaddress.ip_address("2001:4860:4860::8888"), now=0)


def test_ipv4_is_never_trusted_here(tmp_path):
    # GATE-2(g): muon-link's sentinel must not become trusted by any route.
    _, p = _prefixes(tmp_path, WALNUT)
    assert not p.contains(ipaddress.ip_address("192.0.2.1"), now=0)
    assert not p.contains(ipaddress.ip_address("192.168.1.10"), now=0)


def test_an_ipv4_mapped_address_is_not_trusted(tmp_path):
    _, p = _prefixes(tmp_path, [_route("::ffff:0:0/96")])
    assert not p.contains(ipaddress.ip_address("::ffff:192.0.2.1"), now=0)


def test_a_prefix_change_is_picked_up_after_the_refresh(tmp_path):
    table, p = _prefixes(tmp_path, WALNUT, refresh_s=30.0)
    old = ipaddress.ip_address("2a0d:3344:5920:fd0d::abcd")
    new = ipaddress.ip_address("2a0d:3344:5920:aaaa::abcd")
    assert p.contains(old, now=0)
    table.write_text(_route("2a0d:3344:5920:aaaa::/64") + "\n", encoding="ascii")
    assert p.contains(old, now=10)         # still cached
    assert not p.contains(old, now=31)     # re-read
    assert p.contains(new, now=31)


def test_a_missing_route_table_trusts_nothing(tmp_path):
    p = OnlinkPrefixes(str(tmp_path / "absent"))
    assert p.prefixes(now=0) == []
    assert not p.contains(ipaddress.ip_address("2a0d::1"), now=0)


def test_the_floor_does_not_consult_this():
    # A trusted LAN caller must still be refused the floored surfaces: the
    # floor reads the address itself, and on-link trust is not loopback.
    from moonraker import muon_floor
    src = open(muon_floor.__file__, encoding="utf-8").read()
    assert "muon_onlink" not in src
