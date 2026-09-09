# MUON -- the floor.  Surfaces denied over the network in every mode.
#
# SPEC SEC-2 / SEC-3 / DEV-1 (docs/connectivity/SPEC.md in the MuonOS repo).
#
# Why this lives here and not only in the nginx vhost
# ---------------------------------------------------
# The obvious enforcement point is the LAN vhost, which proxies
# ``^/(printer|api|access|server|websocket)`` straight to Moonraker.  Denying
# ``^/server/aux`` there is cheap and worth having, but it is *not sufficient*,
# for two reasons that are easy to miss:
#
#   1. ``/websocket`` is in that same proxy set, and ``WebSocket.prepare``
#      (components/websockets.py:322) authenticates **once, at the upgrade**.
#      Every JSON-RPC call afterwards rides an already-open socket and is never
#      matched against a path again.  ``MoonrakerApp.register_endpoint``
#      registers an RPC method for every HTTP endpoint
#      (components/application.py:381-382), so ``/server/aux/dev_mode`` is also
#      reachable as ``server.aux.post_dev_mode`` over that socket.  A path
#      allowlist in nginx does not constrain it.
#   2. ``aux_api_proxy`` registers a generic ``/server/aux/proxy`` endpoint
#      (components/aux_api_proxy.py:78-81) that takes an arbitrary ``path``
#      argument and forwards it to Aux.  Denying the individual named paths
#      would leave that escape hatch open.
#
# So the deny has to sit where *every* transport converges.  That is
# ``APIDefinition.request`` in common.py: the HTTP handler
# (components/application.py:699-702), ``JsonRPC.execute_method``
# (common.py:838-841) and ``InternalTransport.call_method``
# (components/application.py:190) all funnel through it, and it is handed the
# caller's address.  One check there covers HTTP, the websocket, the HTTP
# JSON-RPC bridge and MQTT at once.
#
# What makes "local" trustworthy
# ------------------------------
# Moonraker runs Tornado with ``xheaders=True`` (components/application.py:315)
# and both vhosts set ``proxy_set_header X-Real-IP $remote_addr``, so the nginx
# hop is transparent: Moonraker sees the real client address and a LAN client
# cannot forge loopback through nginx.  The panel reaches Moonraker over
# 127.0.0.1 (the MuonUI vhost listens on loopback only), so loopback means
# "physically at the machine" and everything else means "over the network".
# tests/test_trusted_clients.py pins both halves of that.
#
# The floor is deliberately not configurable.  SEC-2 says these surfaces are
# denied "in every mode, with no setting that opens them", so there is no
# config option here on purpose -- adding one would be the regression.

from __future__ import annotations

import ipaddress
from typing import Any, Optional

from .utils.exceptions import ServerError

# Endpoint prefixes denied to network callers.  Matched against the registered
# endpoint, not against a URL, so the RPC method names derived from these
# endpoints are covered by the same entry.
FLOOR_PREFIXES = (
    # The developer-mode toggle, and nothing else.
    #
    # `SEC-2` as amended keeps on the floor only what an owner must not be able
    # to consent away, because the consequence is not theirs to undo. `DEV-3`
    # is that: enabling developer mode blows a CM4 one-time-programmable fuse,
    # reversible in software and permanent in hardware, and it is what answers
    # "was this machine ever unlocked?" in a warranty dispute years later. An
    # owner may choose to open the rest of this surface. They cannot unblow a
    # fuse, so that choice is not theirs to make.
    #
    # The rest of /server/aux, and all of /machine/update, left the floor with
    # that amendment: open at Level 0 (the shipped default), denied at Level 1
    # once `SEC-8` lands. Level 0 is a subtraction from this tuple and needs
    # nothing else -- the entry below keeps using the same address check it
    # always has.
    #
    # THIS NARROWING DEPENDS ON KAN-83 AND MUST NOT BE BACKPORTED WITHOUT IT.
    # The old entry was the whole "/server/aux" prefix, and its comment gave
    # the reason: aux_api_proxy re-exports Aux's entire OpenAPI document, and
    # /server/aux/proxy forwarded an arbitrary `path` argument to Aux with no
    # checks. Flooring only the toggle while that hatch is open reaches the
    # toggle straight through the hatch. KAN-83 closed it: _handle_dynamic_proxy
    # now matches `path` against _proxy_allowed, which is built only from routes
    # whose Aux path contains `{...}`. /dev_mode has no path parameters, so it
    # is a static endpoint and the proxy cannot address it. On any commit
    # predating KAN-83 this tuple must stay as it was.
    "/server/aux/dev_mode",
)

# SEC-3: Moonraker answers *who are you*; we answer *what may you do*.
# ``UserInfo.groups`` defaults to ["admin"] upstream and nothing in Moonraker
# reads it, so every authenticated user is an administrator.  These are the
# role names we write into that field instead, so the role is modelled once.
PANEL_ROLE = "panel"
NETWORK_ROLE = "network"


def local_address(ip_addr: Optional[Any]) -> bool:
    """Is this address the machine itself?

    ``parse_ip_address`` hands back whatever ``ipaddress`` makes of
    ``remote_ip``.  A v4-mapped v6 address (``::ffff:127.0.0.1``) is loopback in
    substance but ``IPv6Address.is_loopback`` is False for it, so unwrap first --
    otherwise the panel could be denied its own controls depending on how the
    socket was accepted.
    """
    if ip_addr is None:
        return False
    mapped = getattr(ip_addr, "ipv4_mapped", None)
    if mapped is not None:
        ip_addr = mapped
    try:
        return bool(ip_addr.is_loopback)
    except AttributeError:
        try:
            return ipaddress.ip_address(str(ip_addr)).is_loopback
        except ValueError:
            return False


def role_for_address(ip_addr: Optional[Any]) -> str:
    """The role this caller gets, from where it came from."""
    return PANEL_ROLE if local_address(ip_addr) else NETWORK_ROLE


def is_floor_endpoint(endpoint: str) -> bool:
    for prefix in FLOOR_PREFIXES:
        if endpoint == prefix or endpoint.startswith(prefix + "/"):
            return True
    return False


def _is_internal(transport: Optional[Any]) -> bool:
    """True for component-to-component calls.

    ``InternalTransport`` is only reachable from Python inside this process --
    ``update_manager`` driving an OTA through ``aux_api_proxy``, for instance --
    so it is not a network caller and must not be denied.  Duck-typed rather
    than imported to keep this module free of a cycle with ``common``.
    """
    transport_type = getattr(transport, "transport_type", None)
    return getattr(transport_type, "name", None) == "INTERNAL"


def check_floor(
    endpoint: str,
    transport: Optional[Any] = None,
    ip_addr: Optional[Any] = None,
) -> None:
    """Raise 403 when a network caller touches a floor surface.

    Fail-closed: anything that is neither an internal call nor a request from a
    *known* loopback address is treated as remote.  A transport that carries no
    address (MQTT, say) is therefore denied rather than waved through.
    """
    if not is_floor_endpoint(endpoint):
        return
    if _is_internal(transport):
        return
    if local_address(ip_addr):
        return
    raise ServerError(
        f"'{endpoint}' is not available over the network. This surface is "
        "reachable only from the printer's own panel, in every mode.",
        403,
    )
