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
    # Aux holds passwordless sudo for nmcli and rugix-ctrl.  It binds loopback,
    # but aux_api_proxy re-exports its entire OpenAPI document under this
    # prefix, which puts it back on the network.  Includes the developer-mode
    # toggle (DEV-1) and the /server/aux/proxy escape hatch.
    "/server/aux",
    # Update install/rollback/recover.  A caller who can move the printer
    # between OS versions can move it to one without these controls.
    "/machine/update",
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
