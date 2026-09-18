# MUON -- the floor.  Surfaces denied over the network in every mode.
#
# SPEC SEC-2 / SEC-3 (docs/connectivity/SPEC.md in the MuonOS repo).
#
# `DEV-1` used to be enforced here too. It is not any more -- KAN-371 moved the
# developer-mode gate to `dev_mode_consent` in the Aux API, which tests presence
# rather than address. The long comment on FLOOR_PREFIXES below is the argument;
# read it before adding the toggle back.
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
#      (components/application.py:381-382), so ``/server/aux/bms/ship`` is also
#      reachable as ``server.aux.post_bms_ship`` over that socket.  A path
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
# What makes "local" trustworthy, and how far that goes
# -----------------------------------------------------
# Moonraker runs Tornado with ``xheaders=True`` (components/application.py:315)
# and both vhosts set ``proxy_set_header X-Real-IP $remote_addr``, so the nginx
# hop is transparent: Moonraker sees the real client address and a LAN client
# cannot forge loopback through nginx.  The panel reaches Moonraker over
# 127.0.0.1 (the MuonUI vhost listens on loopback only).
# tests/test_trusted_clients.py pins both halves of that.
#
# What this check therefore means is "the request originated on this device",
# and that is the claim to rely on.  It is NOT the same as "a person is
# standing at the printer", and the difference is not hypothetical: muon-link
# terminates a remote session onto 127.0.0.1:80, so the gateway is a second
# loopback consumer and a remote operator reaching the machine through it
# arrives here indistinguishable from the panel.  ``SEC-3`` records exactly
# this, and ``GATE-2`` is the work that is supposed to close it.  Until GATE-2
# exists, do not put anything on this floor whose justification is physical
# presence -- that is the mistake KAN-371 corrected for the developer-mode
# toggle.  The entries that remain are justified by "no other check holds
# them" (BMS-21), which an on-device origin does answer.
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
    # THE DEVELOPER-MODE TOGGLE IS NO LONGER HERE. Read this before putting it
    # back, because the reason it left is not "the fuse matters less".
    #
    # What the entry did: it denied "/server/aux/dev_mode" and everything under
    # it to any caller that was not loopback, on the grounds that `DEV-3` blows
    # a one-time-programmable fuse and an owner cannot unblow one. The intent
    # was "a person has to be at the machine". The mechanism was "this request
    # arrived from 127.0.0.1", which is a different statement, and the distance
    # between the two is what made this the wrong place for the gate:
    #
    #   * Loopback is not presence. muon-link terminates a *remote* session
    #     onto 127.0.0.1:80, so an operator on the other side of the world
    #     already presents as loopback here. `SEC-3` names `GATE-2` as what is
    #     meant to keep "loopback means the panel" true, and `GATE-2` is not
    #     built. The floor was not delivering presence to begin with.
    #   * It denied far more than the irreversible half. Reading the state,
    #     reading the waiver, opening a consent challenge, restoring defaults,
    #     taking a backup and *leaving* developer mode are all under this
    #     prefix, and none of them blows anything. `DEV-5` calls "restore safe
    #     configuration" a single action; this made it unreachable from the
    #     only interface that offers it.
    #   * The alternative it named does not exist. Fluidd told a LAN caller the
    #     mode "can only be changed at the printer"; MuonUI carries a read-only
    #     indicator and no toggle, so there was no control at the printer to
    #     change it with.
    #
    # What replaced it is a stronger gate in a better place: `dev_mode_consent`
    # in the Aux API. Enabling needs the acknowledged current waiver *and* a
    # single-use, TTL-bounded challenge that only the hardware can confirm, and
    # every inconclusive answer -- absent backend, unreachable backend, unknown
    # backend name -- is a refusal rather than a bypass. A network caller cannot
    # manufacture that from loopback or from anywhere else. Leaving developer
    # mode stays ungated in both places on purpose: recovery must not depend on
    # a working knob, a reachable operator, or an attacker's cooperation.
    #
    # THE STANDING DEPENDENCY, now the whole of `DEV-3`'s protection:
    # `KnobConfirmationBackend` must keep refusing until the knob/DSI firmware
    # is wired to it. Its docstring says "Do not 'temporarily' make this return
    # True". That sentence used to cost a defence-in-depth layer; it now costs
    # the only one. tests/test_muon_floor.py pins the membership below and
    # recipes/aux_api's test_dev_mode_consent.py pins the gate that took over.
    #
    # KAN-350. The battery commands that change pack state.
    #
    # These are here for a different reason from the toggle above, and the
    # difference is worth keeping straight. The toggle is floored because the
    # consequence is not the owner's to undo -- a blown fuse stays blown. These
    # are floored because *nothing else holds them*: ``require_bms_authority``
    # in the Aux API is an empty function body (``BMS-21``), so until KAN-25
    # lands, this tuple is the whole of their access control.
    #
    # They did not need to be here while ``trusted_clients`` held loopback
    # alone, because Moonraker answered 401 before reaching any of them. KAN-350
    # opens that list to the LAN and the hotspot so that Fluidd works with no
    # sign-in (``SEC-1``), which removes the 401 -- and these entries are what
    # make that safe to ship. Do not remove them while ``BMS-21`` is open.
    "/server/aux/bms/mode",
    # Covers /bms/charge and /bms/charge/power both: ``is_floor_endpoint``
    # matches on a path-segment boundary, so this one entry is both routes while
    # still not matching a sibling that merely starts with the same letters.
    "/server/aux/bms/charge",
    # Standby is the one of these a base user could reasonably be given -- it is
    # power saving, not a destructive command. It stays floored anyway, because
    # nobody has measured whether ``SET_STANDBY_ENABLE`` removes power from the
    # compute module. If it does, a caller who enables it over the network
    # strands the printer, and the machine cannot then be asked to undo it. Open
    # it when that measurement exists, and not before.
    "/server/aux/bms/standby",
    "/server/aux/bms/fault",
    # Ship mode. Additionally refused by the Aux client unless
    # BMS_ENABLE_SHIP_COMMAND=1 (KAN-130), so this is the second of two locks
    # rather than the only one. Listed because a defence that depends on an
    # environment variable staying unset is not one to leave alone on the route
    # that powers the pack down.
    "/server/aux/bms/ship",
)

#: The battery routes deliberately NOT floored. Telemetry discloses pack state,
#: not authority, and both UIs need it: ``/bms/link`` is what the panel polls to
#: decide whether the subsystem is alive at all, so flooring it would make a LAN
#: Fluidd report the battery as missing rather than as present. Named here so
#: that a later edit collapsing the entries above into a single
#: ``"/server/aux/bms"`` prefix is recognisable as the mistake it would be.
BMS_TELEMETRY_LEFT_OPEN = (
    "/server/aux/bms/link",
    "/server/aux/bms/status",
    "/server/aux/bms/snapshot",
    "/server/aux/bms/capabilities",
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
