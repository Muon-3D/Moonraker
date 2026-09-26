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
# standing at the printer".  The gateway is a second on-device caller: muon-link
# forwards a remote session to 127.0.0.1:7125.  ``GATE-2`` is what keeps it
# apart from the panel, and it is built: muon-link stamps every forwarded
# request ``X-Real-IP: 192.0.2.1`` (GATE-2(b)), and ``utils/real_ip.py`` refuses
# an ambiguous header before authentication (GATE-2(c), Moonraker#17), so a
# gateway caller arrives here with the sentinel, not loopback.  Even so, do not
# put anything on this floor whose justification is physical presence: any
# process on the device is loopback too.  That is the mistake KAN-371 corrected
# for the developer-mode toggle.  The entries that remain are justified by "no
# other check holds them" (BMS-21), which an on-device origin does answer.
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
    #   * Loopback is not presence. When this entry was removed, `GATE-2` was
    #     not built and a remote muon-link session presented as loopback here.
    #     `GATE-2` has since kept the gateway off loopback (see the header), but
    #     any process on the device is still loopback, so the floor was never
    #     delivering presence and still does not.
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
    # KAN-413 / KAN-411 / KAN-412 (first-run setup spec OS-7, OS-5 and OS-6).
    # Aux routes that only this process's own ``muon_setup`` component should
    # drive. It reaches them through ``aux_api_proxy``'s in-process helpers,
    # which call the Aux API directly and never pass this check, so the floor
    # costs it nothing. What they change is not a network caller's to change:
    #
    #   * ``setup`` -- the whole prefix. ``/setup/complete`` marks first-run
    #     setup finished, or clears it, which decides whether the printer runs
    #     setup again and whether its hotspot is held up (rule H1). The prefix
    #     also covers the older ``/setup`` marker on draft MuonOS#174. Reads
    #     are covered too; nothing off the device needs them, because
    #     ``muon_setup``'s own state carries the fact.
    #   * ``wifi/ap/auto_off`` schedules the hotspot to go off (rule H3). The
    #     owner's own hotspot controls, ``/wifi/ap/up`` and ``/down``, stay
    #     open, as Level 0 intends.
    #   * ``time`` sets the clock and the time zone (07 S9). ``muon_setup``
    #     decides who may (the phone page on the hotspot, 02 §3); a LAN or
    #     remote caller reaching Aux directly would skip that decision.
    #
    # The same reason as the battery entries -- nothing else holds them -- and
    # not physical presence, which this check cannot give (see above).
    "/server/aux/setup",
    "/server/aux/wifi/ap/auto_off",
    "/server/aux/time",
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


# ---------------------------------------------------------------------------
# SEC-8: the protection levels.
#
# The floor above is what no setting opens. This is what the owner may close.
# ``SEC-1`` makes Level 0 (Open) the shipped default: anyone who can reach the
# printer on the LAN or the hotspot may drive it, and KAN-350 made that true by
# opening ``trusted_clients``. Level 1 (Protected) takes back exactly the
# surfaces SEC-2 no longer floors -- ``/server/aux/*`` and ``/machine/update/*``
# -- from any caller that has no identity.
#
# What counts as an identity, and why it is not an address
# --------------------------------------------------------
# ``SEC-8`` puts this check at ``GATE-2``'s enforcement point on purpose. The
# gateway is a second caller on loopback, so "loopback means the panel" is only
# true because muon-link stamps every forwarded request ``X-Real-IP: 192.0.2.1``
# (GATE-2(b)) and ``utils/real_ip.py`` refuses an ambiguous header before
# authentication (GATE-2(c), Moonraker#17). Given both, three callers have an
# identity and one does not:
#
#   * the panel, and anything else on the device: a loopback address that is
#     not the sentinel. The panel vhost listens on 127.0.0.1:100 only.
#   * a component-to-component call (``InternalTransport``) -- ota_deploy
#     driving an install through aux_api_proxy, for instance.
#   * a paired client through the gateway: the sentinel address AND a user that
#     ``muon_gateway`` authenticated. muon-link mints that token only for a
#     client its GATE-3 policy has already admitted, so the user is the NET-11
#     identity SEC-8 names. Neither half is enough alone: the address without
#     the token is any request muon-link forwards, and the token is bound to
#     the sentinel by ``_check_oneshot_token``, so it cannot arrive from
#     anywhere else.
#   * NOT a LAN or hotspot browser. ``trusted_clients`` authenticates it as
#     ``_TRUSTED_USER_`` purely because of where it is, which is exactly what
#     Level 1 exists to stop counting.
#
# No Moonraker user is created, at either level. ``authenticate_request`` puts
# the ``force_logins`` gate before ``_check_trusted_connection``, so a second
# row in ``self.users`` would 401 the panel on everything with no way back
# (MuonOS #87). The level lives in ``components/muon_protection.py``.
# ---------------------------------------------------------------------------

#: Level 0. The shipped default (SEC-1): the LAN and the hotspot drive the
#: printer with no sign-in.
LEVEL_OPEN = 0
#: Level 1. The surfaces below need an identity.
LEVEL_PROTECTED = 1
LEVEL_NAMES = {LEVEL_OPEN: "open", LEVEL_PROTECTED: "protected"}

#: What Level 1 takes back: the two surfaces SEC-2 no longer floors. Matched on
#: the registered endpoint, like FLOOR_PREFIXES, so the JSON-RPC methods derived
#: from these endpoints are covered by the same entry.
PROTECTED_PREFIXES = (
    "/server/aux",
    "/machine/update",
)

#: Under a protected prefix, and governed by something else. SEC-8 excludes the
#: developer-mode toggle by name: its gate is ``dev_mode_consent`` in the Aux
#: API, which asks the hardware rather than the address (KAN-371), and leaving
#: developer mode is ungated on purpose so that recovery never depends on who
#: is asking. The whole prefix goes with it, for the reason the floor gives for
#: removing it: reading the waiver, restoring defaults and taking a backup are
#: all under it, and none of them is authority.
PROTECTED_EXCLUSIONS = ("/server/aux/dev_mode",)

#: The address muon-link stamps on every request it forwards (GATE-2(b)).
#: ``components/muon_gateway.py`` binds its tokens to the same value; a test
#: asserts the two agree.
GATEWAY_SENTINEL = ipaddress.ip_address("192.0.2.1")
#: ``UserInfo.source`` for a user ``muon_gateway`` authenticated.
GATEWAY_USER_SOURCE = "muon_gateway"

# Open here, so a Moonraker with no [muon_protection] section keeps upstream
# behaviour. The component raises this to Protected as soon as it loads, and
# holds it there until it has read the stored level: a configured printer that
# cannot say which level it is at is Protected, not Open.
_protection_level = LEVEL_OPEN


def is_known_level(value: Any) -> bool:
    """Is this exactly one of the levels?

    `type() is int`, not isinstance or `in`: True and 1.0 both compare equal to
    1, and a level that prints as "True" is one nobody set on purpose.
    """
    return type(value) is int and value in LEVEL_NAMES


def set_protection_level(level: int) -> None:
    """Set the level this process enforces. Only muon_protection calls this."""
    global _protection_level
    if not is_known_level(level):
        raise ValueError(f"unknown protection level {level!r}")
    _protection_level = level


def protection_level() -> int:
    return _protection_level


def _matches(endpoint: str, prefixes: Any) -> bool:
    for prefix in prefixes:
        if endpoint == prefix or endpoint.startswith(prefix + "/"):
            return True
    return False


def is_protected_endpoint(endpoint: str) -> bool:
    """Is this one of the surfaces Level 1 takes back?"""
    if _matches(endpoint, PROTECTED_EXCLUSIONS):
        return False
    return _matches(endpoint, PROTECTED_PREFIXES)


def _is_gateway_address(ip_addr: Optional[Any]) -> bool:
    if ip_addr is None:
        return False
    try:
        return ipaddress.ip_address(str(ip_addr)) == GATEWAY_SENTINEL
    except ValueError:
        return False


def has_identity(
    transport: Optional[Any] = None,
    ip_addr: Optional[Any] = None,
    user: Optional[Any] = None,
) -> bool:
    """Does this caller carry an identity SEC-8 Level 1 accepts?

    See the block comment above for the three that do. Fail-closed: an absent
    address, an absent user, or a user from any other source is no identity.
    """
    if _is_internal(transport):
        return True
    if local_address(ip_addr):
        return True
    return (
        _is_gateway_address(ip_addr)
        and user is not None
        and getattr(user, "source", None) == GATEWAY_USER_SOURCE
    )


def check_protection(
    endpoint: str,
    transport: Optional[Any] = None,
    ip_addr: Optional[Any] = None,
    user: Optional[Any] = None,
) -> None:
    """Raise 403 when Level 1 is set and a caller without an identity touches a
    protected surface. At Level 0 this never refuses anything."""
    if _protection_level == LEVEL_OPEN:
        return
    if not is_protected_endpoint(endpoint):
        return
    if has_identity(transport, ip_addr, user):
        return
    raise ServerError(
        f"'{endpoint}' is protected on this printer. The owner turned on "
        "network protection, which can only be turned off at the printer's "
        "panel. A paired device can still reach it.",
        403,
    )
