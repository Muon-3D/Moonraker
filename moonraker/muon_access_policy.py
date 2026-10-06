# MUON -- the level table.  What each principal may do, for every request.
#
# SPEC ACC-7 to ACC-11, ACC-23 and ACC-24 (Muon_Internal_Documentation,
# 20-specification/security/access.md). The design, with the table itself, is
# muon3d-app docs/plans/access-model.md section 3.
#
# This module is the decision, in the shape of muon_floor.py: plain functions
# and one piece of module state, so that ``APIDefinition.request`` in
# common.py can call it for every transport without a server object.
# ``components/muon_access.py`` stores the settings and sets that state. With
# no ``[muon_access]`` section the state stays None and nothing is refused
# here, which keeps a Moonraker without the component on upstream behaviour.
#
# THE ORDER OF CHECKS
#
# ``APIDefinition.request`` runs ``muon_floor.check_floor`` first, then
# ``muon_floor.check_protection``, then ``check_access`` below. The floor is
# unchanged and no setting here opens it (ACC-24). A floor surface therefore
# keeps the floor's reason in its 403.
#
# WHO IS ASKING
#
# Every request resolves to one principal with one level and one role (ACC-7,
# ACC-11):
#
#   * the panel, or a component calling another in-process: above every level
#     and never refused here (ACC-10). "The panel" is a loopback origin that is
#     not the gateway's sentinel, as muon_floor defines it (GATE-2).
#   * a paired client through the gateway: the one-shot token muon_gateway
#     minted carries the principal, its level, its role and whether its path is
#     on the home network. A token from a muon-link that sends none of those is
#     the gateway as it was before this component: admin and Operator, so that
#     muon-link's own policy stays the only limit, exactly as today.
#   * a browser on the LAN or the hotspot signed in with the printer password
#     (Moonraker#32): a signed-out guest with Operator (access-model 6). The
#     password works only from home (ACC-16), so the same login arriving
#     through the gateway is not this principal.
#   * any other caller on the LAN or the hotspot, while the entry is Open: a
#     signed-out guest with Operator, "anyone at home" (ACC-7). While the entry
#     is Protected it is not admitted (ACC-5).
#
# Nobody else is admitted: a request from the gateway's address without the
# gateway's token, or with no address at all (MQTT), is refused everything.
#
# No Moonraker user is created here or by the component (MR-18, MuonOS #87).

from __future__ import annotations

import dataclasses
import ipaddress
import posixpath
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

from . import muon_floor
from .utils.exceptions import ServerError

# ---------------------------------------------------------------------------
# Levels and roles (ACC-7, ACC-8, ACC-11)
# ---------------------------------------------------------------------------

SIGNED_OUT_GUEST = 1
SIGNED_IN_GUEST = 2
MEMBER = 3
ADMIN = 4
#: Above every level a principal can hold: only the panel (ACC-10).
PANEL = 5

LEVEL_NAMES: Dict[int, str] = {
    SIGNED_OUT_GUEST: "signed_out_guest",
    SIGNED_IN_GUEST: "signed_in_guest",
    MEMBER: "member",
    ADMIN: "admin",
    PANEL: "panel",
}
#: The levels a network principal can hold, by name. "panel" is not one.
PRINCIPAL_LEVELS: Dict[str, int] = {
    LEVEL_NAMES[level]: level
    for level in (SIGNED_OUT_GUEST, SIGNED_IN_GUEST, MEMBER, ADMIN)
}

OPERATOR = "operator"
VIEWER = "viewer"
ROLES = (OPERATOR, VIEWER)

ENTRY_OPEN = "open"
ENTRY_PROTECTED = "protected"
ENTRIES = (ENTRY_OPEN, ENTRY_PROTECTED)

RELAXED = "relaxed"
STANDARD = "standard"
STRICT = "strict"
PRESETS = (RELAXED, STANDARD, STRICT)

#: Who owns the printer (ACC-1). Derived from the link; never set here.
OWNER_NONE = "none"
OWNER_ACCOUNT = "account"
OWNER_ORGANISATION = "organisation"
#: Not yet known (the link has not answered since start).
OWNER_UNKNOWN = "unknown"
#: The owners this printer can derive from its link today. An organisation
#: owner is not in the link yet.
DERIVABLE_OWNERS = (OWNER_NONE, OWNER_ACCOUNT)
OWNERS = (OWNER_NONE, OWNER_ACCOUNT, OWNER_ORGANISATION, OWNER_UNKNOWN)

#: The login Moonraker#32 creates for the printer password. It is
#: muon_floor.PANEL_LOGIN_USER there; kept here so this module does not
#: depend on that PR, and tests/test_muon_access.py checks the two agree
#: once both exist.
PASSWORD_LOGIN_USER = "admin"

# ---------------------------------------------------------------------------
# The table (access-model section 3; ACC-23, ACC-24)
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Action:
    name: str
    #: The lowest level for the action under each preset.
    relaxed: int
    standard: int
    strict: int
    #: A read: a Viewer may do it (ACC-11).
    read: bool = False
    #: Only from the home network, at any level.
    home_only: bool = False
    #: Jack, 2026-10-05 (access-model 2.4): a trusted device, which holds the
    #: admin level, may do this one from away too.
    admin_from_away: bool = False
    #: The row cannot be changed by a preset or an override (ACC-24).
    fixed: bool = False
    #: A Viewer may do it although it is not a read. Emergency stop only.
    viewer_allowed: bool = False
    #: Governed by another check, which this module does not repeat. The
    #: principal must still be admitted, and a Viewer still may not write.
    delegated: bool = False
    #: Reachable by a caller on the home network that is not admitted: a
    #: new device asking the panel to let it in (ACC-6) is not, yet.
    home_unadmitted: bool = False

    def level_for(self, preset: str) -> int:
        return {RELAXED: self.relaxed, STANDARD: self.standard,
                STRICT: self.strict}[preset]


_A = Action
_ROWS = (
    # Connect, see status, camera
    _A("read", SIGNED_OUT_GUEST, SIGNED_OUT_GUEST, SIGNED_IN_GUEST, read=True),
    # Never above this; Viewers too (GATE-7)
    _A("emergency_stop", SIGNED_OUT_GUEST, SIGNED_OUT_GUEST, SIGNED_OUT_GUEST,
       fixed=True, viewer_allowed=True),
    # Print, pause, resume, cancel
    _A("print", SIGNED_OUT_GUEST, SIGNED_IN_GUEST, MEMBER),
    # Upload and delete own files
    _A("files", SIGNED_OUT_GUEST, SIGNED_IN_GUEST, MEMBER),
    # Move, home, heat, load filament, macros
    _A("motion", SIGNED_OUT_GUEST, MEMBER, MEMBER),
    # Delete or reprint others' files
    _A("files_others", MEMBER, ADMIN, ADMIN),
    # Raw G-code console
    _A("console", MEMBER, ADMIN, ADMIN),
    # Change Wi-Fi
    _A("wifi", SIGNED_OUT_GUEST, MEMBER, ADMIN, home_only=True,
       admin_from_away=True),
    # Hotspot on/off, hotspot key
    _A("hotspot", ADMIN, ADMIN, ADMIN, home_only=True, admin_from_away=True),
    # Install updates
    _A("updates", ADMIN, ADMIN, ADMIN, home_only=True, admin_from_away=True),
    # Rename the printer
    _A("rename", SIGNED_IN_GUEST, ADMIN, ADMIN),
    # printer.cfg (config root)
    _A("config", ADMIN, ADMIN, ADMIN, home_only=True),
    # Protection: entry, ways in, people, levels, data, private uploads
    _A("protection", ADMIN, ADMIN, ADMIN, fixed=True),
    # The owner: changes only by linking, which LINK-3 confirms at the panel
    _A("owner", SIGNED_OUT_GUEST, SIGNED_OUT_GUEST, SIGNED_OUT_GUEST,
       fixed=True, delegated=True),
    # Developer mode: dev_mode_consent in the Aux API asks the hardware
    # (KAN-371), which is how this row's "panel" is met.
    _A("dev_mode", PANEL, PANEL, PANEL, fixed=True, delegated=True),
    # First-run setup: muon_setup decides its own callers (02 section 3).
    _A("setup", SIGNED_OUT_GUEST, SIGNED_OUT_GUEST, SIGNED_OUT_GUEST,
       fixed=True, delegated=True),
    # server.muon.access.* (AB-MR-2): the settings methods answer
    # {"applied": false} rather than a 403, and requests are asked of the
    # panel, so their handlers apply the protection row themselves
    # (components/muon_access_api.py).
    _A("access_api", SIGNED_OUT_GUEST, SIGNED_OUT_GUEST, SIGNED_OUT_GUEST,
       fixed=True, delegated=True),
    # Asking the panel to allow one change or one new device, and reading
    # the answer (design 2.5, ACC-6). Asking is not acting: the panel
    # decides, so a Viewer may ask too.
    _A("access_request", SIGNED_OUT_GUEST, SIGNED_OUT_GUEST,
       SIGNED_OUT_GUEST, fixed=True, delegated=True, viewer_allowed=True,
       home_unadmitted=True),
    # Not rows of the design's table. Moonraker has surfaces it does not name.
    # A client's own preferences in the database, dismissing a notice, the
    # display's brightness: what a person needs to use the interface at all,
    # so the level of "read", but a write.
    _A("ui_settings", SIGNED_OUT_GUEST, SIGNED_OUT_GUEST, SIGNED_IN_GUEST),
    # Restarting services and the host, backups, history, MQTT, extensions,
    # and every write this module does not recognise: fail closed to admin.
    _A("system", ADMIN, ADMIN, ADMIN),
)
del _A

ACTIONS: Dict[str, Action] = {row.name: row for row in _ROWS}


# ---------------------------------------------------------------------------
# The home network (ACC-4, ACC-16; SEC-10)
# ---------------------------------------------------------------------------
#
# The printer's LAN and its hotspot. The same rule as muon-link's
# ``HomeNetwork::from_interface_addresses`` (muon-link#42), so the gateway and
# Moonraker agree on what "at home" means:
#
#   * the hotspot, 10.42.0.0/24 (NetworkManager's shared-mode default), always,
#     whether or not it is up when the interfaces are read;
#   * each IPv4 interface address's own prefix, if it is at least /8 (a
#     misconfigured /0 or /1 would make half the Internet the home network);
#   * the /64 of each IPv6 address, whatever prefix the interface carries;
#   * nothing from loopback or unspecified addresses.
#
# An IPv4-mapped IPv6 address is compared as the IPv4 address it carries.

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
HOTSPOT_SUBNET: Network = ipaddress.ip_network("10.42.0.0/24")
MIN_IPV4_INTERFACE_PREFIX = 8


def _canonical(ip_addr: Any) -> Optional[Any]:
    try:
        ip = ipaddress.ip_address(str(ip_addr))
    except ValueError:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


@dataclasses.dataclass(frozen=True)
class HomeNetwork:
    subnets: Tuple[Network, ...] = (HOTSPOT_SUBNET,)

    @classmethod
    def from_interface_addresses(
        cls, addresses: Iterable[Tuple[Any, int]]
    ) -> "HomeNetwork":
        subnets: List[Network] = [HOTSPOT_SUBNET]
        for addr, prefix in addresses:
            ip = _canonical(addr)
            if ip is None or ip.is_loopback or ip.is_unspecified:
                continue
            if ip.version == 4:
                if not MIN_IPV4_INTERFACE_PREFIX <= prefix <= 32:
                    continue
                subnet: Network = ipaddress.ip_network(
                    f"{ip}/{prefix}", strict=False)
            else:
                subnet = ipaddress.ip_network(f"{ip}/64", strict=False)
            if subnet not in subnets:
                subnets.append(subnet)
        return cls(tuple(subnets))

    def contains(self, ip_addr: Any) -> bool:
        ip = _canonical(ip_addr)
        if ip is None:
            return False
        return any(
            ip.version == subnet.version and ip in subnet
            for subnet in self.subnets
        )

    def describe(self) -> List[str]:
        return [str(subnet) for subnet in self.subnets]


def interface_addresses(ip_json: Any) -> List[Tuple[str, int]]:
    """(address, prefix) for every address in `ip -json address` output."""
    found: List[Tuple[str, int]] = []
    if not isinstance(ip_json, list):
        return found
    for interface in ip_json:
        if not isinstance(interface, dict):
            continue
        for info in interface.get("addr_info") or []:
            local = info.get("local") if isinstance(info, dict) else None
            prefix = info.get("prefixlen") if isinstance(info, dict) else None
            if isinstance(local, str) and type(prefix) is int:
                found.append((local, prefix))
    return found


# ---------------------------------------------------------------------------
# Settings and the effective level
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class AccessState:
    entry: str = ENTRY_PROTECTED
    #: None follows the owner and the entry (default_preset).
    preset: Optional[str] = None
    overrides: Mapping[str, int] = dataclasses.field(default_factory=dict)
    owner: str = OWNER_UNKNOWN
    #: Until the interfaces have been read, only the hotspot is home.
    home: HomeNetwork = HomeNetwork()


def default_preset(owner: str, entry: str) -> str:
    """A printer with one owner uses Relaxed while Open and Standard while
    Protected (ACC-23); an organisation starts at Standard."""
    if owner == OWNER_ACCOUNT:
        return RELAXED if entry == ENTRY_OPEN else STANDARD
    return STANDARD


def effective_preset(state: AccessState) -> str:
    return state.preset or default_preset(state.owner, state.entry)


def required_level(action: Action, state: AccessState) -> int:
    """The lowest level that may do this action on this printer now.

    The table, then the readings section 3 gives under it:

    * one owner: "member" reads "owner", because there are no members;
    * no owner: there is no admin, so Protection is the panel's. Under Open
      every other row is anyone at home, which is what the printer does today
      (access-model 6, "Identical behaviour"; section 3's note reads tighter,
      to be reconciled in the spec). Under Protected a row above signed-out
      guest needs an approved device, which the gateway presents at the admin
      level;
    * owner not known yet (the link has not answered since start): the
      strictest of what every owner the printer could have would need, and
      the panel only where that is admin. A gap in knowing the owner never
      opens the printer more than its real owner would.
    """
    if state.owner == OWNER_UNKNOWN and not action.delegated:
        level = max(
            required_level(action, dataclasses.replace(state, owner=owner))
            for owner in DERIVABLE_OWNERS
        )
        return PANEL if level >= ADMIN else level
    if action.fixed:
        base = action.standard
    else:
        base = state.overrides.get(
            action.name, action.level_for(effective_preset(state))
        )
    if state.owner in (OWNER_NONE, OWNER_UNKNOWN):
        # (OWNER_UNKNOWN only for a delegated row, handled above otherwise)
        if action.name == "protection":
            return PANEL
        if action.delegated:
            return base
        if state.entry == ENTRY_OPEN:
            return SIGNED_OUT_GUEST
        return SIGNED_OUT_GUEST if base <= SIGNED_OUT_GUEST else ADMIN
    if state.owner == OWNER_ACCOUNT and base == MEMBER:
        return ADMIN
    return base


def overridable(action_name: str) -> bool:
    action = ACTIONS.get(action_name)
    return action is not None and not action.fixed


# ---------------------------------------------------------------------------
# The principal
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Principal:
    #: panel, internal, gateway, password or home
    kind: str
    name: str
    level: int
    role: str
    #: On the printer's home network (the LAN or its hotspot).
    home: bool
    #: Carries an identity (ACC-34): everything except anyone at home.
    identified: bool

    def describe(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "level": LEVEL_NAMES[self.level],
            "role": self.role,
            "home": self.home,
            "identified": self.identified,
        }


PANEL_PRINCIPAL = Principal("panel", "panel", PANEL, OPERATOR, True, True)
INTERNAL_PRINCIPAL = Principal(
    "internal", "internal", PANEL, OPERATOR, True, True
)


def _gateway_principal(user: Any) -> Principal:
    level_name = getattr(user, "access_level", None)
    role = getattr(user, "access_role", None)
    name = str(
        getattr(user, "principal", "") or getattr(user, "username", "") or ""
    )
    home = getattr(user, "access_home", False) is True
    if level_name is None and role is None:
        # A muon-link that sends no principal: the gateway as it was.
        return Principal("gateway", name, ADMIN, OPERATOR, home, True)
    level = PRINCIPAL_LEVELS.get(level_name or "", SIGNED_OUT_GUEST)
    if role not in ROLES:
        role = VIEWER
    return Principal("gateway", name, level, role, home, True)


def _is_password_user(user: Any) -> bool:
    return (
        user is not None
        and getattr(user, "username", None) == PASSWORD_LOGIN_USER
        and getattr(user, "source", None) == "moonraker"
    )


def resolve_principal(
    transport: Optional[Any],
    ip_addr: Optional[Any],
    user: Optional[Any],
    entry: str,
    home: Optional[HomeNetwork] = None,
) -> Optional[Principal]:
    """Who is asking, or None if this caller is not admitted at all."""
    if home is None:
        home = HomeNetwork()
    if muon_floor._is_internal(transport):
        return INTERNAL_PRINCIPAL
    if muon_floor.local_address(ip_addr):
        return PANEL_PRINCIPAL
    if muon_floor._is_gateway_address(ip_addr):
        if (
            user is not None
            and getattr(user, "source", None) == muon_floor.GATEWAY_USER_SOURCE
        ):
            return _gateway_principal(user)
        # From away with no token: nobody is admitted anonymously (SEC-1).
        return None
    if ip_addr is None:
        # No address (MQTT): neither home nor identified.
        return None
    if not home.contains(ip_addr):
        # Reached Moonraker directly from outside the LAN and the hotspot (a
        # forwarded port, a routed VPN). The password works only from home
        # (ACC-16), and Open admits an unidentified caller only from home
        # (ACC-4), so neither is admitted.
        return None
    if _is_password_user(user):
        return Principal(
            "password", "password", SIGNED_OUT_GUEST, OPERATOR, True, True
        )
    if entry == ENTRY_OPEN:
        return Principal(
            "home", "anyone at home", SIGNED_OUT_GUEST, OPERATOR, True, False
        )
    return None


# ---------------------------------------------------------------------------
# Which action a request is
# ---------------------------------------------------------------------------

READ = ACTIONS["read"]

#: Writes, by registered endpoint, matched on a path-segment boundary. The
#: first match wins, so a longer prefix comes before a shorter one.
WRITE_ACTIONS: Tuple[Tuple[str, str], ...] = (
    ("/server/muon/setup", "setup"),
    ("/server/muon/link", "owner"),
    ("/server/muon/protection", "protection"),
    ("/server/muon/access/set_entry", "access_api"),
    ("/server/muon/access/set_private_uploads", "access_api"),
    ("/server/muon/access/set_data", "access_api"),
    ("/server/muon/access/set_levels", "access_api"),
    ("/server/muon/access/request", "access_request"),
    ("/server/muon/access/request_status", "access_request"),
    ("/server/muon/access/cancel_request", "access_request"),
    # answer, and anything new under the prefix: the protection row
    ("/server/muon/access", "protection"),
    ("/server/muon/identity/name", "rename"),
    ("/server/aux/dev_mode", "dev_mode"),
    ("/server/aux/wifi/ap", "hotspot"),
    ("/server/aux/wifi", "wifi"),
    ("/server/aux/update", "updates"),
    ("/server/aux/display", "ui_settings"),
    ("/machine/update", "updates"),
    ("/printer/print", "print"),
    ("/server/job_queue", "print"),
    ("/server/spoolman/spool_id", "print"),
    ("/printer/restart", "motion"),
    ("/printer/firmware_restart", "motion"),
    ("/machine/wled", "motion"),
    # Reads that arrive as POST
    ("/server/connection/identify", "read"),
    ("/access/login", "read"),
    ("/access/logout", "read"),
    ("/access/refresh_jwt", "read"),
    ("/api/login", "read"),
    ("/server/files/metascan", "read"),
    ("/server/analysis/estimate", "read"),
    ("/server/database/item", "ui_settings"),
    ("/server/announcements/dismiss", "ui_settings"),
    ("/server/announcements/update", "ui_settings"),
    ("/server/files/upload", "files"),
    ("/server/files/copy", "files"),
    ("/server/files/zip", "files"),
    ("/server/analysis/process", "files"),
    ("/api/files/moonraker", "files"),
    ("/server/files/move", "files_others"),
    ("/server/files/delete_file", "files_others"),
)

#: Klippy's own endpoints (registered without a leading slash) that only read.
KLIPPY_READS = frozenset((
    "info", "objects/list", "objects/query", "objects/subscribe",
    "gcode/help", "gcode/subscribe_output", "query_endpoints/list",
    "list_endpoints",
))

#: G-code by command word. A command in none of these sets, a macro this
#: printer defines included, is the raw console: the most demanding row that
#: a G-code line can be, so anything unrecognised fails closed.
GCODE_READ = frozenset((
    "M105", "M114", "M115", "GET_POSITION", "QUERY_ENDSTOPS", "QUERY_PROBE",
    "STATUS", "HELP",
))
GCODE_ESTOP = frozenset(("M112",))
GCODE_PRINT = frozenset((
    "PAUSE", "RESUME", "CANCEL_PRINT", "CLEAR_PAUSE", "SDCARD_PRINT_FILE",
    "SDCARD_RESET_FILE", "M24", "M25",
))
GCODE_MOTION = frozenset((
    "G0", "G1", "G2", "G3", "G4", "G10", "G11", "G28", "G90", "G91",
    "M18", "M82", "M83", "M84", "M104", "M106", "M107", "M109", "M117",
    "M140", "M190", "M220", "M221", "M400",
    "SET_HEATER_TEMPERATURE", "TEMPERATURE_WAIT", "TURN_OFF_HEATERS",
    "SET_FAN_SPEED", "SAVE_GCODE_STATE", "RESTORE_GCODE_STATE",
    "BED_MESH_CALIBRATE", "BED_MESH_CLEAR", "BED_MESH_PROFILE",
    # The M1's own operator macros (core/M1/macros in Muon3D_Klipper)
    "CHOME", "LOAD_FILAMENT", "UNLOAD_FILAMENT", "NOZZLE_WIPE_SMART",
    "NOZZLE_WIPE_SMART_STOP",
))

_TRADITIONAL = re.compile(r"[GMT]\d+(\.\d+)?", re.IGNORECASE)
_EXTENDED = re.compile(r"[A-Z_][A-Z0-9_]*", re.IGNORECASE)
_LINE_NUMBER = re.compile(r"^N\d+\s*", re.IGNORECASE)


def _matches(endpoint: str, prefix: str) -> bool:
    return endpoint == prefix or endpoint.startswith(prefix + "/")


def gcode_commands(script: Any) -> List[str]:
    """The command word of each line of a G-code script, upper case."""
    commands: List[str] = []
    for line in str(script or "").splitlines():
        line = _LINE_NUMBER.sub("", line.split(";", 1)[0].strip())
        if not line or line.startswith("#"):
            continue
        match = _TRADITIONAL.match(line)
        if match is None:
            match = _EXTENDED.match(line)
        commands.append((match.group(0) if match else line.split()[0]).upper())
    return commands


def gcode_actions(script: Any) -> Tuple[Action, ...]:
    actions: List[Action] = []
    for command in gcode_commands(script):
        if command in GCODE_READ:
            name = "read"
        elif command in GCODE_ESTOP:
            name = "emergency_stop"
        elif command in GCODE_PRINT:
            name = "print"
        elif command in GCODE_MOTION:
            name = "motion"
        else:
            name = "console"
        actions.append(ACTIONS[name])
    return tuple(actions) or (READ,)


def _klippy_actions(endpoint: str, args: Mapping[str, Any]) -> Tuple[Action, ...]:
    if (
        endpoint in KLIPPY_READS
        or endpoint.startswith("objects/")
        or "/dump_" in endpoint
    ):
        return (READ,)
    if endpoint == "emergency_stop":
        return (ACTIONS["emergency_stop"],)
    if endpoint == "gcode/script":
        return gcode_actions(args.get("script"))
    if endpoint in ("gcode/restart", "gcode/firmware_restart"):
        return (ACTIONS["motion"],)
    if endpoint.startswith("pause_resume/"):
        return (ACTIONS["print"],)
    return (ACTIONS["console"],)


def _file_roots(args: Mapping[str, Any]) -> List[str]:
    """The file roots a file request names: `root`, or the first segment of
    each path argument. gcodes when none is named, as file_manager does."""
    roots: List[str] = []
    root = args.get("root")
    if isinstance(root, str) and root:
        roots.append(root)
    for key in ("path", "source", "dest"):
        value = args.get(key)
        if isinstance(value, str) and value:
            roots.append(value.lstrip("/").split("/", 1)[0])
    items = args.get("items")
    if isinstance(items, (list, tuple)):
        for item in items:
            if isinstance(item, str) and item:
                roots.append(item.lstrip("/").split("/", 1)[0])
    return roots or ["gcodes"]


def _with_roots(action: Action, args: Mapping[str, Any]) -> Tuple[Action, ...]:
    """A write outside the gcodes root is the config row."""
    if any(root != "gcodes" for root in _file_roots(args)):
        return (ACTIONS["config"],)
    return (action,)


def classify(
    endpoint: str,
    request_type: Optional[Any] = None,
    args: Optional[Mapping[str, Any]] = None,
) -> Tuple[Action, ...]:
    """The actions a request is. Usually one; a G-code script is one per
    line. Unrecognised writes are `system`: fail closed."""
    args = args or {}
    method = getattr(request_type, "name", None)
    if not endpoint.startswith("/"):
        return _klippy_actions(endpoint, args)
    if endpoint == "/server/aux/proxy":
        path = args.get("path")
        verb = str(args.get("method", "GET")).upper()
        if not isinstance(path, str):
            return (ACTIONS["system"],)
        inner = posixpath.normpath("/" + path.lstrip("/"))
        verb_type = type("_RT", (), {"name": verb})()
        return classify("/server/aux" + inner, verb_type, {})
    if endpoint == "/server/muon/access/request_status":
        # A GET, but reachable before the caller is admitted
        return (ACTIONS["access_request"],)
    if method == "GET":
        return (READ,)
    if endpoint == "/api/printer/command":
        commands = args.get("commands")
        if isinstance(commands, (list, tuple)):
            return gcode_actions("\n".join(str(c) for c in commands))
        return (ACTIONS["console"],)
    if endpoint == "/server/files/directory":
        name = "files_others" if method == "DELETE" else "files"
        return _with_roots(ACTIONS[name], args)
    for prefix, name in WRITE_ACTIONS:
        if not _matches(endpoint, prefix):
            continue
        actions: Tuple[Action, ...] = (ACTIONS[name],)
        if name in ("files", "files_others"):
            actions = _with_roots(ACTIONS[name], args)
        if name == "files" and str(args.get("print", "")).lower() == "true":
            # An upload that starts printing is a print too
            actions += (ACTIONS["print"],)
        return actions
    return (ACTIONS["system"],)


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------

_state: Optional[AccessState] = None
#: Drives and private uploads (muon_access_files.FileGuard), when the
#: component has set them up. Checked after the table, for every principal
#: but an in-process call: the panel too (design 2.7).
_files: Optional[Any] = None


def set_files(guard: Optional[Any]) -> None:
    global _files
    _files = guard


def set_state(state: Optional[AccessState]) -> None:
    """Set what this process enforces. Only components/muon_access calls it;
    None turns the check off (no [muon_access] section)."""
    global _state
    _state = state


def state() -> Optional[AccessState]:
    return _state


@dataclasses.dataclass(frozen=True)
class Decision:
    allowed: bool
    action: str
    reason: str = ""
    required: Optional[int] = None


def decide_action(
    action: Action, principal: Optional[Principal], state: AccessState
) -> Decision:
    if principal is None:
        reason = (
            "this printer is Protected, and this connection is not signed in "
            "with its password, approved or paired"
            if state.entry == ENTRY_PROTECTED
            else "this connection is not from the printer's home network, "
            "signed in or paired"
        )
        return Decision(False, action.name, reason)
    if principal.level >= PANEL:
        return Decision(True, action.name)
    if principal.role == VIEWER and not (action.read or action.viewer_allowed):
        return Decision(False, action.name, "a Viewer can only watch")
    if action.delegated:
        return Decision(True, action.name)
    required = required_level(action, state)
    if required >= PANEL:
        return Decision(
            False, action.name, "it can be done only at the printer's panel",
            required,
        )
    if action.home_only and not principal.home and not (
        action.admin_from_away and principal.level >= ADMIN
    ):
        return Decision(
            False, action.name,
            "it can be done only from the printer's home network", required,
        )
    if principal.level < required:
        return Decision(
            False, action.name,
            f"it needs {LEVEL_NAMES[required]}, and this connection is "
            f"{LEVEL_NAMES[principal.level]}",
            required,
        )
    return Decision(True, action.name, "", required)


def refusal(decision: Decision) -> ServerError:
    """A 403 whose message names the action first, so a client can read it
    without parsing the sentence: `access-denied:<action>: <reason>`."""
    return ServerError(
        f"access-denied:{decision.action}: '{decision.action}' is not allowed "
        f"on this printer: {decision.reason}.",
        403,
    )


def check_access(
    endpoint: str,
    request_type: Optional[Any] = None,
    args: Optional[Mapping[str, Any]] = None,
    transport: Optional[Any] = None,
    ip_addr: Optional[Any] = None,
    user: Optional[Any] = None,
) -> None:
    """Raise a 403 naming the action when the level table refuses this
    request. Called after the floor and after check_protection."""
    current = _state
    if current is None:
        return
    if muon_floor._is_internal(transport):
        return
    if muon_floor.local_address(ip_addr):
        # The panel is above every level (ACC-10). Checked before the
        # endpoint is classified so the panel never pays for it. Private
        # files still hide from it (design 2.7).
        if _files is not None:
            _files.check(endpoint, request_type, args or {}, PANEL_PRINCIPAL)
        return
    principal = resolve_principal(
        transport, ip_addr, user, current.entry, current.home
    )
    actions = classify(endpoint, request_type, args)
    if principal is None and at_home_unadmitted(actions, ip_addr, current):
        return
    if _files is not None and principal is not None:
        actions = _files.adjust(actions, endpoint, request_type, args or {},
                                principal)
    for action in actions:
        decision = decide_action(action, principal, current)
        if not decision.allowed:
            raise refusal(decision)
    if _files is not None and principal is not None:
        _files.check(endpoint, request_type, args or {}, principal)


def _file_principal(
    transport: Optional[Any], ip_addr: Optional[Any], user: Optional[Any]
) -> Optional[Principal]:
    current = _state
    if current is None or _files is None or muon_floor._is_internal(transport):
        return None
    if muon_floor.local_address(ip_addr):
        return PANEL_PRINCIPAL
    return resolve_principal(transport, ip_addr, user, current.entry,
                             current.home)


def filter_result(
    endpoint: str,
    request_type: Optional[Any],
    args: Optional[Mapping[str, Any]],
    transport: Optional[Any],
    ip_addr: Optional[Any],
    user: Optional[Any],
    coro: Any,
) -> Any:
    """The handler's coroutine, with listings filtered to what the caller
    may see. The coroutine itself when nothing applies."""
    principal = _file_principal(transport, ip_addr, user)
    guard = _files
    if principal is None or guard is None:
        return coro

    async def filtered() -> Any:
        return guard.filter(endpoint, request_type, args or {}, principal,
                            await coro)
    return filtered()


def plan_upload(ip_addr: Optional[Any], user: Optional[Any],
                form_args: Dict[str, Any]) -> Optional[Any]:
    """Where an upload goes, and its tag (rewrites form_args["path"])."""
    principal = _file_principal(None, ip_addr, user)
    if principal is None or _files is None:
        return None
    return _files.plan_upload(principal, form_args)


def finish_upload(plan: Optional[Any], result: Any) -> Dict[str, Any]:
    """What the upload's answer adds: "private", and why not."""
    if plan is None or _files is None:
        return {}
    return _files.finish_upload(plan, result)


def at_home_unadmitted(
    actions: Iterable[Action], ip_addr: Optional[Any], state: AccessState
) -> bool:
    """A caller that is not admitted, on the home network, asking only for
    what such a caller may ask."""
    actions = list(actions)
    return (
        bool(actions)
        and all(action.home_unadmitted for action in actions)
        and ip_addr is not None
        and not muon_floor._is_gateway_address(ip_addr)
        and state.home.contains(ip_addr)
    )


def allowed_actions(
    principal: Optional[Principal], state: AccessState
) -> List[str]:
    """What this principal may do: the capability list a client shows."""
    return [
        name for name, action in ACTIONS.items()
        if decide_action(action, principal, state).allowed
    ]


def effective_table(state: AccessState) -> Dict[str, str]:
    return {
        name: LEVEL_NAMES[required_level(action, state)]
        for name, action in ACTIONS.items()
    }


def parse_overrides(value: Any) -> Dict[str, int]:
    """Stored or posted overrides, as {action: level}. Raises ValueError on
    an unknown action, a fixed row or an unknown level."""
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("'overrides' must be an object of action: level")
    parsed: Dict[str, int] = {}
    for name, level_name in value.items():
        if not overridable(name):
            raise ValueError(f"'{name}' is not a row that can be changed")
        if level_name not in PRINCIPAL_LEVELS:
            raise ValueError(
                f"'{name}' must be one of {sorted(PRINCIPAL_LEVELS)}"
            )
        parsed[name] = PRINCIPAL_LEVELS[level_name]
    return parsed


def describe_overrides(overrides: Mapping[str, int]) -> Dict[str, str]:
    return {name: LEVEL_NAMES[level] for name, level in overrides.items()}


def known(values: Iterable[str], value: Any) -> bool:
    return isinstance(value, str) and value in values
