# MUON -- what a write through the file API is allowed to put in the
# calibration layer.
#
# SPEC CFG-2 / CFG-3, KAN-108 (docs/connectivity/SPEC.md in the MuonOS repo).
#
# The hazard
# ----------
# Klipper is started as ``klippy.py $CORE_CFG -c <printer_data>/calibration/
# calibration.cfg`` (klipper.service.template:21).  The OEM core config is
# root-owned and not writable by the Moonraker user, but the calibration file
# is writable *by design* -- SAVE_CONFIG has to be able to write it -- and
# Moonraker registers that directory as a full-access root
# (file_manager.py:155).  So the calibration file is the one file a network
# client can put content into that Klipper will then load.
#
# Klipper does guard it, but the guard is a blacklist: ``ConfigAutoSave.
# load_main_config`` (klippy/configfile.py:324-340) rejects a calibration key
# that *core already defines* and accepts everything else.  ``core.cfg`` defines
# ``[verify_heater heater_bed]`` but not ``[verify_heater extruder]``, so
#
#     #*# [verify_heater extruder]
#     #*# max_error = 999999
#
# is a section core does not define, is accepted, and disables thermal-runaway
# protection on the hot end persistently -- it survives reboots, because it is
# a config file rather than a runtime command.
#
# The fix is to invert it: an allowlist of the sections and keys calibration is
# *for*.  Anything else is refused at the point of writing.
#
# Where the allowlist comes from
# ------------------------------
# Not invented here.  It is the set of ``configfile.set()`` targets in the
# Klipper fork -- that is, exactly what SAVE_CONFIG itself writes on this
# machine -- minus anything that is not a calibration result.  If a calibration
# routine is added to Klipper and starts saving a new key, this list needs the
# key adding, and the failure mode is a refused write with the key named in the
# message rather than a silently accepted one.
#
# Note this does not constrain SAVE_CONFIG: Klipper writes the file directly on
# disk and never goes through Moonraker's file API.  The guard applies to human
# and remote edits, which is what CFG-2 is about.

from __future__ import annotations

from typing import Dict, FrozenSet, List, Tuple

# The file_manager root that Klipper reads (file_manager.py:155).  CFG-3: this
# is covered explicitly rather than by inheritance, because calibration.cfg is
# excluded from the developer-mode clone (aux_api/dev_mode_routes.py) and is
# therefore live in *both* modes -- the dev-mode boundary does not cover it.
GUARDED_ROOT = "calibration"

# Refuse outright above this rather than reading it.  The vhost allows 1 GiB
# uploads (client_max_body_size in fluidd.nginx.template) and the guard has to
# read what it validates, so without a bound a "calibration file" is a way to
# make Moonraker allocate a gigabyte.  Klipper configs are a few KB; the
# shipped calibration.cfg is under 3 KB.
MAX_GUARDED_BYTES = 1 << 20  # 1 MiB

# PID and MPC model constants, written by heaters.py and control_mpc.py.  The
# MPC set is the one the shipped core/M1/calibration.cfg actually carries;
# tests/test_calibration_guard.py reads that file and fails if this list cannot
# express it, which is how filament_density got here.
#
# Deliberately absent, though control_mpc.py also names them: max_temp,
# min_temp, max_power, max_error, heater_power, cooling_fan,
# ambient_temp_sensor.  Those are the safety envelope and the hardware
# description, not a calibration result -- they belong to the read-only core
# config, and a calibration file that could set heater_power would be a
# calibration file that could set how hard the heater is driven.
_HEATER_TUNING: FrozenSet[str] = frozenset({
    "control",
    "pid_kp", "pid_ki", "pid_kd", "pid_version",
    "block_heat_capacity", "sensor_responsiveness",
    "ambient_transfer", "fan_ambient_transfer",
    "filament_density", "filament_heat_capacity",
})

ALLOWED_SECTION_KEYS: Dict[str, FrozenSet[str]] = {
    # bed_mesh.py saves a profile section, e.g. "[bed_mesh default]".
    "bed_mesh": frozenset({
        "version", "points", "x_count", "y_count",
        "mesh_x_pps", "mesh_y_pps", "algo", "tension",
        "min_x", "max_x", "min_y", "max_y",
    }),
    "extruder": _HEATER_TUNING,
    "heater_bed": _HEATER_TUNING,
    "input_shaper": frozenset({
        "shaper_type_x", "shaper_freq_x", "damping_ratio_x",
        "shaper_type_y", "shaper_freq_y", "damping_ratio_y",
    }),
    "bed_tilt": frozenset({"x_adjust", "y_adjust", "z_adjust"}),
    "skew_correction": frozenset({"xy_skew", "xz_skew", "yz_skew"}),
    "load_cell": frozenset({"counts_per_gram", "reference_tare_counts"}),
    "load_cell_probe": frozenset({
        "z_offset", "reference_max_load_counts",
        "counts_per_gram", "reference_tare_counts", "trigger_phase",
    }),
    "probe": frozenset({"z_offset"}),
}

AUTOSAVE_PREFIX = "#*#"


def _parse(text: str) -> Tuple[List[Tuple[int, str]], List[Tuple[int, str, str]]]:
    """Return (section declarations, assignments) as (line number, ...) tuples.

    Sections are reported separately from the keys inside them because a
    section can be dangerous with no keys at all: ``[include /etc/passwd]`` and
    a bare ``[gcode_macro X]`` both do something, and a guard that only looked
    at assignments would wave them through.

    Both halves of the file are read.  Klipper only loads the ``#*#`` autosave
    block from a calibration file today (configfile.py:313-316), but the plain
    half is parsed too: it costs nothing, and a guard that only looked at the
    block would be one Klipper change away from being wrong.
    """
    sections: List[Tuple[int, str]] = []
    assignments: List[Tuple[int, str, str]] = []
    section = ""
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if line.lstrip().startswith(AUTOSAVE_PREFIX):
            # expose the autosave block's real content
            line = line.lstrip()[len(AUTOSAVE_PREFIX):]
            if line.startswith(" "):
                line = line[1:]
            if not line.strip():
                continue
        elif not line.strip() or line.lstrip()[0] in "#;":
            continue
        if line[:1].isspace():
            # a continuation of the previous value (bed_mesh points, say)
            continue
        stripped = line.strip()
        if stripped.startswith("["):
            section = stripped[1:].split("]", 1)[0].strip()
            sections.append((lineno, section))
            continue
        for sep in (":", "="):
            if sep in stripped:
                key = stripped.split(sep, 1)[0].strip().lower()
                if key:
                    assignments.append((lineno, section, key))
                break
    return sections, assignments


def section_type(section: str) -> str:
    """"bed_mesh default" -> "bed_mesh"; "verify_heater extruder" -> "verify_heater"."""
    return section.split()[0].lower() if section.split() else ""


def violations(text: str) -> List[str]:
    """Every reason this content may not be written to the calibration layer."""
    out: List[str] = []
    sections, assignments = _parse(text)
    for lineno, section in sections:
        if section_type(section) not in ALLOWED_SECTION_KEYS:
            out.append(
                f"line {lineno}: [{section}] is not a calibration section"
            )
    for lineno, section, key in assignments:
        if not section:
            out.append(f"line {lineno}: '{key}' is outside any section")
            continue
        allowed = ALLOWED_SECTION_KEYS.get(section_type(section))
        if allowed is None:
            # already reported at the section declaration
            continue
        if key not in allowed:
            out.append(
                f"line {lineno}: [{section}] '{key}' is not a calibration key"
            )
    return out


def rejection_message(filename: str, found: List[str]) -> str:
    listed = "; ".join(found[:8])
    if len(found) > 8:
        listed += f"; and {len(found) - 8} more"
    return (
        f"'{filename}' was refused: the calibration layer accepts only "
        f"calibration results, and this write does not qualify -- {listed}. "
        "Safety-relevant configuration lives in the read-only OEM config and "
        "is changed only in developer mode, at the machine."
    )
