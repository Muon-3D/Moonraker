# MUON, KAN-203 -- the network step: scan, join, region confirm (spec
# 01 §2.1, 02 §5.5, §5.6 and §5.6a, 03 §4). Work package MR-3.
#
# A join is an `op` ({kind: "join"}) so the HTTP answer comes back at once and
# the surfaces watch `op.phase` move through saving -> region (when asked) ->
# associating -> authenticating -> dhcp -> internet_check -> update_check.
# The region apply inside a join is the same code as POST .../region
# ({kind: "region_apply"}); they differ only in which field records a failure.
#
# Today's image predates OS-2 (stable Aux join codes), OS-3 (hidden networks),
# the region routes (KAN-321) and GET /wifi/uplink (W5). Every fallback is
# marked `# until OS-2` or `# until OS-3` so removing them is one grep.
#
# Secrets (02 §5.6 step 8, 07 S2): the psk goes from the request straight to
# Aux's POST /wifi/connect and nowhere else. It is never stored in the
# document or the op, never logged, and never carried inside an exception:
# refusals are raised `from None` so no traceback holds the connect argv.

from __future__ import annotations

import asyncio
import fcntl
import logging
import os
import socket
import struct
import time
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

from . import caller, clock, model, update
from ...utils.exceptions import ServerError

if TYPE_CHECKING:
    from . import MuonSetup, OpHandle, WriteContext
    from ...common import WebRequest

#: 03 §4: how long the whole join may take; the connect call itself gets
#: longer because Aux's rollback budget sits on top of it.
CONNECT_TIMEOUT = 60.0
SCAN_TIMEOUT = 15.0
REGION_TIMEOUT = 60.0
#: GET /wifi/device/status while a join runs (03 §4).
STATUS_POLL = 0.5

JOIN_PHASES = ("saving", "region", "associating", "authenticating",
               "dhcp", "internet_check", "update_check")

#: nmcli's device states, mapped onto the phases (03 §4 step 2).
DEVICE_PHASES = {
    "preparing": "associating",
    "configuring": "associating",
    "need-auth": "authenticating",
    "ip-config": "dhcp",
    "ip-check": "dhcp",
    "activated": "internet_check",
    "secondaries": "dhcp",
    "connecting": "associating",
    "getting IP configuration": "dhcp",
}

SECURITY_KINDS = ("open", "owe", "wep", "wpa2", "wpa3", "wpa2_wpa3",
                  "enterprise")
#: How Aux's free `security` text sorts (02 §5.5). nmcli's SECURITY column
#: is things like "WPA2", "WPA1 WPA2", "802.1X", "" or "OWE".
SECURITY_MAP = {
    "": "open",
    "--": "open",
    "OPEN": "open",
    "OWE": "owe",
    "WEP": "wep",
    "802.1X": "enterprise",
    "WPA3": "wpa3",
    "WPA2 WPA3": "wpa2_wpa3",
    "WPA3 WPA2": "wpa2_wpa3",
}
_HEX64 = set("0123456789abcdefABCDEF")


def register(setup: MuonSetup) -> None:
    reg = setup.server.register_endpoint
    reg("/server/muon/setup/networks", ["GET"],
        lambda webreq: handle_networks(setup, webreq))
    reg("/server/muon/setup/network", ["POST"],
        lambda webreq: handle_network(setup, webreq))
    reg("/server/muon/setup/region", ["POST"],
        lambda webreq: handle_region(setup, webreq))


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------

def _aux_status(exc: BaseException) -> Optional[int]:
    """The HTTP status Aux answered with, under the Aux* wrapper."""
    cause = getattr(exc, "__cause__", None)
    return getattr(cause, "status_code", None)


async def aux_status(setup: MuonSetup, path: str,
                     timeout: float = SCAN_TIMEOUT) -> Any:
    """GET a route, the Aux* wrappers made an `AuxMissing`-aware read."""
    return await setup.aux("GET", path)


def _region_market(setup: MuonSetup) -> str:
    region = setup._live.get("region")
    if not isinstance(region, dict):
        # Images without the region routes (KAN-321): `none`, so a join
        # confirms the region by itself (02 §5.6a).
        return "none"
    return str(region.get("market") or "none")


async def region_countries(setup: MuonSetup) -> Optional[List[str]]:
    """The countries a declaration may name, or None when the image cannot
    say (no /region/options yet)."""
    from . import AuxMissing, AuxRefused, AuxUnavailable
    try:
        options = await setup.aux("GET", "/region/options")
    except (AuxMissing, AuxRefused, AuxUnavailable):
        return None
    countries = options.get("countries") if isinstance(options, dict) else None
    return countries if isinstance(countries, list) else None


def _invalid(field: str) -> Dict[str, Any]:
    return model.error(
        "invalid_network", f"the `{field}` field is invalid", field=field)


def _ipv4_ioctl(ifname: str) -> Optional[str]:
    """The interface's IPv4, read live off the kernel (SIOCGIFADDR). No
    subprocess, no reliance on machine's refresh cadence."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            req = struct.pack("256s", ifname.encode()[:15])
            return socket.inet_ntoa(
                fcntl.ioctl(sock.fileno(), 0x8915, req)[20:24])
        finally:
            sock.close()
    except OSError:
        return None


def _ipv4_machine(setup: MuonSetup, ifname: str) -> Optional[str]:
    machine = setup.server.lookup_component("machine", None)
    if machine is None:
        return None
    try:
        info = machine.get_system_info().get("network", {}).get(ifname, {})
    except Exception:
        return None
    for addr in info.get("ip_addresses", []):
        if (isinstance(addr, dict) and addr.get("family") == "ipv4"
                and addr.get("address")
                and not addr.get("is_link_local")):
            return addr["address"]
    return None


def interface_ipv4(setup: MuonSetup, ifname: str) -> Optional[str]:
    """The live IPv4 for an uplink interface.

    # until OS-2: without GET /wifi/uplink there is no on-demand address
    # source. `machine`'s network info refreshes on a slow stat cadence, not
    # on demand, so the ioctl answer is taken first and machine's copy is the
    # fallback for test rigs where the interface does not exist.
    """
    return _ipv4_ioctl(ifname) or _ipv4_machine(setup, ifname)


# --------------------------------------------------------------------------
# GET /server/muon/setup/networks (02 §5.5)
# --------------------------------------------------------------------------

def _security(raw: Any) -> str:
    text = str(raw or "").strip().upper()
    if text in SECURITY_MAP:
        return SECURITY_MAP[text]
    if "802.1X" in text or "EAP" in text:
        return "enterprise"
    if "WEP" in text:
        return "wep"
    if "OWE" in text:
        return "owe"
    if "WPA3" in text and "WPA2" in text:
        return "wpa2_wpa3"
    if "WPA3" in text:
        return "wpa3"
    if "WPA" in text:
        return "wpa2"
    return "open" if not text else "wpa2"


def _band(freq: Any) -> Optional[str]:
    try:
        mhz = float(freq)
    except (TypeError, ValueError):
        return None
    if mhz < 3000:
        return "2.4"
    if mhz < 6500:
        return "5"
    return "6"


def normalize_scan(
    setup: MuonSetup, scan: Any, saved_names: List[str]
) -> List[Dict[str, Any]]:
    """02 §5.5: drop empties and our own hotspot, merge by SSID keeping the
    strongest entry, sort strongest first."""
    own = (setup._live["hotspot"].get("ssid") or "").strip()
    channels = set((setup._live.get("region") or {}).get("channels") or [])
    merged: Dict[str, Dict[str, Any]] = {}
    for entry in scan if isinstance(scan, list) else []:
        if not isinstance(entry, dict):
            continue
        ssid = entry.get("ssid")
        if not isinstance(ssid, str) or not ssid.strip() or ssid == own:
            continue
        signal = entry.get("signal")
        signal = signal if isinstance(signal, (int, float)) and not isinstance(
            signal, bool) else 0
        channel = entry.get("chan")
        if isinstance(channel, bool) or not isinstance(channel, int):
            channel = entry.get("channel")
        security = _security(entry.get("security"))
        row = merged.get(ssid)
        if row is None:
            row = {
                "ssid": ssid, "security": security, "signal": signal,
                "band": _band(entry.get("freq")), "channel": channel,
                "bssids": 1, "saved": ssid in saved_names,
                "in_use": entry.get("in_use") is True,
                "supported": security != "wep",
                "channel_permitted": not channels or channel in channels,
            }
            merged[ssid] = row
        else:
            row["bssids"] += 1
            if signal > row["signal"]:
                row["signal"] = signal
                row["band"] = _band(entry.get("freq"))
                row["channel"] = channel
                row["security"] = security
                row["supported"] = security != "wep"
                row["channel_permitted"] = (
                    not channels or channel in channels)
            if entry.get("in_use") is True:
                row["in_use"] = True
    return sorted(merged.values(), key=lambda r: -r["signal"])


async def _saved_ssids(setup: MuonSetup) -> List[str]:
    """The saved profile names (GET /wifi/saved). Until OS-2 lands it, `[]`:
    surfaces show no "Saved" badges."""
    from . import AuxMissing, AuxRefused, AuxUnavailable
    try:
        saved = await setup.aux("GET", "/wifi/saved")
    except (AuxMissing, AuxRefused, AuxUnavailable):
        return []
    names = []
    for profile in saved if isinstance(saved, list) else []:
        name = profile.get("name") if isinstance(profile, dict) else None
        if isinstance(name, str):
            names.append(name)
    return names


async def handle_networks(
    setup: MuonSetup, webreq: WebRequest
) -> Dict[str, Any]:
    from . import AuxMissing, AuxRefused, AuxUnavailable, STARTUP_WAIT
    caller.require(caller.caller_kind(webreq), caller.READ)
    await setup.wait_resolved(STARTUP_WAIT)
    rescan = str(webreq.get_args().get("rescan", "")).lower() == "true"
    try:
        scan = await setup.aux(
            "GET", "/wifi/scan?" + urlencode({"rescan": "true" if rescan
                                              else "false"}))
    except (AuxMissing, AuxRefused, AuxUnavailable) as exc:
        return {"ok": False,
                "error": model.error(
                    "aux_unavailable", f"Wi-Fi scan failed: {exc}"),
                "state": setup.public_state()}
    saved = await _saved_ssids(setup)
    return {
        "ok": True,
        "scanned_at": time.time(),
        "ethernet": ethernet_status(setup),
        "networks": normalize_scan(setup, scan, saved),
    }


def ethernet_status(setup: MuonSetup) -> Dict[str, Any]:
    """{present, carrier, address} for eth0 (02 §5.5)."""
    present = os.path.exists("/sys/class/net/eth0")
    carrier = False
    try:
        carrier = open("/sys/class/net/eth0/carrier").read().strip() == "1"
    except OSError:
        pass
    return {
        "present": present,
        "carrier": carrier,
        "address": _ipv4_ioctl("eth0") or _ipv4_machine(setup, "eth0"),
    }


# --------------------------------------------------------------------------
# The join orchestration (02 §5.6, 03 §4)
# --------------------------------------------------------------------------

def _join_code(exc: Any, result: Any) -> str:
    """The failure code for a join, preferring Aux's code until OS-2 ships
    them everywhere, then free-text mapping."""
    code = None
    if isinstance(result, dict):
        code = result.get("code")
    if code is None:
        code = getattr(exc, "code", None)
    if isinstance(code, str) and code in JOIN_FAILURE_CODES:
        return code
    text = ""
    if isinstance(result, dict):
        text = str(result.get("warning") or result.get("message") or "")
    if not text:
        text = str(exc or "")
    low = text.lower()
    if ("secrets were required" in low or "802-11-wireless-security" in low
            or "wrong password" in low or "psk" in low):
        return "wrong_password"
    if "no network with ssid" in low:
        return "ssid_not_found"
    if "ip configuration" in low or "dhcp" in low:
        return "no_address"
    return "timeout"


JOIN_FAILURE_CODES = {
    "wrong_password", "ssid_not_found", "no_address", "timeout",
    "eap_failed", "cert_invalid", "unsupported_security",
}


async def _ssid_saved_before(setup: MuonSetup, ssid: str) -> bool:
    """Was this SSID already a saved profile before the join? Used for the
    profile cleanup, where "can't tell" is treated as saved so nothing of the
    owner's is ever deleted."""
    from . import AuxMissing, AuxRefused, AuxUnavailable
    try:
        saved = await setup.aux("GET", "/wifi/saved")
    except AuxMissing:
        saved = None
    except (AuxRefused, AuxUnavailable):
        return True
    if isinstance(saved, list):
        return any(
            isinstance(p, dict) and p.get("name") == ssid for p in saved)
    # until OS-2: GET /wifi/show?ssid= stands in on this image.
    try:
        await setup.aux("GET", "/wifi/show?" + urlencode({"ssid": ssid}))
    except AuxMissing:
        return True
    except AuxRefused as exc:
        return exc.status != 404
    except AuxUnavailable:
        return True
    return True


async def _forget_after_join(setup: MuonSetup, ssid: str) -> None:
    """Forget the profile a join may have made, once the connect has ended.

    When /wifi/connect is still running at Aux (the join was cancelled or
    timed out), forgetting now would race it: nmcli can still finish and
    leave -- or activate -- the very profile we promised to remove. In that
    case the cleanup runs as a background task that waits for the connect,
    disconnects if it landed on the SSID, and forgets after that. The psk
    never enters the cleanup: it needs only the SSID."""
    connect = setup._join_connect
    if connect is not None and not connect.done():
        setup._join_cleanup = setup._spawn(_join_cleanup(setup, ssid))
        return
    setup._join_connect = None
    await _forget_profile(setup, ssid)


async def _join_cleanup(setup: MuonSetup, ssid: str) -> None:
    """The deferred forget: wait out the in-flight connect, disconnect if
    it finished on the cancelled SSID, then forget the profile."""
    from . import AuxMissing, AuxRefused, AuxUnavailable
    connect = setup._join_connect
    succeeded = False
    try:
        if connect is not None:
            try:
                result, _ = await asyncio.wait_for(
                    asyncio.shield(connect), CONNECT_TIMEOUT + 5.0)
            except Exception as exc:
                result = None
                if not isinstance(exc, asyncio.CancelledError):
                    logging.info(
                        "muon_setup: join cleanup: the connect never "
                        "finished: %s", exc)
            succeeded = (
                isinstance(result, dict)
                and result.get("status") == "connecting")
        if succeeded:
            # The connect Aux kept running may have put the printer on the
            # SSID the owner cancelled; disconnect before forgetting, but
            # only if the active network is actually that one.
            current: Any = None
            try:
                current = await setup.aux("GET", "/wifi/current")
            except (AuxMissing, AuxRefused, AuxUnavailable) as exc:
                logging.info(
                    "muon_setup: join cleanup: current SSID unknown: %s",
                    exc)
            if isinstance(current, dict) and current.get("ssid") == ssid:
                try:
                    await setup.aux("POST", "/wifi/disconnect")
                except (AuxMissing, AuxRefused, AuxUnavailable) as exc:
                    logging.info(
                        "muon_setup: join cleanup: disconnect failed: %s",
                        exc)
        await _forget_profile(setup, ssid)
    finally:
        if setup._join_connect is connect:
            setup._join_connect = None


async def _forget_profile(setup: MuonSetup, ssid: str) -> None:
    """Delete the profile the failed/cancelled join created -- only when it
    wasn't saved before. The hotspot profile and an owner's pre-existing one
    are never touched."""
    from . import AuxMissing, AuxRefused, AuxUnavailable
    try:
        await setup.aux("DELETE", "/wifi/forget?" + urlencode({"ssid": ssid}))
    except AuxMissing:
        logging.info(
            "muon_setup: this image has no Aux DELETE /wifi/forget; the "
            "partial profile stays")
    except (AuxRefused, AuxUnavailable) as exc:
        logging.info("muon_setup: profile cleanup for %r failed: %s",
                     ssid, exc)


def _join_fail(
    doc: Dict[str, Any], code: str, phase: Optional[str], ssid: str,
    message: str = ""
) -> None:
    step = doc["steps"]["network"]
    step["status"] = model.PENDING
    step["error"] = {
        "code": code, "at_phase": phase, "detail": {"ssid": ssid},
        "message": message or code,
    }


def cancel_cleanup_info(setup: MuonSetup) -> Tuple[Optional[str], bool]:
    """The join's (ssid, forget) from the op, read *before* cancel clears it.
    `forget` is True when the SSID wasn't a saved profile before the join."""
    doc = setup.doc
    op = (doc or {}).get("op") or {}
    if op.get("kind") != "join":
        return None, False
    ssid = op.get("ssid")
    return (ssid if isinstance(ssid, str) else None,
            op.get("forget") is True)


async def cancel_cleanup(setup: MuonSetup, ssid: Optional[str],
                         forget: bool) -> None:
    """02 §5.6a: a cancelled join removes the partial profile -- unless the
    SSID was already saved before the join."""
    if ssid is not None and forget:
        await _forget_after_join(setup, ssid)


# --------------------------------------------------------------------------
# Region apply (02 §5.6a), shared by POST .../region and a join's `region`
# --------------------------------------------------------------------------

REGION_CODES = {
    "country-not-in-token": "region_not_offered",
    "no-token": "needs_reregistration",
    "unreadable-token": "needs_reregistration",
    "bad-token-format": "needs_reregistration",
    "bad-signature": "needs_reregistration",
    "unknown-serial": "needs_reregistration",
    "serial-mismatch": "needs_reregistration",
    "no-signing-key": "needs_reregistration",
    "busy": "region_busy",
}


def _region_code(exc: BaseException) -> str:
    """Map an Aux refusal to the §5.6a table, free-text until OS-2."""
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code in REGION_CODES:
        return REGION_CODES[code]
    text = str(exc).lower()
    # # until OS-2: Aux's region failures arrive as free text.
    if "country-not-in-token" in text or "not in token" in text:
        return "region_not_offered"
    for marker in ("no-token", "no token", "unreadable-token",
                   "unreadable token", "bad-token-format", "bad-signature",
                   "unknown-serial", "serial-mismatch", "no-signing-key",
                   "signing key"):
        if marker in text:
            return "needs_reregistration"
    if "busy" in text:
        return "region_busy"
    return "region_apply_failed"


async def apply_region(
    setup: MuonSetup, country: str
) -> Optional[Dict[str, Any]]:
    """POST /region/country and judge it. Returns None on success or a
    {code, message} error dict."""
    from . import AuxMissing, AuxRefused, AuxUnavailable
    try:
        await setup.aux("POST", "/region/country", {"country": country},
                        timeout=REGION_TIMEOUT)
    except AuxMissing:
        # # until OS-2: this image has no region routes at all.
        return {"code": "region_apply_failed",
                "message": "this image has no region routes"}
    except AuxRefused as exc:
        return {"code": _region_code(exc), "message": str(exc)}
    except AuxUnavailable as exc:
        if _aux_status(exc) == 504:
            # The apply may still have landed; read the declaration before
            # deciding (02 §5.6a).
            try:
                state = await setup.aux("GET", "/region")
            except (AuxMissing, AuxRefused, AuxUnavailable):
                return {"code": "region_busy", "message": str(exc)}
            if (isinstance(state, dict)
                    and state.get("declared_country") == country):
                await setup._refresh_region()
                return None
            return {"code": "region_busy", "message": str(exc)}
        return {"code": "region_apply_failed", "message": str(exc)}
    # Success: refresh what GET /region would now say.
    await setup._refresh_region()
    return None


async def _single_zone_tz(setup: MuonSetup, doc: Dict[str, Any]) -> None:
    """02 §5.6a step 4: a one-zone country sets the zone itself, unless the
    phone or the owner already chose."""
    region = setup._live.get("region") or {}
    country = region.get("declared_country")
    if not isinstance(country, str):
        return
    if setup._internal.get("tz_source") in ("phone", "owner"):
        return
    zones = clock.zones_for_country(country)
    if len(zones) != 1:
        return
    try:
        await clock._set_zone(setup, zones[0])
    except Exception as exc:
        logging.info("muon_setup: could not set the region's zone: %s", exc)
        return
    setup._internal["tz_source"] = "region"
    await setup._persist_internal()


# --------------------------------------------------------------------------
# POST /server/muon/setup/region {rev, country}
# --------------------------------------------------------------------------

async def handle_region(
    setup: MuonSetup, webreq: WebRequest
) -> Dict[str, Any]:
    async def handler(ctx: WriteContext) -> Optional[Dict[str, Any]]:
        doc = ctx.doc
        country = ctx.args.get("country")
        if not isinstance(country, str) or not country:
            return model.error(
                "region_not_offered", "'country' is not a country code")
        countries = await region_countries(setup)
        if countries is not None and country.upper() not in countries:
            return model.error(
                "region_not_offered",
                f"{country!r} is not offered on this printer")
        network = doc["steps"]["network"]
        network["region_error"] = None
        setup.start_op(
            "region_apply",
            _region_runner(setup, str(country).upper(), False),
            country=str(country).upper())
        return None
    return await setup.write(webreq, handler)


def _region_runner(setup: MuonSetup, country: str, from_join: bool):
    async def run(handle: OpHandle) -> None:
        err = await apply_region(setup, country)
        if err is not None:
            await handle.finish(
                lambda doc: _region_outcome(setup, doc, country, err,
                                            from_join))
            return
        await handle.finish(
            lambda doc: _region_outcome(setup, doc, country, None, from_join))
    return run


def _region_outcome(
    setup: MuonSetup, doc: Dict[str, Any], country: str,
    err: Optional[Dict[str, Any]], from_join: bool
) -> None:
    network = doc["steps"]["network"]
    if err is not None:
        # 02 §5.6a: a failed apply is recorded on the step, whether it was
        # POST /region or a join's region phase.
        network["region_error"] = err
        return
    network["region_confirmed"] = True
    network["region_error"] = None
    if network["status"] == model.PENDING and network.get("kind"):
        # The join ran and has an uplink; confirming finishes the step.
        network["status"] = model.DONE
        if doc["state"] != "complete" and doc["cursor"] == "network":
            setup.advance()
    # else: called while network is still pending before a join -- apply
    # only; the join sets region_confirmed (02 §5.6a).
    setup._spawn(_single_zone_tz(setup, doc))


# --------------------------------------------------------------------------
# POST /server/muon/setup/network {rev, kind, ...}
# --------------------------------------------------------------------------

async def handle_network(
    setup: MuonSetup, webreq: WebRequest
) -> Dict[str, Any]:
    async def handler(ctx: WriteContext) -> Optional[Dict[str, Any]]:
        doc = ctx.doc
        step = doc["steps"]["network"]
        args = ctx.args
        kind = args.get("kind")
        if kind == "ethernet":
            # Ethernet is confirmed by an address already being there (02
            # §5.6): no psk, no op.
            address = interface_ipv4(setup, "eth0")
            if address is None:
                return _invalid("kind")
            step.update(kind="ethernet", ssid=None, addresses=[address],
                        hostname_local=_hostname_local(),
                        internet=None, error=None,
                        region_confirmed=True, region_error=None,
                        status=model.DONE)
            if doc["state"] != "complete":
                setup.advance()
            if doc["state"] == "complete":
                setup._spawn(setup.schedule_hotspot_off())
            return None
        if kind != "wifi":
            return _invalid("kind")
        ssid = args.get("ssid")
        if not isinstance(ssid, str) or not (1 <= len(ssid.encode("utf-8"))
                                             <= 32):
            return _invalid("ssid")
        security = args.get("security")
        if security is not None and security not in SECURITY_KINDS:
            return _invalid("security")
        if security in ("wep", "enterprise"):
            return model.error(
                "unsupported_security",
                f"{security} networks are not supported")
        if args.get("hidden") is True:
            # # until OS-3: hidden joins aren't on this image.
            return model.error(
                "unsupported_security", "hidden networks are not supported")
        psk = args.get("psk")
        if security in ("open", "owe"):
            if psk is not None:
                return _invalid("psk")
        elif security not in ("open", "owe"):
            if not isinstance(psk, str) or not _valid_psk(psk):
                return _invalid("psk")
        region_arg = args.get("region")
        if region_arg is not None:
            if not isinstance(region_arg, str) or not region_arg:
                return model.error(
                    "region_not_offered", "region is not a country code")
            countries = await region_countries(setup)
            if (countries is not None
                    and region_arg.upper() not in countries):
                return model.error(
                    "region_not_offered",
                    f"{region_arg!r} is not offered on this printer")
        # Whether this SSID was already saved decides whether a failed join's
        # profile cleanup may run. The answer goes in the op so a later
        # cancel can see it too.
        saved_before = await _ssid_saved_before(setup, ssid)
        # A cleanup still waiting on the last join's connect means another
        # join now would race it; `busy` is the same answer a running op
        # gives.
        cleanup = setup._join_cleanup
        if cleanup is not None and not cleanup.done():
            return model.error(
                "busy", "a join cleanup is still running")
        step["ssid"] = ssid
        step["error"] = None
        step["region_error"] = None
        setup.start_op(
            "join",
            _join_runner(setup, ssid, psk, security or "wpa2",
                         region_arg.upper() if isinstance(region_arg, str)
                         else None,
                         saved_before),
            phase="saving", ssid=ssid, forget=not saved_before)
        return None
    return await setup.write(webreq, handler, after_complete=True)


def _valid_psk(psk: str) -> bool:
    if 8 <= len(psk) <= 63:
        return True
    return len(psk) == 64 and all(ch in _HEX64 for ch in psk)


def _hostname_local() -> Optional[str]:
    host = socket.gethostname()
    return f"{host}.local" if host else None


def _join_runner(
    setup: MuonSetup, ssid: str, psk: Optional[str], security: str,
    region_arg: Optional[str], saved_before: bool
):
    async def run(handle: OpHandle) -> None:
        from . import AuxMissing, AuxRefused, AuxUnavailable
        # Step 3: the region switch runs first, still inside `kind: join`
        # (02 §5.6 step 3).
        if region_arg:
            await handle.update(phase="region")
            err = await apply_region(setup, region_arg)
            if err is not None:
                def failed(doc: Dict[str, Any]) -> None:
                    step = doc["steps"]["network"]
                    step["region_error"] = err
                await handle.finish(failed)
                return
        # Step 4: the join. The connect call runs as a task while the device
        # status poll moves `op.phase`.
        connect = asyncio.ensure_future(
            _connect(setup, ssid, psk))
        setup._join_connect = connect
        deadline = time.monotonic() + setup.join_timeout
        address: Optional[str] = None
        connect_done: Optional[Tuple[Any, Any]] = None
        while handle.current():
            if connect.done() and connect_done is None:
                connect_done = await _connect_result(connect)
            try:
                status = await setup.aux("GET", "/wifi/device/status")
            except (AuxMissing, AuxRefused, AuxUnavailable):
                status = None
            if isinstance(status, dict):
                phase = DEVICE_PHASES.get(str(status.get("state", "")))
                if phase is not None:
                    await handle.update(phase=phase)
            # An uplink IPv4 is what decides (02 §5.6 step 5).
            address = interface_ipv4(setup, "wlan0")
            if address is not None and connect_done is not None:
                break
            if connect_done is not None and connect_done[0] != "connecting":
                break
            if time.monotonic() > deadline:
                break
            await asyncio.sleep(STATUS_POLL)
        if not connect.done():
            # The join outlived join_timeout: the connect keeps running at
            # Aux; the op answers `timeout`.
            code, detail_text = "timeout", "the join took too long"
        else:
            connect_done = connect_done or await _connect_result(connect)
            code, detail_text = _connect_outcome(connect_done)
        if code == "ok":
            await handle.update(phase="internet_check")
            internet = await _internet(setup)
            await handle.update(phase="update_check")
            # 02 §5.6 step 4: refresh the clock state first, then a waited
            # update check.
            await clock.refresh(setup)
            checked = await _update_check(setup)
            if internet is MISSING_UPLINK:
                # until OS-2: no /wifi/uplink on this image -- whether the
                # update check reached Aux is the internet verdict.
                internet = True if checked else None
            if address is None:
                address = interface_ipv4(setup, "wlan0")
            if address is None:
                await _finish_fail(setup, handle, "no_address", "dhcp",
                                   ssid, saved_before, "no IPv4 on wlan0")
                return
            setup._join_connect = None
            await _finish_join(setup, handle, ssid, address, internet,
                               saved_before)
            return
        await _finish_fail(setup, handle, code,
                           _last_phase(setup, handle), ssid, saved_before,
                           detail_text)
    return run


async def _connect(setup: MuonSetup, ssid: str,
                   psk: Optional[str]) -> Tuple[Any, Any]:
    """POST /wifi/connect, boxed so the poll can run beside it. The result is
    (raw_answer, exception) -- the secret never enters either."""
    from . import AuxMissing, AuxRefused, AuxUnavailable
    body: Dict[str, Any] = {"ssid": ssid}
    if psk is not None:
        body["password"] = psk
    try:
        return await setup.aux("POST", "/wifi/connect", body,
                               timeout=CONNECT_TIMEOUT), None
    except (AuxMissing, AuxRefused, AuxUnavailable) as exc:
        return None, exc
    except Exception as exc:  # noqa: BLE001 -- the join must report, not raise
        return None, exc


async def _connect_result(task: "asyncio.Task[Any]") -> Tuple[Any, Any]:
    try:
        return await task
    except asyncio.CancelledError:
        raise
    except Exception:
        return None, ServerError("the join raised", 500)


def _connect_outcome(done: Tuple[Any, Any]) -> Tuple[str, str]:
    """Judge the connect answer. Returns ("ok", "") or (code, detail)."""
    from . import AuxMissing, AuxUnavailable
    result, exc = done
    if exc is None and isinstance(result, dict):
        if result.get("status") == "connecting":
            return "ok", ""
        if result.get("status") == "restored":
            # A failed join that restored the previous connection (03 §4).
            return _join_code(None, result), str(result.get("warning") or "")
        return _join_code(None, result), str(result)
    if isinstance(exc, AuxUnavailable):
        return "timeout", str(exc)
    if isinstance(exc, AuxMissing):
        return "timeout", "this image has no Aux Wi-Fi connect"
    return _join_code(exc, None), str(exc)


def _last_phase(setup: MuonSetup, handle: OpHandle) -> Optional[str]:
    op = (setup.doc or {}).get("op") or {}
    return op.get("phase")


async def _internet(setup: MuonSetup) -> Optional[Any]:
    """GET /wifi/uplink's verdict where the route exists (W5)."""
    from . import AuxMissing, AuxRefused, AuxUnavailable
    try:
        uplink = await setup.aux("GET", "/wifi/uplink")
    except AuxMissing:
        return MISSING_UPLINK
    except AuxUnavailable as exc:
        if _aux_status(exc) == 503:
            return None  # uplink_unavailable
        return None
    except AuxRefused:
        return None
    if isinstance(uplink, dict):
        internet = uplink.get("internet")
        if internet in (True, False) or internet == "portal":
            return internet
        return None
    return None


MISSING_UPLINK = "__no_uplink_route__"


async def _update_check(setup: MuonSetup) -> bool:
    """The join's update_check phase: Aux POST /update/check {wait: true},
    then the status refresh so the update step sees the answer. Returns
    whether Aux answered the check (the interim `internet` signal)."""
    from . import AuxMissing, AuxRefused, AuxUnavailable
    answered = False
    try:
        await setup.aux("POST", "/update/check", {"wait": True},
                        timeout=update.CHECK_TIMEOUT)
        answered = True
    except (AuxMissing, AuxRefused, AuxUnavailable) as exc:
        logging.info("muon_setup: update check failed: %s", exc)
    await update.refresh(setup)
    return answered


async def _finish_join(
    setup: MuonSetup, handle: OpHandle, ssid: str, address: str,
    internet: Any, saved_before: bool
) -> None:
    market = _region_market(setup)
    region = setup._live.get("region") or {}
    declared = region.get("declared_country")
    detected = region.get("detected_country")
    confirmed = (
        market in ("none", "locked")
        or (isinstance(declared, str) and declared == detected)
    )

    def mutate(doc: Dict[str, Any]) -> None:
        step = doc["steps"]["network"]
        step.update(kind="wifi", ssid=ssid, addresses=[address],
                    hostname_local=_hostname_local(),
                    internet=internet,
                    region_confirmed=confirmed)
        if internet == "portal":
            step["error"] = {"code": "portal_required",
                             "detail": {"ssid": ssid}}
        else:
            step["error"] = None
        if confirmed:
            step["status"] = model.DONE
            if doc["state"] != "complete" and doc["cursor"] == "network":
                setup.advance()
        else:
            # Picker: the region line is the question now (02 §5.6a).
            step["status"] = model.PENDING
    await handle.finish(mutate)
    # E5: a join after `complete` reschedules the hotspot auto-off.
    if setup.doc is not None and setup.doc["state"] == "complete":
        setup._spawn(setup.schedule_hotspot_off())


async def _finish_fail(
    setup: MuonSetup, handle: OpHandle, code: str, phase: Optional[str],
    ssid: str, saved_before: bool, detail: str
) -> None:
    await handle.finish(
        lambda doc: _join_fail(doc, code, phase, ssid, detail))
    if not saved_before:
        await _forget_after_join(setup, ssid)
