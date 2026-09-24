# MUON, KAN-203 / KAN-321 -- the region, as the setup surfaces need it.
#
# muon_setup never keeps its own country list (02 §5.2). It reads the Aux
# region routes and reshapes them. Those routes are KAN-321's, and at the time
# of writing they exist only on MuonOS#174 (feat/KAN-321-region-provisioning,
# region_routes.py), whose shapes differ from 03 §3's proposal:
#
#   GET /region          {reason, explanation, domain, declared_country,
#                         configuration, surroundings, detected_country, basis,
#                         enforcement, locked, channels}
#   GET /region/options  {countries, preselect, basis, locked}
#
# Every field below is taken from one of those two. What the spec asks for and
# #174 does not serve is reported as null or empty rather than guessed, and
# is OS-2's to add: the picker's language tier (`for_language`), the countries
# grouped by continent (`all`), `support_code`, and `default_country` whenever
# a detected country hides it behind `preselect`.

from __future__ import annotations

from typing import Any, Dict, Optional

#: #174's `basis` names, as 02 §6's `source` values.
_BASIS_TO_SOURCE = {"joined-network": "ap", "plurality": "neighbours"}


def market(region: Dict[str, Any], options: Dict[str, Any]) -> str:
    """picker | locked | none (02 §5.2).

    #174 marks a unit assessed for exactly one configuration as `locked`, and
    serves an empty `countries` list when there is no usable token.
    """
    if region.get("locked") or options.get("locked"):
        return "locked"
    if not options.get("countries"):
        return "none"
    return "picker"


def applied_country(region: Dict[str, Any]) -> Optional[str]:
    """The country the radio is set for: the declaration, else the domain the
    region agent applied at boot (the token's fallback). `00` is none."""
    declared = region.get("declared_country")
    if isinstance(declared, str) and declared:
        return declared.upper()
    domain = region.get("domain")
    if isinstance(domain, str) and domain and domain != "00":
        return domain.upper()
    return None


def _config(region: Dict[str, Any]) -> Optional[str]:
    config = region.get("configuration")
    return config if isinstance(config, str) and config else None


def state_region(
    region: Dict[str, Any], options: Dict[str, Any]
) -> Dict[str, Any]:
    """02 §6's `region` block."""
    country = applied_country(region)
    declared = bool(region.get("declared_country"))
    source: Optional[str] = None
    if country is not None:
        detected = region.get("detected_country")
        if isinstance(detected, str) and detected.upper() == country:
            source = _BASIS_TO_SOURCE.get(region.get("basis") or "")
        elif not declared:
            # Not declared, so the boot fallback put it there.
            source = "default"
    return {
        "market": market(region, options),
        "country": country,
        "declared": declared,
        "config": _config(region),
        "source": source,
    }


def options_region(
    region: Dict[str, Any], options: Dict[str, Any]
) -> Dict[str, Any]:
    """02 §5.2's `region` block of GET /server/muon/setup/options.

    #174's flat `countries` list has no field to go in: `all` is grouped by
    continent, and grouping is the table's job, not this component's (02 §5.2:
    muon_setup keeps no country list). So `all` stays null until OS-2 serves
    the grouping.
    """
    preselect = options.get("preselect")
    # #174 folds the token's default into `preselect` and says so by leaving
    # `basis` empty. With a detection it is hidden, so it is unknown here.
    default_country = (
        preselect.upper()
        if isinstance(preselect, str) and preselect and not options.get("basis")
        else None
    )
    channels = [c for c in region.get("channels") or [] if isinstance(c, int)]
    return {
        "market": market(region, options),
        "applied": {
            "country": applied_country(region),
            "config": _config(region),
            "declared": bool(region.get("declared_country")),
        },
        "default_country": default_country,
        "permitted_channels": sorted(channels),
        # Not served by #174 yet (OS-2): the language tier, the continent
        # grouping and the support code.
        "for_language": [],
        "all": None,
        "support_code": None,
    }
