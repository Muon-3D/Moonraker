# MUON, KAN-203 / KAN-321 -- the region, as the setup surfaces need it.
#
# muon_setup never keeps its own country list (02 §5.2). The region routes are
# KAN-321's, on draft MuonOS#174 (region_routes.py):
#
#   GET /region          {reason, explanation, domain, declared_country,
#                         configuration, surroundings, detected_country, basis,
#                         enforcement, locked, channels}
#   GET /region/options  {countries, preselect, basis, locked}
#
# Both are passed to the surfaces as Aux returns them (02 §5.2, §6), with one
# field added to the state's copy: `market`, derived here so every surface
# reads it the same way. The picker's tiers are built by each surface from
# MuonUI#31's SPOKEN_IN; the region itself is confirmed after the join
# (02 §5.6a, MR-3).

from __future__ import annotations

import copy
from typing import Any, Dict


def market(region: Dict[str, Any], options: Dict[str, Any]) -> str:
    """none | locked | picker (02 §6, §8 test 10).

    `none` is derived from `countries == []` -- no usable token -- and
    `locked` from `locked == true`, a unit assessed for one configuration.
    """
    if not options.get("countries"):
        return "none"
    if region.get("locked") is True or options.get("locked") is True:
        return "locked"
    return "picker"


def state_region(
    region: Dict[str, Any], options: Dict[str, Any]
) -> Dict[str, Any]:
    """02 §6's `region`: Aux GET /region verbatim, plus `market`."""
    state = {"market": market(region, options)}
    state.update(copy.deepcopy(region))
    return state
