# MUON, KAN-203 -- the "Ready to print" manifest (spec 02 §5.10, decision D6).
#
# The hardware team owns what is on this list, so it is data: MuonOS ships
# /usr/share/muon/setup/ready.json in the image (OS-8), and until it does, or
# whenever the shipped file is unreadable, the built-in default below is used.
# The items and the MUON_SELF_TEST macro name are PROVISIONAL.

from __future__ import annotations

import copy
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

MANIFEST_VERSION = 1
KINDS = ("confirm", "macro", "panel_flow")
_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,47}$")
#: Keys the surfaces resolve to copy. Never copy itself: the manifest has none.
_I18N_KEY_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")

DEFAULT_MANIFEST: Dict[str, Any] = {
    "version": MANIFEST_VERSION,
    "items": [
        {
            "id": "transport_clips", "kind": "confirm", "required": True,
            "title_key": "setup.ready.transport_clips.title",
            "body_key": "setup.ready.transport_clips.body",
            "image": "transport_clips.webp",
        },
        {
            "id": "self_test", "kind": "macro", "required": True,
            "macro": "MUON_SELF_TEST", "est_seconds": 120,
            "title_key": "setup.ready.self_test.title",
            "body_key": "setup.ready.self_test.body",
        },
        {
            "id": "load_filament", "kind": "panel_flow", "required": False,
            "flow": "load_filament",
            "title_key": "setup.ready.load_filament.title",
            "body_key": "setup.ready.load_filament.body",
        },
    ],
}


class ManifestError(ValueError):
    pass


def validate(manifest: Any) -> Dict[str, Any]:
    """Return the manifest if it matches the schema, else raise ManifestError.

    The schema is 02 §5.10's, made strict: unknown kinds, duplicate ids and
    missing i18n keys are refused rather than rendered as blank screens.
    """
    if not isinstance(manifest, dict):
        raise ManifestError("the manifest is not an object")
    if manifest.get("version") != MANIFEST_VERSION:
        raise ManifestError(f"unsupported version {manifest.get('version')!r}")
    items = manifest.get("items")
    if not isinstance(items, list):
        raise ManifestError("'items' is not a list")
    seen = set()
    for index, item in enumerate(items):
        where = f"items[{index}]"
        if not isinstance(item, dict):
            raise ManifestError(f"{where} is not an object")
        item_id = item.get("id")
        if not isinstance(item_id, str) or not _ID_RE.match(item_id):
            raise ManifestError(f"{where}.id is not a valid id")
        if item_id in seen:
            raise ManifestError(f"{where}.id {item_id!r} is repeated")
        seen.add(item_id)
        kind = item.get("kind")
        if kind not in KINDS:
            raise ManifestError(f"{where}.kind {kind!r} is not one of {KINDS}")
        if not isinstance(item.get("required"), bool):
            raise ManifestError(f"{where}.required is not a boolean")
        for key in ("title_key", "body_key"):
            value = item.get(key)
            if not isinstance(value, str) or not _I18N_KEY_RE.match(value):
                raise ManifestError(f"{where}.{key} is not an i18n key")
        if kind == "macro" and not _is_name(item.get("macro")):
            raise ManifestError(f"{where}.macro is required for a macro item")
        if kind == "panel_flow" and not _is_name(item.get("flow")):
            raise ManifestError(f"{where}.flow is required for a panel_flow item")
        image = item.get("image")
        if image is not None and not _is_name(image):
            raise ManifestError(f"{where}.image is not a plain file name")
        est = item.get("est_seconds")
        if est is not None and (
            isinstance(est, bool) or not isinstance(est, (int, float)) or est < 0
        ):
            raise ManifestError(f"{where}.est_seconds is not a duration")
    return manifest


def _is_name(value: Any) -> bool:
    return isinstance(value, str) and bool(_NAME_RE.match(value))


def load(path: Optional[str]) -> Dict[str, Any]:
    """The shipped manifest, or the default with a warning."""
    if path:
        try:
            raw = Path(path).read_text(encoding="utf-8")
        except FileNotFoundError:
            logging.warning(
                "muon_setup: no ready manifest at %s; using the built-in default",
                path,
            )
        except OSError as exc:
            logging.warning(
                "muon_setup: cannot read the ready manifest %s (%s); "
                "using the built-in default", path, exc,
            )
        else:
            try:
                return validate(json.loads(raw))
            except (ValueError, ManifestError) as exc:
                logging.warning(
                    "muon_setup: the ready manifest %s is invalid (%s); "
                    "using the built-in default", path, exc,
                )
    return copy.deepcopy(DEFAULT_MANIFEST)


def item_ids(manifest: Dict[str, Any]) -> List[str]:
    return [item["id"] for item in manifest["items"]]
