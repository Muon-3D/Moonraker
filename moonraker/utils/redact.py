# MUON -- keep secrets and names out of moonraker.log.
#
# Moonraker logs request arguments and bodies at debug level when it runs
# verbose: the HTTP handler (components/application.py), JSON-RPC
# (common.py) and the Aux API proxy (components/aux_api_proxy.py). A field
# that names a person or carries a credential must never reach that log:
#
#   * signer_name -- who signed the developer-mode waiver (MuonOS#353, POST
#     /server/aux/dev_mode). A person's name, kept on the device only.
#   * password, key -- the Wi-Fi password and the hotspot key.
#   * psk -- the Wi-Fi PSK that POST /server/muon/setup/network carries
#     (07 S2), which the field list above does not cover.
#   * reentry_token -- the token that lets a phone back into setup.
#
# Matched by field name, case-insensitively, at any depth.

from __future__ import annotations

import json
from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_FIELDS = frozenset(
    ("signer_name", "password", "key", "psk", "reentry_token"))
REDACTED = "<redacted>"


def is_sensitive(name: Any) -> bool:
    return isinstance(name, str) and name.lower() in SENSITIVE_FIELDS


def redact(value: Any) -> Any:
    """A copy with every sensitive field's value replaced, at any depth."""
    if isinstance(value, dict):
        return {key: _redact_field(key, item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(redact(item) for item in value)
    return value


def _redact_field(key: Any, item: Any) -> Any:
    if is_sensitive(key):
        return REDACTED
    if key == "body" and isinstance(item, str):
        # /server/aux/proxy forwards its `body` argument as a JSON string
        return redact_json_text(item)
    return redact(item)


def redact_json_text(text: Optional[str]) -> Optional[str]:
    """A JSON body, redacted. A body that is not JSON could hold anything, so
    it is replaced whole rather than logged."""
    if not text:
        return text
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return REDACTED
    return json.dumps(redact(parsed))


def redact_url(url: str) -> str:
    """A URL with the values of sensitive query parameters replaced."""
    parts = urlsplit(url)
    if not parts.query:
        return url
    query = [
        (name, REDACTED if is_sensitive(name) else value)
        for name, value in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit(parts._replace(query=urlencode(query, safe="<>")))
