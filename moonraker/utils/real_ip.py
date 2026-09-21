"""Validation for the trusted proxy's single X-Real-IP value."""

from __future__ import annotations

import ipaddress

from tornado.httputil import HTTPHeaders
from tornado.web import HTTPError


def validate_real_ip_header(headers: HTTPHeaders) -> None:
    """Reject ambiguous or malformed X-Real-IP before trusting remote_ip.

    The panel reaches Moonraker directly and omits this header. The gateway
    supplies one parseable address. Tornado's joined header value is not
    sufficient here because duplicate values can otherwise be mistaken for a
    single malformed value while xheaders falls back to the loopback peer.
    """
    values = headers.get_list("X-Real-IP")
    if not values:
        return
    if len(values) != 1:
        raise HTTPError(403, "Multiple X-Real-IP header values")
    try:
        ipaddress.ip_address(values[0])
    except ValueError as err:
        raise HTTPError(403, "Malformed X-Real-IP header") from err
