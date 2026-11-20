# Moonraker Exceptions
#
# Copyright (C) 2023 Eric Callahan <arksine.code@gmail.com>
#
# This file may be distributed under the terms of the GNU GPLv3 license

from __future__ import annotations
from typing import Any, Dict, Optional

class ServerError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        Exception.__init__(self, message)
        self.status_code = status_code

class BodyError(ServerError):
    """MUON: an error whose answer carries fields of its own (a `reason`).

    The HTTP error writer adds `body` beside the usual `error` object, and
    a JSON-RPC error carries it as `error.data`."""
    def __init__(
        self,
        message: str,
        status_code: int = 400,
        body: Optional[Dict[str, Any]] = None
    ) -> None:
        ServerError.__init__(self, message, status_code)
        self.body: Dict[str, Any] = dict(body or {})

class AgentError(ServerError):
    def __init__(self, message: str, error_data: Any) -> None:
        ServerError.__init__(self, message, 424)
        self.error_data = error_data
