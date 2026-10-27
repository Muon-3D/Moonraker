from __future__ import annotations

import json
import unittest
from typing import Any, Optional

import tornado.web
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from moonraker.components.application import (
    AuthorizedRequestHandler,
    _status_line_reason,
)
from moonraker.utils import ServerError

# What Klipper sends back when a gcode_macro calls action_raise_error():
# gcode_macro.py builds it from traceback.format_exception_only(), which ends
# in a newline. Bench run of 22 Oct 2026 (KAN-991).
MACRO_REFUSAL = (
    "Error evaluating 'gcode_macro _HOTEND_FAN_REFUSE:gcode': "
    "gcode.CommandError: M109 refused: hot-end fan fault. Check the fan, "
    "then press Fan checked on the printer (or run HOTEND_FAN_FAULT_CLEAR)\n"
)


class _Authorization:
    async def check_cors(self, origin: Optional[str]) -> bool:
        return False

    async def authenticate_request(self, request: Any, auth_required: bool = True):
        return None


class _Server:
    def __init__(self) -> None:
        self.authorization = _Authorization()

    def lookup_component(self, name: str, default: Any = None) -> Any:
        if name == "authorization":
            return self.authorization
        return default


class _RefusingHandler(AuthorizedRequestHandler):
    # Raises the way DynamicRequestHandler._process_http_request does when a
    # request to Klippy fails.
    def post(self) -> None:
        message = self.request.body.decode()
        try:
            raise ServerError(message, 400)
        except ServerError as e:
            raise tornado.web.HTTPError(e.status_code, reason=str(e)) from e


class StatusLineReasonTests(unittest.TestCase):
    def test_single_line_is_unchanged(self) -> None:
        self.assertEqual(_status_line_reason(400, "Fan fault not cleared"),
                         "Fan fault not cleared")

    def test_only_the_first_non_blank_line_is_kept(self) -> None:
        self.assertEqual(_status_line_reason(400, "\n  first \r\nsecond\n"),
                         "first")

    def test_blank_message_falls_back_to_the_standard_phrase(self) -> None:
        self.assertEqual(_status_line_reason(400, " \n"), "Bad Request")


class MacroRefusalResponseTests(AsyncHTTPTestCase):
    def get_app(self) -> Application:
        return Application([(r"/refuse", _RefusingHandler)], server=_Server())

    def _refuse(self, message: str):
        return self.fetch("/refuse", method="POST", body=message)

    def test_macro_refusal_returns_400_with_its_message(self) -> None:
        response = self._refuse(MACRO_REFUSAL)
        self.assertEqual(response.code, 400)
        self.assertNotIn("\n", response.reason)
        self.assertIn("M109 refused: hot-end fan fault", response.reason)
        error = json.loads(response.body)["error"]
        self.assertEqual(error["code"], 400)
        self.assertEqual(error["message"], MACRO_REFUSAL)

    def test_long_multiline_refusal_still_returns_its_body(self) -> None:
        message = "refused\n" + "Traceback line\n" * 200
        response = self._refuse(message)
        self.assertEqual(response.code, 400)
        self.assertEqual(response.reason, "refused")
        self.assertEqual(json.loads(response.body)["error"]["message"], message)

    def test_short_refusal_is_unchanged(self) -> None:
        message = "Fan fault not cleared: heatsink is still at 27.0C (15C or more)."
        response = self._refuse(message)
        self.assertEqual(response.code, 400)
        self.assertEqual(response.reason, message)
        self.assertEqual(json.loads(response.body)["error"]["message"], message)


if __name__ == "__main__":
    unittest.main()
