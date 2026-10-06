"""Names and secrets never reach moonraker.log (utils/redact.py).

MuonOS#353 adds `signer_name` to POST /server/aux/dev_mode: who signed the
developer-mode waiver. Moonraker logs request arguments at debug level when
it runs verbose, in three places, and each is driven here with a real value:
the Aux API proxy (also in test_aux_api_proxy.py), the HTTP handler and
JSON-RPC. The sensitive names are written out, not imported, so dropping one
from the module fails a test.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from moonraker.common import JsonRPC, TransportType
from moonraker.components import application
from moonraker.utils import redact

NAME = "Ada Lovelace"
SECRETS = {
    "signer_name": NAME,
    "password": "correct horse",
    "key": "hotspot-key-123",
    "reentry_token": "tok-456",
}


class TestTheHelper:
    def test_the_fields(self):
        assert redact.SENSITIVE_FIELDS == {
            "signer_name", "password", "key", "reentry_token"}

    def test_every_field_at_any_depth_and_case(self):
        value = {
            "waiver": {"Signer_Name": NAME, "version": 3},
            "networks": [{"ssid": "home", "PASSWORD": "correct horse"}],
            "key": "hotspot-key-123",
            "reentry_token": "tok-456",
            "keep": "visible",
        }
        out = redact.redact(value)
        assert NAME not in json.dumps(out)
        for secret in SECRETS.values():
            assert secret not in json.dumps(out)
        assert out["keep"] == "visible"
        assert out["waiver"]["version"] == 3
        assert out["networks"][0]["ssid"] == "home"
        # the input is not changed
        assert value["waiver"]["Signer_Name"] == NAME

    def test_a_field_that_only_contains_a_sensitive_word_is_kept(self):
        out = redact.redact({"key_count": 2, "keyboard": "us"})
        assert out == {"key_count": 2, "keyboard": "us"}

    def test_a_proxy_body_given_as_a_json_string(self):
        out = redact.redact({"path": "/x", "body": json.dumps({"key": "k1"})})
        assert "k1" not in json.dumps(out)
        assert out["path"] == "/x"

    def test_a_json_body(self):
        body = json.dumps({"enable": True, "signer_name": NAME})
        out = redact.redact_json_text(body)
        assert out is not None and NAME not in out
        assert json.loads(out)["enable"] is True

    def test_a_body_that_is_not_json_is_not_logged(self):
        assert redact.redact_json_text(f"signer_name={NAME}") == redact.REDACTED
        assert redact.redact_json_text("") == ""
        assert redact.redact_json_text(None) is None

    def test_a_query_string(self):
        url = "http://127.0.0.1:8000/wifi/connect?ssid=home&password=correct+horse"
        out = redact.redact_url(url)
        assert "correct" not in out
        assert "ssid=home" in out
        assert out.startswith("http://127.0.0.1:8000/wifi/connect?")


class _Server:
    def is_verbose_enabled(self) -> bool:
        return True


class TestTheHttpHandler:
    class _Handler:
        server = _Server()

        class api_defintion:   # sic, as in application.py
            endpoint = "/server/aux/dev_mode"

    def test_request_args_are_redacted(self, caplog):
        caplog.set_level(logging.DEBUG)
        application.DynamicRequestHandler._log_debug(
            self._Handler(), "HTTP Request::POST /server/aux/dev_mode",
            dict(SECRETS, enable=True),
        )
        assert "HTTP Request::POST /server/aux/dev_mode" in caplog.text
        for secret in SECRETS.values():
            assert secret not in caplog.text
        assert "'enable': True" in caplog.text

    def test_a_response_is_redacted_too(self, caplog):
        caplog.set_level(logging.DEBUG)
        application.DynamicRequestHandler._log_debug(
            self._Handler(), "HTTP Response::POST /server/aux/dev_mode",
            {"result": {"waiver": {"signer_name": NAME}}},
        )
        assert NAME not in caplog.text

    @pytest.mark.parametrize("hint", ["int", "float", "json"])
    def test_query_conversion_errors_do_not_log_credentials(self, caplog, hint):
        caplog.set_level(logging.DEBUG)
        credential = "test-only-reentry-credential"
        result = application.DynamicRequestHandler._convert_type(
            self._Handler(), credential, hint
        )
        assert result == credential
        assert credential not in caplog.text
        assert hint in caplog.text


class TestJsonRpc:
    @pytest.mark.parametrize("method", [
        "server.aux.post_dev_mode", "server.aux.proxy",
    ])
    def test_params_are_redacted(self, caplog, method: str):
        caplog.set_level(logging.DEBUG)
        rpc = JsonRPC(_Server())   # type: ignore[arg-type]
        rpc._log_request(
            {"jsonrpc": "2.0", "method": method, "id": 1,
             "params": dict(SECRETS, body={"signer_name": NAME})},
            TransportType.WEBSOCKET,
        )
        assert method in caplog.text
        for secret in SECRETS.values():
            assert secret not in caplog.text

    def test_a_result_is_redacted(self, caplog: Any):
        caplog.set_level(logging.DEBUG)
        rpc = JsonRPC(_Server())   # type: ignore[arg-type]
        rpc._log_response(
            {"jsonrpc": "2.0", "id": 1,
             "result": {"waiver": {"signer_name": NAME}}},
            TransportType.WEBSOCKET,
        )
        assert "Response::" in caplog.text
        assert NAME not in caplog.text
