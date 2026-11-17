"""KAN-3603: general settings from Control on an open printer, over any route.

* GET and POST /server/muon/timezone: the time zone after set-up.
* POST /server/muon/identity/name: the rename, on an open printer.

Who may is muon_access_policy's: an Open printer lets any client, Protected the
owner, and the Strict preset ("locked down") the owner. The decision is the same
for GET and POST of the zone. A refusal is always a 403 with a reason; 404 is
only what an absent route says, so Control can tell "hidden" from "not yours".
"""
from __future__ import annotations

import asyncio
import ipaddress
from typing import Any, Dict, Optional

import pytest

from moonraker import muon_access_policy as policy
from moonraker import muon_floor
from moonraker.common import RequestType
from moonraker.utils.exceptions import ServerError

from test_aux_api_proxy import (
    FakeHttpClient, FakeResponse, FakeWebRequest, make_proxy,
)
from test_muon_access import (  # noqa: F401  (the autouse reset is reused)
    HOTSPOT, HTTP, LAN, PASSWORD_USER, SENTINEL, _api, _reset, gateway, state,
)

ZONE = "/server/muon/timezone"
RENAME = "/server/muon/identity/name"
BLUETOOTH = ipaddress.ip_address("192.0.2.2")
OPEN, PROTECTED = policy.ENTRY_OPEN, policy.ENTRY_PROTECTED
NOBODY, LINKED = policy.OWNER_NONE, policy.OWNER_ACCOUNT

#: Every way in: (address, token). "relay" is away from home; the owner's own
#: device through the sentinel is the owner (the admin level).
CLIENTS: Dict[str, Any] = {
    "lan": (LAN, None),
    "hotspot": (HOTSPOT, None),
    "lan_password": (LAN, PASSWORD_USER),
    "relay_guest": (SENTINEL, gateway("signed_out_guest", "operator", home=False)),
    "relay_owner": (SENTINEL, gateway("admin", "operator", home=False)),
    "lan_owner": (SENTINEL, gateway("admin", "operator", home=True)),
    "bluetooth_guest": (BLUETOOTH, gateway("signed_out_guest", "operator", home=False)),
    "bluetooth_owner": (BLUETOOTH, gateway("admin", "operator", home=False)),
}
GUESTS = ["lan", "hotspot", "lan_password", "relay_guest", "bluetooth_guest"]
OWNERS = ["relay_owner", "lan_owner", "bluetooth_owner"]


@pytest.fixture(autouse=True)
def _set_up_is_complete():
    # After set-up 192.0.2.2 is a paired client that started on Bluetooth.
    muon_floor.set_setup_complete_source(lambda: True)
    try:
        yield
    finally:
        muon_floor.set_setup_complete_source(None)


def go(endpoint: str, method: str, client: str, **args: Any) -> Optional[ServerError]:
    ip_addr, user = CLIENTS[client]
    api = _api(endpoint)
    try:
        asyncio.run(api.request(
            dict(args), RequestType[method], HTTP, ip_addr, user))
    except ServerError as err:
        return err
    return None


def printer(entry: str, owner: str, **kw: Any) -> None:
    policy.set_state(state(entry=entry, owner=owner, **kw))


# --------------------------------------------------------------------------
# The time zone
# --------------------------------------------------------------------------

class TestTimezoneByAccessLevel:
    @pytest.mark.parametrize("method", ["GET", "POST"])
    @pytest.mark.parametrize("owner", [NOBODY, LINKED])
    @pytest.mark.parametrize("client", GUESTS + OWNERS)
    def test_open_means_any_client_on_any_route(self, method, owner, client):
        printer(OPEN, owner)
        assert go(ZONE, method, client, zone="Europe/London") is None

    @pytest.mark.parametrize("method", ["GET", "POST"])
    @pytest.mark.parametrize("owner", [NOBODY, LINKED])
    @pytest.mark.parametrize("client", GUESTS)
    def test_protected_refuses_everyone_but_the_owner(self, method, owner, client):
        printer(PROTECTED, owner)
        err = go(ZONE, method, client, zone="Europe/London")
        assert err is not None and err.status_code == 403

    @pytest.mark.parametrize("method", ["GET", "POST"])
    @pytest.mark.parametrize("client", OWNERS)
    def test_protected_lets_the_owner_over_every_route(self, method, client):
        printer(PROTECTED, LINKED)
        assert go(ZONE, method, client, zone="Europe/London") is None

    @pytest.mark.parametrize("method", ["GET", "POST"])
    @pytest.mark.parametrize("client", GUESTS)
    def test_locked_down_refuses_guests_even_on_an_open_entry(self, method, client):
        printer(OPEN, LINKED, preset="strict")
        assert go(ZONE, method, client, zone="Europe/London") is not None

    @pytest.mark.parametrize("client", OWNERS)
    def test_locked_down_still_lets_the_owner(self, client):
        printer(OPEN, LINKED, preset="strict")
        assert go(ZONE, "POST", client, zone="Europe/London") is None

    @pytest.mark.parametrize("owner", [NOBODY, LINKED])
    @pytest.mark.parametrize("preset", [None, "relaxed", "standard", "strict"])
    @pytest.mark.parametrize("entry", [OPEN, PROTECTED])
    def test_get_and_post_always_get_the_same_answer(self, owner, preset, entry):
        printer(entry, owner, preset=preset)
        for client in CLIENTS:
            read = go(ZONE, "GET", client, zone="Europe/London")
            write = go(ZONE, "POST", client, zone="Europe/London")
            assert (read is None) == (write is None), (client, entry, owner, preset)

    def test_a_refusal_is_a_403_with_a_plain_reason_never_a_404(self):
        printer(PROTECTED, LINKED)
        for method in ("GET", "POST"):
            err = go(ZONE, method, "lan", zone="Europe/London")
            assert err.status_code == 403
            assert str(err).startswith("access-denied:timezone")
            assert len(str(err).split(":", 2)[2].strip()) > 10

    def test_a_phone_still_in_bluetooth_setup_cannot(self):
        printer(OPEN, NOBODY)
        muon_floor.set_setup_complete_source(lambda: False)
        err = go(ZONE, "POST", "bluetooth_owner", zone="Europe/London")
        assert err is not None and err.status_code == 403

    def test_it_is_not_on_the_floor(self):
        assert not muon_floor.is_floor_endpoint(ZONE)
        assert not muon_floor.is_protected_endpoint(ZONE)


class TestTimezoneHandler:
    def _server(self, response: FakeResponse):
        proxy, server, client = make_proxy(FakeHttpClient(response))
        return server.handler_for(ZONE), client

    def test_it_serves_get_and_post(self):
        _p, server, _c = make_proxy()
        assert server.verbs_for(ZONE) == ["GET", "POST"]

    def test_get_is_the_zone_from_aux_in_the_result_shape(self):
        handler, client = self._server(FakeResponse(
            {"epoch_ms": 1, "ntp_synced": True, "tz": "Europe/London"}))
        out = asyncio.run(handler(FakeWebRequest("GET")))
        assert out == {"zone": "Europe/London"}
        kind, call = client.calls[-1]
        assert kind == "get" and call["url"] == "http://127.0.0.1:6789/time"

    def test_post_sets_it_through_auxs_existing_zone_route_and_answers_the_same_shape(self):
        handler, client = self._server(FakeResponse(
            {"epoch_ms": 1, "ntp_synced": True, "tz": "Asia/Tokyo"}))
        out = asyncio.run(handler(FakeWebRequest("POST", {"zone": "Asia/Tokyo"})))
        assert out == {"zone": "Asia/Tokyo"}
        kind, call = client.calls[-1]
        assert kind == "post"
        assert call["url"] == "http://127.0.0.1:6789/time/zone"
        assert call["body"] == '{"tz": "Asia/Tokyo"}'

    @pytest.mark.parametrize("bad", [
        None, "", 5, ["Europe/London"], "../etc/passwd", "Europe/../x",
        "/etc/passwd", "a b", "Europe//London", "1Europe", "A/B/C/D",
        "Europe/London; reboot",
    ])
    def test_a_bad_zone_never_reaches_aux(self, bad):
        handler, client = self._server(FakeResponse({"tz": "UTC"}))
        with pytest.raises(Exception) as err:
            asyncio.run(handler(FakeWebRequest("POST", {"zone": bad})))
        assert err.value.status_code == 400
        assert client.calls == []

    @pytest.mark.parametrize("good", [
        "UTC", "Europe/London", "America/Argentina/Buenos_Aires", "Etc/GMT+5",
    ])
    def test_the_zone_name_pattern_is_auxs(self, good):
        handler, client = self._server(FakeResponse({"tz": good}))
        assert asyncio.run(handler(FakeWebRequest("POST", {"zone": good}))) == {
            "zone": good}

    def test_an_unknown_zone_aux_refuses_is_a_400_not_a_403(self):
        class Refused(FakeResponse):
            def raise_for_status(self, message: Optional[str] = None) -> None:
                raise ServerError(message or "Unprocessable", 422)
        handler, _c = self._server(Refused(
            {"detail": {"code": "invalid_timezone", "message": "unknown"}},
            status_code=422))
        with pytest.raises(Exception) as err:
            asyncio.run(handler(FakeWebRequest("POST", {"zone": "Mars/Base"})))
        assert err.value.status_code == 400

    def test_the_zone_route_never_forwards_anything_but_the_zone(self):
        handler, client = self._server(FakeResponse({"tz": "UTC"}))
        asyncio.run(handler(FakeWebRequest(
            "POST", {"zone": "UTC", "path": "/bms/ship", "epoch_ms": 1})))
        assert client.last["body"] == '{"tz": "UTC"}'


# --------------------------------------------------------------------------
# The rename
# --------------------------------------------------------------------------

class TestRenameOnAnOpenPrinter:
    @pytest.mark.parametrize("owner", [NOBODY, LINKED])
    @pytest.mark.parametrize("client", GUESTS + OWNERS)
    def test_the_owner_and_local_guests_can_over_every_route(self, owner, client):
        printer(OPEN, owner)
        assert go(RENAME, "POST", client, name="Walnut") is None

    @pytest.mark.parametrize("owner", [NOBODY, LINKED])
    @pytest.mark.parametrize("client", ["lan", "hotspot", "lan_password"])
    def test_protected_refuses_lan_and_hotspot(self, owner, client):
        printer(PROTECTED, owner)
        err = go(RENAME, "POST", client, name="Walnut")
        assert err is not None and err.status_code == 403
        assert "rename" in str(err)

    @pytest.mark.parametrize("client", OWNERS)
    def test_protected_still_lets_the_owner(self, client):
        printer(PROTECTED, LINKED)
        assert go(RENAME, "POST", client, name="Walnut") is None

    @pytest.mark.parametrize("preset", ["standard", "strict"])
    def test_a_stricter_preset_on_an_open_linked_printer_keeps_guests_out(self, preset):
        printer(OPEN, LINKED, preset=preset)
        assert go(RENAME, "POST", "lan", name="Walnut") is not None
        assert go(RENAME, "POST", "relay_owner", name="Walnut") is None

    def test_a_viewer_cannot_rename_even_when_open(self):
        printer(OPEN, NOBODY)
        ip_addr, _ = CLIENTS["relay_guest"]
        api = _api(RENAME)
        with pytest.raises(ServerError):
            asyncio.run(api.request(
                {"name": "x"}, RequestType.POST, HTTP, ip_addr,
                gateway("signed_out_guest", "viewer", home=False)))
