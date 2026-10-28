"""KAN-429 (MR-5): a remote reader of setup state never sees the link code.

02 §5.9 mirrors muon-link's LinkPhase into `steps.remote.link`, `code` and
`url` included, so the phone page and the panel can show them. Rule S5 also
lets a remote caller (muon-link's Iroh gateway, 192.0.2.1 with the gateway's
token) read setup state. A remote reader has no use for a claimable code,
and a read-only grant must not carry one: for that caller,
`GET /server/muon/setup` and the `muon_setup_changed` notification withhold
`code` and `url` and keep the rest (`phase`, `expires_at`). Hotspot, LAN and
panel callers are unchanged.

A `bluetooth` caller has the hotspot's rights while setup is open and the
remote rights after (ADR 0032 D4 rule 4), so it sees the code only while
setup is open.
"""
from __future__ import annotations

import copy
from typing import Any, Dict, Optional

import pytest

from moonraker import muon_access_policy
from moonraker.common import TransportType, UserInfo

from muon_setup_fakes import (
    BLUETOOTH_IP, GATEWAY_IP, HOTSPOT_IP, LAN_IP, PANEL_IP, Harness, run,
    state_with, user)

CODE = "482913"
URL = "https://muon3d.com/link?c=482913"
EXPIRES = 9999999999
LINK = {"phase": "code", "code": CODE, "url": URL, "expires_at": EXPIRES}
NOTIFICATION = "muon_setup_changed"


def code_state(state: str = "in_progress") -> Dict[str, Any]:
    """The cursor on `remote` in cloud mode, waiting on a code."""
    doc = state_with(
        language={"status": "done", "value": "en"},
        network={"status": "done", "kind": "wifi", "ssid": "HomeWiFi",
                 "internet": True},
        name={"status": "done", "value": "Walnut"},
        update={"status": "done"},
        remote={"status": "pending", "mode": "cloud",
                "link": copy.deepcopy(LINK)},
    )
    doc["cursor"] = "remote"
    doc["state"] = state
    return doc


async def read(kind: str, state: str = "in_progress") -> Dict[str, Any]:
    h = await Harness(stored=code_state(state)).start()
    out = await h.get(kind=kind)
    # The stored document itself keeps the code: only the read is trimmed.
    assert h.doc["steps"]["remote"]["link"]["code"] == CODE
    return out


def link_of(state: Dict[str, Any]) -> Dict[str, Any]:
    return state["steps"]["remote"]["link"]


class TestGet:
    def test_remote_read_withholds_code_and_url(self):
        link = link_of(run(read("remote")))
        assert "code" not in link
        assert "url" not in link
        assert link == {"phase": "code", "expires_at": EXPIRES}

    @pytest.mark.parametrize("kind", ["panel", "hotspot", "lan"])
    def test_local_reads_keep_code_and_url(self, kind: str):
        assert link_of(run(read(kind))) == LINK

    def test_bluetooth_during_setup_keeps_them(self):
        # Hotspot rights while setup is open.
        assert link_of(run(read("bluetooth"))) == LINK

    def test_bluetooth_after_setup_withholds_them(self):
        # Remote rights once setup is complete.
        link = link_of(run(read("bluetooth", state="complete")))
        assert "code" not in link and "url" not in link

    def test_remote_read_after_setup_withholds_them(self):
        link = link_of(run(read("remote", state="complete")))
        assert "code" not in link and "url" not in link

    def test_remote_read_with_no_link_is_unchanged(self):
        async def go():
            h = await Harness(stored=state_with(
                language={"status": "done", "value": "en"})).start()
            remote = await h.get(kind="remote")
            panel = await h.get(kind="panel")
            assert remote == panel
        run(go())


# --------------------------------------------------------------------------
# The notification, as websockets.notify_clients filters it per connection
# --------------------------------------------------------------------------

class FakeConnection:
    def __init__(self, ip: Any, user_info: Optional[UserInfo]) -> None:
        self.ip_addr = ip
        self.user_info = user_info
        self.uid = 1
        self.need_auth = False

    @property
    def transport_type(self) -> TransportType:
        return TransportType.WEBSOCKET


GATEWAY_USER = "muon_gateway"
CONNECTIONS = {
    "panel": FakeConnection(PANEL_IP, user(["panel"])),
    "hotspot": FakeConnection(HOTSPOT_IP, user(["network"])),
    "lan": FakeConnection(LAN_IP, user(["network"])),
    "remote": FakeConnection(
        GATEWAY_IP, user(["network"], source=GATEWAY_USER)),
    # The gateway's address alone, without its token, is still muon-link.
    "remote_address": FakeConnection(GATEWAY_IP, None),
    "bluetooth": FakeConnection(
        BLUETOOTH_IP, user(["network"], source=GATEWAY_USER)),
}


async def notified(kind: str, state: str = "in_progress") -> Any:
    h = await Harness(stored=code_state(state)).start()
    data = [h.setup.public_state()]
    before = copy.deepcopy(data)
    out = muon_access_policy.filter_notification(
        NOTIFICATION, data, CONNECTIONS[kind])
    # One payload goes to every connection: filtering one must not change
    # what the next is sent.
    assert data == before
    return out


class TestNotification:
    @pytest.mark.parametrize("kind", ["remote", "remote_address"])
    def test_remote_connection_is_not_sent_the_code(self, kind: str):
        out = run(notified(kind))
        link = link_of(out[0])
        assert link == {"phase": "code", "expires_at": EXPIRES}

    @pytest.mark.parametrize("kind", ["panel", "hotspot", "lan"])
    def test_local_connections_are_sent_it(self, kind: str):
        out = run(notified(kind))
        assert link_of(out[0]) == LINK

    def test_bluetooth_during_setup_is_sent_it(self):
        assert link_of(run(notified("bluetooth"))[0]) == LINK

    def test_bluetooth_after_setup_is_not(self):
        link = link_of(run(notified("bluetooth", state="complete"))[0])
        assert "code" not in link and "url" not in link

    def test_other_notifications_pass_unchanged(self):
        data = [{"steps": {"remote": {"link": dict(LINK)}}}]
        out = muon_access_policy.filter_notification(
            "status_update", data, CONNECTIONS["remote"])
        assert out == data

    def test_other_connection_is_not_sent_the_code(self):
        # Review: 192.0.2.2 logged in as an ordinary user after setup is
        # `other`, which may not GET the state; nor is it sent the code.
        conn = FakeConnection(BLUETOOTH_IP, user(["network"]))
        for state in ("in_progress", "complete"):
            async def go() -> Any:
                h = await Harness(stored=code_state(state)).start()
                return muon_access_policy.filter_notification(
                    NOTIFICATION, (h.setup.public_state(),), conn)
            link = link_of(run(go())[0])
            assert "code" not in link and "url" not in link

    def test_the_real_payload_shape_is_a_tuple(self):
        # server.py hands notify_clients the event's args: `(state,)`.
        async def go() -> Any:
            h = await Harness(stored=code_state()).start()
            data = (h.setup.public_state(),)
            return data, muon_access_policy.filter_notification(
                NOTIFICATION, data, CONNECTIONS["remote"])
        data, out = run(go())
        assert link_of(out[0]) == {"phase": "code", "expires_at": EXPIRES}
        assert link_of(data[0]) == LINK

    def test_the_filter_is_on_the_name_muon_setup_notifies(self):
        # A rename of the event must not silently drop the filter.
        h = Harness(stored=code_state())
        names = [event.split(":", 1)[1] for event in h.server.notifications]
        assert NOTIFICATION in names
        assert NOTIFICATION in muon_access_policy._notification_filters

    def test_a_payload_without_a_link_passes(self):
        for payload in ([], [None], [{"state": "new"}],
                        [{"steps": {"remote": {"link": None}}}]):
            out = muon_access_policy.filter_notification(
                NOTIFICATION, payload, CONNECTIONS["remote"])
            assert out == payload
