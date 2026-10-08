"""MR-5: POST /remote {mode}, the link-phase poller, and remote/cancel.

02 §5.9 + §8 test 12. FakeMuonLink stands in for the muon_link component;
remote.POLL_SECONDS is shortened so the two-second poll runs at test pace.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

import pytest

from moonraker.components.muon_setup import remote

from muon_setup_fakes import FakeMuonLink, Harness, run, state_with


def cloud_state() -> Dict[str, Any]:
    """Cursor on `remote`, network measured internet, everything before it
    done."""
    doc = state_with(
        language={"status": "done", "value": "en"},
        network={"status": "done", "kind": "wifi", "ssid": "HomeWiFi",
                 "internet": True},
        name={"status": "done", "value": "Walnut"},
        update={"status": "done"},
    )
    return doc


async def remote_harness(
    link: FakeMuonLink,
    synced: bool = True,
    stored: Optional[Dict[str, Any]] = None,
) -> Harness:
    h = await Harness(stored=stored or cloud_state()).start()
    h.with_muon_link(link)
    if synced:
        h.setup._live["clock"]["synced"] = True
    return h


async def settle(h: Harness, ticks: int = 6) -> None:
    """Let the (shortened) poller walk the fake's phase list."""
    for _ in range(ticks):
        await asyncio.sleep(remote.POLL_SECONDS * 3)


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch: Any):
    monkeypatch.setattr(remote, "POLL_SECONDS", 0.01)


def body(**kw: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"rev": 5}
    out.update(kw)
    return out


class TestModes:
    def test_local_finishes_the_step(self):
        async def go():
            h = await remote_harness(FakeMuonLink())
            out = await h.post("/remote", body(mode="local"))
            assert out["ok"] is True
            step = h.doc["steps"]["remote"]
            assert step["status"] == "done" and step["mode"] == "local"
            assert h.doc["cursor"] == "ready"
        run(go())

    def test_later_skips_the_step(self):
        async def go():
            h = await remote_harness(FakeMuonLink())
            out = await h.post("/remote", body(mode="later"))
            assert out["ok"] is True
            step = h.doc["steps"]["remote"]
            assert step["status"] == "skipped" and step["mode"] == "later"
        run(go())

    def test_bad_mode_is_invalid(self):
        async def go():
            h = await remote_harness(FakeMuonLink())
            out = await h.post("/remote", body(mode="self_hosted"))
            assert out["ok"] is False
            assert out["error"]["code"] == "invalid_mode"
        run(go())

    def test_cloud_needs_internet(self):
        async def go():
            doc = cloud_state()
            doc["steps"]["network"]["internet"] = None
            h = await remote_harness(FakeMuonLink(), stored=doc)
            out = await h.post("/remote", body(mode="cloud"))
            assert out["ok"] is False
            assert out["error"]["code"] == "no_internet"
        run(go())

    def test_cloud_needs_a_synced_clock(self):
        async def go():
            h = await remote_harness(FakeMuonLink(), synced=False)
            out = await h.post("/remote", body(mode="cloud"))
            assert out["ok"] is False
            assert out["error"]["code"] == "clock_unsynced"
        run(go())

    def test_cloud_without_muon_link_is_unavailable(self):
        async def go():
            h = await Harness(stored=cloud_state()).start()
            h.setup._live["clock"]["synced"] = True
            out = await h.post("/remote", body(mode="cloud"))
            assert out["ok"] is True
            assert h.doc["steps"]["remote"]["error"]["code"] == (
                "link_unavailable")
        run(go())


class TestLinkFlow:
    def test_a_code_mirrors_then_linked_finishes(self):
        """§8 t12: the phase object lands on remote.link unchanged; linked
        marks done with the account and advances."""
        async def go():
            link = FakeMuonLink([
                {"phase": "connecting"},
                {"phase": "code", "code": "482913",
                 "expires_at": 9999999999, "url": "https://x"},
                {"phase": "linked", "account": "jed@example.com",
                 "connected": True},
            ])
            h = await remote_harness(link)
            out = await h.post("/remote", body(mode="cloud"))
            assert out["ok"] is True
            step = h.doc["steps"]["remote"]
            assert step["mode"] == "cloud" and step["status"] == "pending"
            await settle(h)
            step = h.doc["steps"]["remote"]
            assert step["status"] == "done"
            assert step["account"] == "jed@example.com"
            assert step["link"]["phase"] == "linked"
            assert h.doc["cursor"] == "ready"
        run(go())

    def test_an_expired_code_is_renewed(self):
        """§8 t12: once synced time passes expires_at, start() is called
        again."""
        async def go():
            link = FakeMuonLink([
                {"phase": "code", "code": "111111", "expires_at": 1},
                {"phase": "code", "code": "222222", "expires_at": 9999999999},
            ])
            h = await remote_harness(link)
            await h.post("/remote", body(mode="cloud"))
            await settle(h)
            assert link.starts >= 2  # the initial start plus the renewal
            assert h.doc["steps"]["remote"]["link"]["code"] == "222222"
        run(go())

    def test_start_is_never_called_during_offer(self):
        """§8 t12: an offer mirrors but is never renewed."""
        async def go():
            link = FakeMuonLink([
                {"phase": "offer", "account": "jed@example.com",
                 "authority": "Muon3D", "fingerprint": "9f"},
                {"phase": "offer", "account": "jed@example.com",
                 "authority": "Muon3D", "fingerprint": "9f"},
                {"phase": "offer", "account": "jed@example.com",
                 "authority": "Muon3D", "fingerprint": "9f"},
            ])
            h = await remote_harness(link)
            await h.post("/remote", body(mode="cloud"))
            starts = link.starts
            await settle(h)
            assert link.starts == starts  # no renewal during offer
            assert h.doc["steps"]["remote"]["link"]["phase"] == "offer"
            assert h.doc["steps"]["remote"]["status"] == "pending"
        run(go())

    def test_failed_retries_once_then_link_failed(self):
        async def go():
            link = FakeMuonLink([
                {"phase": "failed", "message": "could not reach"},
                {"phase": "failed", "message": "could not reach"},
            ])
            h = await remote_harness(link)
            await h.post("/remote", body(mode="cloud"))
            await settle(h)
            step = h.doc["steps"]["remote"]
            assert step["error"]["code"] == "link_failed"
            assert step["error"]["detail"]["message"] == "could not reach"
            assert step["status"] == "pending"
            assert link.starts == 2  # the start plus exactly one retry
        run(go())

    def test_a_503_is_link_unavailable(self):
        async def go():
            link = FakeMuonLink()
            link.down = True
            h = await remote_harness(link)
            out = await h.post("/remote", body(mode="cloud"))
            assert out["ok"] is True
            assert h.doc["steps"]["remote"]["error"]["code"] == (
                "link_unavailable")
            assert h.doc["steps"]["remote"]["status"] == "pending"
        run(go())

    def test_phase_unavailable_is_link_unavailable(self):
        async def go():
            link = FakeMuonLink([{"phase": "unavailable"}])
            h = await remote_harness(link)
            await h.post("/remote", body(mode="cloud"))
            await settle(h)
            assert h.doc["steps"]["remote"]["error"]["code"] == (
                "link_unavailable")
        run(go())

    def test_already_linked_finishes_at_once(self):
        """02 §5.9 step 5: a 409 "already linked" becomes done with that
        account (muon_link turns the 409 into the linked phase)."""
        async def go():
            link = FakeMuonLink(
                [{"phase": "linked", "account": "jed@example.com"}])
            h = await remote_harness(link)
            out = await h.post("/remote", body(mode="cloud"))
            assert out["ok"] is True
            step = h.doc["steps"]["remote"]
            assert step["status"] == "done"
            assert step["account"] == "jed@example.com"
        run(go())


class TestPollerStops:
    def test_goto_away_stops_the_poll(self):
        async def go():
            link = FakeMuonLink([
                {"phase": "code", "code": "1", "expires_at": 9999999999},
                {"phase": "code", "code": "1", "expires_at": 9999999999},
                {"phase": "code", "code": "1", "expires_at": 9999999999},
            ])
            h = await remote_harness(link)
            await h.post("/remote", body(mode="cloud"))
            await asyncio.sleep(remote.POLL_SECONDS * 3)
            await h.post("/goto", {"rev": h.doc["rev"], "step": "name"})
            calls = link.status_calls
            await asyncio.sleep(remote.POLL_SECONDS * 4)
            assert link.status_calls == calls  # the poller stopped
            assert h.doc["cursor"] == "name"
        run(go())

    def test_cancel_declines_and_clears(self):
        async def go():
            link = FakeMuonLink([
                {"phase": "code", "code": "1", "expires_at": 9999999999},
            ])
            h = await remote_harness(link)
            await h.post("/remote", body(mode="cloud"))
            out = await h.post("/remote/cancel", {})
            assert out["ok"] is True
            assert link.cancels == 1
            step = h.doc["steps"]["remote"]
            assert step["mode"] is None and step["link"] is None
            assert step["status"] == "pending"
        run(go())

    def test_cancel_is_a_no_op_once_linked(self):
        async def go():
            link = FakeMuonLink()
            doc = cloud_state()
            doc["steps"]["remote"].update(
                status="done", mode="cloud",
                link={"phase": "linked", "account": "a@b.c"},
                account="a@b.c")
            h = await remote_harness(link, stored=doc)
            out = await h.post("/remote/cancel", {})
            assert out["ok"] is True
            assert link.cancels == 0
            assert h.doc["steps"]["remote"]["mode"] == "cloud"
        run(go())


class TestCloudCapability:
    @pytest.mark.parametrize("status,capable", [
        ({"phase": "unlinked"}, True),
        ({"phase": "linked", "account": "a@b.c"}, True),
        ({"phase": "unavailable"}, False),
    ])
    def test_cloud_link_follows_get_link(self, status: Any, capable: bool):
        """02 §5.9: cloud_link is false on `unavailable` and on a 503."""
        async def go():
            link = FakeMuonLink([status, status])
            h = await remote_harness(link)
            await h.setup.refresh_live(full=True)
            assert h.setup._live["capabilities"]["cloud_link"] is capable
        run(go())

    def test_a_503_means_not_capable(self):
        async def go():
            link = FakeMuonLink()
            link.down = True
            h = await remote_harness(link)
            await h.setup.refresh_live(full=True)
            assert h.setup._live["capabilities"]["cloud_link"] is False
        run(go())

    def test_no_component_means_not_capable(self):
        async def go():
            h = await Harness(stored=cloud_state()).start()
            await h.setup.refresh_live(full=True)
            assert h.setup._live["capabilities"]["cloud_link"] is False
        run(go())
