"""KAN-4812 part 3 (and KAN-4949): the panel's live state and remote
navigation, server.muon.panel.{publish,state,navigate,navigate_result}.

Every call goes through APIDefinition.request, so the floor, the level table
and the handler's own checks all run, as they do for a real client.
"""
from __future__ import annotations

import asyncio
import ipaddress
import itertools
import json
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

import pytest

from moonraker import muon_access_policy as policy
from moonraker import muon_floor
from moonraker.common import (
    APIDefinition, BaseRemoteConnection, JsonRPC, RequestType, TransportType,
)
from moonraker.components import muon_panel, muon_panel_nav
from moonraker.components.application import _write_json_error
from moonraker.utils.exceptions import BodyError, ServerError

from muon_access_fakes import HTTP, LAN, LOOPBACK, SENTINEL, caller

Who = Tuple[Any, Any, Any]

OWNER_ONLY = ["settings", "link"]
STATE = {
    "seq": 5, "screen": "home", "params": {}, "modal": None, "busy": False,
    "updated_at": 1700000000.5, "owner_only_routes": OWNER_ONLY,
}


def gateway(level: str, role: str) -> Who:
    return caller({"kind": "gateway", "principal": f"{level}-{role}",
                   "level": level, "role": role, "home": False})


OWNER = gateway("admin", "operator")
MEMBER = gateway("member", "operator")
VIEWER = gateway("admin", "viewer")
HOME = caller({"kind": "home"})
LOCAL_HTTP: Who = (HTTP, LOOPBACK, None)


@pytest.fixture(autouse=True)
def _reset():
    cache = dict(APIDefinition._cache)
    guard = policy._files
    APIDefinition._cache.clear()
    policy.set_files(None)
    policy.set_state(policy.AccessState(
        entry=policy.ENTRY_OPEN, owner=policy.OWNER_ACCOUNT))
    try:
        yield
    finally:
        APIDefinition._cache.clear()
        APIDefinition._cache.update(cache)
        policy.set_files(guard)
        policy.set_state(None)
        muon_floor.set_protection_level(muon_floor.LEVEL_OPEN)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class Loop:
    def __init__(self) -> None:
        self.now = 100.0
        self.timers: List[Any] = []

    def get_loop_time(self) -> float:
        return self.now

    def create_future(self) -> asyncio.Future:
        return asyncio.get_running_loop().create_future()

    def delay_callback(self, delay: float, callback: Callable[..., Any],
                       *args: Any) -> Any:
        timer = type("Timer", (), {"due": self.now + delay,
                                   "callback": callback, "args": args,
                                   "live": True,
                                   "cancel": lambda self: None})()
        self.timers.append(timer)
        return timer

    def advance(self, seconds: float) -> None:
        end = self.now + seconds
        while True:
            due = sorted((t for t in self.timers if t.live),
                         key=lambda t: t.due)
            if not due or due[0].due > end:
                break
            self.now = max(self.now, due[0].due)
            due[0].live = False
            due[0].callback(*due[0].args)
        self.now = end


class Websockets:
    def __init__(self, loop: Loop) -> None:
        self.loop = loop
        self.sent: List[Tuple[float, str, Any, List[int]]] = []

    def notify_clients(self, name: str, data: Any = (), mask: Any = ()) -> None:
        self.sent.append((self.loop.now, name, json.loads(json.dumps(data)),
                          list(mask)))


class Extensions:
    def __init__(self) -> None:
        self.agent_methods: Dict[int, List[str]] = {}


class Access:
    def access_state(self) -> policy.AccessState:
        return policy.state()  # type: ignore[return-value]


class Server:
    error = ServerError

    def __init__(self) -> None:
        self.loop = Loop()
        self.wsm = Websockets(self.loop)
        self.extensions = Extensions()
        self.components: Dict[str, Any] = {
            "websockets": self.wsm, "extensions": self.extensions,
            "muon_access": Access(),
        }
        self.endpoints: Dict[str, APIDefinition] = {}
        self.event_handlers: Dict[str, List[Callable[..., Any]]] = {}

    def lookup_component(self, name: str, default: Any = None) -> Any:
        return self.components.get(name, default)

    def get_event_loop(self) -> Loop:
        return self.loop

    def register_endpoint(self, path: str, verbs: Any, handler: Any,
                          *args: Any, **kwargs: Any) -> None:
        self.endpoints[path] = APIDefinition.create(path, verbs, handler)

    def register_event_handler(self, event: str, callback: Any) -> None:
        self.event_handlers.setdefault(event, []).append(callback)

    def send_event(self, event: str, *args: Any) -> None:
        for callback in self.event_handlers.get(event, []):
            callback(*args)


class Conn(BaseRemoteConnection):
    """A websocket (or unix socket) client, without the socket."""
    ids = itertools.count(1000)

    def __init__(self, ip: Optional[str] = "127.0.0.1", name: str = "muon-panel",
                 unix: bool = False) -> None:
        self._uid = next(self.ids)
        self._client_data = {"name": name, "version": "1", "type": "agent",
                             "url": ""}
        self._identified = True
        self._user_info = None
        self.is_closed = False
        self.unix = unix
        self._ip = None if unix or ip is None else ipaddress.ip_address(ip)
        self.calls: List[Tuple[str, Dict[str, Any]]] = []
        self.on_call: Optional[Callable[[Any, Dict[str, Any]], None]] = None

    @property
    def ip_addr(self) -> Any:
        return self._ip

    @property
    def authentication_ip(self) -> Any:
        return LOOPBACK if self.unix else self._ip

    def send_notification(self, name: str, data: List[Any]) -> None:
        pass

    def call_method(self, method: str, params: Any = None) -> None:
        self.calls.append((method, params))
        if self.on_call is not None:
            self.on_call(self, params)

    def who(self) -> Who:
        return (self, self.ip_addr, None)


class Rig:
    def __init__(self) -> None:
        self.server = Server()
        self.nav = muon_panel_nav.PanelNav(self.server)  # type: ignore

    # -- connections --------------------------------------------------------

    def identify(self, conn: Conn, register: bool = True) -> Conn:
        if register:
            self.server.extensions.agent_methods.setdefault(
                conn.uid, []).append(muon_panel_nav.NAVIGATE_METHOD)
        self.server.send_event("websockets:client_identified", conn)
        return conn

    def panel(self, **kwargs: Any) -> Conn:
        return self.identify(Conn(**kwargs))

    def disconnect(self, conn: Conn) -> None:
        conn.is_closed = True
        self.server.send_event("websockets:client_removed", conn)

    # -- requests -----------------------------------------------------------

    async def call(self, name: str, args: Optional[Dict[str, Any]] = None,
                   who: Who = LOCAL_HTTP) -> Any:
        verb = RequestType.GET if name == "state" else RequestType.POST
        api = self.server.endpoints[f"{muon_panel_nav.PREFIX}/{name}"]
        transport, ip, user = who
        return await api.request(dict(args or {}), verb, transport, ip, user)

    async def publish(self, conn: Conn, **changes: Any) -> Any:
        return await self.call(
            "publish", {"state": {**STATE, **changes}}, conn.who())

    async def result(self, conn: Conn, req_id: str, **fields: Any) -> Any:
        return await self.call(
            "navigate_result", {"req_id": req_id, "ok": True, **fields},
            conn.who())

    def auto_reply(self, conn: Conn, **fields: Any) -> None:
        def on_call(c: Conn, params: Dict[str, Any]) -> None:
            asyncio.get_running_loop().create_task(
                self.result(c, params["req_id"], **fields))
        conn.on_call = on_call

    async def refused(self, awaitable: Awaitable[Any]) -> BodyError:
        with pytest.raises(ServerError) as err:
            await awaitable
        return err.value  # type: ignore[return-value]


def run(scenario: Callable[[Rig], Awaitable[Any]]) -> Any:
    async def main() -> Any:
        return await scenario(Rig())
    return asyncio.run(main())


def reason(err: Any) -> Any:
    return getattr(err, "body", {}).get("reason")


# ---------------------------------------------------------------------------
# Who may publish
# ---------------------------------------------------------------------------


class TestPublishIsThePanelsAlone:
    def test_the_panel_connection_publishes(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            return await rig.publish(panel)
        assert run(scenario) == {"seq": 5}

    def test_a_unix_socket_peer_is_local(self):
        policy.set_state(None)  # the unix socket carries no address to admit

        async def scenario(rig: Rig) -> Any:
            panel = rig.panel(unix=True)
            return await rig.publish(panel)
        assert run(scenario) == {"seq": 5}

    def test_a_local_connection_that_is_not_the_panel(self):
        async def scenario(rig: Rig) -> Any:
            rig.panel()
            other = rig.identify(Conn(name="fluidd"))
            return await rig.refused(rig.publish(other))
        err = run(scenario)
        assert err.status_code == 403 and reason(err) == "not_panel"

    def test_a_wrong_client_name(self):
        async def scenario(rig: Rig) -> Any:
            for name in ("muon-panel2", "Muon-Panel", "", "panel"):
                conn = rig.identify(Conn(name=name))
                err = await rig.refused(rig.publish(conn))
                assert err.status_code == 403, name
            assert rig.nav.view() == {"connected": False}
        run(scenario)

    def test_a_remote_connection_that_says_it_is_the_panel(self):
        async def scenario(rig: Rig) -> Any:
            for ip in ("192.168.1.50", "192.0.2.1", "10.0.0.2"):
                conn = rig.identify(Conn(ip=ip))
                err = await rig.refused(rig.publish(conn))
                assert err.status_code == 403, ip
            assert rig.nav.view() == {"connected": False}
        run(scenario)

    def test_a_connection_that_has_not_identified(self):
        async def scenario(rig: Rig) -> Any:
            conn = Conn()
            conn._identified = False
            conn._client_data["name"] = "unknown"
            return await rig.refused(rig.publish(conn))
        assert run(scenario).status_code == 403

    def test_without_the_remote_method_registered(self):
        async def scenario(rig: Rig) -> Any:
            conn = rig.identify(Conn(), register=False)
            return await rig.refused(rig.publish(conn))
        assert run(scenario).status_code == 403

    def test_a_plain_http_request_has_no_connection(self):
        async def scenario(rig: Rig) -> Any:
            rig.panel()
            return await rig.refused(rig.call(
                "publish", {"state": STATE}, LOCAL_HTTP))
        err = run(scenario)
        assert err.status_code == 403 and reason(err) == "not_panel"

    @pytest.mark.parametrize("who", [OWNER, MEMBER, VIEWER, HOME],
                             ids=["owner", "member", "viewer", "home"])
    def test_no_remote_principal_even_the_owner(self, who: Who):
        async def scenario(rig: Rig) -> Any:
            rig.panel()
            return await rig.refused(rig.call(
                "publish", {"state": STATE}, who))
        err = run(scenario)
        assert err.status_code == 403
        assert "access-denied:panel_only" in str(err)

    def test_the_latest_identified_connection_wins(self):
        async def scenario(rig: Rig) -> Any:
            first = rig.panel()
            await rig.publish(first)
            second = rig.panel()
            err = await rig.refused(rig.publish(first, seq=6))
            assert err.status_code == 403
            assert rig.nav.view() == {"connected": True}
            await rig.publish(second, seq=7)
            # the old one going away changes nothing for the new one
            rig.disconnect(first)
            assert rig.nav.view()["seq"] == 7
        run(scenario)

    def test_a_pending_navigation_to_the_old_panel_fails(self):
        async def scenario(rig: Rig) -> Any:
            first = rig.panel()
            await rig.publish(first)
            task = asyncio.ensure_future(
                rig.call("navigate", {"screen": "files"}, OWNER))
            await asyncio.sleep(0)
            rig.panel()
            return await rig.refused(task)
        err = run(scenario)
        assert err.status_code == 503 and reason(err) == "panel_offline"


class TestThePublishedState:
    def test_seq_is_the_panels_when_it_moves_on(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            a = await rig.publish(panel, seq=5)
            b = await rig.publish(panel, seq=9)
            return a, b, rig.nav.view()["seq"]
        assert run(scenario) == ({"seq": 5}, {"seq": 9}, 9)

    def test_seq_is_ours_when_the_panel_does_not_move_on(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel, seq=9)
            same = await rig.publish(panel, seq=9)
            lower = await rig.publish(panel, seq=2)
            zero = await rig.publish(panel, seq=0)
            return same, lower, zero
        assert run(scenario) == ({"seq": 10}, {"seq": 11}, {"seq": 12})

    def test_seq_never_goes_back_across_panels(self):
        async def scenario(rig: Rig) -> Any:
            first = rig.panel()
            await rig.publish(first, seq=40)
            rig.disconnect(first)
            second = rig.panel()
            return await rig.publish(second, seq=1)
        assert run(scenario) == {"seq": 41}

    @pytest.mark.parametrize("bad", [
        "text", None, [], {"screen": "home", "seq": "x"},
        {**STATE, "screen": ""}, {**STATE, "screen": 3},
        {**STATE, "busy": "yes"}, {**STATE, "owner_only_routes": "settings"},
        {**STATE, "owner_only_routes": [1]}, {**STATE, "params": []},
        {**STATE, "seq": True}, {**STATE, "updated_at": []},
        {**STATE, "params": {"x": "y" * 70000}},
    ])
    def test_a_malformed_state_is_a_400(self, bad: Any):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            return await rig.refused(rig.call(
                "publish", {"state": bad}, panel.who()))
        assert run(scenario).status_code == 400

    def test_state_keeps_the_contract_fields_and_drops_the_rest(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel, modal={"kind": "confirm"}, evil="x")
            return await rig.call("state", who=VIEWER)
        assert run(scenario) == {
            "connected": True, "seq": 5, "screen": "home", "params": {},
            "modal": {"kind": "confirm"}, "busy": False,
            "updated_at": 1700000000.5, "owner_only_routes": OWNER_ONLY,
        }


# ---------------------------------------------------------------------------
# Reading it
# ---------------------------------------------------------------------------


class TestStateAndNotification:
    def test_not_connected(self):
        async def scenario(rig: Rig) -> Any:
            return await rig.call("state", who=VIEWER)
        assert run(scenario) == {"connected": False}

    def test_connected_before_it_has_published(self):
        async def scenario(rig: Rig) -> Any:
            rig.panel()
            return await rig.call("state", who=MEMBER)
        assert run(scenario) == {"connected": True}

    def test_a_viewer_reads_it(self):
        async def scenario(rig: Rig) -> Any:
            await rig.publish(rig.panel())
            return await rig.call("state", who=VIEWER)
        assert run(scenario)["screen"] == "home"

    def test_disconnecting_gives_connected_false_and_says_so(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            rig.disconnect(panel)
            rig.server.loop.advance(1)
            return (await rig.call("state", who=VIEWER),
                    rig.server.wsm.sent[-1])
        state, last = run(scenario)
        assert state == {"connected": False}
        assert last[1:] == ("muon_panel_state", [{"connected": False}], [])

    def test_the_notification_has_the_same_body_and_skips_the_panel(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            rig.server.loop.advance(1)
            return (await rig.call("state", who=VIEWER),
                    rig.server.wsm.sent[-1], panel.uid)
        state, last, uid = run(scenario)
        assert last[1] == "muon_panel_state"
        assert last[2] == [state]
        assert last[3] == [uid]

    def test_at_most_ten_a_second_and_the_latest_is_delivered(self):
        async def scenario(rig: Rig) -> Any:
            loop = rig.server.loop
            panel = rig.panel()
            for seq in range(10, 60):          # 50 publishes in half a second
                await rig.publish(panel, seq=seq, screen=f"s{seq}")
                loop.advance(0.01)
            loop.advance(1)
            return rig.server.wsm.sent
        sent = run(scenario)
        times = [t for t, *_ in sent]
        assert all(b - a >= 0.1 - 1e-9 for a, b in zip(times, times[1:]))
        assert len(sent) <= 8                  # 1 + 0.5 s / 0.1 s, and a tail
        assert len(sent) > 2
        assert sent[-1][2][0]["seq"] == 59
        assert sent[-1][2][0]["screen"] == "s59"

    def test_a_quiet_change_is_sent_at_once(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            rig.server.loop.advance(1)
            before = len(rig.server.wsm.sent)
            await rig.publish(panel)
            return before, len(rig.server.wsm.sent)
        before, after = run(scenario)
        assert after == before + 1


# ---------------------------------------------------------------------------
# Navigating
# ---------------------------------------------------------------------------


class TestNavigate:
    def test_the_happy_path(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            rig.auto_reply(panel, seq=6)
            answer = await rig.call(
                "navigate", {"screen": "files", "params": {"path": "a"}},
                MEMBER)
            assert not rig.nav._pending
            return answer, panel.calls
        answer, calls = run(scenario)
        assert answer == {"seq": 5}     # Moonraker's, not the panel's 6
        (method, params), = calls
        assert method == "muon_panel_navigate"
        assert params["screen"] == "files"
        assert params["params"] == {"path": "a"}
        assert params["caller_role"] == "operator"
        assert isinstance(params["req_id"], str) and params["req_id"]
        assert params["caller_is_owner"] is False
        assert params["caller_level"] == "member"
        assert set(params) == {"req_id", "screen", "params", "caller_role",
                               "caller_is_owner", "caller_level"}

    def test_the_reply_without_a_seq_answers_with_the_current_one(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel, seq=12)
            rig.auto_reply(panel)
            return await rig.call("navigate", {"screen": "files"}, OWNER)
        assert run(scenario) == {"seq": 12}

    def test_each_navigation_has_its_own_req_id(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            rig.auto_reply(panel)
            for _ in range(5):
                await rig.call("navigate", {"screen": "files"}, OWNER)
                rig.server.loop.advance(1)
            return [p["req_id"] for _, p in panel.calls]
        ids = run(scenario)
        assert len(set(ids)) == 5

    def test_the_local_caller_is_the_panel_itself(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            rig.auto_reply(panel)
            await rig.call("navigate", {"screen": "settings"}, LOCAL_HTTP)
            return panel.calls[0][1]["caller_role"]
        assert run(scenario) == "operator"

    def test_stale_seq_is_a_409(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel, seq=5)
            err = await rig.refused(rig.call(
                "navigate", {"screen": "files", "if_seq": 4}, OWNER))
            return err, panel.calls
        err, calls = run(scenario)
        assert err.status_code == 409
        assert err.body == {"reason": "stale_seq", "seq": 5}
        assert calls == []

    def test_the_current_seq_goes_through(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel, seq=5)
            rig.auto_reply(panel)
            return await rig.call(
                "navigate", {"screen": "files", "if_seq": 5}, OWNER)
        assert run(scenario) == {"seq": 5}

    def test_the_panels_403_owner_only_is_passed_through(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            rig.auto_reply(panel, ok=False, status=403, reason="owner_only")
            return await rig.refused(rig.call(
                "navigate", {"screen": "settings"}, OWNER))
        err = run(scenario)
        assert err.status_code == 403 and err.body == {"reason": "owner_only"}

    def test_the_panels_423_is_passed_through(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            rig.auto_reply(panel, ok=False, status=423, reason="busy")
            return await rig.refused(rig.call(
                "navigate", {"screen": "files"}, OWNER))
        err = run(scenario)
        assert err.status_code == 423 and err.body == {"reason": "busy"}

    def test_the_panels_409_is_passed_through(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            rig.auto_reply(panel, ok=False, status=409, reason="modal_open")
            return await rig.refused(rig.call(
                "navigate", {"screen": "files"}, OWNER))
        err = run(scenario)
        assert err.status_code == 409 and err.body == {"reason": "modal_open"}

    @pytest.mark.parametrize("status", [None, 200, 500, "x", 401])
    def test_any_other_status_from_the_panel_is_a_409(self, status: Any):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            rig.auto_reply(panel, ok=False, status=status)
            return await rig.refused(rig.call(
                "navigate", {"screen": "files"}, OWNER))
        err = run(scenario)
        assert err.status_code == 409 and reason(err) == "refused"

    def test_no_answer_is_a_504(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(muon_panel_nav, "NAV_TIMEOUT", 0.05)

        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            err = await rig.refused(rig.call(
                "navigate", {"screen": "files"}, OWNER))
            return err, rig.nav._pending
        err, pending = run(scenario)
        assert err.status_code == 504 and err.body == {"reason": "panel_timeout"}
        assert not pending

    def test_the_wait_is_two_seconds(self):
        assert muon_panel_nav.NAV_TIMEOUT == 2.0
        assert muon_panel_nav.MAX_PENDING == 8

    def test_no_panel_is_a_503(self):
        async def scenario(rig: Rig) -> Any:
            return await rig.refused(rig.call(
                "navigate", {"screen": "files"}, OWNER))
        err = run(scenario)
        assert err.status_code == 503 and err.body == {"reason": "panel_offline"}

    def test_a_panel_that_has_not_published_is_not_ready(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            err = await rig.refused(rig.call(
                "navigate", {"screen": "files"}, OWNER))
            return err, panel.calls
        err, calls = run(scenario)
        assert err.status_code == 503 and calls == []

    def test_a_disconnected_panel_is_a_503(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            rig.disconnect(panel)
            return await rig.refused(rig.call(
                "navigate", {"screen": "files"}, OWNER))
        assert run(scenario).status_code == 503

    @pytest.mark.parametrize("args", [
        {}, {"screen": ""}, {"screen": 4}, {"screen": "x" * 200},
        {"screen": "files", "params": "a"}, {"screen": "files", "params": []},
        {"screen": "files", "if_seq": "x"}, {"screen": "files", "if_seq": 1.5},
        {"screen": "files", "params": {"k": "v" * 20000}},
    ])
    def test_a_malformed_request_is_a_400(self, args: Dict[str, Any]):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            return await rig.refused(rig.call("navigate", args, OWNER))
        assert run(scenario).status_code == 400

    def test_a_viewer_may_not_navigate(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            err = await rig.refused(rig.call(
                "navigate", {"screen": "files"}, VIEWER))
            return err, panel.calls
        err, calls = run(scenario)
        assert err.status_code == 403 and calls == []


class TestOwnerOnlyScreens:
    def test_an_operator_who_is_not_the_owner_is_refused_first(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            err = await rig.refused(rig.call(
                "navigate", {"screen": "settings"}, MEMBER))
            return err, panel.calls
        err, calls = run(scenario)
        assert err.status_code == 403 and err.body == {"reason": "owner_only"}
        assert calls == []                       # the panel was not asked

    def test_someone_at_home_is_not_the_owner(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            policy.set_state(policy.AccessState(
                entry=policy.ENTRY_OPEN, owner=policy.OWNER_ACCOUNT,
                home=policy.HomeNetwork.from_interface_addresses(
                    [(ipaddress.ip_address("192.168.1.10"), 24)])))
            err = await rig.refused(rig.call(
                "navigate", {"screen": "link"}, HOME))
            return err.body, panel.calls
        body, calls = run(scenario)
        assert body == {"reason": "owner_only"} and calls == []

    def test_the_owner_may(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            rig.auto_reply(panel)
            answer = await rig.call("navigate", {"screen": "settings"}, OWNER)
            return answer, panel.calls[0][1]
        answer, params = run(scenario)
        assert answer == {"seq": 5}
        assert params["screen"] == "settings"

    def test_a_screen_that_is_not_listed_is_open_to_an_operator(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            rig.auto_reply(panel)
            return await rig.call("navigate", {"screen": "files"}, MEMBER)
        assert run(scenario) == {"seq": 5}

    def test_the_list_is_the_last_one_published(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel, seq=5, owner_only_routes=[])
            rig.auto_reply(panel)
            first = await rig.call("navigate", {"screen": "settings"}, MEMBER)
            await rig.publish(panel, seq=6, owner_only_routes=["settings"])
            err = await rig.refused(rig.call(
                "navigate", {"screen": "settings"}, MEMBER))
            return first, err
        first, err = run(scenario)
        assert first == {"seq": 5} and err.status_code == 403

    def test_the_gate_does_not_depend_on_muon_access_being_loaded(self):
        policy.set_state(None)

        async def scenario(rig: Rig) -> Any:
            rig.server.components.pop("muon_access")
            panel = rig.panel()
            await rig.publish(panel)
            rig.auto_reply(panel)
            err = await rig.refused(rig.call(
                "navigate", {"screen": "settings"}, MEMBER))
            local = await rig.call(
                "navigate", {"screen": "settings"}, LOCAL_HTTP)
            return err, local
        err, local = run(scenario)
        assert err.status_code == 403 and local == {"seq": 5}


class TestRepliesAreMatched:
    def test_a_late_reply_is_dropped(self, monkeypatch: pytest.MonkeyPatch,
                                     caplog: pytest.LogCaptureFixture):
        monkeypatch.setattr(muon_panel_nav, "NAV_TIMEOUT", 0.05)

        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            await rig.refused(rig.call("navigate", {"screen": "files"}, OWNER))
            req_id = panel.calls[0][1]["req_id"]
            return await rig.result(panel, req_id, seq=99)
        with caplog.at_level("DEBUG"):
            assert run(scenario) == {"accepted": False}
        assert "dropped" in caplog.text

    def test_an_unknown_req_id_is_dropped(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            return [await rig.result(panel, rid) for rid in
                    ("nope", "", 7, None)]
        assert run(scenario) == [{"accepted": False}] * 4

    def test_a_reply_is_used_once(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            rig.auto_reply(panel, seq=6)
            await rig.call("navigate", {"screen": "files"}, OWNER)
            req_id = panel.calls[0][1]["req_id"]
            return await rig.result(panel, req_id)
        assert run(scenario) == {"accepted": False}

    def test_a_foreign_connection_cannot_answer(self, caplog):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            other = rig.identify(Conn(name="fluidd"))
            task = asyncio.ensure_future(
                rig.call("navigate", {"screen": "files"}, OWNER))
            await asyncio.sleep(0)
            req_id = panel.calls[0][1]["req_id"]
            err = await rig.refused(rig.result(other, req_id, seq=77))
            # the navigation is still waiting; the panel answers it
            assert not task.done()
            await rig.result(panel, req_id, seq=6)
            return err, await task
        with caplog.at_level("DEBUG"):
            err, answer = run(scenario)
        assert err.status_code == 403
        assert answer == {"seq": 5}
        assert "dropped" in caplog.text

    def test_a_remote_principal_cannot_answer(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            task = asyncio.ensure_future(
                rig.call("navigate", {"screen": "files"}, OWNER))
            await asyncio.sleep(0)
            req_id = panel.calls[0][1]["req_id"]
            err = await rig.refused(rig.call(
                "navigate_result", {"req_id": req_id, "ok": True}, OWNER))
            assert not task.done()
            rig.nav._drop_panel()
            await rig.refused(task)
            return err
        assert run(scenario).status_code == 403

    def test_the_old_panel_cannot_answer_for_the_new_one(self):
        async def scenario(rig: Rig) -> Any:
            old = rig.panel()
            await rig.publish(old)
            new = rig.panel()
            await rig.publish(new)
            task = asyncio.ensure_future(
                rig.call("navigate", {"screen": "files"}, OWNER))
            await asyncio.sleep(0)
            req_id = new.calls[0][1]["req_id"]
            err = await rig.refused(rig.result(old, req_id))
            assert not task.done()
            await rig.result(new, req_id)
            return err, await task
        err, answer = run(scenario)
        assert err.status_code == 403 and answer == {"seq": 6}


class TestTheCap:
    def test_a_ninth_pending_navigation_is_a_429(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            tasks = []
            for _ in range(8):
                tasks.append(asyncio.ensure_future(
                    rig.call("navigate", {"screen": "files"}, LOCAL_HTTP)))
            await asyncio.sleep(0)
            assert len(rig.nav._pending) == 8
            err = await rig.refused(rig.call(
                "navigate", {"screen": "files"}, LOCAL_HTTP))
            # answering one makes room
            await rig.result(panel, panel.calls[0][1]["req_id"])
            await tasks[0]
            tasks.append(asyncio.ensure_future(
                rig.call("navigate", {"screen": "files"}, LOCAL_HTTP)))
            await asyncio.sleep(0)
            assert len(rig.nav._pending) == 8
            for call in panel.calls[1:]:
                await rig.result(panel, call[1]["req_id"])
            await asyncio.gather(*tasks)
            return err, rig.nav._pending
        err, pending = run(scenario)
        assert err.status_code == 429
        assert not pending


class TestDisconnect:
    def test_pending_navigations_fail_with_503(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            tasks = [asyncio.ensure_future(
                rig.call("navigate", {"screen": "files"}, LOCAL_HTTP))
                for _ in range(3)]
            await asyncio.sleep(0)
            assert len(rig.nav._pending) == 3
            rig.disconnect(panel)
            errs = []
            for task in tasks:
                errs.append(await rig.refused(task))
            return errs, rig.nav._pending, await rig.call("state", who=VIEWER)
        errs, pending, state = run(scenario)
        assert [e.status_code for e in errs] == [503] * 3
        assert all(e.body == {"reason": "panel_offline"} for e in errs)
        assert not pending
        assert state == {"connected": False}

    def test_a_panel_that_comes_back_starts_clean(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            rig.disconnect(panel)
            again = rig.panel()
            return await rig.call("state", who=VIEWER), again.uid
        state, _ = run(scenario)
        assert state == {"connected": True}


# ---------------------------------------------------------------------------
# The access classification
# ---------------------------------------------------------------------------

POST = RequestType.POST
GET = RequestType.GET


def actions(endpoint: str, verb: RequestType) -> List[str]:
    return [a.name for a in policy.classify(endpoint, verb, {})]


class TestClassification:
    def test_state_is_a_read(self):
        assert actions("/server/muon/panel/state", GET) == ["read"]
        assert actions("/server/muon/panel/index.html", GET) == ["read"]

    def test_navigate_is_a_write_for_an_operator(self):
        assert actions("/server/muon/panel/navigate", POST) == ["ui_settings"]
        action = policy.ACTIONS["ui_settings"]
        assert not action.read and not action.viewer_allowed

    def test_publish_and_navigate_result_are_panel_only(self):
        for name in ("publish", "navigate_result"):
            assert actions(f"/server/muon/panel/{name}", POST) == [
                "panel_only"]

    def test_anything_else_under_it_fails_closed(self):
        assert actions("/server/muon/panel/other", POST) == ["system"]

    def test_the_row_is_fixed_and_cannot_be_overridden(self):
        row = policy.ACTIONS["panel_only"]
        assert row.fixed and row.panel_only
        assert not policy.overridable("panel_only")
        with pytest.raises(ValueError):
            policy.parse_overrides({"panel_only": "signed_out_guest"})

    @pytest.mark.parametrize("owner", policy.OWNERS)
    @pytest.mark.parametrize("entry", policy.ENTRIES)
    @pytest.mark.parametrize("preset", (None,) + policy.PRESETS)
    def test_no_principal_holds_it_at_any_setting(self, owner, entry, preset):
        state = policy.AccessState(entry=entry, preset=preset, owner=owner)
        row = policy.ACTIONS["panel_only"]
        assert policy.required_level(row, state) == policy.PANEL
        for who in (OWNER, MEMBER, VIEWER, HOME, caller({"kind": "password"})):
            principal = policy.resolve_principal(
                who[0], who[1], who[2], entry, state.home)
            assert not policy.decide_action(row, principal, state).allowed
        assert policy.decide_action(
            row, policy.PANEL_PRINCIPAL, state).allowed
        assert policy.decide_action(
            row, policy.INTERNAL_PRINCIPAL, state).allowed

    def test_the_capability_list_names_it_only_for_the_panel(self):
        state = policy.state()
        assert "panel_only" in policy.allowed_actions(
            policy.PANEL_PRINCIPAL, state)
        principal = policy.resolve_principal(
            OWNER[0], OWNER[1], OWNER[2], state.entry, state.home)
        assert "panel_only" not in policy.allowed_actions(principal, state)
        assert policy.effective_table(state)["panel_only"] == "panel"

    def test_the_viewer_reads_state_through_the_table(self):
        async def scenario(rig: Rig) -> Any:
            await rig.publish(rig.panel())
            ok = await rig.call("state", who=VIEWER)
            err = await rig.refused(rig.call(
                "navigate", {"screen": "files"}, VIEWER))
            return ok["connected"], str(err)
        connected, message = run(scenario)
        assert connected is True
        assert "access-denied:ui_settings" in message
        assert "Viewer" in message

    def test_a_stranger_is_not_admitted_to_state_on_a_protected_printer(self):
        policy.set_state(policy.AccessState(
            entry=policy.ENTRY_PROTECTED, owner=policy.OWNER_ACCOUNT))

        async def scenario(rig: Rig) -> Any:
            return await rig.refused(rig.call(
                "state", who=(HTTP, LAN, None)))
        assert run(scenario).status_code == 403

    def test_the_gateways_sentinel_is_not_the_panel(self):
        # a muon-link request arrives from loopback with this address; it is
        # a remote principal, so publish is refused before the handler
        async def scenario(rig: Rig) -> Any:
            rig.panel()
            return await rig.refused(rig.call(
                "publish", {"state": STATE}, (HTTP, SENTINEL, OWNER[2])))
        err = run(scenario)
        assert err.status_code == 403
        assert "access-denied:panel_only" in str(err)


# ---------------------------------------------------------------------------
# How a refusal is written
# ---------------------------------------------------------------------------


class Handler:
    def __init__(self) -> None:
        self.status: Optional[int] = None
        self.body = b""
        self._reason = "x"

    def set_status(self, status: int, reason: Any = None) -> None:
        self.status = status

    def set_header(self, *args: Any) -> None:
        pass

    def finish(self, body: Any) -> None:
        self.body = body


class TestTheErrorBodies:
    def test_http_carries_the_reason_beside_the_error(self):
        import tornado.web
        cause = muon_panel_nav.refusal(409, "stale_seq", seq=7)
        try:
            raise tornado.web.HTTPError(409, reason=str(cause)) from cause
        except tornado.web.HTTPError:
            import sys
            handler = Handler()
            _write_json_error(handler, 409, exc_info=sys.exc_info())  # type: ignore
        body = json.loads(handler.body)
        assert handler.status == 409
        assert body["reason"] == "stale_seq" and body["seq"] == 7
        assert body["error"]["code"] == 409

    def test_http_without_a_body_is_unchanged(self):
        handler = Handler()
        _write_json_error(handler, 404)  # type: ignore
        assert set(json.loads(handler.body)) == {"error"}

    def test_json_rpc_carries_it_as_data(self):
        rpc = JsonRPC.__new__(JsonRPC)
        rpc.verbose = False
        err = muon_panel_nav.refusal(409, "stale_seq", seq=7)
        out = rpc.build_error(409, str(err), 3, err, "server.muon.panel.navigate")
        assert out["error"]["data"] == {"reason": "stale_seq", "seq": 7}
        assert out["error"]["code"] == 409

    def test_a_plain_error_has_no_data(self):
        rpc = JsonRPC.__new__(JsonRPC)
        rpc.verbose = False
        out = rpc.build_error(400, "x", 3, ServerError("x"), "m")
        assert "data" not in out["error"]


def test_the_endpoints_are_registered_for_http_and_json_rpc():
    rig = Rig()
    paths = set(rig.server.endpoints)
    assert paths == {f"/server/muon/panel/{n}" for n in (
        "publish", "state", "navigate", "navigate_result")}
    for path, api in rig.server.endpoints.items():
        assert TransportType.HTTP in api.transports
        assert TransportType.WEBSOCKET in api.transports
        assert api.rpc_methods == [path[1:].replace("/", ".")]
    assert muon_panel.PanelNav is muon_panel_nav.PanelNav


# ---------------------------------------------------------------------------
# Review fixes (Moonraker#88)
# ---------------------------------------------------------------------------


class TestThePanelNameCannotBeHeldRemotely:
    """identify is open to guests: a remote one must not hold the name, or
    the method, that the real panel needs when it reconnects."""

    @staticmethod
    def manager() -> Any:
        from moonraker.components.extensions import ExtensionManager

        class Klippy:
            def __init__(self) -> None:
                self.methods: List[str] = []

            def register_method_from_agent(self, conn: Any, name: str) -> None:
                if name in self.methods:
                    raise ServerError("already registered")
                self.methods.append(name)

        class Plain:
            error = ServerError

            def __init__(self) -> None:
                self.components: Dict[str, Any] = {
                    "klippy_connection": Klippy()}

            def register_endpoint(self, *args: Any, **kwargs: Any) -> None:
                pass

            def lookup_component(self, name: str, default: Any = None) -> Any:
                return self.components.get(name, default)

        server = Plain()
        config = type("C", (), {"get_server": lambda self: server})()
        return ExtensionManager(config), server

    @staticmethod
    def register(mgr: Any, conn: Conn, method: str) -> Any:
        from moonraker.common import WebRequest
        request = WebRequest("/connection/register_remote_method",
                             {"method_name": method}, RequestType.POST, conn)
        return asyncio.run(mgr._register_agent_method(request))

    def test_a_remote_guest_cannot_take_the_agent_name(self):
        mgr, _ = self.manager()
        guest = Conn(ip="192.168.1.50")
        with pytest.raises(ServerError) as err:
            mgr.register_agent(guest)
        assert err.value.status_code == 403
        assert "muon-panel" not in mgr.agents
        # so the real panel can still register, whenever it reconnects
        mgr.register_agent(Conn())
        assert "muon-panel" in mgr.agents

    def test_the_gateways_sentinel_cannot_either(self):
        mgr, _ = self.manager()
        with pytest.raises(ServerError):
            mgr.register_agent(Conn(ip="192.0.2.1"))

    def test_another_agent_name_is_unaffected(self):
        mgr, _ = self.manager()
        mgr.register_agent(Conn(ip="192.168.1.50", name="helper"))
        assert "helper" in mgr.agents

    def test_a_remote_connection_cannot_register_the_navigate_method(self):
        mgr, server = self.manager()
        for conn in (Conn(ip="192.168.1.50"),
                     Conn(ip="192.168.1.50", name="helper")):
            with pytest.raises(ServerError) as err:
                self.register(mgr, conn, muon_panel_nav.NAVIGATE_METHOD)
            assert err.value.status_code == 403
        assert server.components["klippy_connection"].methods == []

    def test_a_local_connection_that_is_not_the_panel_cannot_either(self):
        mgr, _ = self.manager()
        with pytest.raises(ServerError):
            self.register(mgr, Conn(name="fluidd"),
                          muon_panel_nav.NAVIGATE_METHOD)

    def test_the_local_panel_registers_it(self):
        mgr, server = self.manager()
        assert self.register(
            mgr, Conn(), muon_panel_nav.NAVIGATE_METHOD) == "ok"
        assert server.components["klippy_connection"].methods == [
            "muon_panel_navigate"]

    def test_other_methods_are_free_to_anyone(self):
        mgr, _ = self.manager()
        assert self.register(mgr, Conn(ip="192.168.1.50"), "x") == "ok"


class TestWhatTheOwnerOnlyCheckSendsAndCompares:
    def test_the_owner_flag_and_level_go_to_the_panel(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            rig.auto_reply(panel)
            await rig.call("navigate", {"screen": "files"}, OWNER)
            rig.server.loop.advance(1)
            await rig.call("navigate", {"screen": "files"}, LOCAL_HTTP)
            return [c[1] for c in panel.calls]
        owner, local = run(scenario)
        assert owner["caller_is_owner"] is True
        assert owner["caller_level"] == "admin"
        assert owner["caller_role"] == "operator"
        assert local["caller_is_owner"] is True
        assert local["caller_level"] == "panel"

    @pytest.mark.parametrize("screen", [
        "Settings", "SETTINGS", "/settings", "settings/", "/settings/",
        "//settings//", " settings ", "/Settings/",
    ])
    def test_screens_compare_without_case_or_edge_slashes(self, screen: str):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            err = await rig.refused(rig.call(
                "navigate", {"screen": screen}, MEMBER))
            return err, panel.calls
        err, calls = run(scenario)
        assert err.body == {"reason": "owner_only"} and calls == []

    def test_the_published_routes_are_normalised_too(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(
                panel, owner_only_routes=["/Settings/", "LINK", "/a/b/"])
            out = []
            for screen in ("settings", "link", "a/b", "A/B/"):
                out.append((await rig.refused(rig.call(
                    "navigate", {"screen": screen}, MEMBER))).body)
                rig.server.loop.advance(1)
            return out
        assert run(scenario) == [{"reason": "owner_only"}] * 4

    def test_the_owner_still_passes_a_differently_spelled_screen(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel)
            rig.auto_reply(panel)
            return await rig.call("navigate", {"screen": "/Settings"}, OWNER)
        assert run(scenario) == {"seq": 5}


class TestSeq:
    def test_the_answer_is_moonrakers_seq_not_the_panels(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel, seq=12)
            rig.auto_reply(panel, seq=2 ** 60)
            return await rig.call("navigate", {"screen": "files"}, OWNER)
        assert run(scenario) == {"seq": 12}

    def test_the_answer_follows_a_publish_made_meanwhile(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            await rig.publish(panel, seq=12)
            task = asyncio.ensure_future(
                rig.call("navigate", {"screen": "files"}, OWNER))
            await asyncio.sleep(0)
            await rig.publish(panel, seq=13)
            await rig.result(panel, panel.calls[0][1]["req_id"], seq=1)
            return await task
        assert run(scenario) == {"seq": 13}

    @pytest.mark.parametrize("seq", [2 ** 53, 2 ** 63, 10 ** 30, -1])
    def test_a_seq_beyond_what_json_holds_is_refused(self, seq: int):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            return await rig.refused(rig.publish(panel, seq=seq))
        assert run(scenario).status_code == 400

    def test_the_largest_seq_is_accepted_then_the_count_stops(self):
        async def scenario(rig: Rig) -> Any:
            panel = rig.panel()
            top = await rig.publish(panel, seq=2 ** 53 - 1)
            err = await rig.refused(rig.publish(panel, seq=1))
            return top, err
        top, err = run(scenario)
        assert top == {"seq": 2 ** 53 - 1} and err.status_code == 400

    def test_the_count_survives_a_reconnect_with_a_lower_seq(self):
        async def scenario(rig: Rig) -> Any:
            first = rig.panel()
            await rig.publish(first, seq=500)
            rig.disconnect(first)
            second = rig.panel()
            a = await rig.publish(second, seq=1)
            b = await rig.publish(second, seq=1)
            return a, b
        assert run(scenario) == ({"seq": 501}, {"seq": 502})


class TestPerCallerLimit:
    @staticmethod
    async def ready(rig: Rig) -> Conn:
        panel = rig.panel()
        await rig.publish(panel)
        return panel

    def test_two_a_second_then_rate_limited(self):
        async def scenario(rig: Rig) -> Any:
            panel = await self.ready(rig)
            rig.auto_reply(panel)
            for _ in range(2):
                await rig.call("navigate", {"screen": "files"}, MEMBER)
            err = await rig.refused(rig.call(
                "navigate", {"screen": "files"}, MEMBER))
            rig.server.loop.advance(1.01)
            again = await rig.call("navigate", {"screen": "files"}, MEMBER)
            return err, again, len(panel.calls)
        err, again, calls = run(scenario)
        assert err.status_code == 429
        assert err.body == {"reason": "rate_limited"}
        assert again == {"seq": 5} and calls == 3

    def test_two_pending_at_most(self):
        async def scenario(rig: Rig) -> Any:
            panel = await self.ready(rig)
            tasks = []
            for _ in range(2):
                tasks.append(asyncio.ensure_future(
                    rig.call("navigate", {"screen": "files"}, MEMBER)))
                await asyncio.sleep(0)
                rig.server.loop.advance(1.01)    # the rate is not the limit
            err = await rig.refused(rig.call(
                "navigate", {"screen": "files"}, MEMBER))
            await rig.result(panel, panel.calls[0][1]["req_id"])
            await tasks[0]
            tasks.append(asyncio.ensure_future(
                rig.call("navigate", {"screen": "files"}, MEMBER)))
            await asyncio.sleep(0)
            for call in panel.calls[1:]:
                await rig.result(panel, call[1]["req_id"])
            await asyncio.gather(*tasks)
            return err
        err = run(scenario)
        assert err.status_code == 429 and err.body == {"reason": "rate_limited"}

    def test_each_principal_has_its_own_allowance(self):
        async def scenario(rig: Rig) -> Any:
            panel = await self.ready(rig)
            rig.auto_reply(panel)
            for who in (MEMBER, OWNER):
                for _ in range(2):
                    await rig.call("navigate", {"screen": "files"}, who)
            return len(panel.calls)
        assert run(scenario) == 4

    def test_a_refused_attempt_does_not_use_the_allowance(self):
        async def scenario(rig: Rig) -> Any:
            panel = await self.ready(rig)
            rig.auto_reply(panel)
            for _ in range(5):
                await rig.refused(rig.call(
                    "navigate", {"screen": "settings"}, MEMBER))
            return await rig.call("navigate", {"screen": "files"}, MEMBER)
        assert run(scenario) == {"seq": 5}

    def test_local_callers_are_exempt(self):
        async def scenario(rig: Rig) -> Any:
            panel = await self.ready(rig)
            rig.auto_reply(panel)
            for _ in range(6):
                await rig.call("navigate", {"screen": "files"}, LOCAL_HTTP)
            return len(panel.calls)
        assert run(scenario) == 6

    def test_the_global_cap_of_eight_stands(self):
        assert muon_panel_nav.MAX_PENDING == 8
        assert muon_panel_nav.CALLER_PENDING == 2
        assert muon_panel_nav.CALLER_RATE == 2


class TestWhoIsSentTheState:
    @staticmethod
    def send(who: Who, state: Optional[policy.AccessState]) -> Any:
        Rig()                                   # registers the filter
        policy.set_state(state)
        conn = Conn(ip=str(who[1]) if who[1] else None)
        conn._user_info = who[2]
        return policy.filter_notification(
            muon_panel_nav.NOTIFICATION, [{"connected": True}], conn)

    def test_a_connection_that_may_read_gets_it(self):
        open_state = policy.state()
        for who in (OWNER, MEMBER, VIEWER, LOCAL_HTTP):
            assert self.send(who, open_state) == [{"connected": True}]

    def test_a_connection_that_is_not_admitted_does_not(self):
        protected = policy.AccessState(
            entry=policy.ENTRY_PROTECTED, owner=policy.OWNER_ACCOUNT)
        assert self.send((HTTP, LAN, None), protected) is None

    def test_a_connection_from_outside_the_home_network_does_not(self):
        assert self.send((HTTP, ipaddress.ip_address("203.0.113.9"), None),
                         policy.state()) is None

    def test_the_decision_is_the_gets(self):
        # whoever the table refuses a read gets no notification either
        strict = policy.AccessState(
            entry=policy.ENTRY_OPEN, preset=policy.STRICT,
            owner=policy.OWNER_ACCOUNT)
        who = (HTTP, ipaddress.ip_address("203.0.113.9"), None)

        async def get(rig: Rig) -> Any:
            return await rig.refused(rig.call("state", who=who))
        policy.set_state(strict)
        assert run(get).status_code == 403
        assert self.send(who, strict) is None

    def test_without_the_level_table_it_is_sent(self):
        assert self.send(OWNER, None) == [{"connected": True}]


def test_the_panel_origin_is_allowed_by_cors():
    import pathlib
    text = (pathlib.Path(__file__).parent.parent / "core" / "M1"
            / "moonraker.core.conf.template").read_text()
    lines = [line.strip() for line in text.splitlines()]
    assert any(line.startswith("*://127.0.0.1:100") for line in lines)
    assert any(line.startswith("*://localhost:100") for line in lines)
