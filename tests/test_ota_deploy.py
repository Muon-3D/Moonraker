"""Cover the OTA status mapping the update UI is driven from (KAN-85).

`ota_deploy.py` is the adapter between the Aux API's OTA status and Moonraker's
update_manager, and it had no tests. The contract it has to honour is written
down in the Aux API's OTA_UPDATE_MANAGER_PLAYBOOK.md:

    Moonraker should treat `check.error` as a warning, not a failed update. A
    failed install or failed commit is represented by `state == "failed"` and
    `last_error`.

That distinction is the whole point. A background update check runs on a timer,
so it fails whenever the printer's internet does. If a failed *check* were
reported as a failed *update*, every Wi-Fi hiccup would tell the user their
printer failed to update -- and the reasonable response to that message is to
intervene during an update, which is the one moment intervening is dangerous.

These are unit tests: no Klippy, no server, no sockets. The fakes below supply
only what BaseDeploy and OtaDeploy actually touch, so the object under test is
a real OtaDeploy built through its real constructor.

They drive coroutines with asyncio.run rather than pytest-asyncio on purpose.
tests/conftest.py defines its own class-scoped `event_loop` fixture, which
newer pytest-asyncio releases no longer support, and nothing here needs a
shared loop.
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any, Dict, List, Optional

import pytest

from moonraker.components.update_manager import ota_deploy
from moonraker.components.update_manager.base_deploy import BaseDeploy
from moonraker.components.update_manager.ota_deploy import OtaDeploy


# --------------------------------------------------------------------------
# Fakes
# --------------------------------------------------------------------------

class FakeServerError(Exception):
    """Stands in for Moonraker's ServerError, which needs a live server."""

    def __init__(self, message: str, status_code: int = 500) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class FakeAux:
    """The aux_api_proxy component, scripted.

    `statuses` is consumed one entry per ota_status() call; the last entry
    repeats once exhausted, so a polling loop settles instead of running off
    the end of the list.
    """

    def __init__(self, statuses: Optional[List[Dict[str, Any]]] = None) -> None:
        self.statuses = list(statuses or [])
        self.calls: List[str] = []
        self.fail_with: Optional[Exception] = None
        # Separate from `fail_with`, which breaks the status reads. A printer
        # that refuses an install answers /update/status perfectly well; it is
        # only POST /update/install that 409s.
        self.start_error: Optional[Exception] = None

    async def ota_status(self) -> Dict[str, Any]:
        self.calls.append("ota_status")
        if self.fail_with is not None:
            raise self.fail_with
        if not self.statuses:
            return {}
        if len(self.statuses) > 1:
            return self.statuses.pop(0)
        return self.statuses[0]

    async def ota_check_server(self) -> Dict[str, Any]:
        self.calls.append("ota_check_server")
        if self.fail_with is not None:
            raise self.fail_with
        return {}

    async def ota_start(self) -> Dict[str, Any]:
        self.calls.append("ota_start")
        if self.start_error is not None:
            raise self.start_error
        return {}

    async def ota_commit(self) -> Dict[str, Any]:
        self.calls.append("ota_commit")
        return {}


class FakeServer:
    def __init__(self, aux: Optional[FakeAux]) -> None:
        self._aux = aux

    def lookup_component(self, name: str, default: Any = None) -> Any:
        if name == "aux_api_proxy":
            return self._aux
        return default

    def error(self, message: str, status_code: int = 500) -> FakeServerError:
        # Moonraker's server.error() *returns* the exception for the caller to
        # raise, so this must not raise on its own.
        return FakeServerError(message, status_code)


class FakeCmdHelper:
    def __init__(self) -> None:
        self.responses: List[tuple[str, bool]] = []
        self.refresh_notifications = 0
        self._umdb: Dict[str, Any] = {}

    def get_refresh_interval(self) -> float:
        return 3600.0

    def get_umdb(self) -> Dict[str, Any]:
        return self._umdb

    def notify_update_response(self, msg: str, is_complete: bool = False) -> None:
        self.responses.append((msg, is_complete))

    def notify_update_refreshed(self) -> None:
        self.refresh_notifications += 1


class FakeConfig:
    def __init__(self, server: FakeServer, name: str = "update_manager os") -> None:
        self._server = server
        self._name = name

    def get_server(self) -> FakeServer:
        return self._server

    def get_name(self) -> str:
        return self._name

    def getint(self, option: str, default: Any = None) -> Any:
        return default

    def get_hash(self) -> "hashlib._Hash":
        return hashlib.sha256(self._name.encode())


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

@pytest.fixture
def cmd_helper(monkeypatch: pytest.MonkeyPatch) -> FakeCmdHelper:
    """BaseDeploy.cmd_helper is a class attribute shared by every deploy.

    monkeypatch restores it, so a test that swaps it cannot leak into the rest
    of the session.
    """
    helper = FakeCmdHelper()
    monkeypatch.setattr(BaseDeploy, "cmd_helper", helper, raising=False)
    return helper


@pytest.fixture
def no_poll_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run the polling loop at full speed.

    The retry path sleeps POLL_SECS * 2 per attempt and gives up after
    MAX_CONSECUTIVE_ERRORS, which is about nine seconds of real waiting for a
    test that is only checking which branch was taken.
    """
    monkeypatch.setattr(ota_deploy, "POLL_SECS", 0.0)


def make_deploy(aux: Optional[FakeAux], cmd_helper: FakeCmdHelper) -> OtaDeploy:
    return OtaDeploy(FakeConfig(FakeServer(aux)))


# --------------------------------------------------------------------------
# The documented contract: check.error is a warning
# --------------------------------------------------------------------------

CHECK_ERROR_STATUS: Dict[str, Any] = {
    "state": "idle",
    "current_version": "1.0.0",
    "update_available": False,
    "check": {
        "state": "failed",
        "error": {
            "kind": "network_unreachable",
            "message": "Could not reach the update server",
        },
    },
}


def test_check_error_becomes_a_warning_and_not_a_terminal_error(cmd_helper):
    """The playbook's rule, at the level of the mapping itself."""
    deploy = make_deploy(FakeAux(), cmd_helper)

    deploy._map_status(CHECK_ERROR_STATUS)

    assert "Could not reach the update server" in deploy._warnings
    # Nothing here is a terminal failure: the top-level error fields are what
    # a failed install or commit sets, and a failed check must not set them.
    assert deploy._terminal_error_message(CHECK_ERROR_STATUS) == ""


def test_check_error_leaves_the_updater_reported_as_valid(cmd_helper):
    """What Fluidd actually renders.

    `is_valid` false is how the UI says the updater itself is broken. A failed
    check must not reach that.
    """
    aux = FakeAux([CHECK_ERROR_STATUS])
    deploy = make_deploy(aux, cmd_helper)

    asyncio.run(deploy.refresh())

    status = deploy.get_update_status()
    assert status["is_valid"] is True
    assert "Could not reach the update server" in status["warnings"]


def test_the_same_check_error_is_not_warned_about_twice(cmd_helper):
    """refresh() clears warnings each time, and the mapper dedupes within one."""
    deploy = make_deploy(FakeAux(), cmd_helper)

    deploy._map_status(CHECK_ERROR_STATUS)
    deploy._map_status(CHECK_ERROR_STATUS)

    assert deploy._warnings.count("Could not reach the update server") == 1


def test_an_update_run_survives_a_check_error(cmd_helper, no_poll_delay):
    """End to end: a check error must not make update() report a failure."""
    aux = FakeAux([CHECK_ERROR_STATUS])
    deploy = make_deploy(aux, cmd_helper)

    assert asyncio.run(deploy.update()) is True

    assert not any("failed" in msg.lower() for msg, _ in cmd_helper.responses), (
        f"a check error was reported to the user as a failure: "
        f"{cmd_helper.responses}"
    )
    # Paired with a positive one: the negative above also holds if update()
    # said nothing at all.
    assert cmd_helper.responses, "the run reported nothing to the user"
    assert deploy.get_update_status()["warnings"] == [
        "Could not reach the update server"
    ]


# --------------------------------------------------------------------------
# The other half of the contract: state == failed with last_error
# --------------------------------------------------------------------------

def test_failed_state_with_last_error_is_a_terminal_failure(cmd_helper):
    status = {
        "state": "failed",
        "last_error": {"kind": "install_failed", "message": "bundle rejected"},
    }
    deploy = make_deploy(FakeAux(), cmd_helper)

    assert deploy._terminal_error_message(status) == "bundle rejected"


def test_the_compatibility_error_string_wins_over_last_error(cmd_helper):
    """`error` is the short string the playbook keeps for Moonraker."""
    status = {
        "state": "failed",
        "error": "install failed",
        "last_error": {"message": "a much longer structured explanation"},
    }
    deploy = make_deploy(FakeAux(), cmd_helper)

    assert deploy._terminal_error_message(status) == "install failed"


def test_an_update_run_raises_on_a_failed_install(cmd_helper, no_poll_delay):
    failed = {
        "state": "failed",
        "current_version": "1.0.0",
        "last_error": {"message": "bundle rejected"},
    }
    aux = FakeAux([failed])
    deploy = make_deploy(aux, cmd_helper)

    with pytest.raises(FakeServerError) as excinfo:
        asyncio.run(deploy.update())

    assert "bundle rejected" in str(excinfo.value)
    assert any(
        "bundle rejected" in msg and complete
        for msg, complete in cmd_helper.responses
    ), f"the failure was never reported to the user: {cmd_helper.responses}"


def test_a_failed_state_with_no_message_still_raises(cmd_helper, no_poll_delay):
    """Failing silently would leave the UI showing a successful update."""
    aux = FakeAux([{"state": "failed", "current_version": "1.0.0"}])
    deploy = make_deploy(aux, cmd_helper)

    with pytest.raises(FakeServerError):
        asyncio.run(deploy.update())


# --------------------------------------------------------------------------
# Version and progress mapping
# --------------------------------------------------------------------------

def test_no_update_available_reports_the_target_as_the_current_version(cmd_helper):
    """Otherwise the UI offers an update that is not on offer.

    The Aux API keeps reporting the last target it saw, so echoing it whenever
    it is present would light up the update button permanently.
    """
    deploy = make_deploy(FakeAux(), cmd_helper)

    deploy._map_status({
        "state": "idle",
        "current_version": "1.0.0",
        "target_version": "2.0.0",
        "update_available": False,
    })

    assert deploy._current == "1.0.0"
    assert deploy._target == "1.0.0"
    status = deploy.get_update_status()
    assert status["version"] == status["remote_version"] == "1.0.0"


def test_an_available_update_reports_the_target_version(cmd_helper):
    deploy = make_deploy(FakeAux(), cmd_helper)

    deploy._map_status({
        "state": "idle",
        "current_version": "1.0.0",
        "target_version": "2.0.0",
        "update_available": True,
    })

    status = deploy.get_update_status()
    assert status["version"] == "1.0.0"
    assert status["remote_version"] == "2.0.0"


def test_progress_is_read_from_the_nested_install_block(cmd_helper):
    """The Aux API moved progress under `install`; the flat field is the old one."""
    deploy = make_deploy(FakeAux(), cmd_helper)

    deploy._map_status({
        "state": "installing",
        "install": {"phase": "downloading", "progress": 42.5},
    })

    assert deploy._progress == 42.5


def test_a_flat_progress_field_still_wins_when_present(cmd_helper):
    deploy = make_deploy(FakeAux(), cmd_helper)

    deploy._map_status({
        "state": "installing",
        "progress": 10.0,
        "install": {"progress": 42.5},
    })

    assert deploy._progress == 10.0


def test_a_non_numeric_progress_is_dropped_rather_than_crashing(cmd_helper):
    deploy = make_deploy(FakeAux(), cmd_helper)

    deploy._map_status({"state": "installing", "progress": "almost done"})

    assert deploy._progress is None


def test_requires_commit_is_surfaced_to_the_client(cmd_helper):
    deploy = make_deploy(FakeAux(), cmd_helper)

    deploy._map_status({"state": "commit_pending", "requires_commit": True})

    assert deploy.get_update_status()["requires_commit"] is True


# --------------------------------------------------------------------------
# States that end an update run without failing it
# --------------------------------------------------------------------------

def test_commit_pending_ends_the_run_successfully(cmd_helper, no_poll_delay):
    """The new image booted and is waiting to be committed. Not a failure."""
    aux = FakeAux([{"state": "commit_pending", "requires_commit": True}])
    deploy = make_deploy(aux, cmd_helper)

    assert asyncio.run(deploy.update()) is True
    assert any("Commit verification is pending" in msg
               for msg, _ in cmd_helper.responses)


def test_committing_ends_the_run_before_the_reboot(cmd_helper, no_poll_delay):
    """Moonraker is about to go down with the reboot, so it announces first."""
    aux = FakeAux([{"state": "committing"}])
    deploy = make_deploy(aux, cmd_helper)

    assert asyncio.run(deploy.update()) is True
    # The message, not merely "something was marked complete". The generic
    # post-loop ending is also is_complete=True, so a bare completeness check
    # passes with the `committing` branch deleted entirely -- which is the one
    # thing this test is here to pin.
    assert any(
        "Preparing to reboot" in msg and complete
        for msg, complete in cmd_helper.responses
    ), cmd_helper.responses


# --------------------------------------------------------------------------
# Failure to reach the Aux API at all
# --------------------------------------------------------------------------

def test_an_unreachable_aux_api_marks_the_updater_invalid(cmd_helper):
    """This one *is* the updater being broken, so is_valid goes false."""
    aux = FakeAux()
    aux.fail_with = RuntimeError("connection refused")
    deploy = make_deploy(aux, cmd_helper)

    asyncio.run(deploy.refresh())

    status = deploy.get_update_status()
    assert status["is_valid"] is False
    assert any("connection refused" in w for w in status["warnings"])


def test_a_missing_aux_component_is_an_error_not_a_crash(cmd_helper):
    """The component is always configured together with this one."""
    deploy = make_deploy(None, cmd_helper)

    with pytest.raises(FakeServerError) as excinfo:
        deploy._aux()

    assert "aux_api_proxy" in str(excinfo.value)


def test_a_non_dict_status_payload_is_rejected(cmd_helper):
    """Everything downstream indexes this, so a list would fail much later."""
    aux = FakeAux()

    async def bad_status() -> Any:
        return ["not", "a", "dict"]

    aux.ota_status = bad_status  # type: ignore[method-assign]
    deploy = make_deploy(aux, cmd_helper)

    with pytest.raises(FakeServerError):
        asyncio.run(deploy._aux_status())


# --------------------------------------------------------------------------
# The status document handed to Fluidd
# --------------------------------------------------------------------------

def test_update_status_is_shaped_the_way_the_clients_expect(cmd_helper):
    deploy = make_deploy(FakeAux(), cmd_helper)
    deploy._map_status({
        "state": "idle",
        "current_version": "1.0.0",
        "update_available": False,
    })

    status = deploy.get_update_status()

    assert status["configured_type"] == "ota"
    assert status["name"] == "os"
    # Fluidd compares the hashes when the versions are not strict semver, so
    # they have to be populated even though this is not a git repository.
    assert status["current_hash"] == "1.0.0"
    assert status["remote_hash"] == "1.0.0"
    assert status["info_tags"] == ["desc=System Image"]


def test_warnings_are_copied_so_callers_cannot_mutate_internal_state(cmd_helper):
    deploy = make_deploy(FakeAux(), cmd_helper)
    deploy._map_status(CHECK_ERROR_STATUS)

    deploy.get_update_status()["warnings"].append("injected")

    assert "injected" not in deploy._warnings


# --------------------------------------------------------------------------
# KAN-216: the surface has to say why, and must not claim what did not happen
# --------------------------------------------------------------------------

COMMIT_PENDING_STATUS: Dict[str, Any] = {
    "state": "commit_pending",
    "current_version": "2.0.0",
    "requires_commit": True,
    "update_available": True,
    "target_version": "2.1.0",
}


def test_an_uncommitted_system_is_explained_to_the_user(cmd_helper):
    """`requires_commit` alone reaches no client, so it is said in prose.

    Fluidd models an update as git_repo | web | zip | OSPackage and has no
    field for this. `warnings` is the one part of the status document it
    renders as text.
    """
    deploy = make_deploy(FakeAux(), cmd_helper)

    deploy._map_status(COMMIT_PENDING_STATUS)

    warnings = deploy.get_update_status()["warnings"]
    assert ota_deploy.COMMIT_PENDING_WARNING in warnings
    # Both halves, because they pull in opposite directions: the refusal
    # invites a restart and a restart is what discards the update.
    assert "roll it back" in ota_deploy.COMMIT_PENDING_WARNING
    assert "no new update can be installed" in ota_deploy.COMMIT_PENDING_WARNING


def test_a_committed_system_is_not_warned_about(cmd_helper):
    """The negative control: this must not fire on an ordinary printer."""
    deploy = make_deploy(FakeAux(), cmd_helper)

    deploy._map_status({
        "state": "idle",
        "current_version": "2.0.0",
        "requires_commit": False,
        "update_available": False,
    })

    assert deploy.get_update_status()["warnings"] == []


def test_the_commit_warning_is_not_repeated_by_the_poller(cmd_helper):
    """_map_status runs once per poll, and only refresh() clears _warnings."""
    deploy = make_deploy(FakeAux(), cmd_helper)

    deploy._map_status(COMMIT_PENDING_STATUS)
    deploy._map_status(COMMIT_PENDING_STATUS)
    deploy._map_status(COMMIT_PENDING_STATUS)

    warnings = deploy.get_update_status()["warnings"]
    assert warnings.count(ota_deploy.COMMIT_PENDING_WARNING) == 1


def test_a_refused_install_is_never_announced_as_started(cmd_helper, no_poll_delay):
    """The defect this ticket was filed for.

    `update()` used to notify "Starting OS image update" before calling
    ota_start, with that call outside any try. A refusal left the claim
    standing as the only line under a dialog Fluidd titles "Updates finished",
    so the UI asserted the update had begun at the moment it was declined.
    """
    aux = FakeAux([COMMIT_PENDING_STATUS])
    aux.start_error = FakeServerError(
        "refusing to install while the running system requires commit", 409
    )
    deploy = make_deploy(aux, cmd_helper)

    with pytest.raises(FakeServerError):
        asyncio.run(deploy.update())

    announced = [msg for msg, _ in cmd_helper.responses]
    assert not any("Starting OS image update" in msg for msg in announced), (
        f"the UI was told the update started after it was refused: {announced}"
    )


def test_a_refused_install_tells_the_user_the_reason(cmd_helper, no_poll_delay):
    """Paired with the negative above, which also holds if nothing was said."""
    aux = FakeAux([COMMIT_PENDING_STATUS])
    aux.start_error = FakeServerError(
        "refusing to install while the running system requires commit", 409
    )
    deploy = make_deploy(aux, cmd_helper)

    with pytest.raises(FakeServerError):
        asyncio.run(deploy.update())

    assert any(
        "requires commit" in msg and is_complete
        for msg, is_complete in cmd_helper.responses
    ), f"the refusal was not reported to the user: {cmd_helper.responses}"


def test_an_accepted_install_still_announces_the_start(cmd_helper, no_poll_delay):
    """Moving the announcement must not lose it on the path that works."""
    aux = FakeAux([{"state": "idle", "current_version": "2.0.0"}])
    deploy = make_deploy(aux, cmd_helper)

    assert asyncio.run(deploy.update()) is True

    assert any("Starting OS image update" in msg
               for msg, _ in cmd_helper.responses)
    assert "ota_start" in aux.calls
