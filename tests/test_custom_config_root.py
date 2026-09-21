# Tests for the `config` root's write grant (KAN-371).
#
# The root registered from `config_custom_config_path` is the developer-mode
# Klipper configuration tree. KAN-291 stopped registering it writable by
# default, for a good reason -- it holds `core.cfg`, which the calibration
# guard never inspects -- and the side effect was that a printer someone had
# deliberately put into developer mode served its configuration files
# read-only, padlocked in Fluidd, with no way to edit the files developer mode
# exists to let you edit.
#
# The grant now follows the mode. These tests drive the real decision methods
# against stubs rather than standing up a server, for the same reason KAN-291's
# own verification did: the interesting behaviour is a handful of branches, and
# every fixture between the test and those branches is a chance for the test to
# pass for a reason that is not the one being asserted.

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

import pytest

from moonraker.components.file_manager.file_manager import (
    CUSTOM_CONFIG_ROOT,
    FileManager,
)

CONFIG_PATH = "/home/printer_data/devmode_custom_config"


class _Observer:
    def __init__(self) -> None:
        self.watched: List[Tuple[str, str]] = []

    def add_root_watch(self, root: str, root_path: str) -> None:
        self.watched.append((root, root_path))


class _Server:
    def __init__(self, aux: Optional[Any] = None, running: bool = True) -> None:
        self._aux = aux
        self._running = running

    def is_running(self) -> bool:
        return self._running

    def lookup_component(self, name: str) -> Any:
        if self._aux is None:
            raise Exception(f"component {name} not loaded")
        return self._aux


class _Aux:
    """Stands in for aux_api_proxy's internal `get` helper."""

    def __init__(self, result: Any = None, error: Optional[Exception] = None):
        self.result = result
        self.error = error
        self.calls: List[str] = []

    async def get(self, path: str) -> Any:
        self.calls.append(path)
        if self.error is not None:
            raise self.error
        return self.result


class _FM:
    """The attribute surface the two methods under test actually touch.

    Deliberately not a FileManager: constructing one needs a database, a
    metadata store, an inotify observer and a data path. The methods are called
    unbound against this, so the code under test is the real code.
    """

    def __init__(
        self,
        *,
        aux: Optional[Any] = None,
        allowed: bool = True,
        registered: bool = True,
        writable_now: bool = False,
        running: bool = True,
    ) -> None:
        self.server = _Server(aux, running)
        self.fs_observer = _Observer()
        self.full_access_roots: Set[str] = (
            {CUSTOM_CONFIG_ROOT} if writable_now else set()
        )
        self.file_paths: Dict[str, str] = {CUSTOM_CONFIG_ROOT: CONFIG_PATH}
        self._custom_config_write_allowed = allowed
        self._custom_config_registered = registered
        self.notifications: List[Tuple[str, str, str]] = []

    def _sched_changed_event(
        self, action: str, root: str, full_path: str, **kwargs: Any
    ) -> Dict[str, Any]:
        self.notifications.append((action, root, full_path))
        return {}

    # The real method, called unbound, so the stub cannot diverge from it.
    def _apply_custom_config_access(self, writable: bool) -> None:
        FileManager._apply_custom_config_access(self, writable)  # type: ignore


def _writable(fm: _FM) -> bool:
    return CUSTOM_CONFIG_ROOT in fm.full_access_roots


class TestTheGrantFollowsDeveloperMode:
    @pytest.mark.asyncio
    async def test_developer_mode_on_makes_the_config_root_writable(self) -> None:
        """The reported defect, stated as a test.

        A printer in developer mode served padlocked configuration files.
        """
        fm = _FM(aux=_Aux({"enabled": True}))
        await FileManager._refresh_custom_config_access(fm)  # type: ignore
        assert _writable(fm)

    @pytest.mark.asyncio
    async def test_developer_mode_off_keeps_it_read_only(self) -> None:
        """KAN-291's hole stays closed. This is the case that one was about:
        a shipped printer must not carry a network-writable `core.cfg`."""
        fm = _FM(aux=_Aux({"enabled": False}), writable_now=True)
        await FileManager._refresh_custom_config_access(fm)  # type: ignore
        assert not _writable(fm)

    @pytest.mark.asyncio
    async def test_leaving_developer_mode_revokes_an_existing_grant(self) -> None:
        """Not the same assertion as the one above, which starts writable by
        construction. This one moves the state in the direction a printer moves
        when the operator turns developer mode off."""
        aux = _Aux({"enabled": True})
        fm = _FM(aux=aux)
        await FileManager._refresh_custom_config_access(fm)  # type: ignore
        assert _writable(fm)
        aux.result = {"enabled": False}
        await FileManager._refresh_custom_config_access(fm)  # type: ignore
        assert not _writable(fm)

    @pytest.mark.asyncio
    async def test_the_image_must_still_opt_in(self) -> None:
        """`enable_custom_config_write_access` is a ceiling, not a default.

        An image that never set it gets a read-only root whatever developer
        mode says -- and does not interrogate Aux about it either.
        """
        aux = _Aux({"enabled": True})
        fm = _FM(aux=aux, allowed=False)
        await FileManager._refresh_custom_config_access(fm)  # type: ignore
        assert not _writable(fm)
        assert aux.calls == []

    @pytest.mark.asyncio
    async def test_an_unregistered_root_is_not_granted_anything(self) -> None:
        """No `config_custom_config_path`, no root, nothing to open."""
        aux = _Aux({"enabled": True})
        fm = _FM(aux=aux, registered=False)
        await FileManager._refresh_custom_config_access(fm)  # type: ignore
        assert not _writable(fm)
        assert aux.calls == []


class TestWhatHappensWhenAuxCannotAnswer:
    """Every one of these is "the last known answer stands".

    A gate that revokes on a failed read loses an operator's edit to a blip in
    a service that has nothing to do with the file being edited. A gate that
    grants on one opens `core.cfg` to the LAN on a printer nobody unlocked.
    Neither error is worth committing to in exchange for a definite answer.
    """

    @pytest.mark.asyncio
    async def test_an_unreachable_aux_does_not_revoke(self) -> None:
        fm = _FM(aux=_Aux(error=RuntimeError("connection refused")))
        fm.full_access_roots.add(CUSTOM_CONFIG_ROOT)
        await FileManager._refresh_custom_config_access(fm)  # type: ignore
        assert _writable(fm)

    @pytest.mark.asyncio
    async def test_an_unreachable_aux_does_not_grant(self) -> None:
        fm = _FM(aux=_Aux(error=RuntimeError("connection refused")))
        await FileManager._refresh_custom_config_access(fm)  # type: ignore
        assert not _writable(fm)

    @pytest.mark.asyncio
    async def test_a_missing_aux_component_is_not_fatal(self) -> None:
        """`lookup_component` raises when the component is not loaded. On a
        stock Moonraker there is no aux_api_proxy at all, and file_manager must
        still start."""
        fm = _FM(aux=None)
        await FileManager._refresh_custom_config_access(fm)  # type: ignore
        assert not _writable(fm)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "payload",
        [
            # The shape the LAN vhost returns when a request falls through to
            # the SPA location: a 200 carrying no state at all.
            "<!doctype html>",
            {},
            {"enabled": "true"},
            {"enabled": None},
            None,
        ],
    )
    async def test_an_unreadable_answer_is_not_an_answer(self, payload: Any) -> None:
        """Anything that is not a boolean is treated as "could not read", not
        as False. Truthiness would read the string "true" and the dict {} as
        opposite answers, and both of them are the same non-answer."""
        fm = _FM(aux=_Aux(payload), writable_now=True)
        await FileManager._refresh_custom_config_access(fm)  # type: ignore
        assert _writable(fm)


class TestWhatTheClientIsTold:
    def test_granting_notifies_and_starts_watching(self) -> None:
        """`permissions` in a file listing is derived from full_access_roots and
        is what draws the padlock. Without the notification the icons stay wrong
        until someone reloads the page."""
        fm = _FM()
        fm._apply_custom_config_access(True)
        assert fm.notifications == [("root_update", CUSTOM_CONFIG_ROOT, CONFIG_PATH)]
        assert fm.fs_observer.watched == [(CUSTOM_CONFIG_ROOT, CONFIG_PATH)]

    def test_revoking_notifies_too(self) -> None:
        fm = _FM(writable_now=True)
        fm._apply_custom_config_access(False)
        assert fm.notifications == [("root_update", CUSTOM_CONFIG_ROOT, CONFIG_PATH)]

    def test_no_change_says_nothing(self) -> None:
        """The refresh runs every 30 seconds. If it notified each time, a
        printer sitting in developer mode would push a filelist_changed at every
        connected browser twice a minute forever."""
        fm = _FM(writable_now=True)
        fm._apply_custom_config_access(True)
        assert fm.notifications == []
        assert fm.fs_observer.watched == []

    def test_a_server_that_is_not_running_is_not_notified(self) -> None:
        """The first refresh happens in component_init, before the server is
        serving. The grant still has to be applied."""
        fm = _FM(running=False)
        fm._apply_custom_config_access(True)
        assert _writable(fm)
        assert fm.notifications == []
