"""Exercise the asynchronous update-manager commit endpoint contract."""

from __future__ import annotations

import asyncio
from typing import Any

from moonraker.components.update_manager.update_manager import UpdateManager


class FakeRequest:
    def get_str(self, name: str) -> str:
        assert name == "name"
        return "os"


class FakeConnection:
    def is_printing(self) -> bool:
        return False


class FakeUpdater:
    async def commit(self) -> None:
        pass


class FakeEventLoop:
    def __init__(self) -> None:
        self.task_count = 0

    def create_task(self, coroutine: Any) -> None:
        self.task_count += 1
        coroutine.close()


class FakeUpdateManager:
    def __init__(self) -> None:
        self.kconn = FakeConnection()
        self.updaters = {"os": FakeUpdater()}
        self.event_loop = FakeEventLoop()


def test_commit_endpoint_is_awaitable_after_scheduling_work():
    """Application endpoints await callbacks, including the commit endpoint."""
    manager = FakeUpdateManager()

    result = asyncio.run(UpdateManager._handle_commit(manager, FakeRequest()))

    assert result == "ok"
    assert manager.event_loop.task_count == 1
