"""Requests waiting on a Klippy that does not answer must not flood the log.

On sloe (2026-11-11) Klippy froze for 13 hours while still connected. A
client polled `printer.info` every 12 s; none of those requests has a
timeout, so about 4000 piled up and each one logged "Request 'info'
pending" every 60 s: 242,000 lines an hour, a 223 MB moonraker.log
(KAN-2243).

Plain pytest, no event-loop plugin: each test drives its own loop.
"""
from __future__ import annotations
import asyncio
import logging

import pytest

from moonraker.components import klippy_connection as kc
from moonraker.components.klippy_connection import KlippyRequest
from moonraker.utils import ServerError


@pytest.fixture(autouse=True)
def fast_intervals(monkeypatch):
    # 20 ms between self-checks; at most one log line per method per 200 ms.
    monkeypatch.setattr(kc, "PENDING_CHECK_INTERVAL", .02)
    monkeypatch.setattr(kc, "PENDING_LOG_INTERVAL", .2)
    KlippyRequest._pending_counts.clear()
    KlippyRequest._pending_last_log.clear()
    yield
    KlippyRequest._pending_counts.clear()
    KlippyRequest._pending_last_log.clear()


def pending_lines(caplog, method):
    return [
        r.getMessage() for r in caplog.records
        if r.getMessage().startswith(f"Request '{method}' pending")
    ]


def test_many_pending_requests_log_once_per_interval(caplog):
    caplog.set_level(logging.INFO)

    async def run():
        reqs = [KlippyRequest("info", {}) for _ in range(50)]
        tasks = [asyncio.ensure_future(r.wait()) for r in reqs]
        # 0.5 s = 25 self-checks per request. Unlimited, that is 1250 lines.
        await asyncio.sleep(.5)
        assert KlippyRequest._pending_counts["info"] == 50
        for r in reqs:
            r.set_result("ok")
        assert await asyncio.gather(*tasks) == ["ok"] * 50

    asyncio.run(run())
    lines = pending_lines(caplog, "info")
    # One line per 200 ms window over 0.5 s: 2 or 3, with slack for a slow box.
    assert 1 <= len(lines) <= 5, lines
    assert "(50 'info' requests waiting)" in lines[0]
    # Nothing is left behind once every request is answered.
    assert KlippyRequest._pending_counts == {}
    assert KlippyRequest._pending_last_log == {}


def test_methods_are_limited_separately(caplog):
    caplog.set_level(logging.INFO)

    async def run():
        a = KlippyRequest("info", {})
        b = KlippyRequest("gcode/script", {})
        tasks = [asyncio.ensure_future(r.wait()) for r in (a, b)]
        await asyncio.sleep(.1)
        a.set_result(1)
        b.set_result(2)
        await asyncio.gather(*tasks)

    asyncio.run(run())
    # A flood of 'info' must not hide a stuck gcode/script, or the reverse.
    # 2 allows for a loaded box stalling the loop past one log window.
    assert 1 <= len(pending_lines(caplog, "info")) <= 2
    assert 1 <= len(pending_lines(caplog, "gcode/script")) <= 2
    # A single waiting request keeps the old wording.
    assert "requests waiting" not in pending_lines(caplog, "gcode/script")[0]


def test_a_lone_request_still_logs_every_interval(caplog):
    caplog.set_level(logging.INFO)

    async def run():
        r = KlippyRequest("gcode/script", {})
        task = asyncio.ensure_future(r.wait())
        await asyncio.sleep(.7)
        r.set_result("done")
        await task

    asyncio.run(run())
    # 0.7 s at one line per 0.2 s: the stuck request keeps reporting.
    assert len(pending_lines(caplog, "gcode/script")) >= 3


def test_explicit_timeout_still_raises_and_is_not_counted(caplog):
    caplog.set_level(logging.INFO)

    async def run():
        r = KlippyRequest("info", {})
        with pytest.raises(ServerError):
            await r.wait(timeout=.05)

    asyncio.run(run())
    assert pending_lines(caplog, "info") == []
    assert KlippyRequest._pending_counts == {}


def test_a_cancelled_wait_gives_its_count_back():
    async def run():
        r = KlippyRequest("info", {})
        task = asyncio.ensure_future(r.wait())
        await asyncio.sleep(.05)
        assert KlippyRequest._pending_counts == {"info": 1}
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert KlippyRequest._pending_counts == {}
