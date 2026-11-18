"""KAN-4346: a file the postprocessor refuses tells the user why (422);
a crash or timeout of the tool stays a generic 500."""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from moonraker.components import gcode_preprocessor as gp
from moonraker.components.gcode_preprocessor import GCodePreprocessorComponent
from moonraker.utils.exceptions import ServerError

PATH = "/tmp/up/part.gcode"
REFUSED = (
    f"avoid_excluded_zone: REFUSED {PATH}: line 42: move ends inside the bed "
    "notch below the hop Z [G1 X10 Y5 Z0.2]\n"
)


class _Server:
    def error(self, message: str, status: int = 400) -> ServerError:
        return ServerError(message, status)

    def get_app_args(self) -> Any:
        return {"data_path": "."}


class _Config:
    def get_server(self) -> _Server:
        return _Server()

    def get(self, name: str, default: Any = None) -> Any:
        return "/usr/bin/avoid_excluded_zone" if name == "binary" else default

    def getfloat(self, name: str, default: float) -> float:
        return default


class _Proc:
    def __init__(self, code: int, out: bytes, err: bytes) -> None:
        self.returncode = code
        self.pid = 0
        self._out, self._err = out, err

    async def communicate(self) -> Any:
        return self._out, self._err


def run(monkeypatch: Any, code: int, out: bytes = b"", err: bytes = b"") -> None:
    async def fake_exec(*args: Any, **kw: Any) -> _Proc:
        return _Proc(code, out, err)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    pre = GCodePreprocessorComponent(_Config())  # type: ignore[arg-type]
    asyncio.run(pre._invoke_preprocessor(PATH))


def test_refusal_is_422_with_the_tools_reason(monkeypatch: Any) -> None:
    with pytest.raises(ServerError) as exc:
        run(monkeypatch, 1, err=REFUSED.encode())
    assert exc.value.status_code == 422
    assert str(exc.value) == (
        "This print can't be used on this printer: line 42: move ends inside "
        "the bed notch below the hop Z [G1 X10 Y5 Z0.2]"
    )


def test_refusal_reason_is_trimmed_and_cleaned(monkeypatch: Any) -> None:
    noisy = b"warming up\n" + REFUSED.encode().replace(b"line 42", b"line\x1b[31m 42")
    noisy = noisy.replace(b"hop Z", b"hop Z" + b"x" * 400)
    with pytest.raises(ServerError) as exc:
        run(monkeypatch, 1, err=noisy)
    msg = str(exc.value)
    assert exc.value.status_code == 422
    assert "\x1b" not in msg and "warming" not in msg and PATH not in msg
    assert len(msg) <= len(gp.REFUSED_PREFIX) + gp.MAX_REASON_LEN
    assert msg.endswith("...")


def test_refusal_with_empty_stderr_still_422(monkeypatch: Any) -> None:
    with pytest.raises(ServerError) as exc:
        run(monkeypatch, 1)
    assert exc.value.status_code == 422


@pytest.mark.parametrize("code", [2, 101, -9])
def test_crash_is_500_and_generic(monkeypatch: Any, code: int) -> None:
    with pytest.raises(ServerError) as exc:
        run(monkeypatch, code, err=b"thread 'main' panicked at /home/secret\n")
    assert exc.value.status_code == 500
    assert str(exc.value) == f"G-code safety postprocessor exited {code}"


def test_timeout_is_500(monkeypatch: Any) -> None:
    class _Hung(_Proc):
        async def communicate(self) -> Any:
            await asyncio.sleep(30)

        async def wait(self) -> int:
            return 0

        def kill(self) -> None:
            pass

    async def fake_exec(*a: Any, **k: Any) -> _Hung:
        return _Hung(0, b"", b"")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    pre = GCodePreprocessorComponent(_Config())  # type: ignore[arg-type]
    pre.timeout = 0.05
    with pytest.raises(ServerError) as exc:
        asyncio.run(pre._invoke_preprocessor(PATH))
    assert exc.value.status_code == 500


def test_success_is_unchanged(monkeypatch: Any) -> None:
    run(monkeypatch, 0, out=b"Processed x: 3 collisions avoided.\n")
