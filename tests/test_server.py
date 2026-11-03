from __future__ import annotations
import pytest
import pytest_asyncio
import asyncio
import logging
import socket
import pathlib
import sys

from moonraker.server import CORE_COMPONENTS, Server, API_VERSION
from moonraker.common import APIDefinition, KlippyState
from moonraker.server import main as servermain
from moonraker.eventloop import EventLoop
from moonraker.utils import ServerError
from moonraker.confighelper import ConfigError
from moonraker import server as server_module
from moonraker.loghelper import LogManager
from moonraker.components.klippy_apis import KlippyAPI
from mocks import MockComponent, MockWebsocket
from conftest import app_args

from typing import (
    TYPE_CHECKING,
    Any,
    AsyncIterator,
    Dict,
    List,
    Optional
)

if TYPE_CHECKING:
    from fixtures import HttpClient, WebsocketClient

# Deprecation notices for the options the old fixture configs set.  They no
# longer do, but a test that builds its own config could.
DEPRECATED_OPTIONS = (
    "database_path", "config_path", "log_path", "secrets_path"
)


def unexpected_warnings(server: Server) -> List[str]:
    return [
        w for w in server.warnings.values()
        if not any(f"Option '{opt}' is deprecated" in w
                   for opt in DEPRECATED_OPTIONS)
    ]


class StubLogManager:
    """The part of LogManager the Server constructor needs."""
    def set_server(self, server: Server) -> None:
        pass

    def set_rollover_info(self, name: str, item: str) -> None:
        pass


def server_args(path_args: Dict[str, Any], **extra: Any) -> Dict[str, Any]:
    args = app_args(path_args)
    args.update(extra)
    return args

# EventLoop binds to the running loop, so these build the Server in a coroutine
@pytest.mark.run_paths(moonraker_conf="invalid_config.conf")
@pytest.mark.asyncio(loop_scope="class")
async def test_invalid_config(path_args: Dict[str, pathlib.Path]):
    evtloop = EventLoop()
    args = server_args(path_args)
    with pytest.raises(ConfigError):
        Server(args, StubLogManager(), evtloop)  # type: ignore

@pytest.mark.asyncio(loop_scope="class")
async def test_config_and_log_warnings(path_args: Dict[str, pathlib.Path]):
    # Server.warnings is a dict of id -> message now.  The warnings that
    # main() collects before logging starts arrive as "startup_warnings".
    evtloop = EventLoop()
    args = server_args(
        path_args,
        startup_warnings=["Log Warning Test", "Config Warning Test"]
    )
    server = Server(args, StubLogManager(), evtloop)  # type: ignore
    expected = ["Log Warning Test", "Config Warning Test"]
    assert list(server.warnings.values()) == expected

@pytest.mark.run_paths(moonraker_conf="unparsed_server.conf")
@pytest.mark.asyncio(loop_scope="class")
async def test_unparsed_config_items(full_server: Server):
    expected_warnings = [
        "Unparsed config section [machine unparsed] detected.",
        "Unparsed config option 'unknown_option: True' detected "
        "in section [server]."]
    warn_cnt = 0
    for warn in full_server.warnings.values():
        for expected in expected_warnings:
            if warn.startswith(expected):
                warn_cnt += 1
    assert warn_cnt == 2

@pytest.mark.run_paths(moonraker_log="moonraker.log")
@pytest.mark.asyncio(loop_scope="class")
async def test_file_logger(base_server: Server,
                           path_args: Dict[str, pathlib.Path]):
    log_path = path_args.get("moonraker.log", None)
    assert log_path is not None and log_path.exists()

@pytest.mark.asyncio(loop_scope="class")
async def test_signal_handler(base_server: Server):
    # The SIGTERM handler schedules _stop_server(), which no longer stops the
    # event loop.  It sets app_running_evt, which run_until_exit() waits on.
    base_server._handle_term_signal()
    await asyncio.wait_for(base_server.run_until_exit(), 5.)
    assert base_server.exit_reason == "terminate"

class TestInstantiation:
    def test_running(self, base_server: Server):
        assert base_server.is_running() is False

    def test_app_args(self,
                      path_args: Dict[str, pathlib.Path],
                      base_server: Server):
        assert base_server.get_app_args() == app_args(path_args)

    def test_api_version(self, base_server: Server):
        ver = base_server.get_api_version()
        assert ver == API_VERSION

    def test_pending_tasks(self, base_server: Server):
        loop = base_server.get_event_loop().aioloop
        assert len(asyncio.all_tasks(loop)) == 0

    def test_klippy_info(self, base_server: Server):
        assert base_server.get_klippy_info() == {}

    def test_klippy_state(self, base_server: Server):
        # Server.get_klippy_state() is gone, the state lives on the connection
        kconn = base_server.klippy_connection
        assert kconn.state == KlippyState.DISCONNECTED
        assert str(kconn.state) == "disconnected"

    def test_host_info(self, base_server: Server):
        hinfo = {
            'hostname': socket.gethostname(),
            'address': "0.0.0.0",
            'port': 7010,
            'ssl_port': 7011
        }
        assert base_server.get_host_info() == hinfo

    def test_klippy_connection(self, base_server: Server):
        assert base_server.klippy_connection.is_connected() is False

    def test_components(self, base_server: Server):
        key_list = sorted(list(base_server.components.keys()))
        assert key_list == [
            "application",
            "internal_transport",
            "jsonrpc",
            "klippy_connection",
            "secrets",
            "template",
            "websockets",
        ]

    def test_endpoint_registered(self, base_server: Server):
        # MoonrakerApp.api_cache became the APIDefinition cache
        app = base_server.moonraker_app
        assert "/server/info" in app.registered_base_handlers
        assert "/server/info" in APIDefinition.get_cache()

    @pytest.mark.asyncio(loop_scope="class")
    async def test_notification(self, base_server: Server):
        base_server.register_notification("test:test_event")
        fut = base_server.event_loop.create_future()
        wsm = base_server.lookup_component("websockets")
        wsm.clients[1] = MockWebsocket(fut)  # type: ignore
        base_server.send_event("test:test_event", "test")
        ret = await fut
        expected = {
            'jsonrpc': "2.0",
            'method': "notify_test_event",
            'params': ("test",)
        }
        assert expected == ret

class TestLoadComponent:
    def test_load_component_fail(self, base_server: Server):
        # With no default, load_component() re-raises what the import raised
        with pytest.raises(ModuleNotFoundError):
            base_server.load_component(
                base_server.config, "invalid_component")

    def test_failed_component_set(self, base_server: Server):
        assert "invalid_component" in base_server.failed_components

    def test_load_component_fail_again(self, base_server: Server):
        # A component that has failed once is not retried
        with pytest.raises(ServerError):
            base_server.load_component(
                base_server.config, "invalid_component")

    def test_load_component_fail_with_default(self, base_server: Server):
        comp = base_server.load_component(
            base_server.config, "invalid_default_component", None)
        assert comp is None
        assert "invalid_default_component" in base_server.failed_components

    def test_lookup_failed(self, base_server: Server):
        with pytest.raises(ServerError):
            base_server.lookup_component("invalid_component")

    def test_lookup_failed_with_default(self, base_server: Server):
        comp = base_server.lookup_component("invalid_component", None)
        assert comp is None

    def test_load_component(self, base_server: Server):
        comp = base_server.load_component(base_server.config, "klippy_apis")
        assert isinstance(comp, KlippyAPI)

    def test_lookup_component(self, base_server: Server):
        comp = base_server.lookup_component('klippy_apis')
        assert isinstance(comp, KlippyAPI)

    def test_component_attr(self, base_server: Server):
        key_list = sorted(list(base_server.components.keys()))
        assert key_list == [
            "application",
            "internal_transport",
            "jsonrpc",
            "klippy_apis",
            "klippy_connection",
            "secrets",
            "template",
            "websockets",
        ]

class TestCoreServer:
    @pytest_asyncio.fixture(scope="class", loop_scope="class")
    async def core_server(self, base_server: Server) -> AsyncIterator[Server]:
        base_server.load_components()
        yield base_server
        await base_server._stop_server("terminate")

    def test_running(self, core_server: Server):
        assert core_server.is_running() is False

    def test_http_servers(self, core_server: Server):
        app = core_server.lookup_component("application")
        assert (
            app.http_server is None and
            app.secure_server is None
        )

    def test_warnings(self, core_server: Server):
        assert unexpected_warnings(core_server) == []

    def test_failed_components(self, core_server: Server):
        assert len(core_server.failed_components) == 0

    def test_lookup_components(self, core_server: Server):
        comps = []
        for comp_name in CORE_COMPONENTS:
            comps.append(core_server.lookup_component(comp_name, None))
        assert None not in comps

    def test_pending_tasks(self, core_server: Server):
        loop = core_server.get_event_loop().aioloop
        assert len(asyncio.all_tasks(loop)) == 0

    def test_register_component_fail(self, core_server: Server):
        with pytest.raises(ServerError):
            core_server.register_component("machine", object())

    def test_register_remote_method(self, core_server: Server):
        core_server.register_remote_method("moonraker_test", lambda: None)
        kconn = core_server.klippy_connection
        assert "moonraker_test" in kconn.remote_methods

    def test_register_method_exists(self, core_server: Server):
        with pytest.raises(ServerError):
            core_server.register_remote_method(
                "shutdown_machine", lambda: None)

class TestServerInit:
    def test_running(self, full_server: Server):
        assert full_server.is_running() is False

    def test_http_servers(self, full_server: Server):
        app = full_server.lookup_component("application")
        assert (
            app.http_server is None and
            app.secure_server is None
        )

    def test_warnings(self, full_server: Server):
        assert unexpected_warnings(full_server) == []

    def test_failed_components(self, full_server: Server):
        assert len(full_server.failed_components) == 0

    def test_lookup_components(self, full_server: Server):
        comps = []
        for comp_name in CORE_COMPONENTS:
            comps.append(full_server.lookup_component(comp_name, None))
        assert None not in comps

    def test_config_backup(self,
                           full_server: Server,
                           path_args: Dict[str, pathlib.Path]):
        cfg = path_args["config_path"].joinpath(".moonraker.conf.bkp")
        assert cfg.is_file()

class TestServerStart:
    @pytest_asyncio.fixture(scope="class", loop_scope="class")
    async def server(self, full_server: Server) -> Server:
        await full_server.start_server(connect_to_klippy=False)
        return full_server

    def test_running(self, server: Server):
        assert server.is_running() is True

    def test_http_servers(self, server: Server):
        app = server.lookup_component("application")
        assert (
            app.http_server is not None and
            app.secure_server is None
        )

@pytest.mark.run_paths(moonraker_conf="base_server_ssl.conf")
class TestSecureServerStart:
    @pytest_asyncio.fixture(scope="class", loop_scope="class")
    async def server(self, full_server: Server) -> Server:
        await full_server.start_server(connect_to_klippy=False)
        return full_server

    def test_running(self, server: Server):
        assert server.is_running() is True

    def test_http_servers(self, server: Server):
        app = server.lookup_component("application")
        assert (
            app.http_server is not None and
            app.secure_server is not None
        )

@pytest.mark.asyncio(loop_scope="class")
async def test_component_init_error(base_server: Server):
    # server_init() looks up the core components, so load them first
    base_server.load_components()
    base_server.register_component("testcomp", MockComponent(err_init=True))
    await base_server.server_init(False)
    assert "testcomp" in base_server.failed_components

@pytest.mark.asyncio(loop_scope="class")
async def test_component_exit_error(base_server: Server,
                                    caplog: pytest.LogCaptureFixture):
    base_server.register_component("testcomp", MockComponent(err_exit=True))
    await base_server._stop_server("terminate")
    expected = "Error executing 'on_exit()' for component: testcomp"
    assert expected in caplog.messages

@pytest.mark.asyncio(loop_scope="class")
async def test_component_close_error(base_server: Server,
                                     caplog: pytest.LogCaptureFixture):
    base_server.register_component("testcomp", MockComponent(err_close=True))
    await base_server._stop_server("terminate")
    expected = "Error executing 'close()' for component: testcomp"
    assert expected in caplog.messages

def test_register_event(base_server: Server):
    def test_func():
        pass
    base_server.register_event_handler("test:my_test", test_func)
    assert base_server.events["test:my_test"] == [test_func]

def test_register_async_event(base_server: Server):
    async def test_func():
        pass
    base_server.register_event_handler("test:my_test", test_func)
    assert base_server.events["test:my_test"] == [test_func]

@pytest.mark.asyncio(loop_scope="class")
async def test_send_event(full_server: Server):
    evtloop = full_server.get_event_loop()
    fut = evtloop.create_future()

    def test_func(arg):
        fut.set_result(arg)
    full_server.register_event_handler("test:my_test", test_func)
    full_server.send_event("test:my_test", "test")
    result = await fut
    assert result == "test"

@pytest.mark.asyncio(loop_scope="class")
async def test_send_async_event(full_server: Server):
    evtloop = full_server.get_event_loop()
    fut = evtloop.create_future()

    async def test_func(arg):
        fut.set_result(arg)
    full_server.register_event_handler("test:my_test", test_func)
    full_server.send_event("test:my_test", "test")
    result = await fut
    assert result == "test"

@pytest.mark.asyncio(loop_scope="class")
async def test_register_remote_method_running(full_server: Server):
    await full_server.start_server(connect_to_klippy=False)
    with pytest.raises(ServerError):
        full_server.register_remote_method(
            "moonraker_test", lambda: None)

class KeepHandlersLogManager(LogManager):
    """LogManager removes every root handler, pytest's caplog included.

    main() builds one, so put the handlers that were there back.
    """
    def __init__(self, app_args: Dict[str, Any], startup_warnings: List[str]):
        saved = list(logging.getLogger().handlers)
        super().__init__(app_args, startup_warnings)
        for hdlr in saved:
            logging.getLogger().addHandler(hdlr)


def run_main(path_args: Dict[str, pathlib.Path],
             monkeypatch: pytest.MonkeyPatch) -> Optional[Any]:
    # main() takes no arguments: it parses sys.argv and starts its own loops
    cmd = [
        "moonraker", "-d", str(path_args["temp_path"]),
        "-c", str(path_args["moonraker.conf"]), "-n"
    ]
    monkeypatch.setattr(sys, "argv", cmd)
    monkeypatch.setattr(server_module, "LogManager", KeepHandlersLogManager)
    code: Optional[Any] = None
    try:
        servermain()
    except SystemExit as e:
        code = e.code
    return code


def test_main(path_args: Dict[str, pathlib.Path],
              monkeypatch: pytest.MonkeyPatch,
              caplog: pytest.LogCaptureFixture):
    tries = [1]

    async def mock_init(self: Server, start_server: bool = True):
        reason = "terminate"
        if tries:
            reason = "restart"
            tries.pop(0)
        self.event_loop.delay_callback(.01, self._stop_server, reason)
    monkeypatch.setattr(Server, "server_init", mock_init)
    code = run_main(path_args, monkeypatch)
    assert (
        code == 0 and
        "Attempting Server Restart..." in caplog.messages and
        "Server Shutdown" == caplog.messages[-1]
    )

@pytest.mark.run_paths(moonraker_conf="invalid_config.conf")
def test_main_config_error(path_args: Dict[str, pathlib.Path],
                           monkeypatch: pytest.MonkeyPatch,
                           caplog: pytest.LogCaptureFixture):
    code = run_main(path_args, monkeypatch)
    assert code == 1 and "Server Config Error" in caplog.messages

@pytest.mark.run_paths(moonraker_conf="invalid_config.conf",
                       moonraker_bkp=".moonraker.conf.bkp")
def test_main_restore_config(path_args: Dict[str, pathlib.Path],
                             monkeypatch: pytest.MonkeyPatch,
                             caplog: pytest.LogCaptureFixture):
    async def mock_init(self: Server, start_server: bool = True):
        self.event_loop.delay_callback(.01, self._stop_server, "terminate")
    monkeypatch.setattr(Server, "server_init", mock_init)
    code = run_main(path_args, monkeypatch)
    # The config error sends main() round again on the backup configuration,
    # and the server starts with a warning that says so.
    assert (
        code == 0 and
        "Server Config Error" in caplog.messages and
        "Attempting Server Restart..." in caplog.messages and
        "Loading most recent working configuration" in caplog.text
    )

class TestEndpoints:
    @pytest_asyncio.fixture(scope="class", loop_scope="class")
    async def server(self, full_server: Server):
        await full_server.start_server()
        yield full_server

    @pytest.mark.asyncio(loop_scope="class")
    async def test_http_server_info(self,
                                    server: Server,
                                    http_client: HttpClient):
        ret = await http_client.get("/server/info")
        comps = list(server.components.keys())
        expected = {
            'klippy_connected': False,
            'klippy_state': "disconnected",
            'components': comps,
            'failed_components': [],
            'registered_directories': ["config", "logs"],
            'warnings': [],
            'websocket_count': 0,
            'moonraker_version': "moonraker-pytest",
            'missing_klippy_requirements': [],
            'api_version': list(API_VERSION),
            'api_version_string': ".".join(str(v) for v in API_VERSION)
        }
        assert ret["result"] == expected

    @pytest.mark.asyncio(loop_scope="class")
    async def test_http_server_config(self,
                                      server: Server,
                                      http_client: HttpClient):
        cfg = server.config.get_parsed_config()
        ret = await http_client.get("/server/config")
        assert ret["result"]["config"] == cfg

    @pytest.mark.asyncio(loop_scope="class")
    async def test_websocket_server_info(self,
                                         server: Server,
                                         websocket_client: WebsocketClient):
        ret = await websocket_client.request("server.info")
        comps = list(server.components.keys())
        expected = {
            'klippy_connected': False,
            'klippy_state': "disconnected",
            'components': comps,
            'failed_components': [],
            'registered_directories': ["config", "logs"],
            'warnings': [],
            'websocket_count': 1,
            'moonraker_version': "moonraker-pytest",
            'missing_klippy_requirements': [],
            'api_version': list(API_VERSION),
            'api_version_string': ".".join(str(v) for v in API_VERSION)
        }
        assert ret == expected

    @pytest.mark.asyncio(loop_scope="class")
    async def test_websocket_server_config(self,
                                           server: Server,
                                           websocket_client: WebsocketClient):
        cfg = server.config.get_parsed_config()
        ret = await websocket_client.request("server.config")
        assert ret["config"] == cfg

def test_server_restart(base_server: Server,
                        http_client: HttpClient,
                        class_loop: asyncio.AbstractEventLoop):
    result = {}

    async def do_restart():
        base_server.load_components()
        await base_server.start_server()
        ret = await http_client.post("/server/restart")
        result.update(ret)
    class_loop.create_task(do_restart())
    class_loop.run_forever()
    assert result["result"] == "ok" and base_server.exit_reason == "restart"

@pytest.mark.no_ws_connect
def test_websocket_restart(base_server: Server,
                           websocket_client: WebsocketClient,
                           class_loop: asyncio.AbstractEventLoop):
    result = {}

    async def do_restart():
        base_server.load_components()
        await base_server.start_server()
        await websocket_client.connect()
        ret = await websocket_client.request("server.restart")
        result["result"] = ret
    class_loop.create_task(do_restart())
    class_loop.run_forever()
    assert result["result"] == "ok" and base_server.exit_reason == "restart"


# TODO:
# test invalid cert, key (probably should do that in test_app.py)
