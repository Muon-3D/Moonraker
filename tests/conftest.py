from __future__ import annotations
import pytest
import pytest_asyncio
import asyncio
import shutil
import re
import pathlib
import sys
import shlex
import tempfile
import subprocess
import logging
from typing import Iterator, Dict, AsyncIterator, Any
from moonraker.server import Server
from moonraker.eventloop import EventLoop
from moonraker.loghelper import LogManager
from moonraker import confighelper
from moonraker.utils import json_wrapper
import dbtool
from fixtures import KlippyProcess, HttpClient, WebsocketClient

ASSETS = pathlib.Path(__file__).parent.joinpath("assets")

need_klippy_restart = pytest.StashKey[bool]()

def pytest_addoption(parser: pytest.Parser, pluginmanager):
    parser.addoption("--klipper-path", action="store", dest="klipper_path")
    parser.addoption("--klipper-exec", action="store", dest="klipper_exec")

def interpolate_config(source_path: pathlib.Path,
                       dest_path: pathlib.Path,
                       keys: Dict[str, Any]
                       ) -> None:
    def interp(match):
        return str(keys[match.group(1)])
    sub_data = re.sub(r"\${([^}]+)}", interp, source_path.read_text())
    dest_path.write_text(sub_data)

@pytest.fixture(scope="session", autouse=True)
def ssl_certs() -> Iterator[Dict[str, pathlib.Path]]:
    with tempfile.TemporaryDirectory(prefix="moonraker-certs-") as tmpdir:
        tmp_path = pathlib.Path(tmpdir)
        cert_path = tmp_path.joinpath("certificate.pem")
        key_path = tmp_path.joinpath("privkey.pem")
        cmd = (
            f"openssl req -newkey rsa:4096 -nodes -keyout {key_path} "
            f"-x509 -days 365 -out {cert_path} -sha256 "
            "-subj '/C=US/ST=NRW/L=Earth/O=Moonraker/OU=IT/"
            "CN=www.moonraker-test.com/emailAddress=mail@moonraker-test.com'"
        )
        args = shlex.split(cmd)
        subprocess.run(args, check=True)
        yield {
            "ssl_certificate_path": cert_path,
            "ssl_key_path": key_path,
        }

# KAN-570: the legacy suites (test_config, test_database, test_server and
# test_klippy_connection) share one Server per test class, so every test,
# async fixture and sync fixture in a class has to see the same loop.
#
# They used to get it by overriding pytest-asyncio's `event_loop` fixture with
# a class-scoped one. pytest-asyncio 0.23 deprecated that and 1.0 removed it,
# and Moonraker's EventLoop now binds to asyncio.get_running_loop(), so a
# Server cannot even be built outside a running loop. Instead, pytest-asyncio
# owns one loop per class (`loop_scope="class"` on these fixtures, and
# `@pytest.mark.asyncio(loop_scope="class")` on the suites' async tests), and
# `class_loop` is that loop: an async fixture run on it that hands back the
# running loop. Between tests it is not running, so the sync fixtures and
# tests that drive it with run_until_complete and run_forever still can.
# Not named `event_loop`: before 1.0 that name is pytest-asyncio's own, and a
# class-scoped test reaching it is a collection error. pytest.ini therefore
# requires pytest-asyncio>=1.0.
@pytest_asyncio.fixture(scope="class", loop_scope="class")
async def class_loop() -> asyncio.AbstractEventLoop:
    return asyncio.get_running_loop()


@pytest.fixture(scope="session")
def session_args(ssl_certs: Dict[str, pathlib.Path]
                 ) -> Iterator[Dict[str, pathlib.Path]]:
    mconf_asset = ASSETS.joinpath(f"moonraker/base_server.conf")
    secrets_asset = ASSETS.joinpath(f"moonraker/secrets.ini")
    pcfg_asset = ASSETS.joinpath(f"klipper/base_printer.cfg")
    with tempfile.TemporaryDirectory(prefix="moonraker-test") as tmpdir:
        tmp_path = pathlib.Path(tmpdir)
        secrets_dest = tmp_path.joinpath("secrets.ini")
        shutil.copy(secrets_asset, secrets_dest)
        cfg_path = tmp_path.joinpath("config")
        cfg_path.mkdir()
        log_path = tmp_path.joinpath("logs")
        log_path.mkdir()
        db_path = tmp_path.joinpath("database")
        db_path.mkdir()
        gcode_path = tmp_path.joinpath("gcode_files")
        gcode_path.mkdir()
        dest_paths = {
            "temp_path": tmp_path,
            "asset_path": ASSETS,
            "config_path": cfg_path,
            "database_path": db_path,
            "log_path": log_path,
            "gcode_path": gcode_path,
            "secrets_path": secrets_dest,
            "klippy_uds_path": tmp_path.joinpath("klippy_uds"),
            "klippy_pty_path": tmp_path.joinpath("klippy_pty"),
            "klipper.dict": ASSETS.joinpath("klipper/klipper.dict"),
            "mconf_asset": mconf_asset,
            "pcfg_asset": pcfg_asset,
        }
        dest_paths.update(ssl_certs)
        mconf_dest = cfg_path.joinpath("moonraker.conf")
        dest_paths["moonraker.conf"] = mconf_dest
        interpolate_config(mconf_asset, mconf_dest, dest_paths)
        pcfg_dest = cfg_path.joinpath("printer.cfg")
        dest_paths["printer.cfg"] = pcfg_dest
        interpolate_config(pcfg_asset, pcfg_dest, dest_paths)
        yield dest_paths

@pytest.fixture(scope="session")
def klippy_session(session_args: Dict[str, pathlib.Path],
                   pytestconfig: pytest.Config) -> Iterator[KlippyProcess]:
    pytestconfig.stash[need_klippy_restart] = False
    kpath = pytestconfig.getoption('klipper_path', "~/klipper")
    kexec = pytestconfig.getoption('klipper_exec', None)
    if kexec is None:
        kexec = sys.executable
    exec = pathlib.Path(kexec).expanduser()
    klipper_path = pathlib.Path(kpath).expanduser()
    base_cmd = f"{exec} {klipper_path}/klippy/klippy.py "
    kproc = KlippyProcess(base_cmd, session_args)
    kproc.start()
    yield kproc
    kproc.stop()

@pytest.fixture(scope="class")
def klippy(klippy_session: KlippyProcess,
           pytestconfig: pytest.Config):
    if pytestconfig.stash[need_klippy_restart]:
        pytestconfig.stash[need_klippy_restart] = False
        klippy_session.restart()
    return klippy_session

@pytest.fixture(scope="class")
def path_args(request: pytest.FixtureRequest,
              session_args: Dict[str, pathlib.Path],
              pytestconfig: pytest.Config
              ) -> Iterator[Dict[str, pathlib.Path]]:
    path_marker = request.node.get_closest_marker("run_paths")
    paths: Dict[str, Any] = {
        "moonraker_conf": "base_server.conf",
        "secrets": "secrets.ini",
        "printer_cfg": "base_printer.cfg",
        "klippy_uds": None,
    }
    if path_marker is not None:
        paths.update(path_marker.kwargs)
    tmp_path = session_args["temp_path"]
    cfg_path = session_args["config_path"]
    mconf_dest = session_args["moonraker.conf"]
    mconf_asset = ASSETS.joinpath(f"moonraker/{paths['moonraker_conf']}")
    pcfg_asset = ASSETS.joinpath(f"klipper/{paths['printer_cfg']}")
    last_uds = session_args["klippy_uds_path"]
    if paths["klippy_uds"] is not None:
        tmp_uds = tmp_path.joinpath(paths["klippy_uds"])
        session_args["klippy_uds_path"] = tmp_uds
    if (
        not mconf_asset.samefile(session_args["mconf_asset"]) or
        paths["klippy_uds"] is not None
    ):
        session_args['mconf_asset'] = mconf_asset
        interpolate_config(mconf_asset, mconf_dest, session_args)
    if not pcfg_asset.samefile(session_args["pcfg_asset"]):
        pcfg_dest = session_args["printer.cfg"]
        session_args["pcfg_asset"] = pcfg_asset
        interpolate_config(pcfg_asset, pcfg_dest, session_args)
        pytestconfig.stash[need_klippy_restart] = True
    if paths["secrets"] != session_args["secrets_path"].name:
        secrets_asset = ASSETS.joinpath(f"moonraker/{paths['secrets']}")
        secrets_dest = tmp_path.joinpath(paths['secrets'])
        shutil.copy(secrets_asset, secrets_dest)
        session_args["secrets_path"] = secrets_dest
    if "moonraker_log" in paths:
        log_path = session_args["log_path"]
        session_args['moonraker.log'] = log_path.joinpath(
            paths["moonraker_log"])
    bkp_dest: pathlib.Path = cfg_path.joinpath(".moonraker.conf.bkp")
    if "moonraker_bkp" in paths:
        bkp_source = ASSETS.joinpath("moonraker/base_server.conf")
        bkp_dest = cfg_path.joinpath(paths["moonraker_bkp"])
        interpolate_config(bkp_source, bkp_dest, session_args)
    if "database" in paths:
        db_source = ASSETS.joinpath(f"moonraker/{paths['database']}")
        db_dest = session_args["database_path"]
        db_args = {"input": str(db_source), "destination": db_dest}
        dbtool.restore(db_args)
    yield session_args
    log = session_args.pop("moonraker.log", None)
    if log is not None and log.is_file():
        log.unlink()
    if bkp_dest.is_file():
        bkp_dest.unlink()
    for item in session_args["database_path"].iterdir():
        if item.is_file():
            item.unlink()
    session_args["klippy_uds_path"] = last_uds
    if paths["klippy_uds"] is not None:
        # restore the original uds path
        interpolate_config(mconf_asset, mconf_dest, session_args)

async def _new_event_loop() -> EventLoop:
    return EventLoop()


def app_args(path_args: Dict[str, Any]) -> Dict[str, Any]:
    """The arguments server.main() builds, for this test session.

    KAN-570: Server reads far more of these than it did when the legacy
    suites were written (data_path, is_backup_config, structured_logging,
    ...), so they are built the way main() builds them, with the session's
    temporary directory as the data path. test_server compares
    get_app_args() against this.
    """
    data_path: pathlib.Path = path_args["temp_path"]
    cfg_file = str(path_args["moonraker.conf"])
    return {
        "data_path": str(data_path),
        "is_default_data_path": False,
        "config_file": cfg_file,
        "backup_config": confighelper.find_config_backup(cfg_file),
        "startup_warnings": [],
        "verbose": False,
        "debug": False,
        "asyncio_debug": False,
        "is_backup_config": False,
        "is_python_package": False,
        "instance_uuid": "0123456789abcdef0123456789abcdef",
        "unix_socket_path": str(data_path.joinpath("comms/moonraker.sock")),
        "structured_logging": False,
        "software_version": "moonraker-pytest",
        "log_file": str(path_args.get("moonraker.log", "")),
        "python_version": sys.version.replace("\n", " "),
        "launch_args": "moonraker-pytest",
        "msgspec_enabled": json_wrapper.MSGSPEC_ENABLED,
        "uvloop_enabled": EventLoop.UVLOOP_ENABLED,
    }


@pytest.fixture(scope="class")
def base_server(path_args: Dict[str, pathlib.Path],
                class_loop: asyncio.AbstractEventLoop
                ) -> Iterator[Server]:
    # EventLoop() binds to the running loop, so build it on the class loop.
    evtloop = class_loop.run_until_complete(_new_event_loop())
    args = app_args(path_args)
    # LogManager replaces every root handler with its own queue handler.
    # Put pytest's capture handlers back beside it, and take its handler
    # away again afterwards, so one class's server cannot swallow the log
    # records of every test after it.
    root = logging.getLogger()
    saved = list(root.handlers)
    log_manager = LogManager(args, args["startup_warnings"])
    added = [h for h in root.handlers if h not in saved]
    for hdlr in saved:
        root.addHandler(hdlr)
    try:
        yield Server(args, log_manager, evtloop)
    finally:
        log_manager.stop_logging()
        for hdlr in added:
            root.removeHandler(hdlr)
        if log_manager.file_hdlr is not None:
            log_manager.file_hdlr.close()

@pytest_asyncio.fixture(scope="class", loop_scope="class")
async def full_server(base_server: Server) -> AsyncIterator[Server]:
    base_server.load_components()
    ret = base_server.server_init(start_server=False)
    await asyncio.wait_for(ret, 4.)
    yield base_server
    if base_server.event_loop.aioloop.is_running():
        await base_server._stop_server(exit_reason="terminate")

@pytest_asyncio.fixture(scope="class", loop_scope="class")
async def ready_server(full_server: Server, klippy: KlippyProcess):
    ret = full_server.start_server(connect_to_klippy=False)
    await asyncio.wait_for(ret, 4.)
    ret = full_server.klippy_connection.connect()
    await asyncio.wait_for(ret, 4.)
    yield full_server

@pytest_asyncio.fixture(scope="class", loop_scope="class")
async def http_client() -> AsyncIterator[HttpClient]:
    client = HttpClient()
    yield client
    client.close()

@pytest_asyncio.fixture(scope="class", loop_scope="class")
async def websocket_client(request: pytest.FixtureRequest
                           ) -> AsyncIterator[WebsocketClient]:
    conn_marker = request.node.get_closest_marker("no_ws_connect")
    client = WebsocketClient()
    if conn_marker is None:
        await client.connect()
    yield client
    client.close()
