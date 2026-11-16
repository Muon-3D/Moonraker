from __future__ import annotations

import asyncio
import configparser
import contextlib
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict
from unittest.mock import AsyncMock

import pytest

from moonraker.common import RequestType, WebRequest
from moonraker.components import muon_usb
from moonraker.components.file_manager.file_manager import FileManager
from moonraker import muon_access_files as access_files
from moonraker import muon_access_policy as policy
from moonraker.utils.exceptions import ServerError


class EventLoop:
    async def run_in_thread(self, callback: Any, *args: Any) -> Any:
        return await asyncio.get_running_loop().run_in_executor(None, callback, *args)


class Files:
    def __init__(self, gcodes: Path) -> None:
        self.paths = {'gcodes': str(gcodes)}
        self.full_access_roots = {'gcodes'}

    def get_directory(self, name: str) -> str:
        return self.paths.get(name, '')

    def register_directory(self, name: str, path: str,
                           full_access: bool = False) -> None:
        assert name == 'usb' and not full_access
        self.paths[name] = path


class Server:
    error = ServerError

    def __init__(self, data: Path) -> None:
        self.data = data
        self.endpoints: Dict[str, Any] = {}
        gcodes = data / 'gcodes'
        gcodes.mkdir()
        self.components: Dict[str, Any] = {
            'file_manager': Files(gcodes),
            'klippy_connection': SimpleNamespace(is_ready=lambda: True),
            'job_state': SimpleNamespace(get_last_stats=lambda: {'state': 'standby'}),
            'klippy_apis': SimpleNamespace(start_print=AsyncMock()),
        }

    def get_app_args(self) -> Dict[str, Any]:
        return {'data_path': str(self.data)}

    def get_event_loop(self) -> EventLoop:
        return EventLoop()

    def register_endpoint(self, path: str, method: Any, handler: Any) -> None:
        self.endpoints[path] = (method, handler)

    def lookup_component(self, name: str, default: Any = None) -> Any:
        return self.components.get(name, default)


class Config:
    def __init__(self, server: Server) -> None:
        self.server = server

    def get_server(self) -> Server:
        return self.server

    def get(self, key: str, default: Any = None) -> Any:
        return str(self.server.data / 'rejected') if key == 'rejected_path' else default


@pytest.fixture
def usb(tmp_path: Path) -> Any:
    server = Server(tmp_path)
    component = muon_usb.load_component(Config(server))  # type: ignore[arg-type]
    server.components['muon_usb'] = component
    return component


def request(path: str = '') -> WebRequest:
    return WebRequest('/server/muon/usb/list', {'path': path})


def gcode(usb: Any, path: str = 'Demo/part.gcode', data: str = 'G1 X1\n') -> Path:
    target = usb.root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(data)
    return target


def test_missing_root_and_lazy_registration(usb: Any) -> None:
    assert asyncio.run(usb._handle_status(request())) == {'sticks': [], 'rejected': []}
    for callback in (usb._handle_list,):
        with pytest.raises(ServerError) as err:
            asyncio.run(callback(request('usb/Demo')))
        assert err.value.status_code == 404
    fm = SimpleNamespace(server=usb.server, event_loop=EventLoop())
    with pytest.raises(ServerError) as err:
        asyncio.run(FileManager._handle_filelist_request(
            fm, WebRequest('/server/files/list', {'root': 'usb'})))
    assert err.value.status_code == 404
    assert usb.server.components['file_manager'].get_directory('usb') == ''
    gcode(usb)
    assert asyncio.run(usb._handle_status(request())) == {
        'sticks': [{'name': 'Demo', 'path': 'usb/Demo'}], 'rejected': []}
    files = usb.server.components['file_manager']
    assert files.get_directory('usb') == str(usb.root)
    assert 'usb' not in files.full_access_roots


def test_rejected_contract_and_corrupt_records(usb: Any) -> None:
    usb.rejected.mkdir()
    (usb.rejected / 'sdb1.json').write_text(json.dumps({
        'name': 'sdb1', 'fstype': 'ntfs', 'label': 'Photo stick',
        'uuid': '123', 'device': '/dev/sdb1'}))
    (usb.rejected / 'bad.json').write_text('{')
    (usb.rejected / 'empty.json').write_text('[]')
    assert usb.status() == {'sticks': [], 'rejected': [
        {'name': 'sdb1', 'fstype': 'ntfs', 'label': 'Photo stick'}]}
    (usb.rejected / 'sdb1.json').unlink()
    assert usb.status()['rejected'] == []


def test_huge_directory_both_endpoints_stat_only(usb: Any, monkeypatch: Any) -> None:
    directory = usb.root / 'Demo'
    directory.mkdir(parents=True)
    for index in range(5000):
        (directory / f'{index}.gcode').touch()
    def no_read(*args: Any, **kwargs: Any) -> Any:
        pytest.fail('Listing must not read file contents')
    monkeypatch.setattr(Path, 'open', no_read)
    monkeypatch.setattr(usb, 'open_gcode', no_read)
    start = time.monotonic()
    listing = asyncio.run(usb._handle_list(request('usb/Demo')))
    assert len(listing['files']) == 5000
    assert time.monotonic() - start < 2
    fm = SimpleNamespace(server=usb.server, event_loop=EventLoop())
    start = time.monotonic()
    files = asyncio.run(FileManager._handle_filelist_request(
        fm, WebRequest('/server/files/list', {'root': 'usb'})))
    assert len(files) == 5000
    assert time.monotonic() - start < 2


def test_hidden_files_extensions_sort_and_depth(usb: Any) -> None:
    import os
    older = gcode(usb, 'Demo/old.gcode')
    gcode(usb, 'Demo/new.GCODE')
    os.utime(older, (1, 1))
    for path in ('Demo/.hidden.gcode', 'Demo/._apple.gcode', 'Demo/no.txt',
                 'Demo/.secret/inside.gcode', 'Demo/a/b/c/yes.gcode',
                 'Demo/a/b/c/d/no.gcode'):
        gcode(usb, path)
    listing = usb.listing('usb/Demo')
    assert [f['name'] for f in listing['files']] == ['new.GCODE', 'old.gcode']
    assert usb.listing('usb/Demo/a/b/c')['files'][0]['name'] == 'yes.gcode'
    assert not usb.listing('usb/Demo/a/b/c')['dirs']
    files = usb.file_list(False)
    assert set(files) == {'Demo/old.gcode', 'Demo/new.GCODE', 'Demo/a/b/c/yes.gcode'}
    with pytest.raises(ServerError, match='depth exceeds 4'):
        usb.listing('usb/Demo/a/b/c/d')
    with pytest.raises(ServerError, match='depth exceeds 4'):
        usb.metadata('usb/Demo/a/b/c/d/no.gcode')


@pytest.mark.parametrize('path', ['usb/../gcodes/x', '/tmp/x', 'usb/Demo/../x',
                                  'usb//Demo', 'usb/Demo/./x', 'gcodes/x',
                                  'usb/Demo/a\nM112.gcode', 'usb/Demo/a\\b.gcode'])
def test_invalid_paths(usb: Any, path: str) -> None:
    gcode(usb)
    for operation in (usb.listing, usb.metadata):
        with pytest.raises(ServerError) as err:
            operation(path)
        assert err.value.status_code == 400
    with pytest.raises(ServerError):
        asyncio.run(usb._handle_print(request(path)))
    usb.server.components['klippy_apis'].start_print.assert_not_called()


def test_symlinks_escape_cycle_and_file_manager_download(usb: Any, tmp_path: Path) -> None:
    gcode(usb)
    outside = tmp_path / 'secret.gcode'
    outside.write_text('secret')
    (usb.root / 'Demo/escape.gcode').symlink_to(outside)
    (usb.root / 'Demo/cycle').symlink_to(usb.root)
    assert len(usb.file_list()) == 1
    for path in ('usb/Demo/escape.gcode', 'usb/Demo/cycle/Demo/part.gcode'):
        for operation in (usb.metadata, usb.listing):
            with pytest.raises(ServerError) as err:
                operation(path)
            assert err.value.status_code == 403
        with pytest.raises(ServerError) as err:
            asyncio.run(usb._handle_print(request(path)))
        assert err.value.status_code == 403
    fm = SimpleNamespace(server=usb.server)
    with pytest.raises(ServerError) as err:
        FileManager.check_reserved_path(fm, usb.root / 'Demo/escape.gcode', False)
    assert err.value.status_code == 403


@pytest.mark.parametrize('state', ['printing', 'paused', 'not_ready'])
def test_print_busy_or_not_ready(usb: Any, state: str) -> None:
    gcode(usb)
    usb.server.components['job_state'].get_last_stats = lambda: {'state': state}
    usb.server.components['klippy_connection'].is_ready = lambda: state != 'not_ready'
    with pytest.raises(ServerError) as err:
        asyncio.run(usb._handle_print(request('usb/Demo/part.gcode')))
    assert err.value.status_code == 409
    assert not (usb.server.data / 'gcodes/usb-import').exists()
    usb.server.components['klippy_apis'].start_print.assert_not_called()


@pytest.mark.parametrize('failure', ['vanished', 'read_error'])
def test_removed_mid_copy_cleans_temporary(usb: Any, monkeypatch: Any, failure: str) -> None:
    source = gcode(usb)
    def fail(src: Any, dst: Any) -> None:
        dst.write(b'partial')
        if failure == 'vanished':
            source.unlink()
        else:
            raise OSError('device read failed')
    monkeypatch.setattr(muon_usb.shutil, 'copyfileobj', fail)
    with pytest.raises(ServerError, match=muon_usb.REMOVED):
        asyncio.run(usb._handle_print(request('usb/Demo/part.gcode')))
    assert not list((usb.server.data / 'gcodes/usb-import').iterdir())
    usb.server.components['klippy_apis'].start_print.assert_not_called()


def test_unicode_listing_copy_then_safety_gated_start(usb: Any) -> None:
    name = '模型 café.gcode'
    source = gcode(usb, 'Demo/' + name)
    listing = asyncio.run(usb._handle_list(request('usb/Demo')))
    assert listing['files'][0]['name'] == name
    assert listing['files'][0]['path'] == 'usb/Demo/' + name
    result = asyncio.run(usb._handle_print(request('usb/Demo/' + name)))
    assert result == {'filename': 'usb-import/' + name}
    assert (usb.server.data / 'gcodes/usb-import' / name).read_bytes() == source.read_bytes()
    assert [p.name for p in (usb.server.data / 'gcodes/usb-import').iterdir()] == [name]
    usb.server.components['klippy_apis'].start_print.assert_awaited_once_with(
        'usb-import/' + name)


@pytest.mark.parametrize(('header', 'seconds', 'slicer'), [
    ('; generated by PrusaSlicer 2.8\n; estimated printing time (normal mode) = 1h 2m 3s',
     3723, 'PrusaSlicer'),
    ('; generated by OrcaSlicer\n; estimated printing time (normal mode) = 2m 4s',
     124, 'OrcaSlicer'),
    (';Generated with Cura_SteamEngine\n;TIME:120.5', 120.5, 'Cura'),
    ('G1 X1', None, None),
])
def test_bounded_metadata(usb: Any, header: str, seconds: Any, slicer: Any) -> None:
    gcode(usb, data=header + '\n' + ('G1 X1\n' * 30000) + '; filament_type = PLA\n')
    result = asyncio.run(usb._handle_metadata(request('usb/Demo/part.gcode')))
    assert result == {'estimated_time': seconds, 'slicer': slicer, 'filament_type': 'PLA'}


def test_metadata_reads_at_most_two_bounded_chunks(usb: Any, monkeypatch: Any) -> None:
    gcode(usb, data='G1 X1\n' * 100000)
    original = usb.open_gcode
    reads = []

    @contextlib.contextmanager
    def tracked(path: str) -> Any:
        with original(path) as source:
            class Reader:
                def read(self, size: int) -> bytes:
                    reads.append(size)
                    return source.read(size)

                def seek(self, offset: int) -> None:
                    source.seek(offset)

                def fileno(self) -> int:
                    return source.fileno()
            yield Reader()

    monkeypatch.setattr(usb, 'open_gcode', tracked)
    assert usb.metadata('usb/Demo/part.gcode') == {
        'estimated_time': None, 'slicer': None}
    assert reads == [65536, 65536]


def test_non_gcode_and_nonregular_files_refused(usb: Any) -> None:
    import os
    gcode(usb, 'Demo/text.txt')
    os.mkfifo(usb.root / 'Demo/fifo.gcode')
    for path in ('usb/Demo/text.txt', 'usb/Demo/fifo.gcode'):
        with pytest.raises(ServerError) as err:
            asyncio.run(usb._handle_print(request(path)))
        assert err.value.status_code == 400
    usb.server.components['klippy_apis'].start_print.assert_not_called()


def test_nonasync_file_manager_listing_uses_usb_rules(usb: Any) -> None:
    gcode(usb)
    gcode(usb, 'Demo/not.txt')
    fm = SimpleNamespace(server=usb.server)
    result = FileManager.get_file_list(fm, 'usb', list_format=True)
    assert len(result) == 1
    assert result[0]['path'] == 'Demo/part.gcode'
    assert result[0]['permissions'] == 'r'


def test_m1_config_enables_component() -> None:
    config = configparser.ConfigParser(interpolation=None)
    config.read(Path(__file__).resolve().parents[1] /
                'core/M1/moonraker.core.conf.template')
    assert config.has_section('muon_usb')


def test_access_classification() -> None:
    assert [a.name for a in policy.classify('/server/muon/usb/print', RequestType.POST)] == ['print']
    for endpoint in ('status', 'list', 'metadata'):
        assert policy.classify('/server/muon/usb/' + endpoint, RequestType.GET) == (policy.READ,)
    assert policy.classify('/server/files/download', RequestType.GET,
                           {'path': 'usb/Demo/part.gcode'}) == (policy.READ,)


def test_access_usb_shared_readonly() -> None:
    scope = access_files.FileScope({}, data_mode='accounts')
    guard = access_files.FileGuard(lambda: scope, lambda *a: None, ServerError)
    who = policy.Principal('home', '', 0, 'viewer', True, False)
    guard.check('/server/files/download', RequestType.GET,
                {'path': 'usb/Demo/part.gcode'}, who)
    for endpoint, args in (
            ('/server/files/directory', {'path': 'usb/new'}),
            ('/server/files/copy', {'dest': 'usb/Demo/new'}),
            ('/server/files/move', {'source': 'usb/Demo/part.gcode'})):
        with pytest.raises(ServerError, match='read-only'):
            guard.check(endpoint, RequestType.POST, args, who)
    with pytest.raises(ServerError, match='read-only'):
        guard.plan_upload(who, {'root': 'usb'})
