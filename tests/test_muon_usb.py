from __future__ import annotations

import asyncio
import configparser
import contextlib
import errno
import json
import os
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
        self.events: list = []
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

    def register_notification(self, event: str, name: Any = None) -> None:
        self.notifications = getattr(self, 'notifications', {})
        self.notifications[event] = name

    def send_event(self, event: str, *args: Any) -> None:
        self.events.append((event, args))

    def lookup_component(self, name: str, default: Any = None) -> Any:
        return self.components.get(name, default)


class Config:
    def __init__(self, server: Server) -> None:
        self.server = server

    def get_server(self) -> Server:
        return self.server

    def get(self, key: str, default: Any = None) -> Any:
        return str(self.server.data / 'rejected') if key == 'rejected_path' else default


class Machine:
    # systemd as Moonraker sees it: starting/stopping the two root units
    def __init__(self, mounts: Dict[str, Any], gone: set) -> None:
        self.mounts, self.gone, self.calls = mounts, gone, []
        self.rw_fails = False
        self.states: Dict[str, str] = {}      # forced ActiveState per unit
        self.stuck: Dict[str, int] = {}       # dev -> stop calls that do not take

    async def unit_active_state(self, unit: str) -> str:
        if unit in self.states:
            return self.states[unit]
        dev = unit.partition('@')[2].removesuffix('.service')
        for mount in self.mounts.values():
            if mount['dev'] == dev:
                return 'active' if mount['rw'] else 'inactive'
        return 'inactive'

    async def do_service_action(self, action: str, unit: str) -> None:
        self.calls.append((action, unit))
        kind, _, rest = unit.partition('@')
        dev = rest.removesuffix('.service')
        for name, mount in self.mounts.items():
            if mount['dev'] != dev:
                continue
            if kind == 'muon-usb-rw' and action == 'stop' and self.stuck.get(dev, 0):
                self.stuck[dev] -= 1
                continue
            if action == 'reset-failed':
                if self.states.get(unit) == 'failed':
                    del self.states[unit]
                continue
            if kind == 'muon-usb-rw' and not (self.rw_fails and action == 'start'):
                mount['rw'] = action == 'start'
            if kind == 'muon-usb-mount' and action == 'stop':
                self.gone.add(name)


@pytest.fixture
def usb(tmp_path: Path, monkeypatch: Any) -> Any:
    monkeypatch.setattr(muon_usb, 'idle_io', lambda: None)
    monkeypatch.setattr(muon_usb, 'syncfs', lambda path: None)   # POSIX only
    server = Server(tmp_path)
    component = muon_usb.load_component(Config(server))  # type: ignore[arg-type]
    mounts: Dict[str, Any] = {'Demo': {'dev': 'sda1', 'fs': 'vfat', 'rw': False},
                              'Other': {'dev': 'sdb1', 'fs': 'exfat', 'rw': False}}
    gone: set = set()
    machine = Machine(mounts, gone)
    server.components['machine'] = machine
    component.mounts, component.machine = mounts, machine
    monkeypatch.setattr(component, 'mount_info', lambda: {
        n: dict(m) for n, m in mounts.items() if n not in gone})
    monkeypatch.setattr(component, 'block_read_only', lambda dev: False)
    # tmp directories are not mountpoints: treat <root>/<name> as a mounted stick
    real_ismount = os.path.ismount
    monkeypatch.setattr(
        os.path, 'ismount',
        lambda p: (Path(p).parent == component.root and Path(p).name not in gone
                   and Path(p).is_dir())
        or real_ismount(p))
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
    assert asyncio.run(usb._handle_status(request())) == {
        'sticks': [], 'rejected': [], 'job': None, 'ejected': []}
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
    status = asyncio.run(usb._handle_status(request()))
    assert [(s['name'], s['path']) for s in status['sticks']] == [('Demo', 'usb/Demo')]
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
    assert usb.status()['sticks'] == []
    assert usb.status()['rejected'] == [
        {'name': 'sdb1', 'fstype': 'ntfs', 'label': 'Photo stick'}]
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
    listing = asyncio.run(usb._handle_list(
        WebRequest('/server/muon/usb/list', {'path': 'usb/Demo', 'limit': 2000})))
    assert len(listing['files']) == muon_usb.MAX_FOLDER_ENTRIES
    assert listing['truncated'] is True
    assert listing['total'] == 5000
    assert time.monotonic() - start < 2
    fm = SimpleNamespace(server=usb.server, event_loop=EventLoop())
    start = time.monotonic()
    files = asyncio.run(FileManager._handle_filelist_request(
        fm, WebRequest('/server/files/list', {'root': 'usb'})))
    assert len(files) == muon_usb.MAX_FOLDER_ENTRIES
    assert time.monotonic() - start < 2


def test_total_file_cap(usb: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr(muon_usb, 'MAX_TOTAL_FILES', 5)
    for folder in ('A', 'B'):
        for index in range(4):
            gcode(usb, f'{folder}/{index}.gcode')
    assert len(usb.file_list()) == 5
    assert usb.listing('usb/A')['truncated'] is False


def test_only_mountpoints_are_sticks(usb: Any, monkeypatch: Any) -> None:
    gcode(usb, 'Real/part.gcode')
    gcode(usb, 'Ghost/part.gcode')
    monkeypatch.setattr(usb, 'is_stick', lambda name: name == 'Real')
    assert [s['name'] for s in usb.status()['sticks']] == ['Real']
    assert [d['name'] for d in usb.listing('usb')['dirs']] == ['Real']
    with pytest.raises(ServerError) as err:
        usb.listing('usb/Ghost')
    assert err.value.status_code == 404
    assert set(usb.file_list(False)) == {'Real/part.gcode'}


def test_startup_cleans_temporaries(tmp_path: Path) -> None:
    server = Server(tmp_path)
    imports = tmp_path / 'gcodes/usb-import'
    imports.mkdir()
    (imports / ('.usb-' + 'ab' * 16)).write_text('partial')
    (imports / 'keep.gcode').write_text('G1\n')
    muon_usb.load_component(Config(server))  # type: ignore[arg-type]
    assert [p.name for p in imports.iterdir()] == ['keep.gcode']


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


def test_not_enough_space_refuses_before_copy(usb: Any, monkeypatch: Any) -> None:
    gcode(usb, data='G1 X1\n' * 100)
    size = (usb.root / 'Demo/part.gcode').stat().st_size
    monkeypatch.setattr(
        muon_usb.shutil, 'disk_usage',
        lambda p: SimpleNamespace(total=0, used=0, free=size + muon_usb.HEADROOM - 1))
    with pytest.raises(ServerError, match='Not enough space on the printer') as err:
        asyncio.run(usb._handle_print(request('usb/Demo/part.gcode')))
    assert err.value.status_code == 507
    assert not list((usb.server.data / 'gcodes/usb-import').iterdir())
    usb.server.components['klippy_apis'].start_print.assert_not_called()


def test_enough_space_copies(usb: Any, monkeypatch: Any) -> None:
    gcode(usb)
    size = (usb.root / 'Demo/part.gcode').stat().st_size
    monkeypatch.setattr(
        muon_usb.shutil, 'disk_usage',
        lambda p: SimpleNamespace(total=0, used=0, free=size + muon_usb.HEADROOM))
    assert asyncio.run(usb._handle_print(request('usb/Demo/part.gcode'))) == {
        'filename': 'usb-import/part.gcode'}


def test_enospc_during_copy_is_not_stick_removed(usb: Any, monkeypatch: Any) -> None:
    gcode(usb)
    def full(src: Any, dst: Any) -> None:
        dst.write(b'partial')
        raise OSError(errno.ENOSPC, 'No space left on device')
    monkeypatch.setattr(muon_usb.shutil, 'copyfileobj', full)
    with pytest.raises(ServerError) as err:
        asyncio.run(usb._handle_print(request('usb/Demo/part.gcode')))
    assert err.value.status_code == 507
    assert err.value.args[0] == muon_usb.NO_SPACE
    assert not list((usb.server.data / 'gcodes/usb-import').iterdir())


def test_copy_fsyncs_before_rename(usb: Any, monkeypatch: Any) -> None:
    gcode(usb)
    calls = []
    real_fsync, real_replace = os.fsync, os.replace
    monkeypatch.setattr(os, 'fsync', lambda fd: (calls.append('fsync'), real_fsync(fd))[1])
    monkeypatch.setattr(
        os, 'replace', lambda *a, **k: (calls.append('replace'), real_replace(*a, **k))[1])
    asyncio.run(usb._handle_print(request('usb/Demo/part.gcode')))
    assert calls.index('fsync') < calls.index('replace')


# ---------------------------------------------------------------------------
# KAN-4814: copy jobs, eject, paging, download (spec v1.1 + v1.2)
# ---------------------------------------------------------------------------

def copy_request(**body: Any) -> WebRequest:
    return WebRequest('/server/muon/usb/copy', body)


def do_copy(usb: Any, **body: Any) -> Dict[str, Any]:
    (usb.root / body['stick']).mkdir(parents=True, exist_ok=True)   # the mountpoint
    async def run() -> Dict[str, Any]:
        result = await usb._handle_copy(copy_request(**body))
        assert result['job_id']
        await usb.task
        return usb.job_snapshot(full=True)
    return asyncio.run(run())


def printer_gcode(usb: Any, path: str, data: str = 'G1 X1\n') -> Path:
    target = usb.server.data / 'gcodes' / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(data)
    return target


def reasons(entries: Any) -> Any:
    return sorted((e['path'], e['reason']) for e in entries)


def test_job_state_machine_to_printer_keeps_structure(usb: Any) -> None:
    gcode(usb, 'Demo/a/one.gcode', 'AAAA')
    gcode(usb, 'Demo/two.gcode', 'BB')
    gcode(usb, 'Demo/notes.txt')
    job = do_copy(usb, direction='to_printer', stick='Demo',
                  items=['usb/Demo'], on_conflict='rename')
    assert job['state'] == 'done'
    assert (job['files_total'], job['files_done']) == (2, 2)
    assert (job['bytes_total'], job['bytes_done']) == (6, 6)
    assert job['direction'] == 'to_printer' and job['stick'] == 'Demo'
    assert job['started_at'] and job['ended_at'] and job['skipped'] == []
    base = usb.server.data / 'gcodes/usb-import/Demo'
    assert (base / 'a/one.gcode').read_text() == 'AAAA'
    assert (base / 'two.gcode').read_text() == 'BB'
    assert [i['state'] for i in job['items']] == ['done', 'done']
    assert job['items'][0] == {
        'path': 'usb/Demo/a/one.gcode', 'dest': 'usb-import/Demo/a/one.gcode',
        'bytes_total': 4, 'bytes_done': 4, 'state': 'done', 'error': None}
    assert not [p for p in base.rglob('.usb-*')]
    assert usb.job_snapshot()['id'] == job['id']
    assert usb.machine.calls == []          # to_printer never needs rw
    states = [args[0]['state'] for ev, args in usb.server.events]
    assert states[-1] == 'done' and len(states) <= 6
    assert usb.server.notifications['muon_usb:job'] == 'muon_usb_job'


def test_copy_all_root_forms_and_custom_dest(usb: Any) -> None:
    gcode(usb, 'Demo/a/one.gcode')
    gcode(usb, 'Demo/b/two.gcode')
    printer_gcode(usb, 'top.gcode')
    printer_gcode(usb, 'sub/deep.gcode')
    printer_gcode(usb, 'sub/readme.txt')
    # to_printer: the stick root
    job = do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'],
                  dest='mine')
    assert job['files_total'] == 2
    assert (usb.server.data / 'gcodes/mine/a/one.gcode').exists()
    # a folder item, plus the same file named again, is copied once
    job = do_copy(usb, direction='to_printer', stick='Demo',
                  items=['usb/Demo/a', 'usb/Demo/a/one.gcode'], on_conflict='replace')
    assert job['files_total'] == 1
    # to_usb: the gcodes root; structure kept under the stick root
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    assert job['state'] == 'done'
    assert {i['dest'] for i in job['items']} >= {
        'usb/Demo/top.gcode', 'usb/Demo/sub/deep.gcode'}
    assert (usb.root / 'Demo/sub/deep.gcode').exists()
    assert not (usb.root / 'Demo/sub/readme.txt').exists()
    job = do_copy(usb, direction='to_usb', stick='Other', items=['sub'],
                  dest='usb/Other/imported')
    assert (usb.root / 'Other/imported/sub/deep.gcode').exists()


def test_rw_window_wraps_to_usb_job_only(usb: Any) -> None:
    printer_gcode(usb, 'p.gcode')
    seen = []
    original = usb._copy_file
    def spy(*args: Any, **kwargs: Any) -> Any:
        seen.append((usb.mounts['Demo']['rw'], usb.status()['sticks'][0]['writable']))
        return original(*args, **kwargs)
    usb._copy_file = spy
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    assert job['state'] == 'done' and seen == [(True, True)]
    assert usb.machine.calls == [('reset-failed', 'muon-usb-rw@sda1.service'),
                                 ('start', 'muon-usb-rw@sda1.service'),
                                 ('stop', 'muon-usb-rw@sda1.service')]
    assert usb.mounts['Demo']['rw'] is False
    assert usb.status()['sticks'][0]['writable'] is False


def test_finally_returns_to_ro_after_failure(usb: Any) -> None:
    printer_gcode(usb, 'p.gcode')
    def boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError('boom')
    usb._copy_file = boom
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    assert job['state'] == 'failed'
    assert usb.machine.calls[-1] == ('stop', 'muon-usb-rw@sda1.service')
    assert usb.mounts['Demo']['rw'] is False


def test_rw_unit_failed_is_a_write_error_not_read_only(usb: Any) -> None:
    # A stale failed state is reset before the start; this path never marks
    # the device read_only (only EROFS or a write-protect switch do).
    printer_gcode(usb, 'p.gcode')
    usb.machine.rw_fails = True
    usb.machine.states['muon-usb-rw@sda1.service'] = 'failed'
    usb.rw_timeout = 0.05
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    assert job['state'] == 'failed'
    assert reasons(job['errors'])[0][1] == 'write_error'
    assert usb.status()['sticks'][0]['read_only'] is False
    assert usb.machine.calls[-1][0] == 'stop'


def test_read_only_stick_fails_immediately(usb: Any, monkeypatch: Any) -> None:
    printer_gcode(usb, 'p.gcode')
    (usb.root / 'Demo').mkdir(parents=True)
    monkeypatch.setattr(usb, 'block_read_only', lambda dev: dev == 'sda1')
    assert usb.status()['sticks'][0]['read_only'] is True
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    assert job['state'] == 'failed' and reasons(job['errors'])[0][1] == 'read_only'
    assert usb.machine.calls == []
    # to_printer from a read-only stick is fine
    gcode(usb, 'Demo/x.gcode')
    assert do_copy(usb, direction='to_printer', stick='Demo',
                   items=['usb/Demo'])['state'] == 'done'


def test_cancel_removes_inflight_temp_keeps_finished(usb: Any, monkeypatch: Any) -> None:
    gcode(usb, 'Demo/a.gcode', 'x' * 30)
    gcode(usb, 'Demo/b.gcode', 'y' * 30)
    usb.server.components['job_state'].get_last_stats = lambda: {'state': 'printing'}
    usb.chunk, usb.rate = 10, 1
    calls = []
    dest = usb.server.data / 'gcodes/usb-import/Demo'
    def fake_sleep(seconds: float) -> None:
        calls.append(seconds)
        if len(calls) == 5:
            assert [p.name for p in dest.glob('.usb-*')]   # in flight
            usb.cancel_job(usb.job_snapshot()['id'])
    usb._sleep = fake_sleep
    usb._now = lambda: 0.0
    job = do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'])
    assert job['state'] == 'cancelled'
    assert (dest / 'a.gcode').read_text() == 'x' * 30
    assert not (dest / 'b.gcode').exists()
    assert not list(dest.glob('.usb-*'))
    assert [i['state'] for i in job['items']] == ['done', 'cancelled']
    assert job['items'][1]['error'] == 'cancelled'


def test_cancel_handler_and_unknown_job(usb: Any) -> None:
    with pytest.raises(ServerError) as err:
        asyncio.run(usb._handle_job_cancel(WebRequest('/x', {'job_id': 'nope'})))
    assert err.value.status_code == 404


def test_cancel_to_usb_returns_ro(usb: Any) -> None:
    printer_gcode(usb, 'a.gcode', 'x' * 30)
    usb.server.components['job_state'].get_last_stats = lambda: {'state': 'paused'}
    usb.chunk, usb.rate = 10, 1
    usb._now = lambda: 0.0
    usb._sleep = lambda s: usb.cancel_job(usb.job_snapshot()['id'])
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    assert job['state'] == 'cancelled'
    assert usb.mounts['Demo']['rw'] is False
    assert not list((usb.root / 'Demo').glob('.usb-*'))


@pytest.mark.parametrize('direction', ['to_printer', 'to_usb'])
def test_stick_removed_mid_copy(usb: Any, direction: str) -> None:
    gcode(usb, 'Demo/a.gcode', 'x' * 30)
    printer_gcode(usb, 'a.gcode', 'x' * 30)
    count = []
    def vanish(handle: Any, size: int) -> bytes:
        count.append(1)
        if len(count) == 2:
            usb.machine.gone.add('Demo')
            raise OSError(errno.EIO, 'gone')
        return handle.read(size)
    usb.chunk = 10
    usb._read = vanish
    items = ['usb/Demo'] if direction == 'to_printer' else ['/']
    job = do_copy(usb, direction=direction, stick='Demo', items=items)
    assert job['state'] == 'failed'
    assert reasons(job['errors'])[0][1] == 'stick_removed'
    assert job['items'][0]['state'] == 'failed'
    for folder in (usb.server.data / 'gcodes/usb-import/Demo', usb.root / 'Demo'):
        assert not list(folder.glob('.usb-*')) if folder.exists() else True


def test_read_error_continues_with_next_file(usb: Any) -> None:
    gcode(usb, 'Demo/a.gcode', 'x')
    gcode(usb, 'Demo/b.gcode', 'y')
    first = []
    def flaky(handle: Any, size: int) -> bytes:
        if not first:
            first.append(1)
            raise OSError(errno.EIO, 'bad sector')
        return handle.read(size)
    usb._read = flaky
    job = do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'])
    assert job['state'] == 'done'
    assert reasons(job['errors']) == [('usb/Demo/a.gcode', 'read_error')]
    assert [i['state'] for i in job['items']] == ['failed', 'done']


def test_no_space_to_printer_stops_cleanly(usb: Any, monkeypatch: Any) -> None:
    gcode(usb, 'Demo/a.gcode', 'x' * 100)
    gcode(usb, 'Demo/b.gcode', 'y' * 100)
    monkeypatch.setattr(usb, 'free_space', lambda p: 100 + muon_usb.HEADROOM - 1)
    job = do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'])
    assert job['state'] == 'failed'
    assert reasons(job['errors']) == [('usb/Demo/a.gcode', 'no_space')]
    assert [i['state'] for i in job['items']] == ['failed', 'cancelled']
    monkeypatch.setattr(usb, 'free_space', lambda p: 100 + muon_usb.HEADROOM)
    assert do_copy(usb, direction='to_printer', stick='Demo',
                   items=['usb/Demo'], on_conflict='replace')['state'] == 'done'


def test_no_space_to_usb_margin_and_enospc(usb: Any, monkeypatch: Any) -> None:
    printer_gcode(usb, 'a.gcode', 'x' * 100)
    monkeypatch.setattr(usb, 'free_space', lambda p: 100 + muon_usb.MARGIN - 1)
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    assert job['state'] == 'failed' and reasons(job['errors'])[0][1] == 'no_space'
    assert usb.mounts['Demo']['rw'] is False
    monkeypatch.setattr(usb, 'free_space', lambda p: 100 + muon_usb.MARGIN)
    assert do_copy(usb, direction='to_usb', stick='Demo', items=['/'])['state'] == 'done'
    def full(handle: Any, data: bytes) -> None:
        raise OSError(errno.ENOSPC, 'full')
    usb._write = full
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'],
                  on_conflict='replace')
    assert job['state'] == 'failed' and reasons(job['errors'])[0][1] == 'no_space'
    assert not list((usb.root / 'Demo').glob('.usb-*'))


@pytest.mark.parametrize(('name', 'bad'), [
    ('a<b.gcode', True), ('a>b.gcode', True), ('a:b.gcode', True),
    ('a"b.gcode', True), ('a\\b.gcode', True), ('a|b.gcode', True),
    ('a?b.gcode', True), ('a*b.gcode', True), ('trail.', True),
    ('trail ', True), ('x' * 256, True), ('x' * 255, False),
    ('\U0001F600' * 128, True), ('\U0001F600' * 127, False),
    ('ok name (1).gcode', False), ('café.gcode', False)])
def test_fat_name_rules(name: str, bad: bool) -> None:
    assert muon_usb.fat_name_problem(name) is bad


def test_fat_names_and_4gib_skip_not_fail(usb: Any, monkeypatch: Any) -> None:
    printer_gcode(usb, 'good.gcode', 'g')
    printer_gcode(usb, 'bad-name.gcode', 'b')
    printer_gcode(usb, 'huge.gcode', 'h' * 20)
    monkeypatch.setattr(muon_usb, 'fat_name_problem', lambda n: n.startswith('bad'))
    monkeypatch.setattr(muon_usb, 'FAT_MAX_FILE', 10)
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    assert job['state'] == 'done'
    assert reasons(job['skipped']) == [('bad-name.gcode', 'name_invalid'),
                                       ('huge.gcode', 'too_large')]
    assert (job['files_total'], job['files_done']) == (1, 1)
    assert {i['state'] for i in job['items']} == {'done', 'skipped'}
    # exFAT has no 4 GiB limit
    job = do_copy(usb, direction='to_usb', stick='Other', items=['huge.gcode'])
    assert job['skipped'] == [] and (usb.root / 'Other/huge.gcode').exists()


def test_to_usb_depth_beyond_four_is_name_invalid(usb: Any) -> None:
    printer_gcode(usb, 'a/b/c/d/e.gcode')
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['a'])
    assert job['skipped'] == []      # four folders deep fits at the stick root
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['a'],
                  dest='usb/Demo/x')
    assert reasons(job['skipped']) == [('a/b/c/d/e.gcode', 'name_invalid')]


def test_folder_full_at_cap(usb: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr(muon_usb, 'MAX_FOLDER_ENTRIES', 3)
    for name in ('x', 'y', 'z'):
        gcode(usb, f'Demo/{name}.gcode')
    printer_gcode(usb, 'new.gcode')
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    assert job['state'] == 'done'
    assert reasons(job['skipped']) == [('new.gcode', 'folder_full')]
    # replacing an existing name adds no entry, so it is allowed
    printer_gcode(usb, 'x.gcode', 'new')
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['x.gcode'],
                  on_conflict='replace')
    assert job['skipped'] == [] and (usb.root / 'Demo/x.gcode').read_text() == 'new'


def test_conflicts_rename_skip_replace(usb: Any) -> None:
    gcode(usb, 'Demo/p.gcode', 'NEW')
    dest = usb.server.data / 'gcodes/usb-import/Demo'
    dest.mkdir(parents=True)
    (dest / 'p.gcode').write_text('OLD')
    job = do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'],
                  on_conflict='rename')
    assert (dest / 'p.gcode').read_text() == 'OLD'
    assert (dest / 'p (1).gcode').read_text() == 'NEW'
    assert job['items'][0]['dest'] == 'usb-import/Demo/p (1).gcode'
    job = do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'],
                  on_conflict='rename')
    assert (dest / 'p (2).gcode').exists()
    job = do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'],
                  on_conflict='skip')
    assert reasons(job['skipped']) == [('usb/Demo/p.gcode', 'exists')]
    assert job['items'][0]['state'] == 'skipped' and job['items'][0]['error'] == 'exists'
    assert (job['files_total'], job['bytes_total']) == (0, 0)
    job = do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'],
                  on_conflict='replace')
    assert (dest / 'p.gcode').read_text() == 'NEW' and job['state'] == 'done'


def test_source_changed_during_copy(usb: Any) -> None:
    source = gcode(usb, 'Demo/a.gcode', 'x' * 30)
    usb.chunk = 10
    count = []
    def grow(handle: Any, size: int) -> bytes:
        count.append(1)
        if len(count) == 2:
            with open(source, 'ab') as other:
                other.write(b'zzz')
        return handle.read(size)
    usb._read = grow
    job = do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'])
    assert reasons(job['errors']) == [('usb/Demo/a.gcode', 'source_changed')]
    assert not list((usb.server.data / 'gcodes/usb-import/Demo').glob('*'))


def test_one_job_at_a_time_and_eject_conflict(usb: Any) -> None:
    gcode(usb, 'Demo/a.gcode')
    async def run() -> None:
        first = await usb._handle_copy(copy_request(
            direction='to_printer', stick='Demo', items=['usb/Demo']))
        with pytest.raises(ServerError) as err:
            await usb._handle_copy(copy_request(
                direction='to_printer', stick='Demo', items=['usb/Demo']))
        assert err.value.status_code == 409
        with pytest.raises(ServerError) as err:
            await usb._handle_eject(WebRequest('/e', {'stick': 'Demo'}))
        assert err.value.status_code == 409
        assert err.value.error_data == {'reason': 'job_running',
                                        'job_id': first['job_id']}
        await usb.task
    asyncio.run(run())
    assert usb.job_snapshot()['state'] == 'done'


@pytest.mark.parametrize('body', [
    {'direction': 'sideways', 'stick': 'Demo', 'items': ['usb/Demo']},
    {'direction': 'to_printer', 'stick': 'Demo', 'items': []},
    {'direction': 'to_printer', 'stick': 'Demo', 'items': ['usb/Demo/../x']},
    {'direction': 'to_printer', 'stick': 'Demo', 'items': ['usb/Other']},
    {'direction': 'to_printer', 'stick': 'Demo', 'items': ['usb/Demo/.hid']},
    {'direction': 'to_printer', 'stick': 'Demo', 'items': ['usb']},
    {'direction': 'to_printer', 'stick': 'Demo', 'items': ['usb/Demo'], 'dest': '../x'},
    {'direction': 'to_printer', 'stick': 'Demo', 'items': ['usb/Demo'],
     'on_conflict': 'explode'},
    {'direction': 'to_usb', 'stick': 'Demo', 'items': ['../secret']},
    {'direction': 'to_usb', 'stick': 'Demo', 'items': ['.hidden/x.gcode']},
    {'direction': 'to_usb', 'stick': 'Demo', 'items': ['/'], 'dest': 'usb/Other'},
    {'direction': 'to_usb', 'stick': 'Demo', 'items': ['/'], 'dest': 'gcodes/x'},
    {'direction': 'to_usb', 'stick': 'Demo', 'items': ['/'], 'dest': 'usb/Demo/../x'},
])
def test_bad_copy_requests_are_400(usb: Any, body: Dict[str, Any]) -> None:
    gcode(usb, 'Demo/a.gcode')
    gcode(usb, 'Other/a.gcode')
    with pytest.raises(ServerError) as err:
        asyncio.run(usb._handle_copy(copy_request(**body)))
    assert err.value.status_code == 400
    assert usb.job_snapshot() is None


def test_missing_stick_is_404(usb: Any) -> None:
    with pytest.raises(ServerError) as err:
        asyncio.run(usb._handle_copy(copy_request(
            direction='to_printer', stick='Ghost', items=['usb/Ghost'])))
    assert err.value.status_code == 404


def test_throttle_only_while_printing(usb: Any) -> None:
    gcode(usb, 'Demo/a.gcode', 'x' * 40)
    usb.chunk = 10
    sleeps = []
    usb._sleep = sleeps.append
    do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'])
    assert sleeps == []
    assert usb.rate == 2 * 1024 * 1024
    usb.server.components['job_state'].get_last_stats = lambda: {'state': 'printing'}
    usb.rate = 100
    usb._now = lambda: 0.0   # time never advances: pure debt
    do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'],
            on_conflict='replace')
    assert len(sleeps) == 4 and sleeps[-1] == pytest.approx(0.4)


def test_job_payload_trims_past_200_items(usb: Any) -> None:
    items = [{'path': f'p{i}', 'dest': f'd{i}', 'bytes_total': 1, 'bytes_done': 0,
              'state': 'pending', 'error': None} for i in range(201)]
    usb.job = {'id': 'j', 'state': 'running', 'items': items, 'skipped': [],
               'errors': [], 'files_total': 201, 'files_done': 3, 'bytes_total': 201,
               'bytes_done': 3, 'current': 'p3', '_last': 3}
    payload = usb.job_snapshot()
    assert 'items' not in payload and payload['item']['path'] == 'p3'
    assert payload['files_total'] == 201 and '_last' not in payload
    assert len(usb.job_snapshot(full=True)['items']) == 201
    usb.job['items'] = items[:200]
    assert len(usb.job_snapshot()['items']) == 200


def test_notifications_are_rate_limited(usb: Any) -> None:
    for index in range(30):
        gcode(usb, f'Demo/f{index:02}.gcode', 'x')
    usb.notify_interval = 10     # at most the first and the final
    do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'])
    events = usb.server.events
    assert 1 <= len(events) <= 3 and events[-1][0] == 'muon_usb:job'
    assert events[-1][1][0]['state'] == 'done'


def test_eject_flow_and_ejected_list(usb: Any, monkeypatch: Any, tmp_path: Path) -> None:
    gcode(usb, 'Demo/a.gcode')
    (tmp_path / 'sys').mkdir()
    (tmp_path / 'sys/sda1').mkdir()
    monkeypatch.setattr(usb, 'block_path', tmp_path / 'sys')
    result = asyncio.run(usb._handle_eject(WebRequest('/e', {'stick': 'Demo'})))
    assert result['stick'] == 'Demo'
    assert ('stop', 'muon-usb-mount@sda1.service') in usb.machine.calls
    status = usb.status()
    assert all(s['name'] != 'Demo' for s in status['sticks'])
    assert [e['name'] for e in status['ejected']] == ['Demo']
    assert status['ejected'][0]['at'] > 0
    (tmp_path / 'sys/sda1').rmdir()              # unplugged: no longer listed
    assert usb.status()['ejected'] == []


def test_eject_unknown_stick(usb: Any) -> None:
    with pytest.raises(ServerError) as err:
        asyncio.run(usb._handle_eject(WebRequest('/e', {'stick': 'Ghost'})))
    assert err.value.status_code == 404


def test_status_additions(usb: Any, monkeypatch: Any) -> None:
    gcode(usb, 'Demo/a.gcode')
    monkeypatch.setattr(muon_usb.shutil, 'disk_usage',
                        lambda p: SimpleNamespace(total=1000, used=400, free=600))
    stick = usb.status()['sticks'][0]
    assert stick == {'name': 'Demo', 'path': 'usb/Demo', 'dev': 'sda1',
                     'unit': 'muon-usb-mount@sda1.service', 'fs': 'vfat',
                     'free_bytes': 600, 'total_bytes': 1000,
                     'writable': False, 'read_only': False}
    usb.mounts['Demo']['fs'] = 'ntfs'     # not supported for writing
    assert usb.status()['sticks'][0]['read_only'] is True


def test_listing_pages_sorted_before_the_cap(usb: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr(muon_usb, 'MAX_FOLDER_ENTRIES', 5)
    (usb.root / 'Demo').mkdir(parents=True)
    for index in range(8):
        path = gcode(usb, f'Demo/f{index}.gcode', 'x' * index)
        os.utime(path, (1000 + index, 1000 + index))      # f7 is newest
    for name in ('dirA', 'dirB'):
        (usb.root / 'Demo' / name).mkdir()
    page = usb.listing('usb/Demo', 0, 4)
    assert sorted(d['name'] for d in page['dirs']) == ['dirA', 'dirB']
    assert [f['name'] for f in page['files']] == ['f7.gcode', 'f6.gcode']
    assert page['total'] == 10 and page['truncated'] is True
    assert page['files'][0]['size'] == 7 and 'modified' in page['files'][0]
    assert 'modified' in page['dirs'][0]
    page = usb.listing('usb/Demo', 4, 4)       # only up to the cap of 5 is reachable
    assert [f['name'] for f in page['files']] == ['f5.gcode']
    assert page['truncated'] is True
    page = usb.listing('usb/Demo', 0, 50)
    assert len(page['dirs']) + len(page['files']) == 5
    # the newest files survive the cap, not whichever the disk listed first
    assert [f['name'] for f in page['files']] == ['f7.gcode', 'f6.gcode', 'f5.gcode']


def test_listing_defaults_and_limits(usb: Any) -> None:
    (usb.root / 'Demo').mkdir(parents=True)
    for index in range(600):
        (usb.root / 'Demo' / f'{index}.gcode').touch()
    page = usb.listing('usb/Demo')
    assert len(page['files']) == muon_usb.DEFAULT_LIMIT and page['total'] == 600
    assert len(usb.listing('usb/Demo', 0, 99999)['files']) == 600
    with pytest.raises(ServerError):
        usb.listing('usb/Demo', -1, 5)
    request_ = WebRequest('/server/muon/usb/list', {'path': 'usb/Demo', 'offset': 590})
    assert len(asyncio.run(usb._handle_list(request_))['files']) == 10


@pytest.mark.parametrize(('header', 'expected'), [
    (None, None), ('', None), ('bytes=0-3', (0, 3)), ('bytes=4-', (4, 9)),
    # ignored (the whole file, 200): a multi-range, or a unit that is not bytes
    ('bytes=0-1,3-4', None), ('items=0-1', None), ('garbage', None),
    ('bytes=-3', (7, 9)), ('bytes=0-999', (0, 9)), ('bytes=9-9', (9, 9)),
    ('bytes=-999', (0, 9)),
])
def test_parse_range_ok(header: Any, expected: Any) -> None:
    assert muon_usb.parse_range(header, 10) == expected


@pytest.mark.parametrize('header', [
    'bytes=10-', 'bytes=10-20', 'bytes=5-2', 'bytes=-0', 'bytes=-', 'bytes=',
    'bytes=a-b', 'bytes=--1'])
def test_parse_range_bad_is_416(header: str) -> None:
    with pytest.raises(muon_usb.RangeNotSatisfiable):
        muon_usb.parse_range(header, 10)
    with pytest.raises(muon_usb.RangeNotSatisfiable):
        muon_usb.parse_range('bytes=0-0', 0)


def test_download_headers_range_and_etag(usb: Any) -> None:
    name = 'mödel 1.gcode'
    gcode(usb, 'Demo/' + name, '0123456789')
    path = 'usb/Demo/' + name
    full = usb.download_info(path)
    assert full['status'] == 200 and (full['start'], full['length']) == (0, 10)
    headers = full['headers']
    assert headers['Content-Length'] == '10' and headers['Accept-Ranges'] == 'bytes'
    assert headers['Content-Disposition'] == (
        "attachment; filename*=UTF-8''m%C3%B6del%201.gcode")
    assert headers['ETag'].startswith('"') and headers['ETag'].endswith('"')
    assert b''.join(usb.iter_file(path, 0, 10)) == b'0123456789'
    part = usb.download_info(path, 'bytes=2-5')
    assert part['status'] == 206 and (part['start'], part['length']) == (2, 4)
    assert part['headers']['Content-Range'] == 'bytes 2-5/10'
    assert part['headers']['Content-Length'] == '4'
    assert b''.join(usb.iter_file(path, 2, 4)) == b'2345'
    bad = usb.download_info(path, 'bytes=50-')
    assert bad['status'] == 416 and bad['headers']['Content-Range'] == 'bytes */10'
    same = usb.download_info(path, None, full['headers']['ETag'])
    assert same['status'] == 304
    (usb.root / 'Demo' / name).write_text('01234567890')       # size changes
    assert usb.download_info(path)['headers']['ETag'] != headers['ETag']


def test_download_chunks_are_small(usb: Any) -> None:
    gcode(usb, 'Demo/big.gcode', 'x' * 1000)
    usb.chunk = 100
    chunks = list(usb.iter_file('usb/Demo/big.gcode', 0, 1000))
    assert len(chunks) == 10 and all(len(c) == 100 for c in chunks)


@pytest.mark.parametrize('path', ['usb/Demo/a.txt', 'usb/Demo/.h.gcode',
                                  'usb/Demo/../x.gcode', 'gcodes/a.gcode'])
def test_download_refuses_what_resolve_refuses(usb: Any, path: str) -> None:
    gcode(usb, 'Demo/a.txt')
    gcode(usb, 'Demo/.h.gcode')
    with pytest.raises(ServerError) as err:
        usb.download_info(path)
    assert err.value.status_code in (400, 403, 404)


def test_download_directory_and_missing(usb: Any) -> None:
    gcode(usb, 'Demo/sub/a.gcode')
    for path, code in (('usb/Demo/sub', 400), ('usb/Demo/gone.gcode', 404)):
        with pytest.raises(ServerError) as err:
            usb.download_info(path)
        assert err.value.status_code == code


def test_endpoints_registered(usb: Any) -> None:
    got = {path: method for path, (method, _) in usb.server.endpoints.items()}
    for name in ('status', 'list', 'metadata', 'job'):
        assert got['/server/muon/usb/' + name] == RequestType.GET
    for name in ('print', 'copy', 'job/cancel', 'eject'):
        assert got['/server/muon/usb/' + name] == RequestType.POST


def test_systemd_escape_and_units() -> None:
    assert muon_usb.systemd_escape('sda1') == 'sda1'
    assert muon_usb.systemd_escape('a-b') == 'a\\x2db'
    assert muon_usb.systemd_escape('a/b') == 'a\\x2fb'


def test_access_new_endpoints() -> None:
    for endpoint in ('status', 'list', 'metadata', 'job', 'file'):
        assert policy.classify('/server/muon/usb/' + endpoint, RequestType.GET) == (policy.READ,)
    for endpoint in ('copy', 'job/cancel', 'eject', 'print'):
        actions = policy.classify('/server/muon/usb/' + endpoint, RequestType.POST)
        assert [a.name for a in actions] == ['print']


def test_access_guard_allows_usb_copy_and_checks_gcodes_reads() -> None:
    scope = access_files.FileScope({}, data_mode='accounts')
    guard = access_files.FileGuard(lambda: scope, lambda *a: None, ServerError)
    who = policy.Principal('home', '', 0, 'viewer', True, False)
    guard.check('/server/muon/usb/copy', RequestType.POST, {
        'direction': 'to_usb', 'stick': 'Demo', 'items': ['/'],
        'dest': 'usb/Demo'}, who)
    with pytest.raises(ServerError, match='not found'):     # reads are checked
        guard.check('/server/muon/usb/copy', RequestType.POST, {
            'direction': 'to_usb', 'stick': 'Demo', 'items': ['a/b.gcode']}, who)
    guard.check('/server/muon/usb/copy', RequestType.POST, {
        'direction': 'to_printer', 'stick': 'Demo', 'items': ['usb/Demo'],
        'dest': 'mine'}, who)
    # the old read-only guard still holds for the file manager
    with pytest.raises(ServerError, match='read-only'):
        guard.check('/server/files/copy', RequestType.POST,
                    {'dest': 'usb/Demo/new'}, who)


def test_unit_derivation_matches_mount_unit(usb: Any) -> None:
    gcode(usb, 'Demo/a.gcode')
    stick = usb.status()['sticks'][0]
    assert stick['unit'] == 'muon-usb-mount@%s.service' % stick['dev']
    assert usb.rw_unit(stick['dev']) == 'muon-usb-rw@sda1.service'


# ---------------------------------------------------------------------------
# KAN-4814 review fixes (findings 5-12)
# ---------------------------------------------------------------------------

RW_UNIT = 'muon-usb-rw@sda1.service'


def temp_name(char: str = 'a', suffix: str = '') -> str:
    return '.usb-' + char * 32 + suffix


# -- 5: startup ------------------------------------------------------------

async def init(usb: Any) -> None:
    await usb.component_init()
    assert usb._startup_task is not None        # a background task, not awaited inline
    await usb._startup_task


def test_startup_stops_live_rw_window_and_checks_every_stick(usb: Any) -> None:
    usb.mounts['Demo']['rw'] = True            # Moonraker died mid-copy
    gcode(usb, 'Demo/a.gcode')
    gcode(usb, 'Other/b.gcode')
    asyncio.run(init(usb))
    assert ('stop', RW_UNIT) in usb.machine.calls
    assert ('stop', 'muon-usb-rw@sdb1.service') not in usb.machine.calls   # inactive
    assert all(not m['rw'] for m in usb.mounts.values())
    assert all(not s['writable'] for s in usb.status()['sticks'])


def test_startup_stuck_rw_is_a_fault(usb: Any) -> None:
    usb.mounts['Demo']['rw'] = True
    gcode(usb, 'Demo/a.gcode')
    usb.machine.stuck['sda1'] = 99
    usb.rw_timeout = 0.05
    asyncio.run(init(usb))
    stick = usb.status()['sticks'][0]
    assert stick['writable'] is True and stick['fault'] == 'stuck_rw'


# -- 6: the real rw flag, verified ro, fault -------------------------------

def test_writable_is_the_mount_flag_not_the_job(usb: Any) -> None:
    gcode(usb, 'Demo/a.gcode')
    assert usb.status()['sticks'][0]['writable'] is False
    usb.mounts['Demo']['rw'] = True            # nobody asked for this
    stick = usb.status()['sticks'][0]
    assert stick['writable'] is True and 'fault' not in stick


def test_leave_rw_retries_stop_start_stop(usb: Any) -> None:
    gcode(usb, 'Demo/a.gcode')
    usb.mounts['Demo']['rw'] = True
    usb.machine.stuck['sda1'] = 1               # the first stop does not take
    usb.rw_timeout = 0.05
    assert asyncio.run(usb._leave_rw('Demo', 'sda1')) is True
    assert [c[0] for c in usb.machine.calls] == ['stop', 'reset-failed', 'start', 'stop']
    assert usb.mounts['Demo']['rw'] is False and 'Demo' not in usb._faults


def test_leave_rw_gives_up_loudly(usb: Any, caplog: Any) -> None:
    gcode(usb, 'Demo/a.gcode')
    usb.mounts['Demo']['rw'] = True
    usb.machine.stuck['sda1'] = 99
    usb.rw_timeout = 0.05
    assert asyncio.run(usb._leave_rw('Demo', 'sda1')) is False
    assert usb.status()['sticks'][0]['fault'] == 'stuck_rw'
    assert 'STILL READ-WRITE' in caplog.text
    usb.mounts['Demo']['rw'] = False            # recovered by itself later
    assert 'fault' not in usb.status()['sticks'][0]


def test_job_waits_for_unit_active_before_writing(usb: Any) -> None:
    printer_gcode(usb, 'p.gcode')
    usb.machine.states[RW_UNIT] = 'activating'  # the mount shows rw, the unit is not done
    usb.rw_timeout = 0.05
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    assert job['state'] == 'failed'
    assert not (usb.root / 'Demo/p.gcode').exists()


# -- 7: a timeout is not read_only -----------------------------------------

def test_rw_timeout_does_not_mark_read_only_and_next_job_retries(usb: Any) -> None:
    printer_gcode(usb, 'p.gcode')
    usb.machine.rw_fails = True
    usb.rw_timeout = 0.05
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    assert job['state'] == 'failed'
    assert reasons(job['errors'])[0][1] != 'read_only'
    assert usb.status()['sticks'][0]['read_only'] is False
    usb.machine.rw_fails = False
    usb.rw_timeout = 5
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    assert job['state'] == 'done' and (usb.root / 'Demo/p.gcode').exists()


def test_erofs_on_write_is_definitive_read_only(usb: Any) -> None:
    printer_gcode(usb, 'p.gcode')
    def refuse(handle: Any, data: bytes) -> None:
        raise OSError(errno.EROFS, 'Read-only file system')
    usb._write = refuse
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    assert job['state'] == 'failed' and reasons(job['errors'])[0][1] == 'read_only'
    assert usb.status()['sticks'][0]['read_only'] is True
    usb._write = lambda handle, data: handle.write(data)
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    assert reasons(job['errors'])[0][1] == 'read_only'      # fails at once
    assert usb.mounts['Demo']['rw'] is False


def test_write_protect_switch_is_read_only(usb: Any, monkeypatch: Any) -> None:
    gcode(usb, 'Demo/a.gcode')
    monkeypatch.setattr(usb, 'block_read_only', lambda dev: True)
    assert usb.status()['sticks'][0]['read_only'] is True


# -- 8: account data mode ---------------------------------------------------

def member(name: str = 'bob') -> Any:
    return policy.Principal('gateway', name, policy.MEMBER, 'member', False, True)


def view_for(scope: Any, who: Any, allowed: Any = ('files', 'files_others')) -> Any:
    return access_files.UsbView(scope, who, lambda name: name in allowed, ServerError)


def test_guard_checks_to_printer_dest_like_an_upload() -> None:
    scope = access_files.FileScope({}, data_mode='accounts')
    guard = access_files.FileGuard(lambda: scope, lambda *a: None, ServerError)
    who = member('bob')
    body = {'direction': 'to_printer', 'stick': 'Demo', 'items': ['usb/Demo']}
    with pytest.raises(ServerError) as err:      # another account's drive
        guard.check('/server/muon/usb/copy', RequestType.POST,
                    dict(body, dest='a/alice/stolen'), who)
    assert err.value.status_code == 403
    guard.check('/server/muon/usb/copy', RequestType.POST, dict(body, dest='a/bob/mine'), who)
    guard.check('/server/muon/usb/copy', RequestType.POST, dict(body), who)   # default dest
    guard.check('/server/muon/usb/copy', RequestType.POST, dict(body, dest='x'),
                policy.PANEL_PRINCIPAL)


def test_to_printer_lands_in_the_members_own_drive(usb: Any) -> None:
    scope = access_files.FileScope({}, data_mode='accounts')
    usb._view = lambda request: view_for(scope, member('bob'))
    gcode(usb, 'Demo/a.gcode', 'AA')
    job = do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'])
    assert job['state'] == 'done'
    assert (usb.server.data / 'gcodes/a/bob/usb-import/Demo/a.gcode').read_text() == 'AA'
    usb._view = lambda request: view_for(scope, member('bob'))
    with pytest.raises(ServerError) as err:
        asyncio.run(usb._handle_copy(copy_request(
            direction='to_printer', stick='Demo', items=['usb/Demo'], dest='a/alice/x')))
    assert err.value.status_code == 403


def test_replace_needs_the_files_permission(usb: Any) -> None:
    scope = access_files.FileScope({}, data_mode='shared')
    usb._view = lambda request: view_for(scope, member('bob'), allowed=())
    gcode(usb, 'Demo/a.gcode', 'NEW')
    target = printer_gcode(usb, 'usb-import/Demo/a.gcode', 'OLD')
    job = do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'],
                  on_conflict='replace')
    assert job['state'] == 'done' and target.read_text() == 'OLD'
    assert reasons(job['skipped']) == [('usb/Demo/a.gcode', 'exists')]
    usb._view = lambda request: view_for(scope, member('bob'), allowed=('files',))
    assert do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'],
                   on_conflict='replace')['skipped'] == []
    assert target.read_text() == 'NEW'


def test_replace_of_someone_elses_upload_needs_files_others(usb: Any) -> None:
    scope = access_files.FileScope(
        {'usb-import/Demo/a.gcode': access_files.Tag('alice', False)}, data_mode='shared')
    usb._view = lambda request: view_for(scope, member('bob'), allowed=('files',))
    gcode(usb, 'Demo/a.gcode', 'NEW')
    target = printer_gcode(usb, 'usb-import/Demo/a.gcode', 'OLD')
    job = do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'],
                  on_conflict='replace')
    assert reasons(job['skipped']) == [('usb/Demo/a.gcode', 'exists')] and target.read_text() == 'OLD'


def test_replace_never_replaces_the_file_being_printed(usb: Any) -> None:
    gcode(usb, 'Demo/a.gcode', 'NEW')
    gcode(usb, 'Demo/b.gcode', 'NEW')
    busy = printer_gcode(usb, 'usb-import/Demo/a.gcode', 'OLD')
    other = printer_gcode(usb, 'usb-import/Demo/b.gcode', 'OLD')
    usb.server.components['job_state'].get_last_stats = lambda: {
        'state': 'printing', 'filename': 'usb-import/Demo/a.gcode'}
    job = do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'],
                  on_conflict='replace')
    assert busy.read_text() == 'OLD' and other.read_text() == 'NEW'
    assert reasons(job['skipped']) == [('usb/Demo/a.gcode', 'in_use')]
    assert [i['error'] for i in job['items']] == ['in_use', None]
    assert (job['files_total'], job['files_done']) == (1, 1)


def test_to_usb_walks_only_what_the_caller_can_see(usb: Any) -> None:
    printer_gcode(usb, 'a/bob/mine.gcode')
    printer_gcode(usb, 'a/alice/hers.gcode')
    scope = access_files.FileScope({}, data_mode='accounts')
    usb._view = lambda request: view_for(scope, member('bob'))
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    assert [i['path'] for i in job['items']] == ['a/bob/mine.gcode']
    assert not (usb.root / 'Demo/a/alice').exists()
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['a'])
    assert [i['path'] for i in job['items']] == ['a/bob/mine.gcode']


def test_to_usb_walk_hides_other_peoples_private_files(usb: Any) -> None:
    printer_gcode(usb, 'open.gcode')
    printer_gcode(usb, 'secret.gcode')
    scope = access_files.FileScope(
        {'secret.gcode': access_files.Tag('alice', True)}, data_mode='shared')
    usb._view = lambda request: view_for(scope, member('bob'))
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    assert [i['path'] for i in job['items']] == ['open.gcode']
    assert job['skipped'] == []                       # not even mentioned
    usb._view = lambda request: view_for(scope, member('alice'))
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'], on_conflict='replace')
    assert sorted(i['path'] for i in job['items']) == ['open.gcode', 'secret.gcode']


# -- 9: temp-file sweeps ----------------------------------------------------

def test_to_usb_sweeps_only_our_old_temps_in_top_and_dest(usb: Any) -> None:
    printer_gcode(usb, 'p.gcode')
    stick = usb.root / 'Demo'
    stick.mkdir(parents=True, exist_ok=True)
    (stick / 'out').mkdir()
    (stick / 'deep/er').mkdir(parents=True)
    old = [stick / temp_name('a'), stick / temp_name('b', '.part'), stick / 'out' / temp_name('c'),
           stick / (temp_name('f') + '.gcode.bak')]
    keep = [stick / '.usb-short', stick / ('.usb-' + 'g' * 32), stick / temp_name('d', 'x'),
            stick / '.usbfile', stick / 'photo.jpg', stick / 'deep/er' / temp_name('e'),
            stick / '.hidden.gcode']
    for path in old + keep:
        path.write_text('x')
        os.utime(path, (1, 1))
    fresh = stick / temp_name('9')
    fresh.write_text('x')
    os.utime(fresh, (time.time() + 600, time.time() + 600))     # not older than the job
    (stick / temp_name('8')).mkdir()                            # a directory, never removed
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'], dest='usb/Demo/out')
    assert job['state'] == 'done'
    assert not any(p.exists() for p in old)
    assert all(p.exists() for p in keep) and fresh.exists() and (stick / temp_name('8')).is_dir()


def test_rw_unit_start_is_not_asked_to_sweep(usb: Any) -> None:
    # The root unit never walks the stick; the sweep is Moonraker's, after rw is active.
    printer_gcode(usb, 'p.gcode')
    seen = []
    original = usb.sweep_folder
    def spy(directory: Any, before: float) -> int:
        seen.append((usb.mounts['Demo']['rw'], usb.machine.calls[:]))
        return original(directory, before)
    usb.sweep_folder = spy
    do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    assert seen and all(rw for rw, _ in seen)
    assert seen[0][1] == [('reset-failed', RW_UNIT), ('start', RW_UNIT)]


def test_startup_cleans_to_printer_temps_recursively_and_in_recorded_dests(tmp_path: Path) -> None:
    server = Server(tmp_path)
    gcodes = tmp_path / 'gcodes'
    for folder in ('usb-import/Demo/a/b', 'mine/sub', 'unrecorded'):
        (gcodes / folder).mkdir(parents=True)
    first = muon_usb.load_component(Config(server))  # type: ignore[arg-type]
    first.record_dest(['mine'])
    first.record_dest(['usb-import', 'Demo'])       # always swept: not recorded
    assert first.recorded_dests() == [['mine']]
    gone = [gcodes / 'usb-import/Demo/a/b' / temp_name('a'), gcodes / 'usb-import' / temp_name('b'),
            gcodes / 'mine/sub' / temp_name('c', '.x')]
    kept = [gcodes / 'unrecorded' / temp_name('d'), gcodes / 'mine/.usb-nothex',
            gcodes / 'mine/keep.gcode', gcodes / 'usb-import/Demo/a' / ('.usb-' + 'a' * 31)]
    for path in gone + kept:
        path.write_text('x')
    muon_usb.load_component(Config(server))  # type: ignore[arg-type]
    assert not any(p.exists() for p in gone)
    assert all(p.exists() for p in kept)


def test_job_records_its_custom_dest(usb: Any) -> None:
    gcode(usb, 'Demo/a.gcode')
    do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'], dest='custom/place')
    assert usb.recorded_dests() == [['custom', 'place']]


# -- 10: print safety -------------------------------------------------------

def test_copy_rate_while_printing_is_2_mb_per_second(usb: Any) -> None:
    assert muon_usb.RATE == 2 * 1024 * 1024 and usb.rate == 2 * 1024 * 1024


@pytest.mark.parametrize(('printing', 'expected'), [(True, 2), (False, 0)])
def test_fdatasync_every_4mb_only_while_printing(usb: Any, monkeypatch: Any,
                                                 printing: bool, expected: int) -> None:
    assert muon_usb.SYNC_EVERY == 4 * 1024 * 1024
    gcode(usb, 'Demo/a.gcode', 'x' * 40)
    calls = []
    monkeypatch.setattr(os, 'fdatasync', lambda fd: calls.append(fd), raising=False)
    usb.chunk, usb.sync_every, usb.rate = 10, 20, 10 ** 9
    usb._sleep = lambda s: None
    usb.server.components['job_state'].get_last_stats = lambda: {
        'state': 'printing' if printing else 'standby'}
    job = do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'])
    assert job['state'] == 'done' and len(calls) == expected


def test_eject_flushes_that_filesystem_only(usb: Any, monkeypatch: Any, tmp_path: Path) -> None:
    gcode(usb, 'Demo/a.gcode')
    flushed = []
    monkeypatch.setattr(muon_usb, 'syncfs', flushed.append)
    monkeypatch.setattr(os, 'sync', lambda: pytest.fail('global sync'), raising=False)
    (tmp_path / 'sys').mkdir()
    monkeypatch.setattr(usb, 'block_path', tmp_path / 'sys')
    asyncio.run(usb._handle_eject(WebRequest('/e', {'stick': 'Demo'})))
    assert flushed == [usb.root / 'Demo']


# -- 11: Range, If-Range ----------------------------------------------------

def test_if_range_etag_and_date_and_ignored_ranges(usb: Any) -> None:
    gcode(usb, 'Demo/r.gcode', '0123456789')
    path = 'usb/Demo/r.gcode'
    full = usb.download_info(path)
    etag, modified = full['headers']['ETag'], full['headers']['Last-Modified']
    assert modified.endswith('GMT')
    for validator in (etag, modified):                   # still the same file: partial
        info = usb.download_info(path, 'bytes=2-5', None, validator)
        assert info['status'] == 206 and info['length'] == 4
    for validator in ('"stale"', 'Wed, 01 Jan 2020 00:00:00 GMT', 'W/' + etag):
        info = usb.download_info(path, 'bytes=2-5', None, validator)    # changed: all of it
        assert info['status'] == 200 and info['length'] == 10 and 'Content-Range' not in info['headers']
    for header in ('bytes=0-1,4-5', 'items=0-1', 'bytes=0-1, 4-5'):
        info = usb.download_info(path, header)
        assert info['status'] == 200 and info['length'] == 10, header
    assert usb.download_info(path, 'bytes=50-')['status'] == 416      # one unsatisfiable range
    assert usb.download_info(path, 'bytes=50-', None, '"stale"')['status'] == 200


# -- 12: renamed names stay legal ------------------------------------------

def test_fit_name_cuts_the_stem_not_the_tail() -> None:
    name = muon_usb.fit_name('x' * 253, ' (12).g', True)
    assert name.endswith(' (12).g') and len(name.encode('utf-16-le')) // 2 == 255
    assert not muon_usb.fat_name_problem(name)
    assert muon_usb.fit_name('short', ' (1).g', True) == 'short (1).g'
    assert muon_usb.fit_name('a. ' + 'x' * 300, ' (1).g', True).endswith('x (1).g')
    wide = muon_usb.fit_name('é' * 200, ' (1).g', False)           # 255 BYTES on the printer
    assert len(wide.encode('utf-8')) <= 255 and wide.endswith(' (1).g')
    emoji = muon_usb.fit_name('😀' * 200, ' (1).g', True)           # 2 UTF-16 units each
    assert len(emoji.encode('utf-16-le')) // 2 <= 255 and not muon_usb.fat_name_problem(emoji)


def test_renamed_copy_to_usb_is_re_checked_and_truncated(usb: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr(muon_usb, 'NAME_LIMIT', 40)               # short names: any OS path limit
    name = 'x' * 38 + '.g'                                         # exactly at the limit
    printer_gcode(usb, name)
    (usb.root / 'Demo').mkdir(parents=True, exist_ok=True)
    (usb.root / 'Demo' / name).write_text('old')
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'], on_conflict='rename')
    assert job['state'] == 'done' and job['skipped'] == []
    written = [p.name for p in (usb.root / 'Demo').iterdir() if p.name != name]
    assert len(written) == 1 and written[0].endswith(' (1).g')
    assert len(written[0].encode('utf-16-le')) // 2 <= 40
    assert job['items'][0]['dest'].endswith(written[0])


# -- round 2: no metadata deferral, shutdown, reset-failed, redaction --------

def test_file_manager_has_no_deferral_hooks() -> None:
    from moonraker.components.file_manager.file_manager import MetadataStorage
    for name in ('defer_prefix', 'release_prefix', 'deferred', 'deferred_prefixes'):
        assert not hasattr(MetadataStorage, name)
    assert not hasattr(muon_usb.MuonUSB, '_release_metadata_when_idle')


def test_to_printer_copy_never_touches_metadata_storage(usb: Any) -> None:
    called: list = []
    storage = SimpleNamespace(parse_metadata=lambda *a: called.append(a))
    usb.server.components['file_manager'].get_metadata_storage = lambda: storage
    gcode(usb, 'Demo/a.gcode')
    job = do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'])
    assert job['state'] == 'done' and called == []


def test_start_resets_a_failed_unit_first(usb: Any) -> None:
    printer_gcode(usb, 'p.gcode')
    usb.machine.states[RW_UNIT] = 'failed'              # left from before
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    calls = [c[0] for c in usb.machine.calls if c[1] == RW_UNIT]
    assert calls[:2] == ['reset-failed', 'start']
    assert job['state'] == 'done' and (usb.root / 'Demo/p.gcode').exists()


def test_failed_state_with_no_reset_is_not_definitive(usb: Any) -> None:
    usb.rw_timeout = 0.05
    gcode(usb, 'Demo/a.gcode')
    usb.machine.states[RW_UNIT] = 'failed'
    assert asyncio.run(usb._wait_active('Demo', RW_UNIT, reset=False)) == 'timeout'
    assert asyncio.run(usb._wait_active('Demo', RW_UNIT, reset=True)) == 'failed'


def test_failed_start_is_write_error_and_never_read_only(usb: Any) -> None:
    printer_gcode(usb, 'p.gcode')
    usb.rw_timeout = 0.05
    orig = usb.machine.do_service_action

    async def failing(action: str, unit: str) -> None:
        await orig(action, unit)
        if action == 'start' and unit == RW_UNIT:
            usb.machine.states[unit] = 'failed'
    usb.machine.do_service_action = failing
    job = do_copy(usb, direction='to_usb', stick='Demo', items=['/'])
    assert job['state'] == 'failed' and reasons(job['errors'])[0][1] == 'write_error'
    assert usb.status()['sticks'][0]['read_only'] is False


def test_leave_rw_cycles_start_with_and_end_on_a_stop(usb: Any) -> None:
    gcode(usb, 'Demo/a.gcode')
    usb.mounts['Demo']['rw'] = True
    usb.machine.stuck['sda1'] = 99
    usb.rw_timeout = 0.05
    asyncio.run(usb._leave_rw('Demo', 'sda1'))
    actions = [c[0] for c in usb.machine.calls if c[0] != 'reset-failed']
    assert actions[0] == 'stop' and actions[-1] == 'stop'
    for i, act in enumerate(actions):
        if act == 'start':
            assert actions[i + 1] == 'stop'


def test_on_exit_fires_one_stop_without_the_retry_loop(usb: Any) -> None:
    gcode(usb, 'Demo/a.gcode')
    usb.mounts['Demo']['rw'] = True
    usb._rw_stick = 'Demo'
    usb.machine.stuck['sda1'] = 99                       # a stop that would not take
    usb.rw_timeout = 5                                   # a loop would wait this long
    asyncio.run(usb.on_exit())
    assert [c for c in usb.machine.calls if c[1] == RW_UNIT] == [('stop', RW_UNIT)]


def test_component_init_does_not_wait_for_the_startup_check(usb: Any) -> None:
    usb.mounts['Demo']['rw'] = True
    gcode(usb, 'Demo/a.gcode')

    async def run() -> None:
        await usb.component_init()
        assert usb.machine.calls == []                   # nothing done inline
        await usb._startup_task
        assert ('stop', RW_UNIT) in usb.machine.calls
    asyncio.run(run())


def _notifications(usb: Any, direction: str, who: Any) -> Any:
    scope = access_files.FileScope({}, data_mode='accounts')
    usb._view = lambda request: view_for(scope, who)
    usb.notify_interval = 0
    if direction == 'to_usb':
        printer_gcode(usb, 'a/bob/mine.gcode')
        do_copy(usb, direction='to_usb', stick='Demo', items=['a/bob'])
    else:
        gcode(usb, 'Demo/sub/a.gcode')
        do_copy(usb, direction='to_printer', stick='Demo', items=['usb/Demo'])
    return [args[0] for ev, args in usb.server.events if ev == 'muon_usb:job']


def test_notification_to_usb_in_accounts_mode_has_basenames_only(usb: Any) -> None:
    events = _notifications(usb, 'to_usb', member('bob'))
    text = repr(events)
    assert events and 'a/bob' not in text and 'mine.gcode' in text
    assert events[-1]['files_total'] == 1
    # the job endpoint is not redacted
    assert usb.job_snapshot(full=True)['items'][0]['path'] == 'a/bob/mine.gcode'


def test_notification_to_usb_for_the_admin_keeps_paths(usb: Any) -> None:
    events = _notifications(usb, 'to_usb', policy.PANEL_PRINCIPAL)
    assert 'a/bob/mine.gcode' in repr(events)


def test_notification_to_printer_keeps_usb_paths_but_not_the_drive(usb: Any) -> None:
    events = _notifications(usb, 'to_printer', member('bob'))
    text = repr(events)
    assert 'usb/Demo/sub/a.gcode' in text and 'a/bob' not in text
