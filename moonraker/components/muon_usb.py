# MUON: removable storage. Read-only by default; copy locally before the
# safety-gated print; copy jobs in both directions (KAN-4814).
from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import errno
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import threading
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, BinaryIO, Dict, Iterator, List, Optional, Tuple
from urllib.parse import quote

from ..common import RequestType
from ..utils.exceptions import AgentError, ServerError
from .file_manager.file_manager import VALID_GCODE_EXTS

if TYPE_CHECKING:
    from ..common import WebRequest
    from ..confighelper import ConfigHelper

MAX_DEPTH = 4
READ_BYTES = 65536
REMOVED = "The USB stick was removed while copying. Nothing was printed."
NO_SPACE = "Not enough space on the printer"
HEADROOM = 256 * 1024 * 1024
MAX_FOLDER_ENTRIES = 2000
MAX_TOTAL_FILES = 10000
SCAN_LIMIT = 50000
DEFAULT_LIMIT = 500
MAX_LIMIT = 2000
CHUNK = 256 * 1024
MARGIN = 1024 * 1024
RATE = 8 * 1024 * 1024
FAT_MAX_FILE = 2 ** 32 - 1
FAT_ILLEGAL = set('<>:"\\|?*')
NOTIFY_INTERVAL = 0.5
NOTIFY_FULL_ITEMS = 200
MOUNT_WAIT = 15.0
STICK_NAME = re.compile(r'[A-Za-z0-9_-]+')
DEVICE_NAME = re.compile(r'[A-Za-z0-9_]+')
CONFLICTS = ('rename', 'skip', 'replace')
WRITABLE_FS = ('vfat', 'exfat')
ACTIVE = ('queued', 'running')
MAX_ITEMS = 10000


class JobBusy(AgentError):
    # 409 with a machine-readable reason: JSON-RPC `extra`, HTTP error body.
    def __init__(self, message: str, job_id: str) -> None:
        extra = {'reason': 'job_running', 'job_id': job_id}
        AgentError.__init__(self, message, extra)
        self.status_code = 409
        self.http_extra = extra


class RangeNotSatisfiable(Exception):
    pass


class CopyError(Exception):
    def __init__(self, reason: str, fatal: bool = False) -> None:
        Exception.__init__(self, reason)
        self.reason = reason
        self.fatal = fatal


class Cancelled(Exception):
    pass


def idle_io() -> None:
    # The calling thread's disk I/O goes to the idle class, so the print's SD
    # card traffic always comes first. Best effort; ionice is Linux only.
    try:
        subprocess.run(['ionice', '-c', '3', '-p', str(threading.get_native_id())],
                       check=False, capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        pass


def systemd_escape(name: str) -> str:
    out = []
    for index, byte in enumerate(name.encode('utf-8')):
        char = chr(byte)
        if (byte < 128 and (char.isalnum() or char in ':_')) or (char == '.' and index):
            out.append(char)
        else:
            out.append('\\x%02x' % byte)
    return ''.join(out)


def parse_range(header: Optional[str], size: int) -> Optional[Tuple[int, int]]:
    """None: serve everything. (start, end), inclusive. Anything that is not
    exactly one satisfiable bytes range raises RangeNotSatisfiable (HTTP 416)."""
    if header is None or not header.strip():
        return None
    match = re.fullmatch(r'\s*bytes\s*=\s*(\d*)\s*-\s*(\d*)\s*', header)
    if not match or (not match[1] and not match[2]) or size <= 0:
        raise RangeNotSatisfiable()
    if not match[1]:
        length = int(match[2])
        if length <= 0:
            raise RangeNotSatisfiable()
        return max(0, size - length), size - 1
    start = int(match[1])
    end = int(match[2]) if match[2] else size - 1
    if start >= size or end < start:
        raise RangeNotSatisfiable()
    return start, min(end, size - 1)


def fat_name_problem(name: str) -> bool:
    return (any(c in FAT_ILLEGAL or ord(c) < 32 for c in name)
            or len(name.encode('utf-16-le')) // 2 > 255
            or name.endswith(('.', ' ')))


def clean_segments(path: str) -> List[str]:
    """The segments of a relative path, or a 400. Same rules as parts()."""
    segments = path.split('/')
    if ('\\' in path or any(ord(c) < 32 or ord(c) == 127 for c in path)
            or any(p in ('', '.', '..') or p.startswith('.') for p in segments)):
        raise ServerError('Invalid path.', 400)
    return segments


class MuonUSB:
    def __init__(self, config: ConfigHelper) -> None:
        self.server = config.get_server()
        self.root = Path(self.server.get_app_args()['data_path']) / 'usb'
        self.rejected = Path(config.get('rejected_path', '/run/muon-usb/rejected'))
        self.block_path = Path('/sys/class/block')
        self.mountinfo_path = Path('/proc/self/mountinfo')
        self._print_lock = asyncio.Lock()
        # copy jobs
        self.job: Optional[Dict[str, Any]] = None
        self.task: Optional[asyncio.Task] = None
        self.machine: Any = None
        self.chunk = CHUNK
        self.rate = RATE
        self.notify_interval = NOTIFY_INTERVAL
        self.rw_timeout = MOUNT_WAIT
        self.eject_timeout = MOUNT_WAIT
        self._sleep = time.sleep
        self._now = time.monotonic
        self._debt = 0.0
        self._cancel = threading.Event()
        self._lock = threading.RLock()
        self._rw_stick: Optional[str] = None
        self._ejecting = False
        self._ro_devs: set = set()
        self.ejected: Dict[str, Dict[str, Any]] = {}
        self._pool: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self.cleanup_temporaries()
        self.ensure_root()
        endpoints = (('status', RequestType.GET), ('list', RequestType.GET),
                     ('metadata', RequestType.GET), ('job', RequestType.GET),
                     ('print', RequestType.POST), ('copy', RequestType.POST),
                     ('job/cancel', RequestType.POST), ('eject', RequestType.POST))
        for name, method in endpoints:
            self.server.register_endpoint(
                '/server/muon/usb/' + name, method,
                getattr(self, '_handle_' + name.replace('/', '_')))
        self.server.register_notification('muon_usb:job', 'muon_usb_job')
        self.register_download()

    # ------------------------------------------------------------------
    # existing read-only machinery
    # ------------------------------------------------------------------

    def cleanup_temporaries(self) -> None:
        # A crash or power loss mid-copy leaves .usb-* files behind.
        fm = self.server.lookup_component('file_manager')
        gcodes = fm.get_directory('gcodes') if fm else ''
        if not gcodes:
            return
        directory = Path(gcodes) / 'usb-import'
        if directory.is_symlink() or not directory.is_dir():
            return
        with contextlib.suppress(OSError):
            for entry in os.scandir(directory):
                if entry.name.startswith('.usb-') and not entry.is_dir(
                        follow_symlinks=False):
                    with contextlib.suppress(OSError):
                        os.unlink(entry.path)

    def is_stick(self, name: str) -> bool:
        # Only a real mountpoint is a stick; a leftover directory is not.
        return os.path.ismount(self.root / name)

    def ensure_root(self) -> None:
        fm = self.server.lookup_component('file_manager')
        if self.root.is_dir() and not self.root.is_symlink():
            if fm.get_directory('usb') != str(self.root):
                fm.register_directory('usb', str(self.root), full_access=False)

    def parts(self, path: str) -> List[str]:
        parts = path.split('/')
        if (not parts or parts[0] != 'usb' or
                '\\' in path or any(ord(c) < 32 or ord(c) == 127 for c in path) or
                any(p in ('', '.', '..') or p.startswith('.') for p in parts)):
            raise ServerError('Invalid USB path.', 400)
        # Four directory levels below usb: <stick>/a/b/c/file.gcode at most.
        dirs = parts[1:-1] if PurePosixPath(path).suffix else parts[1:]
        if len(dirs) > MAX_DEPTH:
            raise ServerError('USB directory depth exceeds 4.', 400)
        return parts[1:]

    def resolve(self, path: str) -> Path:
        parts = self.parts(path)
        target = self.root
        if self.root.is_symlink():
            raise ServerError('USB symlinks are not allowed.', 403)
        for part in parts:
            target = target / part
            if target.is_symlink():
                raise ServerError('USB symlinks are not allowed.', 403)
        if parts and not self.is_stick(parts[0]):
            raise ServerError('The USB stick or path is no longer available.', 404)
        if not target.exists():
            raise ServerError('The USB stick or path is no longer available.', 404)
        # Check actual directory depth too (directory names may contain dots).
        if len(parts) - (not target.is_dir()) > MAX_DEPTH:
            raise ServerError('USB directory depth exceeds 4.', 400)
        return target

    def open_gcode(self, path: str) -> BinaryIO:
        self.resolve(path)
        parts = self.parts(path)
        if not parts or Path(parts[-1]).suffix.lower() not in VALID_GCODE_EXTS:
            raise ServerError('The USB path is not a G-code file.', 400)
        # Anchor every component with openat/O_NOFOLLOW: checking realpath alone
        # would allow a symlink substitution between validation and open.
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=fd)
                os.close(fd)
                fd = child
            source = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=fd)
            if not stat.S_ISREG(os.fstat(source).st_mode):
                os.close(source)
                raise ServerError('The USB path is not a regular file.', 400)
            return os.fdopen(source, 'rb')
        finally:
            os.close(fd)

    def _scan(self, path: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], bool]:
        target = self.resolve(path)
        if not target.is_dir():
            raise ServerError('The USB directory is no longer available.', 404)
        dirs: List[Dict[str, Any]] = []
        files: List[Dict[str, Any]] = []
        at_root = path == 'usb'
        hit_limit = False
        can_nest = len(self.parts(path)) < MAX_DEPTH
        try:
            with os.scandir(target) as entries:
                for entry in entries:
                    if len(dirs) + len(files) >= SCAN_LIMIT:
                        hit_limit = True
                        break
                    if entry.name.startswith('.') or entry.is_symlink():
                        continue
                    if at_root and not self.is_stick(entry.name):
                        continue
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    item = {'name': entry.name, 'path': path + '/' + entry.name,
                            'modified': info.st_mtime}
                    if stat.S_ISDIR(info.st_mode):
                        if can_nest:
                            dirs.append(item)
                    elif (stat.S_ISREG(info.st_mode) and
                          Path(entry.name).suffix.lower() in VALID_GCODE_EXTS):
                        files.append(dict(item, size=info.st_size))
        except OSError:
            raise ServerError('The USB directory is no longer available.', 404)
        return dirs, files, hit_limit

    def listing(self, path: str, offset: int = 0,
                limit: int = DEFAULT_LIMIT) -> Dict[str, Any]:
        if offset < 0 or limit < 1:
            raise ServerError('Invalid offset or limit.', 400)
        limit = min(limit, MAX_LIMIT)
        dirs, files, hit_limit = self._scan(path)
        # Sort BEFORE the cap, so the cap keeps the newest entries.
        for group in (dirs, files):
            group.sort(key=lambda item: (-item['modified'], item['name']))
        ordered = [(True, d) for d in dirs] + [(False, f) for f in files]
        total = len(ordered)
        window = ordered[:MAX_FOLDER_ENTRIES]
        page = window[offset:offset + limit]
        return {'path': path,
                'dirs': [item for is_dir, item in page if is_dir],
                'files': [item for is_dir, item in page if not is_dir],
                'total': total, 'offset': offset,
                'truncated': hit_limit or offset + len(page) < total}

    def file_list(self, list_format: bool = True) -> Any:
        result: Dict[str, Any] = {}
        pending = ['usb']
        while pending:
            listing = self.listing(pending.pop(), 0, MAX_LIMIT)
            pending.extend(item['path'] for item in listing['dirs'])
            for item in listing['files']:
                if len(result) >= MAX_TOTAL_FILES:
                    pending.clear()
                    break
                result[item['path'][4:]] = {
                    'size': item['size'], 'modified': item['modified'],
                    'permissions': 'r'}
        if not list_format:
            return result
        return [dict(info, path=path) for path, info in sorted(result.items())]

    # ------------------------------------------------------------------
    # mounts, status
    # ------------------------------------------------------------------

    def mount_info(self) -> Dict[str, Dict[str, Any]]:
        """{stick name: {dev, fs, rw}} from this process's mount table."""
        result: Dict[str, Dict[str, Any]] = {}
        try:
            text = self.mountinfo_path.read_text()
        except OSError:
            return result
        root = str(self.root)
        for line in text.splitlines():
            left, _, right = line.partition(' - ')
            fields, tail = left.split(), right.split()
            if len(fields) < 6 or len(tail) < 2:
                continue
            point = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4])
            if os.path.dirname(point) != root:
                continue
            result[os.path.basename(point)] = {
                'dev': tail[1].rpartition('/')[2], 'fs': tail[0],
                'rw': 'rw' in fields[5].split(',')}
        return result

    def block_read_only(self, dev: str) -> bool:
        # A write-protect switch makes the kernel mark the device read-only.
        try:
            return (self.block_path / dev / 'ro').read_text().strip() == '1'
        except OSError:
            return False

    @staticmethod
    def mount_unit(dev: str) -> str:
        return f'muon-usb-mount@{systemd_escape(dev)}.service'

    @staticmethod
    def rw_unit(dev: str) -> str:
        return f'muon-usb-rw@{systemd_escape(dev)}.service'

    def stick_read_only(self, info: Optional[Dict[str, Any]]) -> bool:
        return (info is None or info['fs'] not in WRITABLE_FS
                or not DEVICE_NAME.fullmatch(info['dev'])
                or info['dev'] in self._ro_devs
                or self.block_read_only(info['dev']))

    def free_space(self, path: Any) -> int:
        return shutil.disk_usage(path).free

    def status(self) -> Dict[str, Any]:
        sticks = []
        mounts = self.mount_info()
        if self.root.is_dir() and not self.root.is_symlink():
            try:
                names = [p.name for p in self.root.iterdir()
                         if not p.name.startswith('.') and not p.is_symlink()
                         and p.is_dir() and self.is_stick(p.name)]
            except OSError:
                names = []
            for name in names:
                info = mounts.get(name)
                item: Dict[str, Any] = {
                    'name': name, 'path': 'usb/' + name,
                    'dev': info['dev'] if info else None,
                    'unit': self.mount_unit(info['dev']) if info else None,
                    'fs': info['fs'] if info else None,
                    'free_bytes': None, 'total_bytes': None,
                    'writable': self._rw_stick == name,
                    'read_only': self.stick_read_only(info)}
                with contextlib.suppress(OSError):
                    usage = shutil.disk_usage(self.root / name)
                    item['free_bytes'], item['total_bytes'] = usage.free, usage.total
                sticks.append(item)
        present = {s['name'] for s in sticks}
        devs = {m['dev'] for m in mounts.values()}
        self._ro_devs &= devs
        for name, entry in list(self.ejected.items()):
            # Replugged (mounted again), or unplugged: no longer "safe to remove".
            if name in present or not (self.block_path / entry['dev']).exists():
                del self.ejected[name]
        rejected = []
        if self.rejected.is_dir():
            for path in self.rejected.glob('*.json'):
                try:
                    if path.is_symlink() or path.stat().st_size > READ_BYTES:
                        continue
                    data = json.loads(path.read_text())
                    item = {key: data[key] for key in ('name', 'fstype', 'label')}
                    if all(isinstance(v, str) for v in item.values()):
                        rejected.append(item)
                except (OSError, ValueError, KeyError, TypeError):
                    continue
        return {'sticks': sorted(sticks, key=lambda p: p['name']),
                'rejected': sorted(rejected, key=lambda p: p['name']),
                'job': self.job_snapshot(),
                'ejected': [{'name': n, 'at': e['at']}
                            for n, e in sorted(self.ejected.items())]}

    def metadata(self, path: str) -> Dict[str, Any]:
        try:
            with self.open_gcode(path) as source:
                head = source.read(READ_BYTES)
                source.seek(max(0, os.fstat(source.fileno()).st_size - READ_BYTES))
                text = (head + b'\n' + source.read(READ_BYTES)).decode(
                    'utf-8', errors='replace')
        except OSError:
            raise ServerError('The USB stick or path is no longer available.', 404)
        slicer = re.search(r'(PrusaSlicer|OrcaSlicer|BambuStudio|Cura|Muon)', text,
                           re.IGNORECASE)
        seconds = None
        cura = re.search(r'^;\s*TIME:\s*(\d+(?:\.\d+)?)', text, re.MULTILINE)
        duration = re.search(r'estimated printing time[^=\n]*=\s*([^\r\n]+)', text)
        if cura:
            seconds = float(cura[1])
        elif duration:
            units = {'d': 86400, 'h': 3600, 'm': 60, 's': 1}
            matches = re.findall(r'(\d+(?:\.\d+)?)\s*([dhms])', duration[1])
            if matches:
                seconds = sum(float(n) * units[u] for n, u in matches)
        result: Dict[str, Any] = {'estimated_time': seconds,
                                  'slicer': slicer[1] if slicer else None}
        filament = re.search(r';\s*filament_type\s*=\s*([^\r\n;]+)', text)
        if filament:
            result['filament_type'] = filament[1].strip()
        return result

    def copy(self, path: str) -> str:
        fm = self.server.lookup_component('file_manager')
        gcodes = fm.get_directory('gcodes')
        if not gcodes:
            raise ServerError('The G-code directory is not available.', 404)
        destination = Path(gcodes) / 'usb-import'
        try:
            destination.mkdir(exist_ok=True)
        except OSError:
            raise ServerError('Could not create the USB import directory.', 500)
        if destination.is_symlink():
            raise ServerError('The USB import directory is not safe.', 403)
        filename = self.parts(path)[-1]
        temporary = '.usb-' + uuid.uuid4().hex
        directory = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            with self.open_gcode(path) as source:
                before = os.fstat(source.fileno())
                free = shutil.disk_usage(destination).free
                if free < before.st_size + HEADROOM:
                    raise ServerError(NO_SPACE, 507)
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                             0o644, dir_fd=directory)
                with os.fdopen(fd, 'wb') as output:
                    shutil.copyfileobj(source, output)
                    output.flush()
                    os.fsync(output.fileno())
                    if output.tell() != before.st_size:
                        raise OSError('Incomplete USB read')
                after = self.resolve(path).stat()
                if (before.st_dev, before.st_ino, before.st_size) != (
                        after.st_dev, after.st_ino, after.st_size):
                    raise OSError('USB source changed')
                os.replace(temporary, filename, src_dir_fd=directory,
                           dst_dir_fd=directory)
                with contextlib.suppress(OSError):
                    os.fsync(directory)
        except ServerError as err:
            if err.status_code == 507:
                raise
            raise ServerError(REMOVED, 404)
        except OSError as err:
            if err.errno == errno.ENOSPC:
                raise ServerError(NO_SPACE, 507)
            raise ServerError(REMOVED, 404)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=directory)
            os.close(directory)
        return 'usb-import/' + filename

    def check_ready(self) -> None:
        klippy = self.server.lookup_component('klippy_connection')
        job = self.server.lookup_component('job_state')
        if not klippy.is_ready():
            raise ServerError('Klippy is not ready. Nothing was printed.', 409)
        if job.get_last_stats().get('state') in ('printing', 'paused'):
            raise ServerError('The printer is busy. Nothing was printed.', 409)

    # ------------------------------------------------------------------
    # download to the computer
    # ------------------------------------------------------------------

    def download_info(self, path: str, range_header: Optional[str] = None,
                      if_none_match: Optional[str] = None) -> Dict[str, Any]:
        target = self.resolve(path)
        parts = self.parts(path)
        if not parts or Path(parts[-1]).suffix.lower() not in VALID_GCODE_EXTS:
            raise ServerError('The USB path is not a G-code file.', 400)
        info = target.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ServerError('The USB path is not a regular file.', 400)
        size = info.st_size
        etag = '"%x-%x"' % (info.st_mtime_ns, size)
        if if_none_match:
            tags = [t.strip() for t in if_none_match.split(',')]
            if '*' in tags or etag in tags or 'W/' + etag in tags:
                return {'status': 304, 'headers': {'ETag': etag},
                        'start': 0, 'length': 0}
        headers = {'Accept-Ranges': 'bytes', 'ETag': etag,
                   'Content-Type': 'application/octet-stream',
                   'Content-Disposition':
                       "attachment; filename*=UTF-8''" + quote(parts[-1], safe='')}
        try:
            span = parse_range(range_header, size)
        except RangeNotSatisfiable:
            return {'status': 416, 'start': 0, 'length': 0, 'headers': {
                'Accept-Ranges': 'bytes', 'Content-Range': f'bytes */{size}'}}
        if span is None:
            headers['Content-Length'] = str(size)
            return {'status': 200, 'headers': headers, 'start': 0, 'length': size}
        start, end = span
        headers['Content-Length'] = str(end - start + 1)
        headers['Content-Range'] = f'bytes {start}-{end}/{size}'
        return {'status': 206, 'headers': headers, 'start': start,
                'length': end - start + 1}

    def iter_file(self, path: str, start: int, length: int) -> Iterator[bytes]:
        with self.open_gcode(path) as source:
            source.seek(start)
            remaining = length
            while remaining > 0:
                data = source.read(min(self.chunk, remaining))
                if not data:
                    break
                remaining -= len(data)
                yield data

    def io_pool(self) -> concurrent.futures.ThreadPoolExecutor:
        if self._pool is None:
            self._pool = concurrent.futures.ThreadPoolExecutor(
                1, thread_name_prefix='muon-usb-io', initializer=idle_io)
        return self._pool

    def register_download(self) -> None:
        app = self.server.lookup_component('application', None)
        if app is None:
            return
        import tornado.web
        from .application import (
            AuthorizedRequestHandler, _check_file_access, _write_json_error)

        class UsbFileHandler(AuthorizedRequestHandler):
            def initialize(self, usb: MuonUSB) -> None:  # type: ignore[override]
                super().initialize()
                self.usb = usb

            def write_error(self, status_code: int, **kwargs: Any) -> None:
                _write_json_error(self, status_code, **kwargs)

            async def get(self) -> None:
                usb = self.usb
                path = self.get_argument('path', '')
                _check_file_access(self.request, self.current_user,
                                   '/server/muon/usb/file', RequestType.GET,
                                   {'path': path})
                loop = asyncio.get_running_loop()
                headers = self.request.headers
                try:
                    info = await loop.run_in_executor(
                        usb.io_pool(), usb.download_info, path,
                        headers.get('Range'), headers.get('If-None-Match'))
                except ServerError as err:
                    raise tornado.web.HTTPError(err.status_code, reason=str(err))
                self.set_status(info['status'])
                for key, value in info['headers'].items():
                    self.set_header(key, value)
                if info['status'] in (304, 416) or not info['length']:
                    self.finish()
                    return
                chunks = usb.iter_file(path, info['start'], info['length'])
                try:
                    while True:
                        data = await loop.run_in_executor(
                            usb.io_pool(), next, chunks, None)
                        if data is None:
                            break
                        self.write(data)
                        await self.flush()
                except (OSError, ServerError):
                    logging.exception('USB download aborted')
                    self.request.connection.close()
                    return
                finally:
                    chunks.close()
                self.finish()

        prefix = getattr(app, '_route_prefix', '')
        app.mutable_router.add_handler(
            f'{prefix}/server/muon/usb/file', UsbFileHandler, {'usb': self})

    # ------------------------------------------------------------------
    # copy jobs
    # ------------------------------------------------------------------

    def job_snapshot(self, full: bool = False) -> Optional[Dict[str, Any]]:
        """The job object as clients see it. Past 200 items, and unless `full`,
        only the item that changed last is carried, with the totals."""
        with self._lock:
            job = self.job
            if job is None:
                return None
            result = {k: v for k, v in job.items()
                      if not k.startswith('_') and k not in ('items', 'skipped', 'errors')}
            result['skipped'] = [dict(e) for e in job['skipped']]
            result['errors'] = [dict(e) for e in job['errors']]
            items = job['items']
            if full or len(items) <= NOTIFY_FULL_ITEMS:
                result['items'] = [dict(i) for i in items]
            elif 0 <= job.get('_last', -1) < len(items):
                result['item'] = dict(items[job['_last']])
            return result

    def _touch(self, index: Optional[int] = None) -> None:
        with self._lock:
            if self.job is not None:
                self.job['_dirty'] = True
                if index is not None:
                    self.job['_last'] = index

    def _notify(self) -> None:
        with self._lock:
            if self.job is not None:
                self.job['_dirty'] = False
        payload = self.job_snapshot()
        if payload is not None:
            self.server.send_event('muon_usb:job', payload)

    def _db_machine(self) -> Any:
        machine = self.machine or self.server.lookup_component('machine', None)
        if machine is None:
            raise ServerError('Systemd is not available.', 503)
        return machine

    def _printing(self) -> bool:
        job_state = self.server.lookup_component('job_state', None)
        if job_state is None:
            return False
        return job_state.get_last_stats().get('state') in ('printing', 'paused')

    def _pace(self, nbytes: int) -> None:
        # While printing or paused the copy gives way: about 8 MB/s at most.
        if not self._printing():
            return
        now = self._now()
        self._debt = max(self._debt, now) + nbytes / self.rate
        wait = self._debt - now
        if wait > 0:
            self._sleep(wait)

    def _read(self, handle: Any, size: int) -> bytes:
        return handle.read(size)

    def _write(self, handle: Any, data: bytes) -> None:
        handle.write(data)

    # -- requests ----------------------------------------------------------

    def _stick_name(self, value: Any) -> str:
        if not isinstance(value, str) or not STICK_NAME.fullmatch(value):
            raise ServerError('Invalid USB stick.', 400)
        if not self.is_stick(value):
            raise ServerError('The USB stick is no longer available.', 404)
        return value

    def _check_busy(self) -> None:
        job = self.job
        if (job is not None and job['state'] in ACTIVE) or self._ejecting:
            raise JobBusy('A USB job is already running.',
                          job['id'] if job else '')

    async def _handle_copy(self, request: WebRequest) -> Dict[str, Any]:
        self.ensure_root()
        direction = request.get('direction', None)
        if direction not in ('to_printer', 'to_usb'):
            raise ServerError('direction must be to_printer or to_usb.', 400)
        stick = self._stick_name(request.get('stick', None))
        items = request.get('items', None)
        if (not isinstance(items, list) or not items or len(items) > MAX_ITEMS
                or not all(isinstance(i, str) for i in items)):
            raise ServerError('items must be a non-empty list of paths.', 400)
        on_conflict = request.get('on_conflict', 'rename')
        if on_conflict not in CONFLICTS:
            raise ServerError('on_conflict must be rename, skip or replace.', 400)
        dest = request.get('dest', None)
        if dest is not None and not isinstance(dest, str):
            raise ServerError('Invalid dest.', 400)
        self._check_busy()
        req = {'direction': direction, 'stick': stick, 'items': items,
               'on_conflict': on_conflict}
        if direction == 'to_printer':
            for item in items:
                parts = self.parts(item)
                if not parts or parts[0] != stick:
                    raise ServerError('Items must be on the chosen stick.', 400)
            req['dest_parts'] = (clean_segments(dest) if dest
                                 else ['usb-import', stick])
            req['src_parts'] = [self.parts(i) for i in items]
        else:
            req['src_parts'] = []
            for item in items:
                req['src_parts'].append([] if item == '/' else clean_segments(item))
            if dest:
                parts = self.parts(dest)
                if not parts or parts[0] != stick:
                    raise ServerError('dest must be on the chosen stick.', 400)
            else:
                parts = [stick]
            req['dest_parts'] = parts[1:]
        job = {'id': uuid.uuid4().hex, 'direction': direction, 'stick': stick,
               'state': 'queued', 'files_total': 0, 'files_done': 0,
               'bytes_total': 0, 'bytes_done': 0, 'current': None,
               'skipped': [], 'errors': [], 'items': [],
               'started_at': None, 'ended_at': None, '_last': -1}
        self._cancel.clear()
        self._debt = 0.0
        with self._lock:
            self.job = job
        loop = asyncio.get_running_loop()
        self.task = loop.create_task(self._run_job(job, req))
        return {'job_id': job['id']}

    async def _handle_job(self, request: WebRequest) -> Optional[Dict[str, Any]]:
        return self.job_snapshot(full=True)

    def cancel_job(self, job_id: str) -> None:
        job = self.job
        if job is None or job['id'] != job_id:
            raise ServerError('No such USB job.', 404)
        if job['state'] in ACTIVE:
            self._cancel.set()

    async def _handle_job_cancel(self, request: WebRequest) -> Dict[str, Any]:
        job_id = request.get_str('job_id')
        self.cancel_job(job_id)
        return {'job_id': job_id}

    async def _handle_eject(self, request: WebRequest) -> Dict[str, Any]:
        stick = request.get_str('stick')
        self._check_busy()
        stick = self._stick_name(stick)
        info = self.mount_info().get(stick)
        if info is None or not DEVICE_NAME.fullmatch(info['dev']):
            raise ServerError('The USB device is not known.', 404)
        loop = asyncio.get_running_loop()
        self._ejecting = True
        try:
            await loop.run_in_executor(None, getattr(os, 'sync', lambda: None))
            await self._db_machine().do_service_action(
                'stop', self.mount_unit(info['dev']))
            deadline = loop.time() + self.eject_timeout
            while self.is_stick(stick):
                if loop.time() > deadline:
                    raise ServerError('The USB stick could not be unmounted.', 504)
                await asyncio.sleep(0.1)
        finally:
            self._ejecting = False
        self.ejected[stick] = {'dev': info['dev'], 'at': time.time()}
        return {'stick': stick, 'ejected': True}

    # -- read-write window -------------------------------------------------

    async def _wait_rw(self, stick: str, want: bool) -> bool:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.rw_timeout
        while True:
            info = self.mount_info().get(stick)
            if (info is None and not want) or (info is not None and info['rw'] == want):
                return True
            if loop.time() >= deadline:
                return False
            await asyncio.sleep(min(0.2, max(0.01, self.rw_timeout / 10)))

    async def _enter_rw(self, stick: str) -> str:
        """Remount the stick rw. Returns '' or the failure reason."""
        info = self.mount_info().get(stick)
        if info is None:
            return 'stick_removed'
        if self.stick_read_only(info):
            return 'read_only'
        dev = info['dev']
        try:
            await self._db_machine().do_service_action('start', self.rw_unit(dev))
            ok = await self._wait_rw(stick, True)
        except Exception:
            logging.exception('USB rw remount failed')
            ok = False
        if not ok:
            self._ro_devs.add(dev)
            await self._leave_rw(stick, dev)
            return 'read_only'
        self._rw_stick = stick
        return ''

    async def _leave_rw(self, stick: str, dev: Optional[str] = None) -> None:
        self._rw_stick = None
        if dev is None:
            info = self.mount_info().get(stick)
            dev = info['dev'] if info else self._dev_hint
        if not dev:
            return
        try:
            await self._db_machine().do_service_action('stop', self.rw_unit(dev))
            if not await self._wait_rw(stick, False):
                logging.error('USB stick %s did not return to read-only', stick)
        except Exception:
            logging.exception('USB ro remount failed')

    _dev_hint: Optional[str] = None

    # -- the job -------------------------------------------------------------

    async def _run_job(self, job: Dict[str, Any], req: Dict[str, Any]) -> None:
        loop = asyncio.get_running_loop()
        stick = req['stick']
        outcome = 'done'
        rw = False
        thread_done: Optional[asyncio.Future] = None
        try:
            if req['direction'] == 'to_usb':
                info = self.mount_info().get(stick)
                self._dev_hint = info['dev'] if info else None
                reason = await self._enter_rw(stick)
                if reason:
                    self._fail(job, '', reason)
                    outcome = 'failed'
                else:
                    rw = True
            if outcome == 'done':
                with self._lock:
                    job['state'] = 'running'
                    job['started_at'] = time.time()
                self._touch()
                thread_done = loop.create_future()
                threading.Thread(target=self._thread_main, daemon=True,
                                 args=(job, req, loop, thread_done)).start()
                last = 0.0
                while not thread_done.done():
                    await asyncio.wait({thread_done}, timeout=0.2)
                    now = loop.time()
                    if job.get('_dirty') and now - last >= self.notify_interval:
                        last = now
                        self._notify()
                outcome = thread_done.result()
        except asyncio.CancelledError:
            self._cancel.set()
            outcome = 'cancelled'
            if thread_done is not None:
                with contextlib.suppress(Exception):
                    await asyncio.wait({thread_done}, timeout=10)
            raise
        except Exception:
            logging.exception('USB copy job failed')
            self._fail(job, '', 'write_error')
            outcome = 'failed'
        finally:
            if rw:
                await self._leave_rw(stick)
            with self._lock:
                job['state'] = outcome
                job['ended_at'] = time.time()
                job['current'] = None
            self._notify()

    def _fail(self, job: Dict[str, Any], path: str, reason: str) -> None:
        with self._lock:
            job['errors'].append({'path': path, 'reason': reason})
        self._touch()

    def _thread_main(self, job: Dict[str, Any], req: Dict[str, Any],
                     loop: asyncio.AbstractEventLoop, done: asyncio.Future) -> None:
        idle_io()
        try:
            outcome = self._work(job, req)
        except BaseException:
            logging.exception('USB copy worker failed')
            self._fail(job, '', 'write_error')
            outcome = 'failed'
        with contextlib.suppress(RuntimeError):
            loop.call_soon_threadsafe(
                lambda: done.done() or done.set_result(outcome))

    # -- planning ------------------------------------------------------------

    def _gcodes(self) -> Path:
        fm = self.server.lookup_component('file_manager')
        gcodes = fm.get_directory('gcodes') if fm else ''
        if not gcodes:
            raise CopyError('write_error', True)
        return Path(gcodes)

    def _walk(self, shown: str, real: Path, rel: List[str], depth_ok: Any,
              out: List[Dict[str, Any]], seen: set) -> None:
        try:
            with os.scandir(real) as entries:
                listing = sorted(entries, key=lambda e: e.name)
        except OSError:
            return
        for entry in listing:
            if entry.name.startswith('.') or entry.is_symlink():
                continue
            child_rel = rel + [entry.name]
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISDIR(info.st_mode):
                if depth_ok(child_rel):
                    self._walk(shown + '/' + entry.name if shown else entry.name,
                               Path(entry.path), child_rel, depth_ok, out, seen)
            elif (stat.S_ISREG(info.st_mode)
                  and Path(entry.name).suffix.lower() in VALID_GCODE_EXTS):
                self._add_entry(out, seen, shown, entry.name, Path(entry.path),
                                child_rel, info.st_size)

    @staticmethod
    def _add_entry(out: List[Dict[str, Any]], seen: set, shown: str, name: str,
                   real: Path, rel: List[str], size: int) -> None:
        if str(real) in seen:
            return
        seen.add(str(real))
        out.append({'path': (shown + '/' + name) if shown else name,
                    'real': real, 'rel': rel, 'size': size})

    def _plan(self, req: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        entries: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        seen: set = set()
        for item, parts in zip(req['items'], req['src_parts']):
            if req['direction'] == 'to_printer':
                shown = 'usb/' + '/'.join(parts)
                try:
                    target = self.resolve(shown)
                except ServerError:
                    skipped.append({'path': shown, 'reason': 'read_error'})
                    continue
                rel = parts[1:]
                if target.is_dir():
                    base = shown
                    self._walk(base, target, rel, lambda r: len(r) + 1 <= MAX_DEPTH,
                               entries, seen)
                elif Path(parts[-1]).suffix.lower() in VALID_GCODE_EXTS:
                    self._add_entry(entries, seen, shown.rsplit('/', 1)[0],
                                    parts[-1], target, rel, target.stat().st_size)
                else:
                    skipped.append({'path': shown, 'reason': 'name_invalid'})
            else:
                base = self._gcodes()
                target = base.joinpath(*parts)
                shown = '/'.join(parts)
                bad = False
                current = base
                for part in parts:
                    current = current / part
                    if current.is_symlink():
                        bad = True
                if bad or not target.exists():
                    skipped.append({'path': shown or '/', 'reason': 'read_error'})
                elif target.is_dir():
                    self._walk(shown, target, list(parts),
                               lambda r: len(r) <= MAX_DEPTH, entries, seen)
                elif Path(parts[-1]).suffix.lower() in VALID_GCODE_EXTS:
                    self._add_entry(entries, seen, '/'.join(parts[:-1]), parts[-1],
                                    target, list(parts), target.stat().st_size)
                else:
                    skipped.append({'path': shown, 'reason': 'name_invalid'})
        return entries, skipped

    # -- the worker ------------------------------------------------------------

    def _work(self, job: Dict[str, Any], req: Dict[str, Any]) -> str:
        to_usb = req['direction'] == 'to_usb'
        stick = req['stick']
        entries, skipped = self._plan(req)
        dest_parts: List[str] = req['dest_parts']
        vfat = (self.mount_info().get(stick) or {}).get('fs') == 'vfat'
        items: List[Dict[str, Any]] = []
        eligible: List[Dict[str, Any]] = []
        for entry in entries:
            if to_usb:
                full_rel = dest_parts + entry['rel']
                dest_shown = '/'.join(['usb', stick] + full_rel)
            else:
                full_rel = dest_parts + entry['rel']
                dest_shown = '/'.join(full_rel)
            item = {'path': entry['path'], 'dest': dest_shown,
                    'bytes_total': entry['size'], 'bytes_done': 0,
                    'state': 'pending', 'error': None}
            reason = None
            if to_usb:
                if any(fat_name_problem(p) for p in full_rel):
                    reason = 'name_invalid'
                elif len(full_rel) - 1 > MAX_DEPTH:
                    reason = 'name_invalid'
                elif vfat and entry['size'] > FAT_MAX_FILE:
                    reason = 'too_large'
            if reason:
                item.update(state='skipped', error=reason)
                skipped.append({'path': entry['path'], 'reason': reason})
            else:
                eligible.append(entry)
                entry['index'] = len(items)
                entry['full_rel'] = full_rel
            items.append(item)
        with self._lock:
            job['items'] = items
            job['skipped'] = skipped
            job['files_total'] = len(eligible)
            job['bytes_total'] = sum(e['size'] for e in eligible)
        self._touch()
        gcodes = self._gcodes()
        base = self.root / stick if to_usb else gcodes
        outcome = 'done'
        for position, entry in enumerate(eligible):
            index = entry['index']
            try:
                if self._cancel.is_set():
                    raise Cancelled()
                self._copy_file(job, entry, req, base, index)
            except Cancelled:
                self._mark_rest(job, eligible[position:], 'cancelled')
                outcome = 'cancelled'
                break
            except CopyError as err:
                self._set_item(job, index, 'failed', err.reason)
                self._fail(job, entry['path'], err.reason)
                if err.fatal:
                    self._mark_rest(job, eligible[position + 1:], 'cancelled')
                    outcome = 'failed'
                    break
        return outcome

    def _mark_rest(self, job: Dict[str, Any], rest: List[Dict[str, Any]],
                   reason: str) -> None:
        with self._lock:
            for entry in rest:
                item = job['items'][entry['index']]
                if item['state'] in ('pending', 'copying'):
                    item['state'] = 'cancelled'
                    item['error'] = reason
        self._touch()

    def _set_item(self, job: Dict[str, Any], index: int, state: str,
                  error: Optional[str] = None) -> None:
        with self._lock:
            job['items'][index]['state'] = state
            job['items'][index]['error'] = error
        self._touch(index)

    def _skip_item(self, job: Dict[str, Any], entry: Dict[str, Any], reason: str) -> None:
        with self._lock:
            item = job['items'][entry['index']]
            item.update(state='skipped', error=reason)
            job['files_total'] -= 1
            job['bytes_total'] -= entry['size']
            job['skipped'].append({'path': entry['path'], 'reason': reason})
        self._touch(entry['index'])

    def _classify(self, err: OSError, stick: str) -> CopyError:
        if err.errno == errno.ENOSPC:
            return CopyError('no_space', True)
        if err.errno == errno.EROFS:
            return CopyError('read_only', True)
        if not self.is_stick(stick):
            return CopyError('stick_removed', True)
        return CopyError('read_error')

    def _make_dir(self, base: Path, parts: List[str]) -> Path:
        current = base
        for part in parts:
            current = current / part
            if current.is_symlink():
                raise CopyError('write_error')
            try:
                current.mkdir(exist_ok=True)
            except OSError as err:
                raise CopyError('read_only' if err.errno == errno.EROFS
                                else 'write_error', err.errno == errno.EROFS)
            if not current.is_dir():
                raise CopyError('write_error')
        return current

    def _copy_file(self, job: Dict[str, Any], entry: Dict[str, Any],
                   req: Dict[str, Any], base: Path, index: int) -> None:
        to_usb = req['direction'] == 'to_usb'
        stick = req['stick']
        self._set_item(job, index, 'copying')
        with self._lock:
            job['current'] = entry['path']
        try:
            source = (open(entry['real'], 'rb') if to_usb
                      else self.open_gcode(entry['path']))
        except ServerError:
            raise CopyError('stick_removed' if not self.is_stick(stick)
                            else 'read_error', not self.is_stick(stick))
        except OSError as err:
            raise self._classify(err, stick)
        temp: Optional[Path] = None
        try:
            with source:
                before = os.fstat(source.fileno())
                size = before.st_size
                with self._lock:
                    job['bytes_total'] += size - entry['size']
                    job['items'][index]['bytes_total'] = size
                if to_usb:
                    if self.free_space(base) < size + MARGIN:
                        raise CopyError('no_space', True)
                elif self.free_space(base) < size + HEADROOM:
                    raise CopyError('no_space', True)
                full_rel = entry['full_rel']
                folder = self._make_dir(base, full_rel[:-1])
                name = full_rel[-1]
                final = folder / name
                exists = os.path.lexists(final)
                if exists and req['on_conflict'] == 'skip':
                    return self._skip_item(job, entry, 'exists')
                if exists and (final.is_dir() or final.is_symlink()):
                    return self._skip_item(job, entry, 'name_invalid')
                if not exists or req['on_conflict'] == 'rename':
                    with os.scandir(folder) as scan:
                        count = sum(1 for _ in scan)
                    if count >= MAX_FOLDER_ENTRIES:
                        return self._skip_item(job, entry, 'folder_full')
                if exists and req['on_conflict'] == 'rename':
                    stem, suffix = Path(name).stem, Path(name).suffix
                    number = 1
                    while os.path.lexists(folder / f'{stem} ({number}){suffix}'):
                        number += 1
                    name = f'{stem} ({number}){suffix}'
                    final = folder / name
                    with self._lock:
                        job['items'][index]['dest'] = (
                            job['items'][index]['dest'].rsplit('/', 1)[0] + '/' + name)
                temp = folder / ('.usb-' + uuid.uuid4().hex)
                done = 0
                try:
                    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                except OSError as err:
                    raise self._classify(err, stick) if err.errno != errno.EACCES \
                        else CopyError('write_error')
                with os.fdopen(fd, 'wb') as output:
                    while True:
                        if self._cancel.is_set():
                            raise Cancelled()
                        try:
                            data = self._read(source, self.chunk)
                        except OSError as err:
                            raise self._classify(err, stick)
                        if not data:
                            break
                        try:
                            self._write(output, data)
                        except OSError as err:
                            if err.errno in (errno.ENOSPC, errno.EROFS):
                                raise self._classify(err, stick)
                            raise (CopyError('stick_removed', True)
                                   if not self.is_stick(stick)
                                   else CopyError('write_error'))
                        done += len(data)
                        with self._lock:
                            job['bytes_done'] += len(data)
                            job['items'][index]['bytes_done'] = done
                        self._touch(index)
                        self._pace(len(data))
                    output.flush()
                    os.fsync(output.fileno())
                try:
                    after = (entry['real'].stat() if to_usb
                             else self.resolve(entry['path']).stat())
                except (OSError, ServerError):
                    raise CopyError('stick_removed' if not self.is_stick(stick)
                                    else 'source_changed',
                                    not self.is_stick(stick))
                if (done != size or after.st_size != size
                        or after.st_mtime_ns != before.st_mtime_ns):
                    raise CopyError('source_changed')
                try:
                    os.replace(temp, final)
                    temp = None
                    with contextlib.suppress(OSError):
                        dir_fd = os.open(folder, os.O_RDONLY)
                        try:
                            os.fsync(dir_fd)
                        finally:
                            os.close(dir_fd)
                except OSError as err:
                    raise self._classify(err, stick)
            with self._lock:
                job['files_done'] += 1
            self._set_item(job, index, 'done')
        except Cancelled:
            with self._lock:
                with contextlib.suppress(Exception):
                    job['bytes_done'] -= job['items'][index]['bytes_done']
                    job['items'][index]['bytes_done'] = 0
            raise
        finally:
            if temp is not None:
                with contextlib.suppress(OSError):
                    os.unlink(temp)

    # ------------------------------------------------------------------
    # handlers
    # ------------------------------------------------------------------

    async def on_exit(self) -> None:
        # Moonraker stopping mid-copy: the job's finally block returns the stick
        # to read-only before the process goes (the rw unit also BindsTo us).
        task = self.task
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def _handle_status(self, request: WebRequest) -> Dict[str, Any]:
        self.ensure_root()
        return await self.server.get_event_loop().run_in_thread(self.status)

    async def _handle_list(self, request: WebRequest) -> Dict[str, Any]:
        self.ensure_root()
        return await self.server.get_event_loop().run_in_thread(
            self.listing, request.get_str('path'),
            request.get_int('offset', 0), request.get_int('limit', DEFAULT_LIMIT))

    async def _handle_metadata(self, request: WebRequest) -> Dict[str, Any]:
        self.ensure_root()
        return await self.server.get_event_loop().run_in_thread(
            self.metadata, request.get_str('path'))

    async def _handle_print(self, request: WebRequest) -> Dict[str, Any]:
        async with self._print_lock:
            self.check_ready()
            path = request.get_str('path')
            try:
                with self.open_gcode(path):
                    pass
            except OSError:
                raise ServerError(REMOVED, 404)
            filename = await self.server.get_event_loop().run_in_thread(self.copy, path)
            self.check_ready()
            await self.server.lookup_component('klippy_apis').start_print(filename)
            return {'filename': filename}


def load_component(config: ConfigHelper) -> MuonUSB:
    return MuonUSB(config)
