# MUON: read-only removable storage; copy locally before the safety-gated print.
from __future__ import annotations

import asyncio
import contextlib
import errno
import json
import os
import re
import shutil
import stat
import uuid
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, BinaryIO, Dict, List

from ..common import RequestType
from ..utils.exceptions import ServerError
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


class MuonUSB:
    def __init__(self, config: ConfigHelper) -> None:
        self.server = config.get_server()
        self.root = Path(self.server.get_app_args()['data_path']) / 'usb'
        self.rejected = Path(config.get('rejected_path', '/run/muon-usb/rejected'))
        self._print_lock = asyncio.Lock()
        self.cleanup_temporaries()
        self.ensure_root()
        for name in ('status', 'list', 'metadata', 'print'):
            self.server.register_endpoint(
                '/server/muon/usb/' + name,
                RequestType.POST if name == 'print' else RequestType.GET,
                getattr(self, '_handle_' + name))

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

    def listing(self, path: str) -> Dict[str, Any]:
        target = self.resolve(path)
        if not target.is_dir():
            raise ServerError('The USB directory is no longer available.', 404)
        dirs: List[Dict[str, Any]] = []
        files: List[Dict[str, Any]] = []
        at_root = path == 'usb'
        truncated = False
        try:
            with os.scandir(target) as entries:
                for entry in entries:
                    if len(dirs) + len(files) >= MAX_FOLDER_ENTRIES:
                        truncated = True
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
                        if len(self.parts(path)) < MAX_DEPTH:
                            dirs.append(item)
                    elif (stat.S_ISREG(info.st_mode) and
                          Path(entry.name).suffix.lower() in VALID_GCODE_EXTS):
                        files.append(dict(item, size=info.st_size))
        except OSError:
            raise ServerError('The USB directory is no longer available.', 404)
        for group in (dirs, files):
            group.sort(key=lambda item: (-item['modified'], item['name']))
        return {'path': path, 'dirs': dirs, 'files': files, 'truncated': truncated}

    def file_list(self, list_format: bool = True) -> Any:
        result: Dict[str, Any] = {}
        pending = ['usb']
        while pending:
            listing = self.listing(pending.pop())
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

    def status(self) -> Dict[str, Any]:
        sticks = []
        if self.root.is_dir() and not self.root.is_symlink():
            try:
                sticks = [{'name': p.name, 'path': 'usb/' + p.name}
                          for p in self.root.iterdir()
                          if not p.name.startswith('.') and not p.is_symlink()
                          and p.is_dir() and self.is_stick(p.name)]
            except OSError:
                pass
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
                'rejected': sorted(rejected, key=lambda p: p['name'])}

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

    async def _handle_status(self, request: WebRequest) -> Dict[str, Any]:
        self.ensure_root()
        return await self.server.get_event_loop().run_in_thread(self.status)

    async def _handle_list(self, request: WebRequest) -> Dict[str, Any]:
        self.ensure_root()
        return await self.server.get_event_loop().run_in_thread(
            self.listing, request.get_str('path'))

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
