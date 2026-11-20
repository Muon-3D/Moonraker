from __future__ import annotations

import asyncio
import configparser
import gzip
import hashlib
import os
import re
import threading
from pathlib import Path
from typing import Any, Dict, List

import pytest
import tornado.httpclient
import tornado.httpserver
import tornado.netutil
import tornado.web

from moonraker import muon_access_policy as policy
from moonraker.common import RequestType
from moonraker.components import muon_panel
from moonraker.utils.exceptions import ServerError

HTML = (b'<!doctype html><meta http-equiv="Content-Security-Policy" '
        b"content=\"default-src 'self'\"><title>panel</title>"
        + b"<p>muon</p>" * 2000)
GZIP = gzip.compress(HTML, 9, mtime=0)


class EventLoop:
    def __init__(self) -> None:
        self.threads: List[threading.Thread] = []

    async def run_in_thread(self, callback: Any, *args: Any) -> Any:
        def call() -> Any:
            self.threads.append(threading.current_thread())
            return callback(*args)
        return await asyncio.get_running_loop().run_in_executor(None, call)


class App:
    def __init__(self) -> None:
        self.routes: List[Any] = []

    def register_handler(self, pattern: str, handler: Any,
                         params: Any = None) -> None:
        self.routes.append((pattern, handler, params))


class Server:
    error = ServerError

    def __init__(self) -> None:
        self.app = App()
        self.loop = EventLoop()

    def lookup_component(self, name: str, default: Any = None) -> Any:
        return self.app if name == 'application' else default

    def get_event_loop(self) -> EventLoop:
        return self.loop

    def is_verbose_enabled(self) -> bool:
        return False

    def register_endpoint(self, *args: Any, **kwargs: Any) -> None:
        pass

    def register_event_handler(self, *args: Any) -> None:
        pass


class Config:
    def __init__(self, server: Server, path: Path) -> None:
        self.server = server
        self.path = path

    def get_server(self) -> Server:
        return self.server

    def get(self, key: str, default: Any = None) -> Any:
        return str(self.path) if key == 'path' else default


class Client:
    def __init__(self, base: str) -> None:
        self.base = base

    async def fetch(self, method: str = 'GET', path: str = muon_panel.ENDPOINT,
                    **headers: str) -> Any:
        headers = {k.replace('_', '-'): v for k, v in headers.items()}
        http = tornado.httpclient.AsyncHTTPClient()
        return await http.fetch(
            self.base + path, method=method, raise_error=False,
            headers=headers, decompress_response=False,
            body=b'' if method in ('POST', 'PUT') else None)


@pytest.fixture
def panel_file(tmp_path: Path) -> Path:
    path = tmp_path / 'index.html'
    path.write_bytes(HTML)
    return path


def run(path: Path, scenario: Any) -> Any:
    async def main() -> Any:
        server = Server()
        panel = muon_panel.load_component(Config(server, path))  # type: ignore
        pattern, handler, params = server.app.routes[0]
        web = tornado.web.Application(
            [(pattern, handler, params)], server=server, serve_traceback=False)
        sockets = tornado.netutil.bind_sockets(0, '127.0.0.1')
        http = tornado.httpserver.HTTPServer(web)
        http.add_sockets(sockets)
        client = Client(f'http://127.0.0.1:{sockets[0].getsockname()[1]}')
        try:
            return await scenario(server, panel, client)
        finally:
            http.stop()
            await http.close_all_connections()
    return asyncio.run(main())


def test_200_with_headers(panel_file: Path) -> None:
    digest = hashlib.sha256(HTML).hexdigest()

    async def scenario(server: Any, panel: Any, client: Client) -> Any:
        return await client.fetch(Accept_Encoding='identity')
    res = run(panel_file, scenario)
    assert res.code == 200
    assert res.body == HTML
    h = res.headers
    assert h['Content-Type'] == 'text/html; charset=utf-8'
    assert h['ETag'] == f'"{digest[:32]}"'
    assert h['X-Muon-Panel-Version'] == digest[:12]
    assert h['Cache-Control'] == 'no-cache'
    assert h['X-Content-Type-Options'] == 'nosniff'
    assert h['Vary'] == 'Accept-Encoding'
    assert 'Content-Security-Policy' not in h
    assert 'Content-Encoding' not in h


def test_query_string_is_ignored(panel_file: Path) -> None:
    async def scenario(server: Any, panel: Any, client: Client) -> Any:
        return await client.fetch(
            path=muon_panel.ENDPOINT + '?path=/etc/passwd',
            Accept_Encoding='identity')
    assert run(panel_file, scenario).body == HTML


def test_head_has_no_body(panel_file: Path) -> None:
    async def scenario(server: Any, panel: Any, client: Client) -> Any:
        return await client.fetch('HEAD')
    res = run(panel_file, scenario)
    assert res.code == 200
    assert not res.body
    assert res.headers['ETag'].startswith('"')
    assert int(res.headers['Content-Length']) > 0


def test_if_none_match_gives_304(panel_file: Path) -> None:
    async def scenario(server: Any, panel: Any, client: Client) -> Any:
        first = await client.fetch()
        etag = first.headers['ETag']
        hit = await client.fetch(If_None_Match=etag)
        weak = await client.fetch(If_None_Match='W/' + etag)
        miss = await client.fetch(If_None_Match='"other"')
        return hit, weak, miss
    hit, weak, miss = run(panel_file, scenario)
    for res in (hit, weak):
        assert res.code == 304
        assert not res.body
        assert res.headers['ETag']
        assert res.headers['Cache-Control'] == 'no-cache'
    assert miss.code == 200


def test_gzip_round_trips(panel_file: Path) -> None:
    async def scenario(server: Any, panel: Any, client: Client) -> Any:
        return await client.fetch(Accept_Encoding='gzip, deflate')
    res = run(panel_file, scenario)
    assert res.headers['Content-Encoding'] == 'gzip'
    assert res.headers['Vary'] == 'Accept-Encoding'
    assert len(res.body) < len(HTML)
    assert gzip.decompress(res.body) == HTML
    assert res.headers['ETag'] == f'"{hashlib.sha256(HTML).hexdigest()[:32]}"'


def test_gzip_q_values() -> None:
    assert muon_panel.accepts_gzip('gzip, br')
    assert not muon_panel.accepts_gzip('gzip;q=0, br')
    assert not muon_panel.accepts_gzip('br')


def test_cache_reused_then_refreshed_on_mtime(panel_file: Path) -> None:
    new = HTML.replace(b'muon', b'MUON')  # same size

    async def scenario(server: Any, panel: Any, client: Client) -> Any:
        a = await client.fetch()
        page_a = panel._page
        await client.fetch()
        assert panel._page is page_a  # unchanged file: same cached object
        panel_file.write_bytes(new)
        st = panel_file.stat()
        os.utime(panel_file, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
        b = await client.fetch(Accept_Encoding='identity')
        return a, b
    a, b = run(panel_file, scenario)
    assert a.headers['ETag'] != b.headers['ETag']
    assert b.body == new


def test_refreshes_when_size_changes(panel_file: Path) -> None:
    async def scenario(server: Any, panel: Any, client: Client) -> Any:
        await client.fetch()
        st = panel_file.stat()
        panel_file.write_bytes(HTML + b'x')
        os.utime(panel_file, ns=(st.st_atime_ns, st.st_mtime_ns))
        return await client.fetch(Accept_Encoding='identity')
    assert run(panel_file, scenario).body == HTML + b'x'


def test_missing_file_is_404_json(tmp_path: Path) -> None:
    async def scenario(server: Any, panel: Any, client: Client) -> Any:
        return await client.fetch()
    res = run(tmp_path / 'nope.html', scenario)
    assert res.code == 404
    assert b'Traceback' not in res.body
    assert b'"error"' in res.body


def test_symlink_is_refused(tmp_path: Path, panel_file: Path) -> None:
    link = tmp_path / 'link.html'
    try:
        link.symlink_to(panel_file)
    except (OSError, NotImplementedError):
        pytest.skip('symlinks unavailable')

    async def scenario(server: Any, panel: Any, client: Client) -> Any:
        return await client.fetch()
    res = run(link, scenario)
    assert res.code == 500
    assert b'Traceback' not in res.body


def test_directory_is_refused(tmp_path: Path) -> None:
    async def scenario(server: Any, panel: Any, client: Client) -> Any:
        return await client.fetch()
    assert run(tmp_path, scenario).code == 500


def test_oversize_is_refused(tmp_path: Path, monkeypatch: Any) -> None:
    big = tmp_path / 'big.html'
    big.write_bytes(b'a' * 1024)
    monkeypatch.setattr(muon_panel, 'MAX_BYTES', 1000)

    async def scenario(server: Any, panel: Any, client: Client) -> Any:
        return await client.fetch()
    res = run(big, scenario)
    assert res.code == 500
    assert b'Traceback' not in res.body


def test_other_methods_are_refused(panel_file: Path) -> None:
    async def scenario(server: Any, panel: Any, client: Client) -> Any:
        return [await client.fetch(m) for m in ('POST', 'PUT', 'DELETE')]
    assert [r.code for r in run(panel_file, scenario)] == [405, 405, 405]


def test_work_runs_off_the_event_loop(panel_file: Path) -> None:
    async def scenario(server: Any, panel: Any, client: Client) -> Any:
        await client.fetch()
        return server.loop.threads
    threads = run(panel_file, scenario)
    assert threads
    assert all(t is not threading.main_thread() for t in threads)


def test_event_loop_stays_responsive_while_loading(
        panel_file: Path, monkeypatch: Any) -> None:
    gate = threading.Event()
    real = muon_panel.load_page

    def slow(path: str, cached: Any) -> Any:
        gate.wait(5)
        return real(path, cached)
    monkeypatch.setattr(muon_panel, 'load_page', slow)

    async def scenario(server: Any, panel: Any, client: Client) -> Any:
        task = asyncio.ensure_future(client.fetch())
        for _ in range(5):
            await asyncio.sleep(0.01)
        assert not task.done()  # parked in the executor; the loop kept ticking
        gate.set()
        return await task
    assert run(panel_file, scenario).code == 200


def test_route_pattern() -> None:
    server = Server()
    muon_panel.load_component(Config(server, Path('x')))  # type: ignore
    pattern = server.app.routes[0][0]
    assert re.fullmatch(pattern, '/server/muon/panel/index.html')
    assert not re.fullmatch(pattern, '/server/muon/panel/indexXhtml')


def test_access_classification_is_a_read() -> None:
    names = [a.name for a in policy.classify(muon_panel.ENDPOINT,
                                             RequestType.GET)]
    assert names == ['read']
    home = policy.HomeNetwork.from_interface_addresses(
        policy.interface_addresses([{"ifname": "wlan0", "addr_info": [
            {"family": "inet", "local": "192.168.1.10", "prefixlen": 24}]}]))
    action = policy.ACTIONS['read']
    viewer = policy.Principal('gateway', 'g', 1, 'viewer', False, True)
    guest: Dict[str, Any] = {}
    for entry in (policy.ENTRY_OPEN, policy.ENTRY_PROTECTED):
        state = policy.AccessState(
            entry=entry, owner=policy.OWNER_ORGANISATION, home=home)
        assert policy.decide_action(action, viewer, state).allowed
        guest[entry] = policy.decide_action(
            action, policy.Principal('home', 'h', 1, 'operator', True, False),
            state).allowed
    assert guest[policy.ENTRY_OPEN]


def test_m1_config_enables_component() -> None:
    config = configparser.ConfigParser(interpolation=None)
    config.read(Path(__file__).resolve().parents[1] /
                'core/M1/moonraker.core.conf.template')
    assert config.has_section('muon_panel')
    assert config.get('muon_panel', 'path') == '/usr/share/muon-panel/index.html'
