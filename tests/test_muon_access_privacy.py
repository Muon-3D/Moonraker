"""Privacy at history, notifications and the upload/write boundaries."""
import asyncio
import copy
import inspect
import json
from types import SimpleNamespace
from pathlib import Path

import pytest

from moonraker import muon_access_policy as policy
from moonraker import muon_floor
from moonraker.components import application
from moonraker.common import APIDefinition, RequestType
from moonraker.components.websockets import WebsocketManager
from moonraker.utils.exceptions import ServerError
from muon_access_fakes import printer, restart
from test_muon_access_drives import (
    ANA, BEN, ADMIN, HOME, PANEL, ANA_DRIVE, BEN_DRIVE,
    a_printer, listing, refused, request, upload,
)


@pytest.fixture(autouse=True)
def reset():
    yield
    policy.set_state(None)
    policy.set_files(None)
    muon_floor.set_protection_level(muon_floor.LEVEL_OPEN)


def clients():
    manager = WebsocketManager.__new__(WebsocketManager)
    manager.clients = {}
    messages = []
    for uid, who in enumerate((ANA, BEN, ADMIN, HOME, PANEL)):
        received = []
        transport, ip, user = who
        manager.clients[uid] = SimpleNamespace(
            uid=uid, need_auth=False, transport_type=transport.transport_type,
            ip_addr=ip, user_info=user, queue_message=received.append)
        messages.append(received)
    return manager, messages


@pytest.mark.parametrize("endpoint,key", [
    ("/server/history/list", "jobs"), ("/server/history/job", "job")])
@pytest.mark.parametrize("who", [BEN, ADMIN, HOME, PANEL])
def test_history_hides_name_metadata_and_thumbnails(endpoint, key, who):
    a_printer(private=True)
    upload("", "secret.gcode", ANA)
    job = {"filename": "secret.gcode", "job_id": "1", "total_duration": 42,
           "filament_used": 3, "exists": True,
           "metadata": {"filename": "secret.gcode", "thumbnails": [
               {"relative_path": ".thumbs/secret.png"}]}}
    result = {key: [job] if key == "jobs" else job, "count": 1}
    original = copy.deepcopy(result)
    out = request(endpoint, "GET", {}, who, result=result)
    hidden = out[key][0] if key == "jobs" else out[key]
    assert hidden["filename"] == "private file"
    assert "secret" not in json.dumps(out)
    assert hidden["total_duration"] == 42 and hidden["filament_used"] == 3
    assert result == original
    assert request(endpoint, "GET", {}, ANA, result=result) == original


def test_history_stays_private_after_move_delete_and_restart():
    access, server = a_printer(private=True)
    upload("", "secret.gcode", ANA)
    access._on_files_changed({"action": "move_file",
                             "item": {"root": "gcodes", "path": "moved.gcode"},
                             "source_item": {"root": "gcodes",
                                             "path": "secret.gcode"}})
    access._on_files_changed({"action": "delete_file",
                             "item": {"root": "gcodes", "path": "moved.gcode"}})
    asyncio.run(access.save_index())
    printer(server=restart(server))
    for filename in ("secret.gcode", "moved.gcode"):
        out = request("/server/history/job", "GET", {}, ADMIN,
                      result={"job": {"filename": filename}})
        assert out["job"]["filename"] == "private file"


@pytest.mark.parametrize("name", ["filelist_changed", "history_changed"])
def test_notifications_never_name_a_private_file_to_other_clients(name):
    a_printer(private=True)
    upload("", "secret.gcode", ANA)
    manager, messages = clients()
    info = ({"action": "create_file", "item": {"root": "gcodes",
                                                "path": "secret.gcode"}}
            if name == "filelist_changed" else
            {"action": "added", "job": {"filename": "secret.gcode",
                                         "metadata": {"filename": "secret.gcode"}}})
    manager.notify_clients(name, [info])
    assert "secret.gcode" in json.dumps(messages[0])
    for received in messages[1:]:
        assert "secret" not in json.dumps(received)


def test_public_file_notifications_still_reach_every_client():
    a_printer(private=True)
    manager, messages = clients()
    manager.notify_clients("filelist_changed", [
        {"action": "create_file", "item": {"root": "gcodes", "path": "open.gcode"}}])
    assert all("open.gcode" in json.dumps(m) for m in messages)


@pytest.mark.parametrize("name", [
    f"../../{BEN_DRIVE}/drop.gcode", f"../../{BEN_DRIVE}/drop.ufp"])
def test_complete_multipart_destination_cannot_escape_own_drive(name):
    a_printer("accounts", private=True)
    with pytest.raises(ServerError) as err:
        upload("", name, ANA)
    assert err.value.status_code == 403


@pytest.mark.parametrize("method", ["copy", "move", "zip"])
@pytest.mark.parametrize("dest", ["gcodes/secret.gcode", "gcodes/private"])
def test_operations_cannot_overwrite_private_destinations(method, dest):
    a_printer(private=True)
    upload("", "secret.gcode", ANA)
    upload("private", "nested.gcode", ANA)
    args = {"dest": dest, "source": "gcodes/public.gcode"}
    if method == "zip":
        args["items"] = ["gcodes/public.gcode"]
    assert refused(f"/server/files/{method}", "POST", args, BEN) == 404


def test_upload_cannot_overwrite_a_private_file():
    a_printer(private=True)
    upload("", "secret.gcode", ANA)
    with pytest.raises(ServerError) as err:
        upload("", "secret.gcode", BEN)
    assert err.value.status_code == 404


def test_copying_the_root_cannot_read_private_descendants():
    a_printer(private=True)
    upload("", "secret.gcode", ANA)
    assert refused("/server/files/copy", "POST",
                   {"source": "gcodes", "dest": "config/snapshot"}, BEN) == 404


def test_history_keeps_the_print_time_uploader_when_a_path_is_reused():
    from moonraker.components.history import History
    access, server = a_printer(private=True)
    upload("", "secret.gcode", ANA)
    history = History.__new__(History)
    history.server = server
    history.file_manager = SimpleNamespace(get_metadata_storage=lambda: {})
    history.current_job = SimpleNamespace(filename="secret.gcode", metadata={})
    history.grab_job_metadata()
    ana_job = {"filename": "secret.gcode", "metadata": history.current_job.metadata}
    access._on_files_changed({"action": "delete_file",
                             "item": {"root": "gcodes", "path": "secret.gcode"}})
    upload("", "secret.gcode", BEN)
    history.current_job = SimpleNamespace(filename="secret.gcode", metadata={})
    history.grab_job_metadata()
    ben_job = {"filename": "secret.gcode", "metadata": history.current_job.metadata}
    for who, own, other in ((ANA, ana_job, ben_job), (BEN, ben_job, ana_job)):
        out = request("/server/history/list", "GET", {}, who,
                      result={"jobs": [own, other]})
        assert out["jobs"][0]["filename"] == "secret.gcode"
        assert out["jobs"][1]["filename"] == "private file"


@pytest.mark.parametrize("name", ["secret-32x32.png", "secret.png"])
def test_direct_thumbnail_download_is_private(name):
    a_printer(private=True)
    upload("sub", "secret.gcode", ANA)
    for who in (BEN, ADMIN, HOME, PANEL):
        assert refused("/server/files/download", "GET",
                       {"path": f"gcodes/sub/.thumbs/{name}"}, who) == 404
    assert refused("/server/files/download", "GET",
                   {"path": f"gcodes/sub/.thumbs/{name}"}, ANA) is None


def test_case_insensitive_upload_root_keeps_privacy_and_routing():
    access, _ = a_printer("accounts", private=True)
    out = upload("", "secret.gcode", ANA, root="Gcodes")
    assert out["item"]["path"] == f"{ANA_DRIVE}/secret.gcode"
    assert out["private"] is True
    assert listing([out["item"]["path"]], ADMIN) == []


def test_upload_index_read_failure_denies_reads_and_preserves_admin_delete():
    access, server = a_printer(private=True)
    upload("", "secret.gcode", ANA)
    server.database.ns("muon_access_files").fail_get = True
    printer(server=restart(server))
    assert listing(["secret.gcode", "untagged.gcode"], ADMIN) == []
    for who in (ANA, ADMIN):
        assert refused("/server/files/download", "GET",
                       {"path": "gcodes/secret.gcode"}, who) == 404
    assert refused("/server/files/delete_file", "DELETE",
                   {"path": "gcodes/secret.gcode"}, ADMIN) is None


def test_private_upload_is_durable_before_acknowledgement():
    access, server = a_printer(private=True)
    upload("", "secret.gcode", ANA)
    # No manual save and no outstanding background task may be needed.
    printer(server=restart(server))
    assert listing(["secret.gcode"], ADMIN) == []


def test_index_write_failure_refuses_private_upload():
    access, server = a_printer(private=True)
    server.database.ns("muon_access_files").fail_insert = True
    with pytest.raises(ServerError) as err:
        upload("", "secret.gcode", ANA)
    assert err.value.status_code == 500


def test_upload_handler_reserves_private_tag_before_file_is_published():
    post = inspect.getsource(application.FileUploadHandler.post)
    assert "await muon_access_policy.prepare_upload" in post
    assert post.index("prepare_upload") < post.index("finalize_upload")


@pytest.mark.parametrize("method", ["copy", "move", "zip"])
def test_private_operation_tag_precedes_its_first_notification(method):
    a_printer(private=True)
    upload("", "secret.gcode", ANA)
    endpoint = f"/server/files/{method}"
    args = {"source": "gcodes/secret.gcode", "dest": "gcodes/new.gcode"}
    if method == "zip":
        args["items"] = ["gcodes/secret.gcode"]
    manager, messages = clients()

    async def publish(web_request):
        if hasattr(policy, "prepare_file_operation"):
            await policy.prepare_file_operation(web_request, args)
        manager.notify_clients("filelist_changed", [
            {"action": "create_file", "item": {"root": "gcodes",
                                                "path": "new.gcode"}}])
        return {"item": {"root": "gcodes", "path": "new.gcode"}}
    APIDefinition._cache.pop(endpoint, None)
    api = APIDefinition.create(endpoint, ["POST"], publish)
    asyncio.run(api.request(args, RequestType.POST, *ANA))
    assert "new.gcode" in json.dumps(messages[0])
    assert all("new.gcode" not in json.dumps(m) for m in messages[1:])
    source = (Path(application.__file__).parent / "file_manager" /
              "file_manager.py").read_text()
    assert source.count("await muon_access_policy.prepare_file_operation") == 2
