"""AB-MR-3: drives and private uploads (ACC-29 to ACC-34).

Requests go through APIDefinition.request with a stub handler that returns
what file_manager would, so the table, the file checks and the listing
filter all run as they do for a real client. Uploads go through the same
plan/finish calls application.FileUploadHandler makes.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import pytest

from moonraker import muon_access_files as files
from moonraker import muon_access_policy as policy
from moonraker import muon_floor
from moonraker.common import APIDefinition, RequestType
from moonraker.utils.exceptions import ServerError

from muon_access_fakes import Link, caller, printer, restart

ANA = caller({"kind": "gateway", "level": "signed-in-guest", "role": "operator",
              "home": True, "principal": "acct:ana@example.com"})
BEN = caller({"kind": "gateway", "level": "signed-in-guest", "role": "operator",
              "home": True, "principal": "acct:ben@example.com"})
ADMIN = caller({"kind": "gateway", "level": "admin", "role": "operator",
                "home": True, "principal": "device:sam-phone"})
GUEST_DEVICE = caller({"kind": "gateway", "level": "signed-out-guest",
                       "role": "operator", "home": True,
                       "principal": "device:visitor"})
HOME = caller({"kind": "home"})
PASSWORD = caller({"kind": "password"})
PANEL = caller({"kind": "panel"})

ANA_DRIVE = "a/acct_ana@example.com"
BEN_DRIVE = "a/acct_ben@example.com"


@pytest.fixture(autouse=True)
def _reset():
    yield
    policy.set_state(None)
    policy.set_files(None)
    muon_floor.set_protection_level(muon_floor.LEVEL_OPEN)


def a_printer(mode: str = "shared", private: bool = False,
              owner: str = "none", entry: str = "open") -> Any:
    link = (Link("linked", "sam@example.com") if owner == "account"
            else Link("unlinked"))
    access, _p, server = printer(old_level=1 if entry == "protected" else 0,
                                 link=link)
    asyncio.run(access.update({"data_mode": mode, "private_uploads": private}))
    return access, server


def request(endpoint: str, method: str, args: Dict[str, Any], who: Any,
            result: Any = None) -> Any:
    async def handler(web_request: Any) -> Any:
        return result if result is not None else {"reached": endpoint}
    # APIDefinition.create caches by endpoint: a fresh one per stub result
    APIDefinition._cache.pop(endpoint, None)
    api = APIDefinition.create(endpoint, [method], handler,
                               is_remote=not endpoint.startswith("/"))
    return asyncio.run(api.request(dict(args), RequestType[method], *who))


def refused(endpoint: str, method: str, args: Dict[str, Any],
            who: Any) -> Optional[int]:
    try:
        request(endpoint, method, args, who)
    except ServerError as err:
        return err.status_code
    return None


def upload(path: str, name: str, who: Any, root: str = "gcodes") -> Dict[str, Any]:
    """Plan and finish an upload as FileUploadHandler does; the final path is
    where file_manager would put it."""
    transport, ip, user = who
    form_args = {"root": root, "path": path, "filename": name}
    plan = policy.plan_upload(ip, user, form_args)
    directory = form_args["path"].strip("/")
    final = f"{directory}/{name}" if directory else name
    result: Dict[str, Any] = {"item": {"root": root, "path": final},
                              "action": "create_file"}
    result.update(policy.finish_upload(plan, result))
    return result


def listing(paths: List[str], who: Any) -> List[str]:
    out = request("/server/files/list", "GET", {}, who,
                  result=[{"path": p} for p in paths])
    return [item["path"] for item in out]


SHARED_FILE = "benchy.gcode"
FILES = [SHARED_FILE, f"{ANA_DRIVE}/ana.gcode", f"{BEN_DRIVE}/ben.gcode"]


class TestEachDataMode:
    def test_shared(self):
        a_printer("shared")
        # Accounts see the shared drive and their own, never another's
        assert listing(FILES, ANA) == [SHARED_FILE, f"{ANA_DRIVE}/ana.gcode"]
        assert listing(FILES, HOME) == [SHARED_FILE]
        assert listing(FILES, ADMIN) == FILES
        assert upload("", "part.gcode", ANA)["item"]["path"] == "part.gcode"

    def test_accounts(self):
        a_printer("accounts")
        # An account sees its own drive only; uploads go there
        assert listing(FILES, ANA) == [f"{ANA_DRIVE}/ana.gcode"]
        assert upload("", "part.gcode", ANA)["item"]["path"] == (
            f"{ANA_DRIVE}/part.gcode")
        assert upload("sub", "p.gcode", ANA)["item"]["path"] == (
            f"{ANA_DRIVE}/sub/p.gcode")
        # Anyone without an account uses the shared drive
        assert listing(FILES, HOME) == [SHARED_FILE]
        assert listing(FILES, GUEST_DEVICE) == [SHARED_FILE]
        assert upload("", "x.gcode", PASSWORD)["item"]["path"] == "x.gcode"
        # An admin sees every drive
        assert listing(FILES, ADMIN) == FILES
        # Reading the shared drive is refused to an account, as listing is
        assert refused("/server/files/metadata", "GET",
                       {"filename": SHARED_FILE}, ANA) == 404

    def test_both(self):
        a_printer("both")
        assert listing(FILES, ANA) == [SHARED_FILE, f"{ANA_DRIVE}/ana.gcode"]
        assert upload("", "part.gcode", ANA)["item"]["path"] == "part.gcode"
        assert upload(ANA_DRIVE, "mine.gcode", ANA)["item"]["path"] == (
            f"{ANA_DRIVE}/mine.gcode")

    @pytest.mark.parametrize("mode", ["shared", "accounts", "both"])
    def test_another_accounts_drive_is_never_reachable(self, mode):
        a_printer(mode)
        ben_file = f"{BEN_DRIVE}/ben.gcode"
        assert refused("/server/files/metadata", "GET",
                       {"filename": ben_file}, ANA) == 404
        assert refused("/printer/print/start", "POST",
                       {"filename": ben_file}, ANA) == 404
        assert refused("/server/files/download", "GET",
                       {"path": f"gcodes/{ben_file}"}, ANA) == 404
        with pytest.raises(ServerError) as err:
            upload(BEN_DRIVE, "drop.gcode", ANA)
        assert err.value.status_code == 403
        # From a file Ana may read (her own) into Ben's drive
        assert refused("/server/files/copy", "POST",
                       {"source": f"gcodes/{ANA_DRIVE}/ana.gcode",
                        "dest": f"gcodes/{BEN_DRIVE}/copy.gcode"}, ANA) == 403
        assert refused("/server/files/metadata", "GET",
                       {"filename": ben_file}, ADMIN) is None

    def test_the_drives_directory(self):
        a_printer("both")
        result = {"dirs": [{"dirname": "acct_ana@example.com"},
                           {"dirname": "acct_ben@example.com"}],
                  "files": []}
        out = request("/server/files/directory", "GET",
                      {"path": "gcodes/a"}, ANA, result=result)
        assert [d["dirname"] for d in out["dirs"]] == ["acct_ana@example.com"]
        out = request("/server/files/directory", "GET",
                      {"path": "gcodes/a"}, ADMIN, result=result)
        assert len(out["dirs"]) == 2
        assert refused("/server/files/directory", "GET",
                       {"path": f"gcodes/{BEN_DRIVE}"}, ANA) == 404
        # Someone with no account has no drive to look for
        assert refused("/server/files/directory", "GET",
                       {"path": "gcodes/a"}, HOME) == 404


class TestPrivateUploads:
    def _private_upload(self) -> str:
        a_printer("shared", private=True)
        result = upload("", "secret.gcode", ANA)
        assert result["private"] is True and "reason" not in result
        return result["item"]["path"]

    def test_only_the_uploader_lists_reads_downloads_and_prints_it(self):
        path = self._private_upload()
        assert listing([SHARED_FILE, path], ANA) == [SHARED_FILE, path]
        for who in (BEN, ADMIN, HOME, PANEL):
            assert listing([SHARED_FILE, path], who) == [SHARED_FILE], who
            assert refused("/server/files/metadata", "GET",
                           {"filename": path}, who) == 404
            assert refused("/server/files/thumbnails", "GET",
                           {"filename": path}, who) == 404
            assert refused("/server/files/download", "GET",
                           {"path": f"gcodes/{path}"}, who) == 404
            assert refused("/printer/print/start", "POST",
                           {"filename": path}, who) == 404
            assert refused("/server/job_queue/job", "POST",
                           {"filenames": [path]}, who) == 404
            assert refused("/server/files/copy", "POST",
                           {"source": f"gcodes/{path}",
                            "dest": "gcodes/mine.gcode"}, who) == 404
        assert refused("/server/files/metadata", "GET",
                       {"filename": path}, ANA) is None
        assert refused("/printer/print/start", "POST",
                       {"filename": path}, ANA) is None

    def test_an_admin_may_delete_it_but_not_read_it(self):
        path = self._private_upload()
        assert refused("/server/files/metadata", "GET",
                       {"filename": path}, ADMIN) == 404
        assert refused("/server/files/download", "GET",
                       {"path": f"gcodes/{path}"}, ADMIN) == 404
        assert refused("/server/files/delete_file", "DELETE",
                       {"path": f"gcodes/{path}"}, ADMIN) is None
        assert refused("/server/files/delete_file", "DELETE",
                       {"path": f"gcodes/{path}"}, PANEL) is None
        # Anyone else is told it is not there
        assert refused("/server/files/delete_file", "DELETE",
                       {"path": f"gcodes/{path}"}, BEN) == 404

    def test_a_console_print_of_it_is_refused(self):
        path = self._private_upload()
        assert refused("gcode/script", "POST",
                       {"script": f"SDCARD_PRINT_FILE FILENAME=\"{path}\""},
                       ADMIN) == 404

    def test_the_tag_is_in_the_metadata(self):
        path = self._private_upload()
        out = request("/server/files/metadata", "GET", {"filename": path},
                      ANA, result={"size": 10})
        assert out == {"size": 10, "uploader": "acct:ana@example.com",
                       "private": True}

    def test_off_means_tagged_but_not_private(self):
        a_printer("shared", private=False)
        result = upload("", "open.gcode", ANA)
        assert result["private"] is False and "reason" not in result
        assert listing(["open.gcode"], BEN) == ["open.gcode"]


class TestNoIdentity:
    @pytest.mark.parametrize("who", [HOME, PASSWORD],
                             ids=["anyone at home", "the password"])
    @pytest.mark.parametrize("mode", ["shared", "accounts", "both"])
    def test_an_anonymous_upload_lands_shared_and_says_why(self, who, mode):
        access, _s = a_printer(mode, private=True)
        result = upload("", "slicer.gcode", who)
        assert result["item"]["path"] == "slicer.gcode"
        assert result["private"] is False
        assert result["reason"] == "no-identity"
        assert "slicer.gcode" not in access.index
        # Shared: everyone allowed the drive sees it
        assert listing(["slicer.gcode"], BEN) == (
            [] if mode == "accounts" else ["slicer.gcode"])


class TestTheTagFollowsTheFile:
    def test_move_delete_copy_zip_and_restart(self):
        access, server = a_printer("shared", private=True)
        path = upload("", "secret.gcode", ANA)["item"]["path"]
        handler = server.event_handlers["file_manager:filelist_changed"][0]
        handler({"action": "move_file",
                 "item": {"root": "gcodes", "path": "moved.gcode"},
                 "source_item": {"root": "gcodes", "path": path}})
        assert "moved.gcode" in access.index and path not in access.index
        # A copy by its uploader stays private
        request("/server/files/copy", "POST",
                {"source": "gcodes/moved.gcode", "dest": "gcodes/copy.gcode"},
                ANA, result={"item": {"root": "gcodes",
                                      "path": "copy.gcode"},
                             "action": "create_file"})
        assert access.index["copy.gcode"].private is True
        # So does a zip holding it
        request("/server/files/zip", "POST",
                {"items": ["gcodes/copy.gcode"], "dest": "gcodes/out.zip"},
                ANA, result={"destination": {"root": "gcodes",
                                             "path": "out.zip"},
                             "action": "zip_files"})
        assert access.index["out.zip"] == files.Tag(
            "acct:ana@example.com", True)
        handler({"action": "delete_file",
                 "item": {"root": "gcodes", "path": "moved.gcode"}})
        assert "moved.gcode" not in access.index
        # The index survives a restart
        asyncio.run(access.save_index())
        access2, _p, _s = printer(server=restart(server))
        assert access2.index["copy.gcode"].private is True


class TestOwnFilesAndOthers:
    """Under Standard, on a printer with one owner: deleting your own upload
    is "files" (signed-in guest), reprinting someone else's is
    "files_others" (admin)."""

    def test_delete_own_and_reprint_others(self):
        a_printer("shared", private=False, owner="account", entry="protected")
        mine = upload("", "mine.gcode", ANA)["item"]["path"]
        assert refused("/server/files/delete_file", "DELETE",
                       {"path": f"gcodes/{mine}"}, ANA) is None
        assert refused("/server/files/delete_file", "DELETE",
                       {"path": f"gcodes/{mine}"}, BEN) == 403
        assert refused("/printer/print/start", "POST",
                       {"filename": mine}, BEN) == 403
        assert refused("/printer/print/start", "POST",
                       {"filename": mine}, ANA) is None
        # An untagged shared file is nobody's: printing it is "print"
        assert refused("/printer/print/start", "POST",
                       {"filename": SHARED_FILE}, BEN) is None


class TestTheHandlersAreWired:
    """Downloads and uploads do not pass APIDefinition.request."""

    def test_download_upload_and_its_answer(self):
        import inspect
        from moonraker.components import application
        get = inspect.getsource(application.FileRequestHandler.get)
        post = inspect.getsource(application.FileUploadHandler.post)
        assert '"/server/files/download"' in get
        assert "_check_file_access" in get
        assert "muon_access_policy.plan_upload" in post
        assert "muon_access_policy.finish_upload" in post
        # plan before the file is placed, finish after
        assert post.index("plan_upload") < post.index("finalize_upload")
        assert post.index("finalize_upload") < post.index("finish_upload")
