# MUON -- drives and private uploads (ACC-29 to ACC-34, AB-MR-3).
#
# Pure logic over the `gcodes` root, in the shape of muon_access_policy.py:
# which files a principal may see, read, print, move and delete, and where an
# upload goes. components/muon_access.py holds the uploader index and the
# settings, and muon_access_policy calls in here for every file request.
#
# WHERE PRINTS ARE KEPT (ACC-29, ACC-30; access-model 2.6)
#
#   shared    every file in gcodes/ (the default)
#   accounts  a principal with an account sees gcodes/a/<account>/ only, and
#             its uploads go there; an admin sees every drive
#   both      the shared drive plus the principal's own drive
#
# An account is a principal that came through the gateway at the signed-in
# guest level or above: a person with a Muon3D account. A signed-out guest,
# the password and anyone at home have none, and use the shared drive in every
# mode. Nobody but an admin (or the panel) sees another account's drive.
#
# PRIVATE UPLOADS (ACC-31, ACC-34; access-model 2.7)
#
# With private uploads on, an upload from a caller with an identity is tagged
# with its uploader, and only the uploader may list it, read its metadata or
# thumbnail, download it, print it again, copy or move it. Everyone else is
# told it does not exist, owners and admins included, and the panel too:
# design 2.7 names the owner, and anyone at the panel can reset the printer,
# which is the limit the app states (ACC-33). An admin, or the panel, may
# still delete it, to free space.
#
# An identity here is a key the printer admitted: a caller through the
# gateway. A browser signed in with the password is not one (every password
# guest is the same principal, and the printer holds no key for it), nor is
# anyone at home. Their uploads go to the shared drive, not private, and the
# answer says so: "private": false, "reason": "no-identity" (ACC-34).
#
# NOT COVERED HERE
#
# Print history and file-list notifications name the file to every client;
# both are outside a request this module sees. See the PR.

from __future__ import annotations

import dataclasses
import hashlib
import posixpath
import re
from typing import Any, Dict, Mapping, Optional, Tuple

from . import muon_access_policy as policy

DRIVES = "a"
SHARED = "shared"
ACCOUNTS = "accounts"
BOTH = "both"
NO_IDENTITY = "no-identity"

_SAFE = re.compile(r"[^A-Za-z0-9._@+-]")


@dataclasses.dataclass(frozen=True)
class Tag:
    uploader: str
    private: bool

    def as_dict(self) -> Dict[str, Any]:
        return {"uploader": self.uploader, "private": self.private}


def drive_name(principal_name: str) -> str:
    """The directory of a principal's drive under gcodes/a/."""
    name = _SAFE.sub("_", principal_name)
    if name in ("", ".", "..") or len(name) > 64:
        name = hashlib.sha256(principal_name.encode()).hexdigest()[:16]
    return name


def has_account(principal: policy.Principal) -> bool:
    return (principal.kind == "gateway"
            and policy.SIGNED_IN_GUEST <= principal.level <= policy.ADMIN)


def can_tag(principal: policy.Principal) -> bool:
    """ACC-34: only a caller the printer holds a key for has an identity."""
    return principal.kind == "gateway"


def is_admin(principal: policy.Principal) -> bool:
    return principal.level >= policy.ADMIN


def gcodes_path(path: Any) -> Optional[str]:
    """`gcodes/x/y.gcode` as `x/y.gcode`; None for any other root."""
    if not isinstance(path, str):
        return None
    clean = posixpath.normpath("/" + path.lstrip("/")).lstrip("/")
    root, _, rest = clean.partition("/")
    return rest if root == "gcodes" else None


def relative(path: Any) -> Optional[str]:
    """A path already relative to gcodes, normalised."""
    if not isinstance(path, str) or not path:
        return None
    return posixpath.normpath("/" + path.lstrip("/")).lstrip("/")


def drive_of(path: str) -> Optional[str]:
    parts = path.split("/")
    if len(parts) >= 2 and parts[0] == DRIVES:
        return parts[1]
    return None


@dataclasses.dataclass(frozen=True)
class FileScope:
    index: Mapping[str, Tag]
    data_mode: str = SHARED
    private_uploads: bool = False

    def own_drive(self, principal: policy.Principal) -> Optional[str]:
        return drive_name(principal.name) if has_account(principal) else None

    def in_scope(self, path: str, principal: policy.Principal) -> bool:
        """The drives rule alone, before private files."""
        if is_admin(principal):
            return True
        drive = drive_of(path)
        own = self.own_drive(principal)
        if drive is not None:
            return drive == own
        if self.data_mode == ACCOUNTS and own is not None:
            return False
        return True

    def hidden_private(self, path: str, principal: policy.Principal) -> bool:
        tag = self.index.get(path)
        return tag is not None and tag.private and tag.uploader != principal.name

    def readable(self, path: str, principal: policy.Principal) -> bool:
        return (not self.hidden_private(path, principal)
                and self.in_scope(path, principal))

    def deletable(self, path: str, principal: policy.Principal) -> bool:
        if self.hidden_private(path, principal):
            # ACC-31: an owner or an admin may delete it
            return is_admin(principal)
        return self.in_scope(path, principal)

    def dir_deletable(self, path: str, principal: policy.Principal) -> bool:
        prefix = path.rstrip("/") + "/"
        for file_path in self.index:
            if file_path.startswith(prefix) and not self.deletable(
                    file_path, principal):
                return False
        return self.in_scope(prefix + "x", principal)

    def upload(
        self, principal: policy.Principal, dir_path: str
    ) -> Tuple[str, Optional[Tag], Dict[str, Any]]:
        """Where an upload goes, its tag, and what the answer says. Raises
        ValueError if the principal may not write there."""
        directory = relative(dir_path) or ""
        if directory == ".":
            directory = ""
        own = self.own_drive(principal)
        named = drive_of(posixpath.join(directory, "x"))
        if named is not None and named != own and not is_admin(principal):
            # Aimed at another account's drive: refused, never nested
            raise ValueError("not your drive")
        if (self.data_mode == ACCOUNTS and own is not None
                and named != own):
            directory = posixpath.join(DRIVES, own, directory).rstrip("/")
        if not self.in_scope(posixpath.join(directory, "x"), principal):
            raise ValueError("not your drive")
        answer: Dict[str, Any]
        tag: Optional[Tag] = None
        if can_tag(principal):
            private = self.private_uploads
            tag = Tag(principal.name, private)
            answer = {"private": private}
        else:
            answer = {"private": False}
            if self.private_uploads:
                answer["reason"] = NO_IDENTITY
        return directory, tag, answer


# ---------------------------------------------------------------------------
# The guard muon_access_policy calls for every file request
# ---------------------------------------------------------------------------

#: Requests that read one file, by the argument that names it (relative to
#: gcodes).
READ_BY_FILENAME = (
    "/server/files/metadata", "/server/files/thumbnails",
    "/server/files/metascan", "/server/analysis/estimate",
    "/server/analysis/process", "/printer/print/start",
)

_PRINT_FILE = re.compile(r"^\s*SDCARD_PRINT_FILE\b(.*)$", re.IGNORECASE)
_FILENAME_ARG = re.compile(r"FILENAME\s*=\s*(\"[^\"]*\"|\S+)", re.IGNORECASE)


def printed_files(script: Any) -> list:
    """The files a G-code script prints with SDCARD_PRINT_FILE."""
    found = []
    for line in str(script or "").splitlines():
        match = _PRINT_FILE.match(line.split(";", 1)[0])
        if match is None:
            continue
        arg = _FILENAME_ARG.search(match.group(1))
        if arg is not None:
            found.append(arg.group(1).strip('"'))
    return found


class FileGuard:
    def __init__(self, scope: Any, record: Any, error: Any) -> None:
        #: () -> FileScope, the settings and index now
        self.scope = scope
        #: (path, Tag) -> None, records an upload's tag
        self.record = record
        self.error = error

    def _not_found(self, path: str) -> Exception:
        # Never confirm a file exists that the caller may not see
        return self.error(f"File '{path}' not found", 404)

    def _read(self, scope: FileScope, path: Optional[str],
              principal: policy.Principal) -> None:
        if path is not None and not scope.readable(path, principal):
            raise self._not_found(path)

    def _write(self, scope: FileScope, path: Optional[str],
               principal: policy.Principal) -> None:
        if path is not None and not scope.in_scope(path, principal):
            raise self.error(f"'{path}' is in another account's drive.", 403)

    def _referenced(self, endpoint: str, request_type: Any,
                    args: Mapping[str, Any]) -> Tuple[str, list]:
        """("print" | "delete" | "", the gcodes paths a request names)."""
        method = getattr(request_type, "name", None)
        if endpoint == "/printer/print/start":
            return "print", [relative(args.get("filename"))]
        if endpoint == "/server/job_queue/job" and method == "POST":
            names = args.get("filenames")
            if isinstance(names, str):
                names = [n.strip() for n in names.split(",")]
            return "print", [relative(n) for n in names or []]
        if endpoint == "gcode/script":
            return "print", [relative(n)
                             for n in printed_files(args.get("script"))]
        if endpoint == "/server/files/delete_file":
            return "delete", [gcodes_path(args.get("path"))]
        return "", []

    def adjust(self, actions: Tuple[policy.Action, ...], endpoint: str,
               request_type: Any, args: Mapping[str, Any],
               principal: policy.Principal) -> Tuple[policy.Action, ...]:
        """The table's rows by whose files these are (access-model 3):
        deleting only your own uploads is "files", and printing another
        person's upload again is "files_others" too. A file hidden from the
        caller is left to check(), which answers 404 rather than reveal it."""
        kind, paths = self._referenced(endpoint, request_type, args)
        scope = self.scope()
        tags = [(p, scope.index.get(p)) for p in paths if p is not None]
        visible = [(p, t) for p, t in tags
                   if not scope.hidden_private(p, principal)]
        if not visible:
            return actions
        own = all(t is not None and t.uploader == principal.name
                  for _p, t in visible)
        others = any(t is not None and t.uploader != principal.name
                     for _p, t in visible)
        if kind == "delete" and own:
            return tuple(policy.ACTIONS["files"] if a.name == "files_others"
                         else a for a in actions)
        if kind == "print" and others:
            return actions + (policy.ACTIONS["files_others"],)
        return actions

    def check(self, endpoint: str, request_type: Any,
              args: Mapping[str, Any], principal: policy.Principal) -> None:
        scope = self.scope()
        method = getattr(request_type, "name", None)
        if endpoint in READ_BY_FILENAME:
            self._read(scope, relative(args.get("filename")), principal)
        elif endpoint == "/server/files/download":
            self._read(scope, gcodes_path(args.get("path")), principal)
        elif endpoint == "/server/job_queue/job" and method == "POST":
            names = args.get("filenames")
            if isinstance(names, str):
                names = [n.strip() for n in names.split(",")]
            for name in names or []:
                self._read(scope, relative(name), principal)
        elif endpoint == "gcode/script":
            for name in printed_files(args.get("script")):
                self._read(scope, relative(name), principal)
        elif endpoint in ("/server/files/move", "/server/files/copy"):
            self._read(scope, gcodes_path(args.get("source")), principal)
            self._write(scope, gcodes_path(args.get("dest")), principal)
        elif endpoint == "/server/files/zip":
            for item in args.get("items") or []:
                self._read(scope, gcodes_path(item), principal)
            self._write(scope, gcodes_path(args.get("dest")), principal)
        elif endpoint == "/server/files/delete_file":
            path = gcodes_path(args.get("path"))
            if path is not None and not scope.deletable(path, principal):
                raise self._not_found(path)
        elif endpoint == "/server/files/directory":
            path = gcodes_path(args.get("path", "gcodes"))
            if path is None or path in ("", "."):
                return
            if method == "DELETE":
                if not scope.dir_deletable(path, principal):
                    raise self._not_found(path)
            elif not self._dir_visible(scope, path, principal):
                raise self._not_found(path)

    @staticmethod
    def _dir_visible(scope: FileScope, path: str,
                     principal: policy.Principal) -> bool:
        if path == DRIVES:
            return is_admin(principal) or scope.own_drive(principal) is not None
        return scope.in_scope(path + "/x", principal)

    def filter(self, endpoint: str, request_type: Any,
               args: Mapping[str, Any], principal: policy.Principal,
               result: Any) -> Any:
        scope = self.scope()
        method = getattr(request_type, "name", None)
        if (endpoint == "/server/files/list"
                and args.get("root", "gcodes") == "gcodes"
                and isinstance(result, list)):
            return [item for item in result
                    if not isinstance(item, dict)
                    or scope.readable(str(item.get("path", "")), principal)]
        if (endpoint == "/server/files/directory" and method == "GET"
                and isinstance(result, dict)):
            base = gcodes_path(args.get("path", "gcodes"))
            if base is None:
                return result
            base = "" if base in ("", ".") else base
            result = dict(result)
            result["files"] = [
                f for f in result.get("files", [])
                if scope.readable(posixpath.join(base, f.get("filename", "")),
                                  principal)]
            result["dirs"] = [
                d for d in result.get("dirs", [])
                if self._dir_visible(
                    scope, posixpath.join(base, d.get("dirname", "")),
                    principal)]
            return result
        if endpoint == "/server/files/copy" and isinstance(result, dict):
            # file_manager's copy event names no source, so the tags are
            # copied here: a private file's copy stays private
            source = gcodes_path(args.get("source"))
            copied = result.get("item") or {}
            dest = (relative(copied.get("path"))
                    if copied.get("root") == "gcodes" else None)
            if source is not None and dest is not None:
                prefix = source.rstrip("/") + "/"
                for path, tag in list(scope.index.items()):
                    if path == source:
                        self.record(dest, tag)
                    elif path.startswith(prefix):
                        self.record(dest.rstrip("/") + "/" + path[len(prefix):],
                                    tag)
            return result
        if endpoint == "/server/files/zip" and isinstance(result, dict):
            # An archive of a private file is private to who made it
            archive: Dict[str, Any] = result.get("destination") or {}
            items = [gcodes_path(i) for i in args.get("items") or []]
            holds_private = any(
                tag.private for path, tag in scope.index.items()
                for item in items if item is not None
                and (path == item or path.startswith(item.rstrip("/") + "/")))
            if holds_private and archive.get("root") == "gcodes":
                self.record(str(archive.get("path", "")),
                            Tag(principal.name, True))
            return result
        if endpoint == "/server/files/metadata" and isinstance(result, dict):
            path = relative(args.get("filename"))
            tag = scope.index.get(path or "")
            if tag is not None:
                # The uploader tag in the metadata (AB-MR-3)
                result = dict(result, uploader=tag.uploader,
                              private=tag.private)
        return result

    def plan_upload(self, principal: policy.Principal,
                    form_args: Dict[str, Any]) -> Optional[Any]:
        if form_args.get("root", "gcodes") != "gcodes":
            return None
        try:
            directory, tag, answer = self.scope().upload(
                principal, form_args.get("path", ""))
        except ValueError:
            raise self.error(
                "Uploads may not go to another account's drive.", 403)
        form_args["path"] = directory
        return (tag, answer)

    def finish_upload(self, plan: Any, result: Any) -> Dict[str, Any]:
        tag, answer = plan
        item = result.get("item", {}) if isinstance(result, dict) else {}
        path = item.get("path")
        if tag is not None and isinstance(path, str):
            self.record(path, tag)
        return dict(answer)
