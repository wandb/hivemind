"""Small fail-closed primitives for scheduler-owned files.

The scheduled importer stores only configuration and content-free status on
disk, but both still reveal project names, source filters, and run timing.  Keep
those files private, reject links, and never silently repair an existing path.
"""

from __future__ import annotations

import errno
import os
import secrets
import stat
from contextlib import suppress
from pathlib import Path

from .errors import ImporterError


class PrivatePathError(ImporterError):
    """A scheduler path cannot be opened without weakening its guarantees."""


def _absolute(path: Path) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        raise PrivatePathError("scheduler paths must be absolute")
    if ".." in expanded.parts:
        raise PrivatePathError("scheduler paths cannot contain parent traversal")
    return expanded


def _validate_directory(path: Path, *, private: bool) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise PrivatePathError("scheduler directory could not be inspected") from error
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise PrivatePathError("scheduler directory must not be a symlink")
    if details.st_uid != os.geteuid():
        raise PrivatePathError("scheduler directory must be owned by the current user")
    if private and stat.S_IMODE(details.st_mode) != 0o700:
        raise PrivatePathError(
            "existing scheduler directory must already have mode 0700; refusing to chmod it"
        )


def ensure_private_directory(path: Path) -> Path:
    """Create one private application directory or validate the existing one."""
    path = _absolute(path)
    if path.exists() or path.is_symlink():
        _validate_directory(path, private=True)
        return path
    parent = path.parent
    if not parent.exists():
        raise PrivatePathError("scheduler directory parent does not exist")
    _validate_directory(parent, private=False)
    try:
        path.mkdir(mode=0o700)
    except OSError as error:
        raise PrivatePathError("scheduler directory could not be created") from error
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fchmod(descriptor, 0o700)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise PrivatePathError("new scheduler directory could not be secured") from error
    _validate_directory(path, private=True)
    return path


def validate_private_file(path: Path) -> os.stat_result:
    """Require one current-user-owned, non-linked regular file at mode 0600."""
    path = _absolute(path)
    try:
        details = path.lstat()
    except OSError as error:
        raise PrivatePathError("private scheduler file could not be inspected") from error
    if (
        stat.S_ISLNK(details.st_mode)
        or not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_nlink != 1
    ):
        raise PrivatePathError("private scheduler file has an unsafe owner or file type")
    if stat.S_IMODE(details.st_mode) != 0o600:
        raise PrivatePathError(
            "existing scheduler files must already have mode 0600; refusing to chmod them"
        )
    return details


def read_private_bytes(path: Path, *, limit: int = 1024 * 1024) -> bytes:
    """Read a bounded private file without following a final-component link."""
    path = _absolute(path)
    validate_private_file(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PrivatePathError("private scheduler file could not be opened") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise PrivatePathError("private scheduler file changed while it was opened")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise PrivatePathError("private scheduler file exceeds its size limit")
        closed = path.lstat()
        if (opened.st_dev, opened.st_ino) != (closed.st_dev, closed.st_ino):
            raise PrivatePathError("private scheduler file changed while it was read")
        return b"".join(chunks)
    except OSError as error:
        raise PrivatePathError("private scheduler file could not be read") from error
    finally:
        os.close(descriptor)


def atomic_write_private(
    path: Path,
    payload: bytes,
    *,
    require_private_parent: bool = True,
) -> None:
    """Atomically replace a mode-0600 file inside an owned directory."""
    path = _absolute(path)
    if path.exists() or path.is_symlink():
        validate_private_file(path)
    _validate_directory(path.parent, private=require_private_parent)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(temporary, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory = os.open(
            path.parent,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        validate_private_file(path)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise PrivatePathError("scheduler path must not contain a symlink") from error
        raise PrivatePathError("private scheduler file could not be written") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            temporary.unlink()
