"""Small no-follow filesystem boundary for a private, local application directory.

POSIX uses directory descriptors; Windows pins every ancestor against rename or
deletion and opens files with OPEN_REPARSE_POINT. Neither backend grants protection
against a compromised host administrator. No recursive deletion primitive exists.
"""

from contextlib import contextmanager
import os
from pathlib import Path
import stat


class UnsafeStorage(Exception):
    def __init__(self) -> None:
        super().__init__("Storage safety check failed.")


def _name(value: str) -> str:
    if not value or value in {".", ".."} or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_.-" for c in value):
        raise UnsafeStorage()
    return value


def _regular(info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or getattr(info, "st_file_attributes", 0) & 0x400:
        raise UnsafeStorage()


if os.name == "nt":
    import ctypes
    from ctypes import wintypes
    import msvcrt

    _kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    _create = _kernel.CreateFileW
    _create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _create.restype = wintypes.HANDLE
    _close = _kernel.CloseHandle
    _close.argtypes = [wintypes.HANDLE]
    _close.restype = wintypes.BOOL

    def _handle(path: Path, *, directory: bool = False, create: bool = False, write: bool = False):
        handle = _create(str(path), 0x80 if directory else (0x40000000 if write else 0x80000000),
                         3 if directory else 1, None, 1 if create else 3,
                         0x00200000 | (0x02000000 if directory else 0), None)
        if handle == wintypes.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle


class Directory:
    def __init__(self, path: Path, fd: int | None = None):
        self.path, self.fd = path, fd

    def names(self) -> set[str]:
        # Bound enumeration even when an unexpected directory is encountered.
        with os.scandir(self.path if self.fd is None else self.fd) as entries:
            result = set()
            for entry in entries:
                if len(result) >= 4096:
                    raise UnsafeStorage()
                result.add(entry.name)
            return result

    @contextmanager
    def child(self, name: str, *, create: bool = False):
        name = _name(name)
        if create:
            try:
                if self.fd is None:
                    os.mkdir(self.path / name, 0o700)
                else:
                    os.mkdir(name, 0o700, dir_fd=self.fd)
            except FileExistsError:
                pass
        if self.fd is None:
            with directory(self.path / name) as child:
                yield child
        else:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd)
            try:
                yield Directory(self.path / name, fd)
            finally:
                os.close(fd)

    def open(self, name: str, *, create: bool = False):
        name = _name(name)
        if self.fd is None:
            handle = _handle(self.path / name, create=create, write=create)
            try:
                fd = msvcrt.open_osfhandle(handle, os.O_BINARY | (os.O_WRONLY if create else os.O_RDONLY))
            except BaseException:
                _close(handle)
                raise
        else:
            flags = os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_WRONLY | os.O_CREAT | os.O_EXCL if create else os.O_RDONLY)
            fd = os.open(name, flags, 0o600, dir_fd=self.fd)
        try:
            _regular(os.fstat(fd))
            return os.fdopen(fd, "wb" if create else "rb")
        except BaseException:
            os.close(fd)
            raise

    def unlink(self, name: str) -> None:
        name = _name(name)
        try:
            # Refuse unexpected links/types even though unlink itself never follows.
            info = os.stat(self.path / name, follow_symlinks=False) if self.fd is None else os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        _regular(info)
        if self.fd is None:
            os.unlink(self.path / name)
        else:
            os.unlink(name, dir_fd=self.fd)
        self.sync()

    def rename_new(self, source: str, target: str) -> None:
        source, target = _name(source), _name(target)
        # No overwrite: another completed file must never be replaced.
        if self.fd is None:
            os.rename(self.path / source, self.path / target)
        else:
            if target in self.names():
                raise FileExistsError()
            # The exclusive namespace lock and private directory protect this
            # check/rename from other application writers. Never create hardlinks.
            os.rename(source, target, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        self.sync()

    def rmdir(self, name: str) -> None:
        name = _name(name)
        if self.fd is None:
            os.rmdir(self.path / name)
        else:
            os.rmdir(name, dir_fd=self.fd)
        self.sync()

    def sync(self) -> None:
        if self.fd is not None:
            os.fsync(self.fd)


@contextmanager
def directory(path: Path):
    """Reject links in every ancestor and keep directory identity pinned for I/O."""
    path = Path(os.path.abspath(path))
    if os.name == "nt":
        if str(path).startswith("\\\\"):
            raise UnsafeStorage()
        handles = []
        try:
            for parent in (*reversed(path.parents), path):
                handle = _handle(parent, directory=True)
                handles.append(handle)
                info = parent.lstat()
                if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                    raise UnsafeStorage()
            yield Directory(path)
        finally:
            for handle in reversed(handles):
                _close(handle)
    else:
        fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in path.parts[1:]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            yield Directory(path, fd)
        finally:
            os.close(fd)


@contextmanager
def namespace_lock(folder: Directory):
    """A nonblocking interprocess lock released automatically on worker crash."""
    try:
        stream = folder.open(".lock", create=True)
        stream.close()
    except FileExistsError:
        pass
    # Lock needs read/write access; normal files remain immutable.
    if os.name == "nt":
        handle = _create(str(folder.path / ".lock"), 0xC0000000, 0, None, 3, 0x00200000, None)
        if handle == wintypes.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
        except BaseException:
            _close(handle)
            raise
    else:
        import fcntl
        fd = os.open(".lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder.fd)
    try:
        _regular(os.fstat(fd))
        if os.name != "nt":
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)
