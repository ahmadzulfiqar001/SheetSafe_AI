"""Fixed synthetic smoke payload, intended only for the later isolated adapter.

There is no arbitrary Python, file path, command, or environment-based dispatch.
Importing this module performs no I/O. Do not invoke this payload on the host.
Its observations are untrusted fixture output, never external runtime evidence.
"""

from contextlib import ExitStack
import errno
import json
import os
import sys


FIXTURE_ID = "smoke-v1"


def parse_fixture_id(arguments: list[str]) -> str:
    if type(arguments) is not list or len(arguments) != 1 or type(arguments[0]) is not str:
        raise ValueError("Unsupported fixture.")
    if arguments[0] != FIXTURE_ID:
        raise ValueError("Unsupported fixture.")
    return FIXTURE_ID


def _check_payload_preconditions() -> None:
    # Defense against accidental invocation. These checks do not prove that all
    # container restrictions are enforced; that remains the broker's job.
    if sys.platform != "linux" or os.getuid() != 10001 or os.getgid() != 10001:
        raise RuntimeError("Fixture precondition failed.")
    if not os.statvfs("/").f_flag & os.ST_RDONLY:
        raise RuntimeError("Fixture precondition failed.")
    with open("/proc/self/status", encoding="ascii") as stream:
        status = stream.read(8193)
    if len(status) > 8192:
        raise RuntimeError("Fixture precondition failed.")
    values = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
    if values.get("NoNewPrivs", "").strip() != "1" or int(values.get("CapEff", "1").strip(), 16) != 0:
        raise RuntimeError("Fixture precondition failed.")


def _smoke() -> None:
    _check_payload_preconditions()
    with ExitStack() as cleanup:
        workspace = os.open("/work", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        cleanup.callback(os.close, workspace)
        owner = os.fstat(workspace)
        if owner.st_uid != 10001 or owner.st_gid != 10001:
            raise RuntimeError("Fixture workspace check failed.")
        # A fresh runtime must supply an empty writable tmpfs. Existing output
        # fails, rather than overwriting a marker or accepting stale state.
        os.mkdir("output", mode=0o700, dir_fd=workspace)
        output = os.open("output", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=workspace)
        cleanup.callback(os.close, output)
        marker = os.open("smoke-marker.txt", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=output)
        with os.fdopen(marker, "wb") as stream:
            stream.write(b"SheetSafe synthetic smoke fixture v1\n")
            stream.flush()
            os.fsync(stream.fileno())

    protected_path = "/sheetsafe-smoke-denied"
    try:
        probe = os.open(protected_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError as error:
        if error.errno not in {errno.EROFS, errno.EACCES, errno.EPERM}:
            raise RuntimeError("Fixture protected-write check failed.") from None
    else:
        os.close(probe)
        os.unlink(protected_path)  # Only our newly created, exclusive probe.
        raise RuntimeError("Fixture protected-write check failed.")
    print(json.dumps({
        "fixture_id": FIXTURE_ID, "marker_created": True,
        "protected_write_denied": True, "runtime_verification": "UNVERIFIED",
    }, separators=(",", ":")))


def main(arguments: list[str]) -> int:
    try:
        parse_fixture_id(arguments)
    except ValueError:
        print("unsupported_fixture", file=sys.stderr)
        return 2
    try:
        _smoke()
    except Exception:
        # Do not print paths, exception text, environment or host diagnostics.
        print("fixture_failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
