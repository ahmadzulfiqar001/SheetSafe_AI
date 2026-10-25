"""Build-stage ONLY: fixed base-runtime copy, no jobs or external commands.

Never run on the host. The source is the pinned Debian amd64 Python image.
Native library closure is conservatively retained, not claimed minimal by scan.
Future build must inspect contents/linkage/licenses/vulnerabilities before approval.
"""

import os
from pathlib import Path
import shutil
import sys


def main() -> None:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Runtime staging requires the reviewed Linux build stage")
    target = Path("/opt/parser-runtime")
    target.mkdir(exist_ok=False)
    (target / "usr/local/bin").mkdir(parents=True)
    (target / "usr/local/lib").mkdir(parents=True)
    shutil.copy2("/usr/local/bin/python3.12", target / "usr/local/bin/python3.12")
    shutil.copytree("/usr/local/lib/python3.12", target / "usr/local/lib/python3.12",
        ignore=shutil.ignore_patterns("site-packages", "dist-packages", "__pycache__", "*.pyc",
            "test", "tests", "ensurepip", "idlelib", "tkinter", "turtledemo", "venv", "config-3.12-*",
            "_tkinter.*", "_test*", "_ctypes_test.*", "_xxtestfuzz.*", "xxlimited*"))
    # CPython's config directory contains build-only python.o/Makefile assets.
    # Runtime sysconfig data remains in the separate _sysconfigdata module.
    # Exclude native GUI/test/example extensions as well as Python-level trees.
    # No shell, OS executables, pip, app DB, /etc or home tree is copied.
    shutil.copytree("/lib/x86_64-linux-gnu", target / "lib/x86_64-linux-gnu", symlinks=False)
    (target / "lib64").mkdir()
    shutil.copy2("/lib64/ld-linux-x86-64.so.2", target / "lib64/ld-linux-x86-64.so.2")
    # The final image has no base ld.so cache or LD_LIBRARY_PATH. Place libpython
    # in the loader's standard multiarch search directory as well as its prefix.
    for destination in ("usr/local/lib/libpython3.12.so.1.0", "lib/x86_64-linux-gnu/libpython3.12.so.1.0"):
        shutil.copy2("/usr/local/lib/libpython3.12.so.1.0", target / destination)


if __name__ == "__main__":
    main()
