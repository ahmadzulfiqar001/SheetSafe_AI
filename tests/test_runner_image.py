"""Review image/fixture contracts without building or executing any payload."""

import ast
import fnmatch
import gzip
import io
import json
from pathlib import Path
import shlex
import tarfile

import pytest

from runner.image.bootstrap import FIXTURE_ID, parse_fixture_id
from runner.policy import FixtureRequest, SandboxPolicy


IMAGE_ROOT = Path(__file__).resolve().parents[1] / "runner" / "image"


def instructions():
    text = (IMAGE_ROOT / "Dockerfile").read_text(encoding="utf-8").replace("\\\n", " ")
    return [line.strip().split(None, 1) for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def test_image_has_exact_pinned_source_and_independent_final_stage():
    rows = instructions()
    assert rows[:3] == [
        ["FROM", "docker.io/library/python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS python_source"],
        ["FROM", "scratch"],
        ["COPY", "--from=python_source / /"],
    ]
    # This exact graph replaces the old single-stage contract. An independent
    # final stage copies files, not inherited image configuration. No third
    # stage, installer, ARG substitution, extra ENV or startup override is allowed.
    assert [command for command, _ in rows] == [
        "FROM", "FROM", "COPY", "LABEL", "ENV", "WORKDIR", "COPY", "USER", "WORKDIR",
        "STOPSIGNAL", "ENTRYPOINT", "CMD",
    ]


def test_image_non_root_fixed_exec_entrypoint_and_read_only_fixture_definition():
    ordered = instructions()
    rows = dict(ordered)
    policy = SandboxPolicy()
    assert rows["USER"] == f"{policy.uid}:{policy.gid}"
    assert rows["WORKDIR"] == policy.workdir
    assert [arg for cmd, arg in ordered if cmd == "WORKDIR"] == [
        "/opt/sheetsafe",
        policy.workdir,
    ]
    assert ordered.index(["WORKDIR", "/opt/sheetsafe"]) < ordered.index(
        ["COPY", "--chown=0:0 --chmod=0444 bootstrap.py /opt/sheetsafe/bootstrap.py"]
    ) < ordered.index(["USER", f"{policy.uid}:{policy.gid}"]) < ordered.index(
        ["WORKDIR", policy.workdir]
    )
    assert json.loads(rows["ENTRYPOINT"]) == list(policy.entrypoint)
    assert json.loads(rows["CMD"]) == [FixtureRequest("smoke-v1").fixture_id]
    assert rows["COPY"] == "--chown=0:0 --chmod=0444 bootstrap.py /opt/sheetsafe/bootstrap.py"
    assert dict(item.split("=", 1) for item in shlex.split(rows["ENV"])) == dict(policy.environment)
    assert rows["STOPSIGNAL"] == "SIGTERM"


def test_bootstrap_directory_traversal_and_file_readability_by_uid_10001():
    """Verify /opt and /opt/sheetsafe are traversable (0755, 0:0) and bootstrap.py is readable (0444, 0:0) by UID 10001."""
    policy = SandboxPolicy()
    ordered = instructions()

    def can_traverse_dir(uid: int, gid: int, dir_uid: int, dir_gid: int, mode: int) -> bool:
        if uid == dir_uid:
            return bool(mode & 0o100)
        if gid == dir_gid:
            return bool(mode & 0o010)
        return bool(mode & 0o001)

    def can_write_entry(uid: int, gid: int, entry_uid: int, entry_gid: int, mode: int) -> bool:
        if uid == entry_uid:
            return bool(mode & 0o200)
        if gid == entry_gid:
            return bool(mode & 0o020)
        return bool(mode & 0o002)

    def can_read_file(uid: int, gid: int, file_uid: int, file_gid: int, mode: int) -> bool:
        if uid == file_uid:
            return bool(mode & 0o400)
        if gid == file_gid:
            return bool(mode & 0o040)
        return bool(mode & 0o004)

    # Confirm the broken 0444 directory mode denies traversal to UID 10001
    assert not can_traverse_dir(policy.uid, policy.gid, 0, 0, 0o444)

    # Simulate Dockerfile final-stage effective permissions for /opt -> /opt/sheetsafe -> bootstrap.py
    active_uid, active_gid = 0, 0
    fs_entries: dict[str, tuple[str, int, int, int]] = {
        "/opt": ("dir", 0, 0, 0o755),
    }
    in_final_stage = False
    for cmd, arg in ordered:
        if cmd == "FROM" and arg == "scratch":
            in_final_stage = True
            active_uid, active_gid = 0, 0
        elif in_final_stage and cmd == "USER":
            u_str, g_str = arg.split(":", 1)
            active_uid, active_gid = int(u_str), int(g_str)
        elif in_final_stage and cmd == "WORKDIR":
            if arg not in fs_entries:
                fs_entries[arg] = ("dir", active_uid, active_gid, 0o755)
        elif in_final_stage and cmd == "COPY" and "bootstrap.py" in arg:
            # BuildKit preserves existing parent directory mode/owner if already created;
            # otherwise it applies --chmod to newly created parent directories.
            if "/opt/sheetsafe" not in fs_entries:
                fs_entries["/opt/sheetsafe"] = ("dir", 0, 0, 0o444)
            fs_entries["/opt/sheetsafe/bootstrap.py"] = ("file", 0, 0, 0o444)

    assert fs_entries["/opt"] == ("dir", 0, 0, 0o755)
    assert fs_entries["/opt/sheetsafe"] == ("dir", 0, 0, 0o755)
    assert fs_entries["/opt/sheetsafe/bootstrap.py"] == ("file", 0, 0, 0o444)

    for dir_path in ("/opt", "/opt/sheetsafe"):
        kind, d_uid, d_gid, d_mode = fs_entries[dir_path]
        assert kind == "dir"
        assert (d_uid, d_gid) == (0, 0)
        assert can_traverse_dir(policy.uid, policy.gid, d_uid, d_gid, d_mode)
        assert not can_write_entry(policy.uid, policy.gid, d_uid, d_gid, d_mode)

    f_kind, f_uid, f_gid, f_mode = fs_entries["/opt/sheetsafe/bootstrap.py"]
    assert f_kind == "file"
    assert (f_uid, f_gid, f_mode) == (0, 0, 0o444)
    assert can_read_file(policy.uid, policy.gid, f_uid, f_gid, f_mode)
    assert not can_write_entry(policy.uid, policy.gid, f_uid, f_gid, f_mode)
    assert (f_mode & 0o111) == 0

    # Verify OCI archive layer merge if the local permission-review archive is present
    review_archive = (
        IMAGE_ROOT.parents[1]
        / "var"
        / "step7n-image-permissions"
        / "runner-image.tar"
    )
    if review_archive.is_file():
        merged: dict[str, tuple[bytes, int, int, int]] = {}
        with tarfile.open(review_archive, "r:") as archive:
            manifest = json.loads(archive.extractfile("manifest.json").read())[0]
            for layer_name in manifest["Layers"]:
                raw_layer = archive.extractfile(layer_name).read()
                layer_bytes = (
                    gzip.decompress(raw_layer)
                    if raw_layer.startswith(b"\x1f\x8b")
                    else raw_layer
                )
                with tarfile.open(
                    fileobj=io.BytesIO(layer_bytes), mode="r:"
                ) as layer_tar:
                    for entry in layer_tar:
                        norm_name = entry.name.lstrip("./")
                        if norm_name in (
                            "opt",
                            "opt/sheetsafe",
                            "opt/sheetsafe/bootstrap.py",
                            "work",
                        ):
                            merged[norm_name] = (
                                entry.type,
                                entry.uid,
                                entry.gid,
                                entry.mode,
                            )
        assert merged["opt"] == (b"5", 0, 0, 0o755)
        assert merged["opt/sheetsafe"] == (b"5", 0, 0, 0o755)
        assert merged["opt/sheetsafe/bootstrap.py"] == (b"0", 0, 0, 0o444)
        assert merged["work"] == (b"5", 10001, 10001, 0o755)


def test_final_definition_has_only_the_approved_environment_and_reviewed_copies():
    rows = instructions()
    declared = [arguments for command, arguments in rows if command == "ENV"]
    assert len(declared) == 1
    entries = shlex.split(declared[0])
    assert len(entries) == 3  # Duplicate declarations cannot hide behind dict().
    assert dict(item.split("=", 1) for item in entries) == {
        "LANG": "C.UTF-8", "HOME": "/nonexistent", "PATH": "/usr/local/bin:/usr/bin:/bin",
    }
    assert [arguments for command, arguments in rows if command == "COPY"] == [
        "--from=python_source / /",
        "--chown=0:0 --chmod=0444 bootstrap.py /opt/sheetsafe/bootstrap.py",
    ]


def test_build_context_whitelist_excludes_credentials_code_and_runtime_content():
    patterns = (IMAGE_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    # Evaluate representative context paths, including a future accidental copy
    # of the repository or environment into this deliberately tiny build root.
    def included(name):
        allowed = True
        for pattern in patterns:
            negate = pattern.startswith("!")
            if fnmatch.fnmatchcase(name, pattern[1:] if negate else pattern):
                allowed = negate
        return allowed

    assert {name for name in ("Dockerfile", ".dockerignore", "bootstrap.py") if included(name)} == {
        "Dockerfile", ".dockerignore", "bootstrap.py",
    }
    for name in (".env", ".env.local", "key.pem", "data.xlsx", "var/app.sqlite3", "backend/main.py", ".venv/bin/python", "__pycache__/bootstrap.pyc"):
        assert not included(name)


@pytest.mark.parametrize("arguments", [[], ["other"], ["smoke-v1", "--privileged"],
    ["../smoke-v1"], ["smoke-v1\n"], [None], "smoke-v1", ("smoke-v1",)])
def test_payload_dispatch_rejects_unknown_fixture_or_arguments(arguments):
    with pytest.raises(ValueError, match="Unsupported fixture"):
        parse_fixture_id(arguments)


def test_payload_dispatch_matches_the_only_allowed_request():
    assert parse_fixture_id(["smoke-v1"]) == FIXTURE_ID == FixtureRequest("smoke-v1").fixture_id


def test_payload_is_compilable_and_has_no_user_code_or_process_dispatch():
    source = (IMAGE_ROOT / "bootstrap.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    compile(tree, "fixed-bootstrap", "exec")  # Compile only; never execute the fixture.
    imports = {
        node.module if isinstance(node, ast.ImportFrom) else alias.name
        for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imports <= {"contextlib", "errno", "json", "os", "sys"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"eval", "exec", "compile", "__import__"}
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in {"system", "popen", "spawnl", "spawnv", "execv", "execve"}
