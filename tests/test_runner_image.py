"""Review image/fixture contracts without building or executing any payload."""

import ast
import fnmatch
import json
from pathlib import Path
import shlex

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
        "FROM", "FROM", "COPY", "LABEL", "ENV", "COPY", "USER", "WORKDIR",
        "STOPSIGNAL", "ENTRYPOINT", "CMD",
    ]


def test_image_non_root_fixed_exec_entrypoint_and_read_only_fixture_definition():
    rows = dict(instructions())
    policy = SandboxPolicy()
    assert rows["USER"] == f"{policy.uid}:{policy.gid}"
    assert rows["WORKDIR"] == policy.workdir
    assert json.loads(rows["ENTRYPOINT"]) == list(policy.entrypoint)
    assert json.loads(rows["CMD"]) == [FixtureRequest("smoke-v1").fixture_id]
    assert rows["COPY"] == "--chown=0:0 --chmod=0444 bootstrap.py /opt/sheetsafe/bootstrap.py"
    assert dict(item.split("=", 1) for item in shlex.split(rows["ENV"])) == dict(policy.environment)
    assert rows["STOPSIGNAL"] == "SIGTERM"


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
