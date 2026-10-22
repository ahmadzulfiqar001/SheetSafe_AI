"""Review image/fixture contracts without building or executing any payload."""

import ast
import fnmatch
import json
from pathlib import Path
import re
import shlex

import pytest

from runner.image.bootstrap import FIXTURE_ID, parse_fixture_id
from runner.policy import FixtureRequest, SandboxPolicy


IMAGE_ROOT = Path(__file__).resolve().parents[1] / "runner" / "image"


def instructions():
    text = (IMAGE_ROOT / "Dockerfile").read_text(encoding="utf-8").replace("\\\n", " ")
    return [line.strip().split(None, 1) for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def test_image_has_one_digest_pinned_official_base_and_no_override_arguments():
    rows = instructions()
    assert rows[0][0] == "FROM"
    assert re.fullmatch(r"docker\.io/library/python:3\.12-slim-bookworm@sha256:[0-9a-f]{64}", rows[0][1])
    # No network installer, build-argument image substitution, arbitrary build
    # scripts, ports, volume declarations or additional stages may slip in.
    assert [command for command, _ in rows].count("FROM") == 1
    assert {command for command, _ in rows} <= {
        "FROM", "LABEL", "ENV", "COPY", "USER", "WORKDIR", "STOPSIGNAL", "ENTRYPOINT", "CMD",
    }


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
