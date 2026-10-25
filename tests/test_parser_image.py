"""Static packaging only. Never build, invoke bootstrap or access Docker."""

import ast
import fnmatch
import json
from pathlib import Path
import re
import tomllib

import pytest

from runner.parser_policy import ParserPolicy


ROOT = Path("parser_worker/image")


def locked_wheel_paths():
    """Expected artifact names come from existing authorized hashes, not globbing.

    Unit tests need no downloaded files; real artifact bytes are a build prerequisite.
    """
    lock = {p["name"]: p for p in tomllib.loads(Path("uv.lock").read_text())["package"]}
    paths = set()
    for line in (ROOT / "requirements.lock").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, version, digest = re.fullmatch(
            r"([a-z-]+)==([0-9.]+) --hash=(sha256:[0-9a-f]{64})", line).groups()
        assert lock[name]["version"] == version
        wheels = [w for w in lock[name]["wheels"] if w["hash"] == digest]
        assert len(wheels) == 1
        paths.add("var/parser-wheelhouse/linux-amd64-cp312/" + wheels[0]["url"].rsplit("/", 1)[1])
    assert len(paths) == 8
    return paths


def test_dockerfile_fixed_source_minimal_runtime_and_closed_entrypoint():
    text = (ROOT / "Dockerfile").read_text()
    policy = ParserPolicy()
    assert f"FROM --platform=linux/amd64 {policy.source_image} AS parser_build" in text
    final = text.split("FROM scratch", 1)[1]
    assert "RUN " not in final and "ADD " not in text and "COPY . " not in text
    assert "COPY --from=parser_build / /" not in final
    assert "USER 10001:10001" in final and "CMD []" in final
    entrypoint = next(line for line in final.splitlines() if line.startswith("ENTRYPOINT "))
    assert json.loads(entrypoint.removeprefix("ENTRYPOINT ")) == list(policy.entrypoint)
    assert "ENV LANG=C.UTF-8 \\\n    HOME=/nonexistent \\\n    PATH=/usr/local/bin" in final
    for forbidden in ("backend/", "runner/", "tests/", ".env", "uv.lock", "pyproject.toml", "VOLUME ", "HEALTHCHECK ", "EXPOSE "):
        assert forbidden not in text
    for flag in ("--isolated", "--only-binary=:all:", "--require-hashes", "--no-deps", "--no-cache-dir", "--no-compile"):
        assert flag in text
    commands = [json.loads(line[4:]) for line in text.splitlines() if line.startswith("RUN ")]
    assert len(commands) == 2 and all(command[0] == "/usr/local/bin/python" for command in commands)


def test_exact_dependency_closure_hashes_and_linux_wheel_match_uv_lock():
    expected = {"annotated-types", "defusedxml", "et-xmlfile", "openpyxl", "pydantic", "pydantic-core", "typing-extensions", "typing-inspection"}
    lock = {p["name"]: p for p in tomllib.loads(Path("uv.lock").read_text())["package"]}
    seen = set()
    for line in (ROOT / "requirements.lock").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([a-z-]+)==([0-9.]+) --hash=(sha256:[0-9a-f]{64})", line)
        assert match
        name, version, digest = match.groups()
        assert name not in seen and name in expected and lock[name]["version"] == version
        matching = [w for w in lock[name]["wheels"] if w["hash"] == digest]
        assert len(matching) == 1
        url = matching[0]["url"]
        if name == "pydantic-core":
            assert "cp312-cp312-manylinux_2_17_x86_64" in url
        else:
            assert "none-any.whl" in url
        seen.add(name)
    assert seen == expected


def allowed_context(path):
    """Evaluate this restricted ignore grammar; not actual Engine evidence."""
    allowed = True
    for rule in (ROOT / "Dockerfile.dockerignore").read_text().splitlines():
        if not rule or rule.startswith("#"):
            continue
        include = rule.startswith("!")
        pattern = rule[1:] if include else rule
        # Directory-only rules do not whitelist arbitrary descendants because
        # immediately following subtree-deny rules cover those descendants.
        if fnmatch.fnmatchcase(path, pattern):
            allowed = include
    return allowed


@pytest.mark.parametrize("path", [".env", ".env.local", ".git/config", ".venv/private", "backend/main.py",
    "runner/docker_backend.py", "tests/ingestion_fixtures.py", "var/private.xlsx", "private.csv",
    "parser_worker/secret.env", "ingestion/unreviewed.py", "parser_worker/image/archive.tar", "parser_worker/image/.env"])
def test_context_canaries_excluded(path):
    assert not allowed_context(path)


@pytest.mark.parametrize("path", ["var/parser-wheelhouse/linux-amd64-cp312/unreviewed.whl",
    "var/parser-wheelhouse/linux-amd64-cp312/.env", "var/step8cr-inspection/engine-info.json",
    "var/parser-wheelhouse/linux-amd64-cp312/pydantic_core-2.50.1-cp312-cp312-win_amd64.whl"])
def test_offline_context_rejects_unreviewed_artifacts(path):
    assert not allowed_context(path)


def test_only_exact_reviewed_context_files_and_copy_sources():
    permitted = {"ingestion/__init__.py", "ingestion/contracts.py", "ingestion/parser_jobs.py",
        "parser_worker/__init__.py", "parser_worker/common.py", "parser_worker/csv_parser.py",
        "parser_worker/xlsx_archive.py", "parser_worker/xlsx_parser.py", "parser_worker/entrypoint.py",
        *(f"parser_worker/image/{name}" for name in ("Dockerfile", "Dockerfile.dockerignore", "bootstrap.py", "stage_runtime.py", "requirements.lock"))}
    # The fourteen source files must exist in a clean checkout. Ignored wheels
    # are prepared/verified separately, never required by static unit tests.
    assert all(allowed_context(p) and Path(p).is_file() for p in permitted)
    permitted |= locked_wheel_paths()
    listed = {line[1:] for line in (ROOT / "Dockerfile.dockerignore").read_text().splitlines()
        if line.startswith("!") and not line.endswith("/")}
    assert listed == permitted and all(allowed_context(p) for p in permitted)
    for line in (ROOT / "Dockerfile").read_text().splitlines():
        if line.startswith("COPY ") and "--from=" not in line:
            sources = [piece for piece in line.split()[1:-1] if not piece.startswith("--")]
            assert sources and set(sources) <= permitted


def test_offline_install_has_no_index_and_exact_wheel_copies_only_in_build_stage():
    text = (ROOT / "Dockerfile").read_text()
    build, final = text.split("FROM scratch", 1)
    commands = [json.loads(line[4:]) for line in build.splitlines() if line.startswith("RUN ")]
    install = commands[0]
    assert "--no-index" in install and "--find-links=/build/wheels" in install
    assert "--require-hashes" in install and "--only-binary=:all:" in install and "--no-deps" in install
    copied = set()
    for line in build.splitlines():
        if line.startswith("COPY var/"):
            _, source, destination = line.split()
            assert destination == "/build/wheels/" and "*" not in source
            copied.add(source)
    assert copied == locked_wheel_paths()
    assert "/build/wheels" not in final and ".whl" not in final and "var/" not in final


def test_no_dynamic_exec_network_db_or_host_paths_in_runtime_worker():
    paths = [Path("parser_worker/entrypoint.py"), ROOT / "bootstrap.py", Path("ingestion/parser_jobs.py")]
    for path in paths:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec", "compile", "open", "__import__"}
            modules = ([a.name for a in node.names] if isinstance(node, ast.Import)
                else [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
            assert not any(m.split(".")[0] in {"backend", "sqlite3", "socket", "subprocess", "httpx", "requests", "docker", "importlib"} for m in modules)
    build = (ROOT / "stage_runtime.py").read_text()
    assert "shutil.rmtree" not in build and "subprocess" not in build
    assert '"site-packages"' in build and '"ensurepip"' in build
    assert '"config-3.12-*"' in build
    for excluded in ("_tkinter.*", "_test*", "_ctypes_test.*", "_xxtestfuzz.*", "xxlimited*"):
        assert f'"{excluded}"' in build
    assert 'shutil.copytree("/",' not in build
