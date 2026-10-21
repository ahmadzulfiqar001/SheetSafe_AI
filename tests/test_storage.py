"""Actual synthetic files, isolated roots, controlled clocks and fault injection."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
from threading import Event
import time
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest

from backend.config import Settings
from backend.main import create_app
from backend.security.lifecycle import LifecycleCoordinator
from backend.security.sessions import SessionError, SessionService
from backend.storage.database import Database
from backend.storage.files import (
    ARTIFACT_LIMIT, CHUNK_SIZE, INPUT_LIMIT, LOG_LIMIT, PARSED_LIMIT, PrivateStorage,
)
from backend.storage.filesystem import Directory, directory, namespace_lock
from backend.storage.schema import APPLICATION_ID, MIGRATIONS, SCHEMA_VERSION


@pytest.fixture
def env(tmp_path, monkeypatch):
    clock = [int(time.time())]
    monkeypatch.setattr("backend.security.sessions.utc_now", lambda: clock[0])
    settings = Settings(_env_file=None, environment="test", database_path=tmp_path / "meta.sqlite3",
                        database_busy_timeout_ms=100, cleanup_adapter_timeout_seconds=2)
    db = Database(settings, clock=lambda: clock[0])
    db.initialize()
    storage = PrivateStorage(db, settings)
    storage.initialize()
    lifecycle = LifecycleCoordinator(db, settings, storage=storage)
    sessions = SessionService(db, settings, lifecycle)
    first, second = sessions.create("192.0.2.1"), sessions.create("192.0.2.2")
    return clock, settings, db, storage, lifecycle, sessions, first, second


def put(storage, principal, data=b"name,value\nsynthetic,1\n", **options):
    args = dict(category="original", file_type="csv", byte_count=len(data),
                chunks=(data[i:i+CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)))
    args.update(options)
    return storage.store(principal, **args)


def location(db, storage, object_id):
    with db.connection() as c:
        row = c.execute("SELECT o.*,n.namespace_id FROM storage_objects o JOIN storage_namespaces n USING(session_id) WHERE object_id=?", (object_id,)).fetchone()
    return storage.root / row["namespace_id"] / row["category"] / (object_id + "." + row["file_type"])


def job(db, issued):
    with db.connection() as c:
        return dict(c.execute("SELECT * FROM cleanup_requests WHERE session_id=?", (issued.principal.session_id,)).fetchone())


def add_run(db, issued, stored):
    owner, run_id, dataset = issued.principal.session_id, uuid4().hex, uuid4().hex
    with db.transaction() as c:
        c.execute("""INSERT INTO datasets(dataset_id,session_id,source_sha256,storage_ref,file_type,
            byte_count,idempotency_key,request_sha256,created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
            (dataset, owner, stored.sha256, stored.object_id, "csv", stored.byte_count, uuid4().hex, "a"*64, db.now()))
        c.execute("INSERT INTO dataset_versions(dataset_id,version,session_id,created_at) VALUES (?,1,?,?)", (dataset,owner,db.now()))
        c.execute("""INSERT INTO runs(run_id,session_id,dataset_id,dataset_version,question,
            idempotency_key,request_sha256,created_at,updated_at) VALUES (?,?,?,1,?,?,?,?,?)""",
            (run_id,owner,dataset,"synthetic count",uuid4().hex,"a"*64,db.now(),db.now()))
    return run_id


def test_roundtrip_hash_immutable_original_and_no_paths(env):
    _, _, db, storage, _, _, first, _ = env
    data = b"synthetic,original\n1,2\n"
    result = put(storage,first.principal,data)
    assert storage.read(first.principal,result.object_id) == data
    assert result.sha256 == hashlib.sha256(data).hexdigest()
    assert len(result.object_id) == 32 and str(storage.root) not in repr(result)
    with pytest.raises(SessionError) as e:
        put(storage,first.principal,b"replacement")
    assert e.value.status_code == 409
    assert storage.read(first.principal,result.object_id) == data
    path = location(db,storage,result.object_id)
    assert not list(path.parent.glob("*.part"))
    with db.transaction() as c, pytest.raises(sqlite3.IntegrityError):
        c.execute("UPDATE storage_objects SET sha256=? WHERE object_id=?", ("b"*64,result.object_id))


@pytest.mark.parametrize("bad", ["../outside", "/etc/passwd", "C:\\Windows\\win.ini", "a"*31, "A"*32, "a"*33, "a"*32+":stream", "", None])
def test_malformed_ids_are_safe_404(env,bad):
    storage, first = env[3], env[6]
    with pytest.raises(SessionError) as e:
        storage.read(first.principal,bad)
    assert e.value.status_code == 404
    assert not str(e.value)


def test_ownership_and_unknown_id_indistinguishable(env):
    _,_,db,storage,_,_,first,second = env
    result = put(storage,first.principal)
    for ref in (result.object_id,uuid4().hex):
        with pytest.raises(SessionError) as e:
            storage.read(second.principal,ref)
        assert e.value.status_code == 404
    run = add_run(db,first,result)
    with pytest.raises(SessionError) as e:
        put(storage,second.principal,b"print(1)",category="candidate",file_type="py",run_id=run,candidate_version=1)
    assert e.value.status_code == 404


@pytest.mark.parametrize("category,file_type,limit", [("original","csv",INPUT_LIMIT),("version","csv",PARSED_LIMIT)])
def test_exact_input_limits_and_oversize_without_creating_files(env,category,file_type,limit):
    storage, first = env[3], env[6]
    with pytest.raises(SessionError) as e:
        put(storage,first.principal,category=category,file_type=file_type,byte_count=limit+1)
    assert e.value.status_code == 413
    chunk = b"s"*CHUNK_SIZE
    result = storage.store(first.principal,category=category,file_type=file_type,byte_count=limit,
                           chunks=(chunk for _ in range(limit//CHUNK_SIZE)))
    assert result.byte_count == limit
    assert len(storage.read(first.principal,result.object_id)) == limit


@pytest.mark.parametrize("options,status", [({"file_type":"html"},415),({"category":"../escape"},415),
    ({"file_type":"xlsm"},415),({"byte_count":0},413),({"byte_count":True},413),
    ({"chunks":[b"a"*(CHUNK_SIZE+1)]},400),({"byte_count":1},413),({"byte_count":100},400)])
def test_types_size_and_stream_contract(env,options,status):
    with pytest.raises(SessionError) as e:
        put(env[3],env[6].principal,**options)
    assert e.value.status_code == status


def test_tampered_content_and_unexpected_file_type_rejected(env):
    _,_,db,storage,_,_,first,_ = env
    result = put(storage,first.principal)
    path = location(db,storage,result.object_id)
    path.write_bytes(b"corrupt")
    with pytest.raises(SessionError) as e:
        storage.read(first.principal,result.object_id)
    assert e.value.status_code == 503
    path.unlink()
    path.mkdir()
    with pytest.raises(SessionError):
        storage.read(first.principal,result.object_id)


def test_hardlink_read_and_cleanup_rejected_without_touching_target(env,tmp_path):
    _,_,db,storage,life,sessions,first,_ = env
    result = put(storage,first.principal)
    path = location(db,storage,result.object_id)
    target = tmp_path/"synthetic-outside.csv"
    target.write_bytes(b"outside-synthetic")
    path.unlink(); os.link(target,path)
    with pytest.raises(SessionError): storage.read(first.principal,result.object_id)
    sessions.revoke(first.credential,first.principal.session_id)
    asyncio.run(life.run_once())
    assert job(db,first)["state"] == "BLOCKED"
    assert target.read_bytes() == b"outside-synthetic" and path.exists()


def test_symlink_read_cleanup_and_ancestor_rejected(env,tmp_path):
    _,settings,db,storage,life,sessions,first,_ = env
    result = put(storage,first.principal)
    path = location(db,storage,result.object_id)
    target = tmp_path/"synthetic-target.csv"
    target.write_bytes(b"untouched-synthetic")
    path.unlink()
    try:
        path.symlink_to(target)
    except OSError as e:
        pytest.skip(f"OS symlink privilege unavailable: {type(e).__name__}")
    with pytest.raises(SessionError): storage.read(first.principal,result.object_id)
    sessions.revoke(first.credential,first.principal.session_id)
    asyncio.run(life.run_once())
    assert job(db,first)["state"] == "BLOCKED"
    assert target.read_bytes() == b"untouched-synthetic"
    linked = tmp_path/"linked"
    linked.symlink_to(storage.root,target_is_directory=True)
    with pytest.raises(SessionError):
        PrivateStorage(db,settings.model_copy(update={"private_storage_path":linked})).check_ready()


def test_interrupted_stream_never_seals_and_is_cleaned_after_restart(env):
    _,settings,db,storage,_,sessions,first,_ = env
    def broken():
        yield b"synthetic"
        raise RuntimeError("synthetic interrupted producer")
    with pytest.raises(RuntimeError):
        put(storage,first.principal,b"synthetic-more",chunks=broken())
    with db.connection() as c:
        row = c.execute("SELECT * FROM storage_objects").fetchone()
        assert row["state"] == "STAGING"
    with pytest.raises(SessionError): storage.read(first.principal,row["object_id"])
    sessions.revoke(first.credential,first.principal.session_id)
    restarted = PrivateStorage(db,settings); restarted.initialize()
    life = LifecycleCoordinator(db,settings,storage=restarted)
    asyncio.run(life.run_once())
    assert job(db,first)["state"] == "COMPLETE"
    assert list(storage.root.iterdir()) == [storage.root/".sheetsafe-root"]


def test_rename_then_db_failure_remains_unreadable_and_recoverable(env,monkeypatch):
    _,_,db,storage,life,sessions,first,_ = env
    original = Directory.rename_new
    def crash(self,*args):
        original(self,*args)
        raise sqlite3.OperationalError("synthetic DB commit failure")
    monkeypatch.setattr(Directory,"rename_new",crash)
    with pytest.raises(SessionError): put(storage,first.principal)
    with db.connection() as c:
        row = c.execute("SELECT * FROM storage_objects").fetchone()
        assert row["state"] == "STAGING"
    assert location(db,storage,row["object_id"]).exists()
    with pytest.raises(SessionError): storage.read(first.principal,row["object_id"])
    sessions.revoke(first.credential,first.principal.session_id)
    asyncio.run(life.run_once())
    assert job(db,first)["state"] == "COMPLETE"


def test_delete_expiry_idempotence_and_other_session_survives(env):
    clock,_,db,storage,life,sessions,first,second = env
    first_file, second_file = put(storage,first.principal), put(storage,second.principal)
    first_path, second_path = location(db,storage,first_file.object_id), location(db,storage,second_file.object_id)
    sessions.revoke(first.credential,first.principal.session_id)
    with pytest.raises(SessionError): storage.read(first.principal,first_file.object_id)
    asyncio.run(life.run_once()); asyncio.run(life.run_once())
    assert job(db,first)["state"] == "COMPLETE" and job(db,first)["storage_status"] == "VERIFIED"
    assert not first_path.exists() and second_path.exists()
    assert storage.read(second.principal,second_file.object_id)
    clock[0] = second.principal.expires_at
    asyncio.run(life.run_once())
    assert job(db,second)["state"] == "COMPLETE" and not second_path.exists()
    assert job(db,second)["completed_at"] < job(db,second)["deadline_at"]
    with db.connection() as c:
        assert c.execute("SELECT count(*) FROM storage_objects").fetchone()[0] == 0
        assert not c.execute("PRAGMA foreign_key_check").fetchall()


def test_revocation_during_write_is_immediate_and_prevents_finalize(env):
    clock,_,db,storage,life,sessions,first,_ = env
    entered, release = Event(), Event()
    def blocked():
        yield b"syn"
        entered.set()
        assert release.wait(5)
        yield b"thetic"
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(put,storage,first.principal,b"synthetic",chunks=blocked())
        assert entered.wait(5)
        try:
            sessions.revoke(first.credential,first.principal.session_id)
            with pytest.raises(SessionError): sessions.authenticate(first.credential)
            asyncio.run(life.run_once())
            assert job(db,first)["state"] == "RETRY" and job(db,first)["completed_at"] is None
        finally: release.set()
        with pytest.raises(SessionError): future.result(timeout=5)
    clock[0] += 3
    asyncio.run(life.run_once())
    assert job(db,first)["state"] == "COMPLETE"
    with pytest.raises(SessionError): storage.publish(first.principal,uuid4().hex)


def test_quarantine_budgets_and_publication_stays_disabled(env):
    _,_,db,storage,_,_,first,_ = env
    original = put(storage,first.principal)
    run = add_run(db,first,original)
    args = dict(category="quarantine",file_type="json",run_id=run,candidate_version=1)
    result = put(storage,first.principal,b'{"synthetic":1}',**args)
    with pytest.raises(SessionError) as e: storage.publish(first.principal,result.object_id)
    assert e.value.status_code == 409
    with pytest.raises(SessionError): put(storage,first.principal,b"x",**{**args,"category":"validated"})
    with pytest.raises(SessionError): put(storage,first.principal,byte_count=ARTIFACT_LIMIT+1,**args)
    for _ in range(9): put(storage,first.principal,b"{}",**args)
    with pytest.raises(SessionError) as e: put(storage,first.principal,b"{}",**args)
    assert e.value.status_code == 413
    with pytest.raises(SessionError):
        put(storage,first.principal,category="temporary",file_type="txt",run_id=run,candidate_version=2,byte_count=LOG_LIMIT+1)
    # A separate candidate gets its own artifact budget; 20 MiB aggregate is exact.
    for _ in range(2): put(storage,first.principal,b"s"*ARTIFACT_LIMIT,**{**args,"candidate_version":2})
    with pytest.raises(SessionError): put(storage,first.principal,b"{}",**{**args,"candidate_version":2})


def test_unregistered_file_blocks_truthful_cleanup_and_recovery(env,caplog):
    _,_,db,storage,life,sessions,first,_ = env
    result=put(storage,first.principal)
    path=location(db,storage,result.object_id)
    unexpected=path.parent/"unknown-sensitive-name.txt"
    unexpected.write_text("synthetic confidential body")
    receipt=sessions.revoke(first.credential,first.principal.session_id)
    asyncio.run(life.run_once())
    assert job(db,first)["state"] == "BLOCKED"
    assert unexpected.exists()
    assert "unknown-sensitive-name" not in caplog.text and "confidential body" not in caplog.text
    assert str(storage.root) not in caplog.text
    unexpected.unlink()  # Only this test-owned synthetic fixture is removed.
    assert life.resume_blocked(receipt)
    asyncio.run(life.run_once())
    assert job(db,first)["state"] == "COMPLETE"


def test_failed_unlink_is_retried_after_restart(env,monkeypatch):
    clock,settings,db,storage,life,sessions,first,_=env
    result=put(storage,first.principal)
    sessions.revoke(first.credential,first.principal.session_id)
    original=Directory.unlink
    with monkeypatch.context() as patch:
        patch.setattr(Directory,"unlink",lambda *a: (_ for _ in ()).throw(PermissionError("sensitive local path")))
        asyncio.run(life.run_once())
    assert job(db,first)["state"] == "RETRY" and location(db,storage,result.object_id).exists()
    clock[0]+=3
    restarted=LifecycleCoordinator(db,settings,storage=PrivateStorage(db,settings))
    asyncio.run(restarted.run_once())
    assert job(db,first)["state"] == "COMPLETE"


def test_storage_root_identity_mismatch_and_orphans_fail_closed(env,tmp_path):
    _,settings,db,storage,_,_,_,_=env
    replacement=tmp_path/"replacement";replacement.mkdir()
    with pytest.raises(SessionError):
        PrivateStorage(db,settings.model_copy(update={"private_storage_path":replacement})).initialize()
    unknown=storage.root/"unregistered";unknown.mkdir()
    with pytest.raises(SessionError): storage.check_ready()
    assert unknown.exists()


def test_duplicate_server_ids_never_overwrite(env,monkeypatch):
    _,_,db,storage,_,_,first,_=env
    result=put(storage,first.principal,category="version")
    class Duplicate:
        hex=result.object_id
    monkeypatch.setattr("backend.storage.files.uuid4",Duplicate)
    with pytest.raises(SessionError): put(storage,first.principal,b"changed",category="version")
    assert storage.read(first.principal,result.object_id)==b"name,value\nsynthetic,1\n"


def test_app_wires_real_cleanup_and_safe_storage_readiness(tmp_path):
    app=create_app(Settings(_env_file=None,environment="test",database_path=tmp_path/"app.sqlite3",
                            allowed_origins=("https://testserver",)))
    with TestClient(app,base_url="https://testserver") as client:
        assert client.get("/api/v1/ready").status_code==200
        sessions=app.state.sessions
        issued=sessions.create("192.0.2.5")
        stored=put(app.state.storage,issued.principal)
        path=location(app.state.database,app.state.storage,stored.object_id)
        response=client.delete("/api/v1/sessions/"+issued.principal.session_id,headers={
            "Origin":"https://testserver", "X-CSRF-Token":issued.principal.csrf_token,
            "Cookie":app.state.settings.session_cookie_name+"="+issued.credential})
        assert response.status_code==200
        asyncio.run(app.state.lifecycle.run_once())
        assert not path.exists() and job(app.state.database,issued)["state"]=="COMPLETE"
        marker=app.state.storage.root/".sheetsafe-root"
        marker.write_bytes(b"incorrect")
        failure=client.get("/api/v1/ready")
        assert failure.status_code==503 and str(tmp_path) not in failure.text
        assert client.get("/api/v1/health").status_code==200
    assert app.state.storage is None


def test_v3_migration_preserves_existing_sessions(tmp_path):
    settings=Settings(_env_file=None,database_path=tmp_path/"old.sqlite3")
    db=Database(settings)
    c=sqlite3.connect(settings.database_path,isolation_level=None)
    try:
        c.execute("BEGIN IMMEDIATE")
        for target in (1,2,3):
            for statement in MIGRATIONS[target]: c.execute(statement)
        c.execute(f"PRAGMA application_id={APPLICATION_ID}");c.execute("PRAGMA user_version=3")
        c.execute("INSERT INTO sessions(session_id,auth_token_hash,audit_pseudonym) VALUES ('old',?,'pseudo')",("a"*64,))
        c.commit()
    finally:c.close()
    db.initialize();PrivateStorage(db,settings).initialize()
    with db.connection() as c:
        assert c.execute("PRAGMA user_version").fetchone()[0]==SCHEMA_VERSION
        assert c.execute("SELECT session_id FROM sessions").fetchone()[0]=="old"


@pytest.mark.skipif(os.name != "nt", reason="Windows reparse-point regression")
def test_windows_directory_junction_rejected_in_reads_and_cleanup(env,tmp_path):
    _,_,db,storage,life,sessions,first,_=env
    result=put(storage,first.principal)
    path=location(db,storage,result.object_id)
    external=tmp_path/"synthetic-external";external.mkdir()
    protected=external/"canary.txt";protected.write_bytes(b"keep synthetic canary")
    path.unlink();path.parent.rmdir()
    created=subprocess.run(["cmd.exe","/d","/c","mklink","/J",str(path.parent),str(external)],
                           capture_output=True,check=False)
    assert created.returncode==0, "Could not create isolated junction fixture"
    try:
        with pytest.raises(SessionError): storage.read(first.principal,result.object_id)
        sessions.revoke(first.credential,first.principal.session_id)
        asyncio.run(life.run_once())
        assert job(db,first)["state"]=="BLOCKED"
        assert protected.read_bytes()==b"keep synthetic canary"
    finally:
        # Remove only the junction itself, never recurse into its target.
        os.rmdir(path.parent)


def test_cleanup_uses_matching_revoked_request_only(env):
    from backend.security.lifecycle import CleanupContext
    from backend.storage.filesystem import UnsafeStorage
    _,_,db,storage,life,sessions,first,second=env
    result=put(storage,second.principal)
    receipt=sessions.revoke(first.credential,first.principal.session_id)
    life._claim()
    context=CleanupContext(receipt,second.principal.session_id,db.now()+10)
    with pytest.raises(UnsafeStorage): asyncio.run(storage.remove_and_verify(context))
    assert storage.read(second.principal,result.object_id)


def test_all_registered_categories_and_legacy_code_references_cleaned(env):
    _,_,db,storage,life,sessions,first,_=env
    source=put(storage,first.principal)
    run=add_run(db,first,source)
    put(storage,first.principal,b"normalized synthetic",category="version")
    candidate=put(storage,first.principal,b"# inert synthetic source",category="candidate",file_type="py",run_id=run,candidate_version=1)
    for category in ("temporary","quarantine"):
        put(storage,first.principal,b"{}",category=category,file_type="json",run_id=run,candidate_version=1)
    with db.transaction() as c:
        c.execute("INSERT INTO attempts(attempt_id,run_id,candidate_version,code_ref,code_sha256) VALUES (?,?,1,?,?)",
                  (uuid4().hex,run,candidate.object_id,candidate.sha256))
        with pytest.raises(sqlite3.IntegrityError):
            c.execute("DELETE FROM sessions WHERE session_id=?",(first.principal.session_id,))
    sessions.revoke(first.credential,first.principal.session_id)
    asyncio.run(life.run_once())
    assert job(db,first)["state"]=="COMPLETE"
    assert job(db,first)["runtime_status"]=="NONE_REGISTERED"
    with db.connection() as c:
        for table in ("datasets","dataset_versions","runs","attempts","storage_objects","storage_namespaces"):
            assert c.execute(f"SELECT count(*) FROM {table}").fetchone()[0]==0


def test_runtime_evidence_without_runner_still_blocks(env):
    _,_,db,storage,life,sessions,first,_=env
    source=put(storage,first.principal)
    run=add_run(db,first,source)
    with db.transaction() as c: c.execute("UPDATE runs SET state='EXECUTE' WHERE run_id=?",(run,))
    path=location(db,storage,source.object_id)
    sessions.revoke(first.credential,first.principal.session_id)
    asyncio.run(life.run_once())
    assert job(db,first)["state"]=="BLOCKED" and job(db,first)["last_error_code"]=="RUNNER_REQUIRED"
    assert path.exists()


def test_existing_user_directory_is_never_adopted_or_deleted(tmp_path):
    existing=tmp_path/"userfiles";existing.mkdir()
    canary=existing/"synthetic.txt";canary.write_text("synthetic only")
    settings=Settings(_env_file=None,database_path=tmp_path/"metadata.sqlite3",private_storage_path=existing)
    db=Database(settings);db.initialize()
    with pytest.raises(SessionError): PrivateStorage(db,settings).initialize()
    assert canary.read_text()=="synthetic only"


def test_storage_configuration_defaults_next_to_db_without_resolving_links(tmp_path):
    settings=Settings(_env_file=None,database_path=tmp_path/"meta.sqlite3")
    assert settings.storage_path==tmp_path/"storage"
    explicit=Settings(_env_file=None,database_path=tmp_path/"meta.sqlite3",private_storage_path=tmp_path/"custom")
    assert explicit.storage_path==tmp_path/"custom"


def test_files_removed_but_database_purge_failure_recovers_after_restart(env,monkeypatch):
    clock,settings,db,storage,life,sessions,first,_=env
    source=put(storage,first.principal)
    add_run(db,first,source)
    path=location(db,storage,source.object_id)
    sessions.revoke(first.credential,first.principal.session_id)
    def fail(*args): raise sqlite3.OperationalError("synthetic purge failure")
    monkeypatch.setattr(life,"_purge_metadata",fail)
    asyncio.run(life.run_once())
    assert not path.exists() and job(db,first)["state"]=="RETRY"
    with db.connection() as c:
        assert c.execute("SELECT count(*) FROM storage_objects").fetchone()[0]==1
    clock[0]+=3
    recovered=LifecycleCoordinator(db,settings,storage=PrivateStorage(db,settings))
    asyncio.run(recovered.run_once())
    assert job(db,first)["state"]=="COMPLETE"
