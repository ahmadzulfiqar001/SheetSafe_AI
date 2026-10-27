# SheetSafe AI — Operations, Backup & Recovery Runbook

This runbook documents operational procedures for running, monitoring, backing up, and recovering the SheetSafe AI control-plane service, SQLite database, and private storage repository.

---

## 1. System Architecture & Component Topology

```
[Browser / User]
       │ (HTTP/HTTPS)
       ▼
[Streamlit UI Dashboard] (Port 8501)
       │ (Internal HTTPX Client, HttpOnly cookies, X-CSRF-Token)
       ▼
[FastAPI Control Plane] (Port 8000)
   ├── [SQLite 3 WAL Database] (`var/sheetsafe.sqlite3`)
   ├── [Private Scoped Storage] (`var/storage/`)
   ├── [Retention Worker] (`LifecycleCoordinator`, 10s interval)
   ├── [AST Policy & Deterministic Code Compiler] (`backend/codegen.py`)
   └── [Independent Numerical Verifier] (`validator/numerical_verifier.py`)
```

---

## 2. Service Startup & Shutdown Procedures

### Windows Development / Demo
```powershell
# 1. Start FastAPI Control Plane:
.\launch_local_demo.ps1 -Component fastapi

# 2. Start Streamlit Dashboard (in a separate terminal):
.\launch_local_demo.ps1 -Component streamlit

# 3. Shutdown:
# Press Ctrl+C in each terminal. Uvicorn and Streamlit perform graceful termination.
```

### Linux Production (Systemd Service)
```ini
# /etc/systemd/system/sheetsafe-api.service
[Unit]
Description=SheetSafe AI FastAPI Control Plane
After=network.target docker.service

[Service]
Type=simple
User=sheetsafe
WorkingDirectory=/opt/sheetsafe
EnvironmentFile=/opt/sheetsafe/.env.production
ExecStart=/opt/sheetsafe/.venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8000 --workers 2 --no-proxy-headers
Restart=on-failure
RestartSec=5s
KillSignal=SIGTERM
TimeoutStopSec=15s

[Install]
WantedBy=multi-user.target
```

---

## 3. SQLite Online Backup & WAL Checkpointing

SQLite operates in Write-Ahead Logging (`WAL`) mode with foreign key enforcement. A standard file copy during active transactions can result in corrupted backups.

### Safe Online Backup Command
Use the SQLite online backup API or `VACUUM INTO`:

```bash
# Method A: SQLite VACUUM INTO (Atomic snapshot of current committed state)
sqlite3 var/sheetsafe.sqlite3 "VACUUM INTO 'var/backups/sheetsafe_backup_$(date +%Y%m%d_%H%M%S).sqlite3';"

# Method B: SQLite Online Backup Tool
sqlite3 var/sheetsafe.sqlite3 ".backup 'var/backups/sheetsafe_backup_online.sqlite3'"
```

### WAL Checkpoint Verification
To ensure pending WAL frames are flushed into the main database file:
```bash
sqlite3 var/sheetsafe.sqlite3 "PRAGMA wal_checkpoint(TRUNCATE);"
```
*Expected return:* `0|0|0` (checkpoint succeeded, WAL truncated).

---

## 4. Private Storage Monitoring & Retention Worker

1. **Storage Structure**: Private storage is partitioned by session (`var/storage/<session_id>/...`).
2. **Immediate Revocation**: Calling `DELETE /api/v1/sessions/{id}` marks the session as revoked immediately (`access_revoked=True`) in SQLite.
3. **Asynchronous Retention Cleanup**: The `LifecycleCoordinator` retention worker scans every 10 seconds and deletes physical storage files matching revoked or expired sessions.
4. **Monitoring Cleanup Health**:
   ```sql
   -- Inspect active/pending cleanup operations in cleanup_requests:
   SELECT session_id, reason, state, attempts, storage_status, runtime_status, requested_at, deadline_at
   FROM cleanup_requests
   WHERE state != 'COMPLETE';
   ```
   If a cleanup operation remains in `PENDING` or `RETRY` beyond the 5-minute deadline (`deadline_at`), inspect worker logs for filesystem permission errors or stuck locks.

---

## 5. Disaster Recovery & Database Restoration

In the event of database corruption or hardware failure:

### Step 1: Stop Services
```bash
sudo systemctl stop sheetsafe-api
```

### Step 2: Verify Backup File Integrity
```bash
sqlite3 var/backups/sheetsafe_backup_latest.sqlite3 "PRAGMA integrity_check;"
# Expected output: "ok"
```

### Step 3: Restore Database File
```bash
# Archive existing corrupted database and sidecars
mv var/sheetsafe.sqlite3 var/sheetsafe.sqlite3.corrupted
rm -f var/sheetsafe.sqlite3-wal var/sheetsafe.sqlite3-shm

# Restore clean snapshot
cp var/backups/sheetsafe_backup_latest.sqlite3 var/sheetsafe.sqlite3
chmod 0600 var/sheetsafe.sqlite3
```

### Step 4: Restart & Probe Readiness
```bash
sudo systemctl start sheetsafe-api
curl -f http://127.0.0.1:8000/api/v1/health
curl -f http://127.0.0.1:8000/api/v1/ready
```

---

## 6. Health & Readiness Probe Interpretation

| Endpoint | HTTP Status | Response | Interpretation |
| :--- | :--- | :--- | :--- |
| `/api/v1/health` | `200 OK` | `{"status":"ok"}` | Process is alive, event loop is responsive. |
| `/api/v1/ready` | `200 OK` | `{"status":"ready"}` | Database accessible, storage root writable, retention worker active. |
| `/api/v1/ready` | `503 Service Unavailable` | `{"status":"not_ready",...}` | Database locked, storage unwritable, or migration mismatch. Service fails closed. |

