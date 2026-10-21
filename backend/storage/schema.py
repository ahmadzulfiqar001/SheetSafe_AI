"""Ordered, transactional schema migrations. Timestamps are UTC Unix seconds.

Published migrations are immutable; future changes add a new numbered entry.
Only metadata/references belong here, never raw uploads or inference credentials.
"""

SCHEMA_VERSION = 4
APPLICATION_ID = 0x53534149  # SSAI, identifies this application's SQLite files.

RUN_STATES = (
    "PLAN_AND_CODE", "AWAIT_CONFIRMATION", "NEEDS_CLARIFICATION", "QUEUED",
    "POLICY_CHECK", "EXECUTE", "VALIDATE", "REPAIR", "COMPLETE",
    "BLOCKED_POLICY", "TIMED_OUT", "RESOURCE_LIMIT", "SECURITY_FAILURE",
    "PROVIDER_UNAVAILABLE", "CANCELLED", "FAILED_VALIDATION",
    "FAILED_EXECUTION", "INTERRUPTED",
)

_RUN_STATES_SQL = ", ".join(f"'{state}'" for state in RUN_STATES)

MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: (
        """CREATE TABLE sessions (
            session_id TEXT PRIMARY KEY CHECK(length(session_id) > 0),
            auth_token_hash TEXT NOT NULL UNIQUE
                CHECK(length(auth_token_hash) = 64 AND auth_token_hash NOT GLOB '*[^0-9a-f]*'),
            audit_pseudonym TEXT NOT NULL UNIQUE CHECK(length(audit_pseudonym) > 0),
            mode TEXT NOT NULL DEFAULT 'synthetic' CHECK(mode IN ('synthetic', 'private')),
            consent_at INTEGER,
            created_at INTEGER NOT NULL DEFAULT (unixepoch()) CHECK(created_at > 0),
            expires_at INTEGER NOT NULL DEFAULT (unixepoch() + 3600),
            revoked_at INTEGER,
            deletion_requested_at INTEGER,
            CHECK(expires_at > created_at AND expires_at <= created_at + 3600),
            CHECK(mode != 'private' OR consent_at IS NOT NULL),
            CHECK(consent_at IS NULL OR consent_at >= created_at),
            CHECK(revoked_at IS NULL OR revoked_at >= created_at),
            CHECK(deletion_requested_at IS NULL OR deletion_requested_at >= created_at)
        ) STRICT""",
        """CREATE TABLE datasets (
            dataset_id TEXT PRIMARY KEY CHECK(length(dataset_id) > 0),
            session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
            source_sha256 TEXT NOT NULL
                CHECK(length(source_sha256) = 64 AND source_sha256 NOT GLOB '*[^0-9a-f]*'),
            storage_ref TEXT NOT NULL CHECK(length(storage_ref) > 0),
            file_type TEXT NOT NULL CHECK(file_type IN ('csv', 'xlsx')),
            byte_count INTEGER NOT NULL CHECK(byte_count BETWEEN 1 AND 20971520),
            created_at INTEGER NOT NULL DEFAULT (unixepoch()) CHECK(created_at > 0),
            idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) > 0),
            request_sha256 TEXT NOT NULL
                CHECK(length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'),
            UNIQUE(dataset_id, session_id),
            UNIQUE(session_id, idempotency_key)
        ) STRICT""",
        """CREATE TABLE dataset_versions (
            dataset_id TEXT NOT NULL,
            version INTEGER NOT NULL CHECK(version >= 1),
            session_id TEXT NOT NULL,
            parsing_settings_json TEXT NOT NULL DEFAULT '{}'
                CHECK(json_valid(parsing_settings_json) AND json_type(parsing_settings_json) = 'object'),
            profile_json TEXT NOT NULL DEFAULT '{}'
                CHECK(json_valid(profile_json) AND json_type(profile_json) = 'object'),
            state TEXT NOT NULL DEFAULT 'PENDING'
                CHECK(state IN ('PENDING', 'PROFILING', 'READY', 'NEEDS_CLARIFICATION', 'REJECTED', 'FAILED')),
            created_at INTEGER NOT NULL DEFAULT (unixepoch()) CHECK(created_at > 0),
            PRIMARY KEY(dataset_id, version),
            UNIQUE(dataset_id, version, session_id),
            FOREIGN KEY(dataset_id, session_id)
                REFERENCES datasets(dataset_id, session_id) ON DELETE CASCADE
        ) STRICT""",
        f"""CREATE TABLE runs (
            run_id TEXT PRIMARY KEY CHECK(length(run_id) > 0),
            session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
            dataset_id TEXT NOT NULL,
            dataset_version INTEGER NOT NULL,
            question TEXT NOT NULL CHECK(length(question) > 0),
            interpretation_json TEXT NOT NULL DEFAULT '{{}}'
                CHECK(json_valid(interpretation_json) AND json_type(interpretation_json) = 'object'),
            plan_json TEXT NOT NULL DEFAULT '{{}}'
                CHECK(json_valid(plan_json) AND json_type(plan_json) = 'object'),
            state TEXT NOT NULL DEFAULT 'PLAN_AND_CODE' CHECK(state IN ({_RUN_STATES_SQL})),
            state_version INTEGER NOT NULL DEFAULT 0 CHECK(state_version >= 0),
            candidate_versions INTEGER NOT NULL DEFAULT 0 CHECK(candidate_versions BETWEEN 0 AND 3),
            execution_attempts INTEGER NOT NULL DEFAULT 0
                CHECK(execution_attempts BETWEEN 0 AND candidate_versions),
            validation_status TEXT NOT NULL DEFAULT 'PENDING'
                CHECK(validation_status IN ('PENDING', 'PASSED', 'FAILED')),
            cleanup_status TEXT NOT NULL DEFAULT 'PENDING'
                CHECK(cleanup_status IN ('PENDING', 'CONFIRMED', 'FAILED')),
            created_at INTEGER NOT NULL DEFAULT (unixepoch()) CHECK(created_at > 0),
            updated_at INTEGER NOT NULL DEFAULT (unixepoch()) CHECK(updated_at >= created_at),
            confirmation_expires_at INTEGER,
            queued_at INTEGER,
            admitted_at INTEGER,
            deadline_at INTEGER,
            lease_owner TEXT,
            lease_expires_at INTEGER,
            heartbeat_at INTEGER,
            cancel_requested_at INTEGER,
            idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) > 0),
            request_sha256 TEXT NOT NULL
                CHECK(length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'),
            UNIQUE(session_id, idempotency_key),
            FOREIGN KEY(dataset_id, dataset_version, session_id)
                REFERENCES dataset_versions(dataset_id, version, session_id) ON DELETE CASCADE,
            CHECK(state != 'COMPLETE' OR (validation_status = 'PASSED' AND cleanup_status = 'CONFIRMED')),
            CHECK(confirmation_expires_at IS NULL OR confirmation_expires_at >= created_at),
            CHECK(queued_at IS NULL OR queued_at >= created_at),
            CHECK(admitted_at IS NULL OR (admitted_at >= created_at AND
                (queued_at IS NULL OR admitted_at >= queued_at))),
            CHECK(heartbeat_at IS NULL OR heartbeat_at >= created_at),
            CHECK(cancel_requested_at IS NULL OR cancel_requested_at >= created_at),
            CHECK(deadline_at IS NULL OR
                (admitted_at IS NOT NULL AND deadline_at BETWEEN admitted_at AND admitted_at + 180)),
            CHECK((lease_owner IS NULL AND lease_expires_at IS NULL AND heartbeat_at IS NULL) OR
                (lease_owner IS NOT NULL AND length(lease_owner) > 0 AND lease_expires_at IS NOT NULL
                 AND heartbeat_at IS NOT NULL AND lease_expires_at > heartbeat_at))
        ) STRICT""",
        """CREATE TABLE attempts (
            attempt_id TEXT PRIMARY KEY CHECK(length(attempt_id) > 0),
            run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            candidate_version INTEGER NOT NULL CHECK(candidate_version BETWEEN 1 AND 3),
            execution_number INTEGER CHECK(execution_number BETWEEN 1 AND 3),
            code_ref TEXT NOT NULL CHECK(length(code_ref) > 0),
            code_sha256 TEXT NOT NULL
                CHECK(length(code_sha256) = 64 AND code_sha256 NOT GLOB '*[^0-9a-f]*'),
            state TEXT NOT NULL DEFAULT 'GENERATED'
                CHECK(state IN ('GENERATED', 'BLOCKED_POLICY', 'EXECUTING', 'EXECUTED',
                    'FAILED_EXECUTION', 'TIMED_OUT', 'RESOURCE_LIMIT', 'SECURITY_FAILURE',
                    'VALIDATING', 'FAILED_VALIDATION', 'VALIDATED', 'CANCELLED', 'INTERRUPTED')),
            error_signature TEXT,
            change_summary TEXT,
            runtime_receipt_json TEXT NOT NULL DEFAULT '{}'
                CHECK(json_valid(runtime_receipt_json) AND json_type(runtime_receipt_json) = 'object'),
            checks_json TEXT NOT NULL DEFAULT '{}'
                CHECK(json_valid(checks_json) AND json_type(checks_json) = 'object'),
            created_at INTEGER NOT NULL DEFAULT (unixepoch()) CHECK(created_at > 0),
            started_at INTEGER,
            finished_at INTEGER,
            UNIQUE(run_id, candidate_version),
            UNIQUE(run_id, execution_number),
            CHECK(execution_number IS NULL OR execution_number <= candidate_version),
            CHECK(started_at IS NULL OR started_at >= created_at),
            CHECK(finished_at IS NULL OR finished_at >= coalesce(started_at, created_at))
        ) STRICT""",
        # Audit context is deliberately not a foreign key: content-free events can
        # outlive deleted session/run metadata for their separate retention period.
        """CREATE TABLE audit_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE CHECK(length(event_id) > 0),
            session_pseudonym TEXT NOT NULL CHECK(length(session_pseudonym) > 0),
            run_id TEXT,
            attempt_id TEXT,
            state TEXT,
            event_type TEXT NOT NULL CHECK(length(event_type) > 0),
            policy_version TEXT,
            image_digest TEXT,
            build_version TEXT NOT NULL CHECK(length(build_version) > 0),
            details_json TEXT NOT NULL DEFAULT '{}'
                CHECK(json_valid(details_json) AND json_type(details_json) = 'object'),
            created_at INTEGER NOT NULL DEFAULT (unixepoch()) CHECK(created_at > 0),
            expires_at INTEGER NOT NULL DEFAULT (unixepoch() + 86400),
            CHECK(expires_at > created_at AND expires_at <= created_at + 86400),
            CHECK(attempt_id IS NULL OR run_id IS NOT NULL)
        ) STRICT""",
        """CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END""",
        """CREATE TRIGGER audit_events_no_early_delete BEFORE DELETE ON audit_events
            WHEN OLD.expires_at > unixepoch()
            BEGIN SELECT RAISE(ABORT, 'audit retention has not expired'); END""",
        "CREATE INDEX sessions_expiry ON sessions(expires_at)",
        "CREATE INDEX datasets_owner ON datasets(session_id)",
        "CREATE INDEX runs_queue ON runs(state, queued_at)",
        "CREATE INDEX runs_owner ON runs(session_id)",
        "CREATE INDEX runs_dataset ON runs(dataset_id, dataset_version, session_id)",
        "CREATE INDEX runs_lease ON runs(lease_expires_at) WHERE lease_owner IS NOT NULL",
        "CREATE INDEX audit_events_owner_sequence ON audit_events(session_pseudonym, sequence)",
        "CREATE INDEX audit_events_run_sequence ON audit_events(run_id, sequence)",
        "CREATE INDEX audit_events_expiry ON audit_events(expires_at)",
    ),
    2: (
        """CREATE TABLE session_creation_limits (
            scope TEXT NOT NULL CHECK(scope IN ('ip', 'global')),
            key_hash TEXT NOT NULL
                CHECK(length(key_hash) = 64 AND key_hash NOT GLOB '*[^0-9a-f]*'),
            window_start INTEGER NOT NULL CHECK(window_start > 0),
            request_count INTEGER NOT NULL CHECK(request_count >= 1),
            PRIMARY KEY(scope, key_hash)
        ) STRICT""",
        "CREATE INDEX session_creation_limits_expiry ON session_creation_limits(window_start)",
    ),
    3: (
        """CREATE TABLE cleanup_requests (
            request_id TEXT PRIMARY KEY CHECK(length(request_id) > 0),
            session_id TEXT NOT NULL UNIQUE CHECK(length(session_id) > 0),
            session_pseudonym TEXT NOT NULL CHECK(length(session_pseudonym) > 0),
            reason TEXT NOT NULL CHECK(reason IN ('MANUAL', 'EXPIRED', 'REVOKED')),
            requested_at INTEGER NOT NULL CHECK(requested_at > 0),
            deadline_at INTEGER NOT NULL CHECK(deadline_at = requested_at + 300),
            state TEXT NOT NULL DEFAULT 'PENDING'
                CHECK(state IN ('PENDING', 'RUNNING', 'RETRY', 'BLOCKED', 'COMPLETE')),
            phase TEXT NOT NULL DEFAULT 'RESOURCES' CHECK(phase IN ('RESOURCES', 'CHECKPOINT')),
            attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 10),
            next_attempt_at INTEGER NOT NULL,
            lease_token TEXT,
            lease_expires_at INTEGER,
            last_error_code TEXT CHECK(last_error_code IN (
                'STORAGE_REQUIRED', 'RUNNER_REQUIRED', 'UNVERIFIED', 'ADAPTER_TIMEOUT',
                'ADAPTER_FAILURE', 'DATABASE_FAILURE', 'CHECKPOINT_BUSY',
                'LEASE_EXPIRED', 'RETRY_EXHAUSTED')),
            deadline_missed_at INTEGER,
            failure_recorded INTEGER NOT NULL DEFAULT 0 CHECK(failure_recorded IN (0, 1)),
            storage_status TEXT NOT NULL DEFAULT 'UNVERIFIED'
                CHECK(storage_status IN ('UNVERIFIED', 'NONE_REGISTERED', 'VERIFIED')),
            runtime_status TEXT NOT NULL DEFAULT 'UNVERIFIED'
                CHECK(runtime_status IN ('UNVERIFIED', 'NONE_REGISTERED', 'VERIFIED')),
            completed_at INTEGER,
            retain_until INTEGER,
            CHECK((state = 'RUNNING' AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
                OR (state != 'RUNNING' AND lease_token IS NULL AND lease_expires_at IS NULL)),
            CHECK((state = 'COMPLETE' AND completed_at IS NOT NULL AND retain_until = completed_at + 86400)
                OR (state != 'COMPLETE' AND completed_at IS NULL AND retain_until IS NULL)),
            CHECK(state != 'COMPLETE' OR (phase='CHECKPOINT' AND completed_at >= requested_at
                AND storage_status IN ('NONE_REGISTERED', 'VERIFIED')
                AND runtime_status IN ('NONE_REGISTERED', 'VERIFIED')))
        ) STRICT""",
        "CREATE INDEX cleanup_due ON cleanup_requests(state, next_attempt_at)",
        "CREATE INDEX cleanup_retention ON cleanup_requests(retain_until)",
        """CREATE TABLE cleanup_daily_metrics (
            day_start INTEGER NOT NULL CHECK(day_start >= 0 AND day_start % 86400 = 0),
            metric TEXT NOT NULL CHECK(metric IN ('COMPLETED', 'DEADLINE_MISSED')),
            value INTEGER NOT NULL CHECK(value > 0),
            expires_at INTEGER NOT NULL CHECK(expires_at = day_start + 2592000),
            PRIMARY KEY(day_start, metric)
        ) STRICT""",
        "DROP TRIGGER audit_events_no_early_delete",
        """CREATE TRIGGER audit_events_no_early_delete BEFORE DELETE ON audit_events
            WHEN OLD.expires_at > retention_now()
            BEGIN SELECT RAISE(ABORT, 'audit retention has not expired'); END""",
        """CREATE TRIGGER sessions_no_reactivation BEFORE UPDATE ON sessions
            WHEN (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at)
                OR (OLD.deletion_requested_at IS NOT NULL AND NEW.deletion_requested_at IS NOT OLD.deletion_requested_at)
                OR (OLD.expires_at <= unixepoch() AND
                    (NEW.expires_at > OLD.expires_at OR NEW.created_at > OLD.created_at))
                OR (EXISTS(SELECT 1 FROM cleanup_requests WHERE session_id=OLD.session_id)
                    AND (NEW.revoked_at IS NULL OR NEW.deletion_requested_at IS NULL))
            BEGIN SELECT RAISE(ABORT, 'session lifecycle is irreversible'); END""",
        """CREATE TRIGGER sessions_no_cleanup_id_reuse BEFORE INSERT ON sessions
            WHEN EXISTS(SELECT 1 FROM cleanup_requests WHERE session_id=NEW.session_id)
            BEGIN SELECT RAISE(ABORT, 'session identifier is retired'); END""",
        """CREATE TRIGGER cleanup_request_identity_immutable BEFORE UPDATE ON cleanup_requests
            WHEN NEW.request_id IS NOT OLD.request_id OR NEW.session_id IS NOT OLD.session_id
                OR NEW.session_pseudonym IS NOT OLD.session_pseudonym
                OR NEW.requested_at IS NOT OLD.requested_at OR NEW.deadline_at IS NOT OLD.deadline_at
                OR (OLD.state='COMPLETE' AND NEW.state != 'COMPLETE')
            BEGIN SELECT RAISE(ABORT, 'cleanup identity is immutable'); END""",
        """CREATE TRIGGER cleanup_request_requires_revocation BEFORE INSERT ON cleanup_requests
            WHEN EXISTS(SELECT 1 FROM sessions WHERE session_id=NEW.session_id AND
                (revoked_at IS NULL OR deletion_requested_at IS NULL OR audit_pseudonym != NEW.session_pseudonym))
            BEGIN SELECT RAISE(ABORT, 'cleanup requires matching revoked owner'); END""",
        *tuple(
            f"""CREATE TRIGGER {table}_owner_immutable BEFORE UPDATE ON {table}
                WHEN {condition}
                BEGIN SELECT RAISE(ABORT, 'resource ownership is immutable'); END"""
            for table, condition in (
                ("datasets", "NEW.session_id IS NOT OLD.session_id OR NEW.dataset_id IS NOT OLD.dataset_id"),
                ("dataset_versions", "NEW.session_id IS NOT OLD.session_id OR NEW.dataset_id IS NOT OLD.dataset_id OR NEW.version IS NOT OLD.version"),
                ("runs", "NEW.session_id IS NOT OLD.session_id OR NEW.run_id IS NOT OLD.run_id OR NEW.dataset_id IS NOT OLD.dataset_id OR NEW.dataset_version IS NOT OLD.dataset_version"),
                ("attempts", "NEW.run_id IS NOT OLD.run_id OR NEW.attempt_id IS NOT OLD.attempt_id"),
            )
        ),
        # Trusted cleanup changes cancellation metadata or deletes rows; it never
        # needs to republish or reinterpret an inactive session's content.
        *tuple(
            f"""CREATE TRIGGER {table}_inactive_insert BEFORE INSERT ON {table}
                WHEN EXISTS(SELECT 1 FROM sessions WHERE session_id=NEW.session_id AND
                    (revoked_at IS NOT NULL OR deletion_requested_at IS NOT NULL OR expires_at <= unixepoch()))
                BEGIN SELECT RAISE(ABORT, 'session is inactive'); END"""
            for table in ("datasets", "dataset_versions", "runs")
        ),
        *tuple(
            f"""CREATE TRIGGER {table}_inactive_update BEFORE UPDATE ON {table}
                WHEN EXISTS(SELECT 1 FROM sessions WHERE session_id=NEW.session_id AND
                    (revoked_at IS NOT NULL OR deletion_requested_at IS NOT NULL OR expires_at <= unixepoch()))
                BEGIN SELECT RAISE(ABORT, 'session is inactive'); END"""
            for table in ("datasets", "dataset_versions")
        ),
        """CREATE TRIGGER runs_no_inactive_publication
            BEFORE UPDATE OF state, question, interpretation_json, plan_json, dataset_id, dataset_version, session_id ON runs
            WHEN (NEW.state NOT IN ('CANCELLED', 'INTERRUPTED') OR NEW.question IS NOT OLD.question
                OR NEW.interpretation_json IS NOT OLD.interpretation_json OR NEW.plan_json IS NOT OLD.plan_json) AND
                EXISTS(SELECT 1 FROM sessions WHERE session_id=NEW.session_id AND
                    (revoked_at IS NOT NULL OR deletion_requested_at IS NOT NULL OR expires_at <= unixepoch()))
            BEGIN SELECT RAISE(ABORT, 'session is inactive'); END""",
        *tuple(
            f"""CREATE TRIGGER attempts_inactive_{operation.lower()} BEFORE {operation} ON attempts
                WHEN EXISTS(SELECT 1 FROM runs JOIN sessions USING(session_id) WHERE run_id=NEW.run_id AND
                    (revoked_at IS NOT NULL OR deletion_requested_at IS NOT NULL OR expires_at <= unixepoch()))
                BEGIN SELECT RAISE(ABORT, 'session is inactive'); END"""
            for operation in ("INSERT", "UPDATE")
        ),
    ),
    4: (
        """CREATE TABLE storage_identity (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            root_id TEXT NOT NULL UNIQUE CHECK(length(root_id)=32)
        ) STRICT""",
        """CREATE TABLE storage_namespaces (
            session_id TEXT PRIMARY KEY REFERENCES sessions(session_id) ON DELETE CASCADE,
            namespace_id TEXT NOT NULL UNIQUE CHECK(length(namespace_id)=32 AND namespace_id NOT GLOB '*[^0-9a-f]*'),
            cleaned_at INTEGER
        ) STRICT""",
        """CREATE TABLE storage_objects (
            object_id TEXT PRIMARY KEY CHECK(length(object_id)=32 AND object_id NOT GLOB '*[^0-9a-f]*'),
            session_id TEXT NOT NULL REFERENCES storage_namespaces(session_id) ON DELETE CASCADE,
            category TEXT NOT NULL CHECK(category IN ('original','version','candidate','temporary','quarantine','validated')),
            file_type TEXT NOT NULL CHECK(file_type IN ('csv','xlsx','py','png','json','txt')),
            run_id TEXT REFERENCES runs(run_id) ON DELETE RESTRICT,
            candidate_version INTEGER NOT NULL DEFAULT 0 CHECK(candidate_version BETWEEN 0 AND 3),
            state TEXT NOT NULL DEFAULT 'STAGING' CHECK(state IN ('STAGING','SEALED')),
            byte_count INTEGER NOT NULL CHECK(byte_count>0),
            sha256 TEXT CHECK(length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
            created_at INTEGER NOT NULL CHECK(created_at>0),
            CHECK(state!='SEALED' OR sha256 IS NOT NULL),
            CHECK((category IN ('original','version') AND run_id IS NULL AND candidate_version=0)
                OR (category NOT IN ('original','version') AND run_id IS NOT NULL AND candidate_version BETWEEN 1 AND 3))
        ) STRICT""",
        "CREATE INDEX storage_objects_owner ON storage_objects(session_id)",
        "CREATE UNIQUE INDEX storage_single_original ON storage_objects(session_id) WHERE category='original'",
        "CREATE UNIQUE INDEX storage_single_candidate ON storage_objects(run_id,candidate_version) WHERE category='candidate'",
        """CREATE TRIGGER storage_identity_immutable BEFORE UPDATE ON storage_identity
            BEGIN SELECT RAISE(ABORT, 'storage root identity is immutable'); END""",
        """CREATE TRIGGER storage_identity_no_delete BEFORE DELETE ON storage_identity
            BEGIN SELECT RAISE(ABORT, 'storage root identity is required'); END""",
        """CREATE TRIGGER storage_namespace_immutable BEFORE UPDATE ON storage_namespaces
            WHEN NEW.session_id IS NOT OLD.session_id OR NEW.namespace_id IS NOT OLD.namespace_id
            BEGIN SELECT RAISE(ABORT, 'storage ownership is immutable'); END""",
        """CREATE TRIGGER storage_object_immutable BEFORE UPDATE ON storage_objects
            WHEN NEW.object_id IS NOT OLD.object_id OR NEW.session_id IS NOT OLD.session_id
                OR NEW.category IS NOT OLD.category OR NEW.file_type IS NOT OLD.file_type
                OR NEW.run_id IS NOT OLD.run_id OR NEW.candidate_version IS NOT OLD.candidate_version
                OR NEW.byte_count IS NOT OLD.byte_count OR NEW.created_at IS NOT OLD.created_at
                OR (OLD.state='SEALED')
            BEGIN SELECT RAISE(ABORT, 'storage metadata is immutable'); END""",
        *tuple(
            f"""CREATE TRIGGER {table}_active_insert BEFORE INSERT ON {table}
                WHEN NOT EXISTS(SELECT 1 FROM sessions WHERE session_id=NEW.session_id
                    AND revoked_at IS NULL AND deletion_requested_at IS NULL AND expires_at>retention_now())
                BEGIN SELECT RAISE(ABORT, 'session is inactive'); END"""
            for table in ('storage_namespaces', 'storage_objects')
        ),
        """CREATE TRIGGER storage_active_seal BEFORE UPDATE ON storage_objects
            WHEN NOT EXISTS(SELECT 1 FROM sessions WHERE session_id=NEW.session_id
                AND revoked_at IS NULL AND deletion_requested_at IS NULL AND expires_at>retention_now())
            BEGIN SELECT RAISE(ABORT, 'session is inactive'); END""",
        """CREATE TRIGGER storage_run_owner BEFORE INSERT ON storage_objects
            WHEN NEW.run_id IS NOT NULL AND NOT EXISTS(
                SELECT 1 FROM runs WHERE run_id=NEW.run_id AND session_id=NEW.session_id)
            BEGIN SELECT RAISE(ABORT, 'storage run owner mismatch'); END""",
        """CREATE TRIGGER storage_no_unverified_session_delete BEFORE DELETE ON sessions
            WHEN EXISTS(SELECT 1 FROM storage_namespaces WHERE session_id=OLD.session_id AND cleaned_at IS NULL)
                OR EXISTS(SELECT 1 FROM storage_objects WHERE session_id=OLD.session_id)
            BEGIN SELECT RAISE(ABORT, 'storage cleanup is not verified'); END""",
    ),
}
