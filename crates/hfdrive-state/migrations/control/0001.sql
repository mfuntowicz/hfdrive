-- HF Drive control database schema version 1.
-- The control database owns: the selected account, the account registry, the
-- connection-to-account/root registry, the control-side setup journal mirror
-- used to reconcile account/control commits, the IPC operation ledger, and
-- global settings. It never stores credential material: oauth_ref/s3_ref name
-- DPAPI-protected files outside the database.

CREATE TABLE selected_account (
    slot INTEGER PRIMARY KEY CHECK (slot = 1),
    account_key BLOB NOT NULL CHECK (length(account_key) = 32),
    selected_at_ms INTEGER NOT NULL CHECK (selected_at_ms >= 0)
);

CREATE TABLE accounts (
    account_key BLOB PRIMARY KEY CHECK (length(account_key) = 32),
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    namespace TEXT NOT NULL,
    credential_ref TEXT NOT NULL,
    auth_epoch INTEGER NOT NULL CHECK (auth_epoch >= 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'needs_sign_in', 'signed_out')),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    UNIQUE (issuer, subject)
);

-- Registry of connection ids to their account and exact resource binding.
-- registered = 0 rows are draft reservations and must never appear as
-- connected Explorer roots.
CREATE TABLE connections (
    connection_id BLOB PRIMARY KEY CHECK (length(connection_id) = 16),
    account_key BLOB NOT NULL CHECK (length(account_key) = 32),
    workspace_id BLOB NOT NULL CHECK (length(workspace_id) = 16),
    owner_kind TEXT NOT NULL CHECK (owner_kind IN ('personal', 'organization')),
    owner_id TEXT NOT NULL,
    owner_namespace TEXT NOT NULL,
    bucket_id TEXT NOT NULL,
    bucket_name TEXT NOT NULL,
    prefix TEXT NOT NULL,
    root_path TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('read_only', 'writable')),
    registered INTEGER NOT NULL CHECK (registered IN (0, 1)),
    volume_guid TEXT,
    volume_serial INTEGER CHECK (volume_serial IS NULL OR volume_serial >= 0),
    sync_root_id TEXT,
    oauth_ref TEXT,
    s3_ref TEXT,
    config_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
);
CREATE INDEX connections_by_account ON connections (account_key);

-- Control-side mirror of the account-local setup journal. It carries the full
-- draft so a crash between the account and control commits can be reconciled
-- idempotently in either direction.
CREATE TABLE setup_registry (
    setup_id BLOB PRIMARY KEY CHECK (length(setup_id) = 16),
    connection_id BLOB NOT NULL UNIQUE CHECK (length(connection_id) = 16),
    operation_id BLOB NOT NULL CHECK (length(operation_id) = 16),
    account_key BLOB NOT NULL CHECK (length(account_key) = 32),
    binding_json TEXT NOT NULL,
    initialize INTEGER NOT NULL CHECK (initialize IN (0, 1)),
    request_fingerprint BLOB NOT NULL CHECK (length(request_fingerprint) = 32),
    phase TEXT NOT NULL CHECK (
        phase IN ('reserved', 'credentials_recorded', 'probed', 'preview_ready', 'registering', 'connected')
    ),
    status TEXT NOT NULL CHECK (status IN ('active', 'failed', 'connected', 'abandoned')),
    created_resources_json TEXT NOT NULL,
    preview_json TEXT,
    root_path TEXT,
    mode TEXT CHECK (mode IS NULL OR mode IN ('read_only', 'writable')),
    credential_ref TEXT,
    probe_evidence_json TEXT,
    failure_reason TEXT,
    evidence_generation INTEGER NOT NULL CHECK (evidence_generation >= 0),
    account_committed INTEGER NOT NULL CHECK (account_committed IN (0, 1)),
    control_committed INTEGER NOT NULL CHECK (control_committed IN (0, 1)),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
);
CREATE INDEX setup_registry_by_operation ON setup_registry (operation_id);
CREATE INDEX setup_registry_by_account ON setup_registry (account_key);

-- Idempotency ledger for IPC mutations. An operation whose effect may already
-- have reached an external system stays external_pending until the caller
-- reconciles it; it is never replayed automatically.
CREATE TABLE operation_ledger (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    kind TEXT NOT NULL,
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    effect_class TEXT NOT NULL CHECK (effect_class IN ('none', 'local', 'external')),
    state TEXT NOT NULL CHECK (state IN ('pending', 'external_pending', 'committed', 'failed', 'abandoned')),
    account_key BLOB CHECK (account_key IS NULL OR length(account_key) = 32),
    connection_id BLOB CHECK (connection_id IS NULL OR length(connection_id) = 16),
    result_json TEXT,
    error_code TEXT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
);
CREATE INDEX operation_ledger_by_state ON operation_ledger (state, updated_at_ms);

CREATE TABLE settings (
    scope_id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL CHECK (revision >= 0),
    value_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
);
