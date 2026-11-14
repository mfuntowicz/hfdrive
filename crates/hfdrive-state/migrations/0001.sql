-- HF Drive account-local database schema version 1.
-- One database per credential partition (issuer + subject). It owns connection
-- bindings, catalog item state, durable work (outbox/snapshots/transfers),
-- publication baselines, event cursors, conflicts, journaled local actions,
-- the local setup journal, the probe created-key journal and settings.
-- It never stores credential material: oauth_ref/s3_ref name DPAPI-protected
-- files outside the database.

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
    volume_guid TEXT,
    volume_serial INTEGER CHECK (volume_serial IS NULL OR volume_serial >= 0),
    sync_root_id TEXT,
    oauth_ref TEXT,
    s3_ref TEXT,
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    mode TEXT NOT NULL CHECK (mode IN ('read_only', 'writable')),
    observed_commit BLOB CHECK (observed_commit IS NULL OR length(observed_commit) = 16),
    published_commit BLOB CHECK (published_commit IS NULL OR length(published_commit) = 16),
    applied_commit BLOB CHECK (applied_commit IS NULL OR length(applied_commit) = 16),
    config_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
);
CREATE INDEX connections_by_account ON connections (account_key);

CREATE TABLE items (
    connection_id BLOB NOT NULL REFERENCES connections(connection_id) ON DELETE CASCADE,
    item_id BLOB NOT NULL CHECK (length(item_id) = 16),
    parent_id BLOB CHECK (parent_id IS NULL OR length(parent_id) = 16),
    name TEXT NOT NULL,
    name_key TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('file', 'directory')),
    revision BLOB NOT NULL CHECK (length(revision) = 16),
    content_version_id BLOB CHECK (content_version_id IS NULL OR length(content_version_id) = 16),
    deleted INTEGER NOT NULL CHECK (deleted IN (0, 1)),
    metadata_json TEXT NOT NULL,
    PRIMARY KEY (connection_id, item_id)
);
CREATE INDEX items_by_parent_name
    ON items (connection_id, parent_id, name_key);

CREATE TABLE filesystem_identities (
    connection_id BLOB NOT NULL REFERENCES connections(connection_id) ON DELETE CASCADE,
    item_id BLOB NOT NULL CHECK (length(item_id) = 16),
    volume_id TEXT NOT NULL,
    file_id TEXT NOT NULL,
    path TEXT NOT NULL,
    usn INTEGER CHECK (usn IS NULL OR usn >= 0),
    PRIMARY KEY (connection_id, item_id)
);
CREATE INDEX filesystem_identities_by_path
    ON filesystem_identities (connection_id, path);

CREATE TABLE common_bases (
    connection_id BLOB NOT NULL REFERENCES connections(connection_id) ON DELETE CASCADE,
    item_id BLOB NOT NULL CHECK (length(item_id) = 16),
    commit_id BLOB NOT NULL CHECK (length(commit_id) = 16),
    item_json TEXT NOT NULL,
    PRIMARY KEY (connection_id, item_id, commit_id)
);

CREATE TABLE local_observations (
    connection_id BLOB NOT NULL REFERENCES connections(connection_id) ON DELETE CASCADE,
    item_id BLOB NOT NULL CHECK (length(item_id) = 16),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    observed_usn INTEGER CHECK (observed_usn IS NULL OR observed_usn >= 0),
    dirty INTEGER NOT NULL CHECK (dirty IN (0, 1)),
    pin_requested INTEGER NOT NULL CHECK (pin_requested IN (0, 1)),
    pin_complete INTEGER NOT NULL CHECK (pin_complete IN (0, 1)),
    excluded INTEGER NOT NULL CHECK (excluded IN (0, 1)),
    scan_epoch INTEGER NOT NULL CHECK (scan_epoch >= 0),
    PRIMARY KEY (connection_id, item_id)
);

CREATE TABLE outbox (
    connection_id BLOB NOT NULL REFERENCES connections(connection_id) ON DELETE CASCADE,
    operation_id BLOB NOT NULL CHECK (length(operation_id) = 16),
    item_id BLOB CHECK (item_id IS NULL OR length(item_id) = 16),
    base_commit BLOB CHECK (base_commit IS NULL OR length(base_commit) = 16),
    base_json TEXT,
    observed_generation INTEGER NOT NULL CHECK (observed_generation >= 0),
    intent_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('observed', 'snapshot_ready', 'payload_ready', 'metadata_ready',
                  'publish_unknown', 'published', 'local_apply_pending', 'complete')
    ),
    snapshot_id BLOB CHECK (snapshot_id IS NULL OR length(snapshot_id) = 16),
    object_ref_json TEXT,
    candidate_commit BLOB CHECK (candidate_commit IS NULL OR length(candidate_commit) = 16),
    candidate_head_json TEXT,
    expected_etag TEXT,
    retry_class TEXT NOT NULL CHECK (retry_class IN ('none', 'backoff', 'needs_user', 'needs_auth')),
    next_attempt_at_ms INTEGER CHECK (next_attempt_at_ms IS NULL OR next_attempt_at_ms >= 0),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    PRIMARY KEY (connection_id, operation_id)
);
CREATE INDEX outbox_by_state
    ON outbox (connection_id, state, next_attempt_at_ms);

CREATE TABLE snapshots (
    connection_id BLOB NOT NULL REFERENCES connections(connection_id) ON DELETE CASCADE,
    snapshot_id BLOB NOT NULL CHECK (length(snapshot_id) = 16),
    path TEXT NOT NULL,
    size INTEGER CHECK (size IS NULL OR size >= 0),
    sha256 BLOB CHECK (sha256 IS NULL OR length(sha256) = 32),
    status TEXT NOT NULL CHECK (status IN ('capturing', 'ready', 'consumed', 'released')),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    PRIMARY KEY (connection_id, snapshot_id)
);
CREATE INDEX snapshots_by_path ON snapshots (connection_id, path);

CREATE TABLE transfers (
    connection_id BLOB NOT NULL REFERENCES connections(connection_id) ON DELETE CASCADE,
    transfer_id BLOB NOT NULL CHECK (length(transfer_id) = 16),
    operation_id BLOB CHECK (operation_id IS NULL OR length(operation_id) = 16),
    direction TEXT NOT NULL CHECK (direction IN ('upload', 'download')),
    version_id BLOB CHECK (version_id IS NULL OR length(version_id) = 16),
    range_start INTEGER CHECK (range_start IS NULL OR range_start >= 0),
    range_end INTEGER CHECK (range_end IS NULL OR range_end >= 0),
    state TEXT NOT NULL CHECK (state IN ('pending', 'in_progress', 'succeeded', 'failed', 'cancelled')),
    sdk_resume_json TEXT,
    logical_bytes INTEGER NOT NULL CHECK (logical_bytes >= 0),
    wire_bytes INTEGER NOT NULL CHECK (wire_bytes >= 0),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    PRIMARY KEY (connection_id, transfer_id),
    CHECK (range_start IS NULL OR range_end IS NULL OR range_start <= range_end)
);
CREATE INDEX transfers_by_operation ON transfers (connection_id, operation_id);

CREATE TABLE commits (
    connection_id BLOB NOT NULL REFERENCES connections(connection_id) ON DELETE CASCADE,
    commit_id BLOB NOT NULL CHECK (length(commit_id) = 16),
    parent_id BLOB CHECK (parent_id IS NULL OR length(parent_id) = 16),
    catalog_root BLOB CHECK (catalog_root IS NULL OR length(catalog_root) = 32),
    operation_ids_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('candidate', 'committed', 'applied')),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    PRIMARY KEY (connection_id, commit_id)
);
CREATE INDEX commits_by_parent ON commits (connection_id, parent_id);

CREATE TABLE event_cursors (
    connection_id BLOB PRIMARY KEY REFERENCES connections(connection_id) ON DELETE CASCADE,
    cursor TEXT,
    pending_head_refresh INTEGER NOT NULL CHECK (pending_head_refresh IN (0, 1)),
    volume_id TEXT NOT NULL,
    journal_id TEXT NOT NULL,
    usn_cursor INTEGER CHECK (usn_cursor IS NULL OR usn_cursor >= 0),
    scan_epoch INTEGER NOT NULL CHECK (scan_epoch >= 0),
    scan_complete INTEGER NOT NULL CHECK (scan_complete IN (0, 1)),
    scan_invalidated INTEGER NOT NULL CHECK (scan_invalidated IN (0, 1)),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
);

CREATE TABLE conflicts (
    connection_id BLOB NOT NULL REFERENCES connections(connection_id) ON DELETE CASCADE,
    conflict_id BLOB NOT NULL CHECK (length(conflict_id) = 16),
    item_id BLOB NOT NULL CHECK (length(item_id) = 16),
    competing_ops_json TEXT NOT NULL,
    revisions_json TEXT NOT NULL,
    original_names_json TEXT NOT NULL,
    resolution_state TEXT NOT NULL CHECK (
        resolution_state IN ('unresolved', 'keep_local', 'keep_remote', 'keep_both', 'recovered')
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    PRIMARY KEY (connection_id, conflict_id)
);
CREATE INDEX conflicts_by_item ON conflicts (connection_id, item_id);

CREATE TABLE local_actions (
    connection_id BLOB NOT NULL REFERENCES connections(connection_id) ON DELETE CASCADE,
    action_id BLOB NOT NULL CHECK (length(action_id) = 16),
    item_id BLOB CHECK (item_id IS NULL OR length(item_id) = 16),
    kind TEXT NOT NULL CHECK (
        kind IN ('create_placeholder', 'update_placeholder', 'rename', 'delete_placeholder',
                 'hydrate', 'dehydrate', 'set_pin', 'convert_to_normal', 'other')
    ),
    expected_file_id TEXT,
    expected_generation INTEGER CHECK (expected_generation IS NULL OR expected_generation >= 0),
    expected_usn INTEGER CHECK (expected_usn IS NULL OR expected_usn >= 0),
    old_version BLOB CHECK (old_version IS NULL OR length(old_version) = 16),
    new_version BLOB CHECK (new_version IS NULL OR length(new_version) = 16),
    source_path TEXT,
    target_path TEXT,
    recovery_path TEXT,
    state TEXT NOT NULL CHECK (
        state IN ('pending', 'in_progress', 'applied', 'failed', 'requeued', 'recovered')
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    PRIMARY KEY (connection_id, action_id)
);
CREATE INDEX local_actions_by_state ON local_actions (connection_id, state);

-- Local setup journal. Its commits are account-side only; the control-side
-- mirror lives in the control database and the two are reconciled explicitly.
CREATE TABLE setup_intents (
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
CREATE INDEX setup_intents_by_operation ON setup_intents (operation_id);

-- Exact probe-created-key journal: one row per storage key this run may create.
-- Cleanup enumerates only rows of the run, and only rows confirmed created.
CREATE TABLE probe_keys (
    run_id BLOB NOT NULL CHECK (length(run_id) = 16),
    connection_id BLOB NOT NULL CHECK (length(connection_id) = 16),
    setup_id BLOB CHECK (setup_id IS NULL OR length(setup_id) = 16),
    key TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved', 'create_in_flight', 'created', 'not_created', 'deleted')),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    PRIMARY KEY (run_id, connection_id, key)
);
CREATE INDEX probe_keys_by_run ON probe_keys (run_id, connection_id);

CREATE TABLE settings (
    scope_id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL CHECK (revision >= 0),
    value_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
);
