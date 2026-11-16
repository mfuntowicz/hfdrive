-- Activity projection evidence and durable failure text.
--
-- * `work_errors`: the real failure classification and text recorded at the
--   failure site (never synthesized at projection time); deleted when the
--   work item reaches its next durable state.
-- * `snapshots.operation_id`: links an in-flight capture to the outbox
--   operation it serves, so the capturing stage is projectable against its
--   real observed item name.
-- * `items_by_version`: resolves an item from a transfer's content version.
-- * keyset paging indexes: the exact (connection, created_at_ms, work id)
--   ordering used by the bounded work-row listing queries.

CREATE TABLE work_errors (
    connection_id BLOB NOT NULL REFERENCES connections(connection_id) ON DELETE CASCADE,
    work_kind TEXT NOT NULL CHECK (work_kind IN ('outbox', 'action', 'transfer')),
    work_id BLOB NOT NULL CHECK (length(work_id) = 16),
    error_code TEXT NOT NULL,
    error_detail TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    PRIMARY KEY (connection_id, work_kind, work_id)
);
CREATE INDEX work_errors_by_connection ON work_errors (connection_id);

ALTER TABLE snapshots ADD COLUMN operation_id BLOB
    CHECK (operation_id IS NULL OR length(operation_id) = 16);
CREATE INDEX snapshots_by_operation ON snapshots (connection_id, operation_id);

CREATE INDEX items_by_version ON items (connection_id, content_version_id);

-- Keyset paging over unfinished work: (connection, created_at_ms, work id)
-- matches the strict-after ordering of the activity projection queries.
CREATE INDEX outbox_work_page ON outbox (connection_id, created_at_ms, operation_id);
CREATE INDEX local_actions_work_page ON local_actions (connection_id, created_at_ms, action_id);
CREATE INDEX transfers_work_page ON transfers (connection_id, created_at_ms, transfer_id);
