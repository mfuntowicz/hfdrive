-- Active durable work is scheduled oldest-first and completed history is
-- never rescanned: `list_active_outbox` reads one connection's non-complete
-- rows in (created_at_ms, operation_id) order. This partial index carries the
-- (connection, state, created_at_ms, operation_id) columns that scan needs and
-- holds only non-complete rows, so the active listing stays bounded without
-- walking completed history at all.
CREATE INDEX outbox_active_by_creation
    ON outbox (connection_id, state, created_at_ms, operation_id)
    WHERE state <> 'complete';
