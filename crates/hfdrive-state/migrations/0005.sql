-- Acknowledging an older HEAD read must not consume a newer invalidation.
ALTER TABLE event_cursors ADD COLUMN head_refresh_generation INTEGER NOT NULL DEFAULT 0
    CHECK (typeof(head_refresh_generation) = 'integer' AND head_refresh_generation >= 0);

-- Idle scheduling must not scan completed historical work.
CREATE INDEX outbox_pending_dispatch ON outbox (connection_id, next_attempt_at_ms)
    WHERE state <> 'complete';
