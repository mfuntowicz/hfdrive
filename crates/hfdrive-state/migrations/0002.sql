ALTER TABLE setup_intents ADD COLUMN bucket_creation_operation_id BLOB CHECK (bucket_creation_operation_id IS NULL OR length(bucket_creation_operation_id) = 16);
CREATE UNIQUE INDEX setup_intents_bucket_creation ON setup_intents(bucket_creation_operation_id) WHERE bucket_creation_operation_id IS NOT NULL;
