ALTER TABLE setup_registry ADD COLUMN bucket_creation_operation_id BLOB CHECK (bucket_creation_operation_id IS NULL OR length(bucket_creation_operation_id) = 16);
CREATE UNIQUE INDEX setup_registry_bucket_creation ON setup_registry(bucket_creation_operation_id) WHERE bucket_creation_operation_id IS NOT NULL;
ALTER TABLE operation_ledger ADD COLUMN bucket_creation_operation_id BLOB CHECK (bucket_creation_operation_id IS NULL OR length(bucket_creation_operation_id) = 16);
