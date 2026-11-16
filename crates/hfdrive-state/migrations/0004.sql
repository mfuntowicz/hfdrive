-- Local observation facts and stable local presence evidence.
--
-- * `local_observations.observed_size` / `observed_write_time_100ns`: the
--   exact local facts recorded with the generation at observation time.
--   Authoritative metadata scans compare live facts against these, so
--   unchanged files are never re-queued and superseded generations stay
--   visible instead of being discarded.
-- * `filesystem_identities` already records the stable NTFS identity (volume
--   + 128-bit file id) seen for an item. A scan may infer a deletion only for
--   an item that carries this local-presence proof on the current volume: an
--   item whose remote material was never populated locally is absent from the
--   local tree by design and is never turned into a tombstone.
ALTER TABLE local_observations ADD COLUMN observed_size INTEGER
    CHECK (observed_size IS NULL OR observed_size >= 0);
ALTER TABLE local_observations ADD COLUMN observed_write_time INTEGER;
