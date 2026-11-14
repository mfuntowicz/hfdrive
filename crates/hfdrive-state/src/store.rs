//! Synchronous persistence operations over the control and account databases.
//!
//! Every method runs on the dedicated database worker thread and performs no
//! network or filesystem awaits: only SQLite statements and in-memory work.
//! Multi-statement changes use short transactions; nothing spans both
//! databases atomically — cross-database changes are journaled and reconciled.
//!
//! Account-scoped methods take the `AccountKey` explicitly so the database the
//! caller means is never inferred from mutable selection state.

use crate::convert as c;
use crate::error::StateError;
use crate::model::*;
use crate::schema::{self, DatabaseKind};
use crate::sql as s;
use hfdrive_core::ids::{
    AccountKey, ActionId, CommitId, ConflictId, ConnectionId, GenerationId, ItemId, OperationId,
    SetupId, SnapshotId, TransferId,
};
use hfdrive_core::storage::Sha256Digest;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub(crate) type SResult<T> = Result<T, StateError>;

const SETUP_COLUMNS: &str = "setup_id, connection_id, operation_id, account_key, binding_json, initialize, bucket_creation_operation_id, \
     request_fingerprint, phase, status, created_resources_json, preview_json, root_path, mode, \
     credential_ref, probe_evidence_json, failure_reason, evidence_generation, account_committed, control_committed";

const CONTROL_CONNECTION_COLUMNS: &str = "connection_id, account_key, workspace_id, owner_kind, owner_id, \
     owner_namespace, bucket_id, bucket_name, prefix, root_path, mode, registered, volume_guid, volume_serial, \
     sync_root_id, oauth_ref, s3_ref, config_json";

const ACCOUNT_CONNECTION_COLUMNS: &str = "connection_id, account_key, workspace_id, owner_kind, owner_id, \
     owner_namespace, bucket_id, bucket_name, prefix, root_path, volume_guid, volume_serial, sync_root_id, \
     oauth_ref, s3_ref, schema_version, mode, config_json";

const OUTBOX_COLUMNS: &str = "connection_id, operation_id, item_id, base_commit, base_json, observed_generation, \
     intent_json, state, snapshot_id, object_ref_json, candidate_commit, candidate_head_json, expected_etag, \
     retry_class, next_attempt_at_ms";

const OPERATION_COLUMNS: &str = "operation_id, kind, request_digest, effect_class, state, account_key, \
     connection_id, result_json, error_code, bucket_creation_operation_id";

const LOCAL_ACTION_COLUMNS: &str = "connection_id, action_id, item_id, kind, expected_file_id, expected_generation, \
     expected_usn, old_version, new_version, source_path, target_path, recovery_path, state";

const ITEM_COLUMNS: &str = "connection_id, item_id, parent_id, name, name_key, kind, revision, content_version_id, \
     deleted, metadata_json";

/// The worker-owned database context: the control database plus lazily opened
/// account databases, all on this one thread.
pub(crate) struct Db {
    pub(crate) paths: crate::StatePaths,
    pub(crate) control: Connection,
    accounts: BTreeMap<AccountKey, Connection>,
}

impl Db {
    pub(crate) fn open(paths: crate::StatePaths) -> SResult<Self> {
        let control = schema::open_database(&paths.control_database(), DatabaseKind::Control)?;
        Ok(Self { paths, control, accounts: BTreeMap::new() })
    }

    fn account_conn(&mut self, account: AccountKey) -> SResult<&Connection> {
        if !self.accounts.contains_key(&account) {
            let paths = self.paths.account(account);
            let conn = schema::open_database(&paths.database(), DatabaseKind::Account)?;
            self.accounts.insert(account, conn);
        }
        Ok(self.accounts.get(&account).expect("just opened"))
    }

    pub(crate) fn checkpoint(&mut self) -> SResult<()> {
        for conn in self.accounts.values() {
            schema::checkpoint(conn)?;
        }
        schema::checkpoint(&self.control)
    }

    // ---------------------------------------------------------------
    // Accounts and selection (control database)
    // ---------------------------------------------------------------

    pub(crate) fn record_account(&mut self, record: &AccountRecord) -> SResult<()> {
        let now = schema::checked_i64(schema::now_ms())?;
        self.control.execute(
            "INSERT INTO accounts (account_key, issuer, subject, namespace, credential_ref, auth_epoch, status, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
             ON CONFLICT(account_key) DO UPDATE SET
               issuer = excluded.issuer, subject = excluded.subject, namespace = excluded.namespace,
               credential_ref = excluded.credential_ref, auth_epoch = excluded.auth_epoch,
               status = excluded.status, updated_at_ms = excluded.updated_at_ms",
            params![
                record.account_key.as_bytes().as_slice(),
                record.issuer,
                record.subject,
                record.namespace,
                record.credential_ref.0,
                schema::checked_i64(record.auth_epoch)?,
                s::account_status_text(record.status),
                now,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn get_account(&mut self, account: AccountKey) -> SResult<Option<AccountRecord>> {
        query_optional(
            &self.control,
            "SELECT account_key, issuer, subject, namespace, credential_ref, auth_epoch, status
             FROM accounts WHERE account_key = ?1",
            params![account.as_bytes().as_slice()],
            s::read_account,
        )
    }

    pub(crate) fn list_accounts(&mut self) -> SResult<Vec<AccountRecord>> {
        query_many(
            &self.control,
            "SELECT account_key, issuer, subject, namespace, credential_ref, auth_epoch, status
             FROM accounts ORDER BY account_key",
            [],
            s::read_account,
        )
    }

    pub(crate) fn set_account_status(&mut self, account: AccountKey, status: AccountStatus) -> SResult<()> {
        let changed = self.control.execute(
            "UPDATE accounts SET status = ?2, updated_at_ms = ?3 WHERE account_key = ?1",
            params![
                account.as_bytes().as_slice(),
                s::account_status_text(status),
                schema::checked_i64(schema::now_ms())?,
            ],
        )?;
        if changed == 0 {
            return Err(StateError::UnknownAccount(account));
        }
        Ok(())
    }

    pub(crate) fn selected_account(&mut self) -> SResult<Option<AccountKey>> {
        query_optional(
            &self.control,
            "SELECT account_key FROM selected_account WHERE slot = 1",
            [],
            |row| c::account_key(row.get_ref(0)?),
        )
    }

    pub(crate) fn select_account(&mut self, account: AccountKey) -> SResult<()> {
        if self.get_account(account)?.is_none() {
            return Err(StateError::UnknownAccount(account));
        }
        self.control.execute(
            "INSERT INTO selected_account (slot, account_key, selected_at_ms) VALUES (1, ?1, ?2)
             ON CONFLICT(slot) DO UPDATE SET account_key = excluded.account_key, selected_at_ms = excluded.selected_at_ms",
            params![account.as_bytes().as_slice(), schema::checked_i64(schema::now_ms())?],
        )?;
        Ok(())
    }

    pub(crate) fn clear_selected_account(&mut self) -> SResult<()> {
        self.control.execute("DELETE FROM selected_account WHERE slot = 1", [])?;
        Ok(())
    }

    // ---------------------------------------------------------------
    // Operation ledger (control database)
    // ---------------------------------------------------------------

    pub(crate) fn begin_operation(&mut self, request: &BeginOperationRequest) -> SResult<BeginOutcome> {
        let digest = request_digest(&request.kind, &request.request);
        if let Some(record) = self.get_operation(request.operation_id)? {
            if record.request_digest != digest {
                return Err(StateError::OperationConflict { operation_id: request.operation_id });
            }
            return match record.state {
                // Answer from the persisted record; nothing is re-executed.
                OperationState::Committed | OperationState::Pending => Ok(BeginOutcome::Replayed(record)),
                OperationState::ExternalPending | OperationState::Failed | OperationState::Abandoned => {
                    Err(StateError::OperationNotReplayable {
                        operation_id: request.operation_id,
                        state: record.state,
                    })
                }
            };
        }
        let now = schema::checked_i64(schema::now_ms())?;
        self.control.execute(
            "INSERT INTO operation_ledger
               (operation_id, kind, request_digest, effect_class, state, account_key, connection_id, bucket_creation_operation_id, result_json, error_code, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6, ?7, NULL, NULL, ?8, ?8)",
            params![
                request.operation_id.as_bytes().as_slice(),
                request.kind,
                digest.as_bytes().as_slice(),
                s::effect_class_text(request.effect_class),
                request.account_key.map(|k| k.as_bytes().to_vec()),
                request.connection_id.map(|id| *id.as_bytes()).map(|b| b.to_vec()),
                request.bucket_creation_operation_id.map(|id| *id.as_bytes()).map(|b| b.to_vec()),
                now,
            ],
        )?;
        Ok(BeginOutcome::Fresh(
            self.get_operation(request.operation_id)?.expect("just inserted"),
        ))
    }

    pub(crate) fn get_operation(&mut self, operation_id: OperationId) -> SResult<Option<OperationRecord>> {
        query_optional(
            &self.control,
            &format!("SELECT {OPERATION_COLUMNS} FROM operation_ledger WHERE operation_id = ?1"),
            params![operation_id.as_bytes().as_slice()],
            s::read_operation,
        )
    }

    fn set_operation_state(
        &mut self,
        operation_id: OperationId,
        allowed_from: &[OperationState],
        to: OperationState,
        result_json: Option<&serde_json::Value>,
        error_code: Option<&str>,
    ) -> SResult<OperationRecord> {
        let record = self
            .get_operation(operation_id)?
            .ok_or_else(|| StateError::not_found("operation", operation_id))?;
        if !allowed_from.contains(&record.state) {
            return Err(StateError::OperationNotMutable { operation_id, state: record.state });
        }
        let result_text = result_json.map(|value| c::to_json("result_json", value)).transpose()?;
        self.control.execute(
            "UPDATE operation_ledger SET state = ?2, result_json = ?3, error_code = ?4, updated_at_ms = ?5
             WHERE operation_id = ?1",
            params![
                operation_id.as_bytes().as_slice(),
                s::operation_state_text(to),
                result_text,
                error_code,
                schema::checked_i64(schema::now_ms())?,
            ],
        )?;
        self.get_operation(operation_id)?.ok_or_else(|| StateError::not_found("operation", operation_id))
    }

    pub(crate) fn mark_dispatched(&mut self, operation_id: OperationId) -> SResult<OperationRecord> {
        self.set_operation_state(
            operation_id,
            &[OperationState::Pending],
            OperationState::ExternalPending,
            None,
            None,
        )
    }

    pub(crate) fn finish_operation(
        &mut self,
        operation_id: OperationId,
        result: &serde_json::Value,
    ) -> SResult<OperationRecord> {
        self.set_operation_state(
            operation_id,
            &[OperationState::Pending, OperationState::ExternalPending],
            OperationState::Committed,
            Some(result),
            None,
        )
    }

    pub(crate) fn fail_operation(&mut self, operation_id: OperationId, error_code: &str) -> SResult<OperationRecord> {
        self.set_operation_state(
            operation_id,
            &[OperationState::Pending, OperationState::ExternalPending],
            OperationState::Failed,
            None,
            Some(error_code),
        )
    }

    pub(crate) fn abandon_operation(&mut self, operation_id: OperationId) -> SResult<OperationRecord> {
        // An uncertain external effect must be reconciled before abandonment;
        // cleanup must never silently drop a real remote change.
        self.set_operation_state(
            operation_id,
            &[OperationState::Pending, OperationState::Failed],
            OperationState::Abandoned,
            None,
            None,
        )
    }

    /// Resolves an interrupted operation after the caller recovered the truth
    /// about its external effect. Never automatic.
    pub(crate) fn reconcile_operation(
        &mut self,
        operation_id: OperationId,
        resolution: OperationResolution,
    ) -> SResult<OperationRecord> {
        match resolution {
            OperationResolution::EffectFound { result } => self.set_operation_state(
                operation_id,
                &[OperationState::ExternalPending, OperationState::Failed],
                OperationState::Committed,
                Some(&result),
                None,
            ),
            OperationResolution::EffectAbsentSafeToRetry => self.set_operation_state(
                operation_id,
                &[OperationState::ExternalPending, OperationState::Failed],
                OperationState::Pending,
                None,
                None,
            ),
            OperationResolution::GiveUp { reason } => {
                self.set_operation_state(
                    operation_id,
                    &[OperationState::ExternalPending, OperationState::Failed],
                    OperationState::Failed,
                    None,
                    Some(&reason),
                )?;
                self.set_operation_state(
                    operation_id,
                    &[OperationState::Failed],
                    OperationState::Abandoned,
                    None,
                    None,
                )
            }
        }
    }

    pub(crate) fn pending_external_operations(&mut self) -> SResult<Vec<OperationRecord>> {
        query_many(
            &self.control,
            &format!("SELECT {OPERATION_COLUMNS} FROM operation_ledger WHERE state = 'external_pending' ORDER BY created_at_ms"),
            [],
            s::read_operation,
        )
    }

    // ---------------------------------------------------------------
    // Setup journal. The account database is authoritative; the control
    // database keeps a mirror so a crash between the two commits can be
    // reconciled idempotently in either direction.
    // ---------------------------------------------------------------

    pub(crate) fn reserve_setup(&mut self, draft: &SetupDraft) -> SResult<SetupReservation> {
        if self.get_account(draft.account_key)?.is_none() {
            return Err(StateError::UnknownAccount(draft.account_key));
        }
        let fingerprint = setup_fingerprint(draft)?;
        let bucket_creation_operation_id = self.get_operation(draft.operation_id)?
            .and_then(|record| record.bucket_creation_operation_id);
        if let Some(record) = self.setup_by_operation(draft.operation_id)? {
            if record.request_fingerprint != fingerprint {
                return Err(StateError::OperationConflict { operation_id: draft.operation_id });
            }
            return Ok(SetupReservation::from(&record));
        }
        let setup_id = SetupId::new();
        let connection_id = ConnectionId::new();
        let now = schema::checked_i64(schema::now_ms())?;
        let binding_json = c::to_json("binding_json", &draft.binding)?;
        let created_empty = c::to_json("created_resources_json", &Vec::<CreatedResource>::new())?;
        {
            let account = self.account_conn(draft.account_key)?;
            account.execute(
                "INSERT INTO setup_intents
                   (setup_id, connection_id, operation_id, account_key, binding_json, initialize, bucket_creation_operation_id, request_fingerprint,
                    phase, status, created_resources_json, preview_json, root_path, mode, credential_ref,
                    probe_evidence_json, failure_reason, evidence_generation, account_committed, control_committed,
                    created_at_ms, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'reserved', 'active', ?9, NULL, NULL, NULL, NULL, NULL, NULL, 0, 1, 0, ?10, ?10)",
                params![
                    setup_id.as_bytes().as_slice(),
                    connection_id.as_bytes().as_slice(),
                    draft.operation_id.as_bytes().as_slice(),
                    draft.account_key.as_bytes().as_slice(),
                    binding_json,
                    i64::from(draft.initialize),
                    bucket_creation_operation_id.map(|id| *id.as_bytes()).map(|id| id.to_vec()),
                    fingerprint.as_bytes().as_slice(),
                    created_empty,
                    now,
                ],
            )?;
        }
        let mirror = SetupMirror {
            setup_id,
            connection_id,
            operation_id: draft.operation_id,
            account_key: draft.account_key,
            binding_json: c::to_json("binding_json", &draft.binding)?,
            initialize: draft.initialize,
            bucket_creation_operation_id,
            request_fingerprint: fingerprint,
            phase: SetupPhase::Reserved,
            status: SetupStatus::Active,
            created_resources_json: created_empty,
            preview_json: None,
            root_path: None,
            mode: None,
            credential_ref: None,
            probe_evidence_json: None,
            failure_reason: None,
            evidence_generation: 0,
            account_committed: true,
        };
        self.write_setup_control_mirror(&mirror)?;
        {
            let account = self.account_conn(draft.account_key)?;
            account.execute(
                "UPDATE setup_intents SET control_committed = 1 WHERE setup_id = ?1",
                params![setup_id.as_bytes().as_slice()],
            )?;
        }
        let record = self
            .get_setup(setup_id)?
            .ok_or_else(|| StateError::not_found("setup", setup_id))?;
        Ok(SetupReservation::from(&record))
    }

    fn write_setup_control_mirror(&mut self, row: &SetupMirror) -> SResult<()> {
        let now = schema::checked_i64(schema::now_ms())?;
        self.control.execute(
            "INSERT INTO setup_registry
               (setup_id, connection_id, operation_id, account_key, binding_json, initialize, bucket_creation_operation_id, request_fingerprint,
                phase, status, created_resources_json, preview_json, root_path, mode, credential_ref,
                probe_evidence_json, failure_reason, evidence_generation, account_committed, control_committed,
                created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, 1, ?20, ?20)
             ON CONFLICT(setup_id) DO UPDATE SET
               phase = excluded.phase, status = excluded.status,
               created_resources_json = excluded.created_resources_json,
               preview_json = excluded.preview_json, root_path = excluded.root_path, mode = excluded.mode,
               credential_ref = excluded.credential_ref, probe_evidence_json = excluded.probe_evidence_json,
               failure_reason = excluded.failure_reason, evidence_generation = excluded.evidence_generation,
               account_committed = excluded.account_committed, control_committed = 1,
               updated_at_ms = excluded.updated_at_ms",
            params![
                row.setup_id.as_bytes().as_slice(),
                row.connection_id.as_bytes().as_slice(),
                row.operation_id.as_bytes().as_slice(),
                row.account_key.as_bytes().as_slice(),
                row.binding_json,
                i64::from(row.initialize),
                row.bucket_creation_operation_id.as_ref().map(|id| id.as_bytes().as_slice()),
                row.request_fingerprint.as_bytes().as_slice(),
                s::phase_text(row.phase),
                s::setup_status_text(row.status),
                row.created_resources_json,
                row.preview_json,
                row.root_path,
                row.mode.map(s::mode_text),
                row.credential_ref,
                row.probe_evidence_json,
                row.failure_reason,
                schema::checked_i64(row.evidence_generation)?,
                i64::from(row.account_committed),
                now,
            ],
        )?;
        Ok(())
    }

    fn setup_mirror_of(record: &SetupRecord) -> SResult<SetupMirror> {
        Ok(SetupMirror {
            setup_id: record.setup_id,
            connection_id: record.connection_id,
            operation_id: record.operation_id,
            account_key: record.account_key,
            binding_json: c::to_json("binding_json", &record.binding)?,
            initialize: record.initialize,
            bucket_creation_operation_id: record.bucket_creation_operation_id,
            request_fingerprint: record.request_fingerprint,
            phase: record.phase,
            status: record.status,
            created_resources_json: c::to_json("created_resources_json", &record.created_resources)?,
            preview_json: record.preview_json.as_ref().map(|v| v.to_string()),
            root_path: record.root_path.as_ref().map(|p| p.to_string_lossy().into_owned()),
            mode: record.mode,
            credential_ref: record.credential_ref.as_ref().map(|r| r.0.clone()),
            probe_evidence_json: record.probe_evidence_json.as_ref().map(|v| v.to_string()),
            failure_reason: record.failure_reason.clone(),
            evidence_generation: record.evidence_generation,
            account_committed: record.account_committed,
        })
    }

    fn setup_by_operation(&mut self, operation_id: OperationId) -> SResult<Option<SetupRecord>> {
        for account in self.list_accounts()? {
            let found = {
                let conn = self.account_conn(account.account_key)?;
                query_optional(
                    conn,
                    &format!("SELECT {SETUP_COLUMNS} FROM setup_intents WHERE operation_id = ?1"),
                    params![operation_id.as_bytes().as_slice()],
                    s::read_setup,
                )?
            };
            if found.is_some() {
                return Ok(found);
            }
        }
        Ok(None)
    }

    pub(crate) fn get_setup(&mut self, setup_id: SetupId) -> SResult<Option<SetupRecord>> {
        for account in self.list_accounts()? {
            let found = {
                let conn = self.account_conn(account.account_key)?;
                query_optional(
                    conn,
                    &format!("SELECT {SETUP_COLUMNS} FROM setup_intents WHERE setup_id = ?1"),
                    params![setup_id.as_bytes().as_slice()],
                    s::read_setup,
                )?
            };
            if found.is_some() {
                return Ok(found);
            }
        }
        Ok(None)
    }

    pub(crate) fn get_setup_by_connection(&mut self, connection_id: ConnectionId) -> SResult<Option<SetupRecord>> {
        for account in self.list_accounts()? {
            let found = {
                let conn = self.account_conn(account.account_key)?;
                query_optional(
                    conn,
                    &format!("SELECT {SETUP_COLUMNS} FROM setup_intents WHERE connection_id = ?1"),
                    params![connection_id.as_bytes().as_slice()],
                    s::read_setup,
                )?
            };
            if found.is_some() {
                return Ok(found);
            }
        }
        Ok(None)
    }

    pub(crate) fn list_setups(&mut self, account: Option<AccountKey>) -> SResult<Vec<SetupRecord>> {
        let accounts = match account {
            Some(key) => vec![self.get_account(key)?.ok_or(StateError::UnknownAccount(key))?],
            None => self.list_accounts()?,
        };
        let mut out = Vec::new();
        for record in accounts {
            let conn = self.account_conn(record.account_key)?;
            out.extend(query_many(
                conn,
                &format!("SELECT {SETUP_COLUMNS} FROM setup_intents ORDER BY created_at_ms"),
                [],
                s::read_setup,
            )?);
        }
        Ok(out)
    }

    /// Applies a setup journal mutation to the account database (authoritative
    /// commit) and then mirrors it to the control database. A crash between the
    /// two commits is repaired by `reconcile_setup_commits`, never by replaying
    /// external effects.
    fn mutate_setup<F>(&mut self, setup_id: SetupId, mutate: F) -> SResult<SetupRecord>
    where
        F: FnOnce(&mut SetupRecord) -> SResult<()>,
    {
        let mut record = self
            .get_setup(setup_id)?
            .ok_or(StateError::UnknownSetup(setup_id))?;
        mutate(&mut record)?;
        let now = schema::checked_i64(schema::now_ms())?;
        let account_key = record.account_key;
        {
            let account = self.account_conn(account_key)?;
            let changed = account.execute(
                "UPDATE setup_intents SET phase = ?2, status = ?3, created_resources_json = ?4, preview_json = ?5,
                        root_path = ?6, mode = ?7, credential_ref = ?8, probe_evidence_json = ?9, failure_reason = ?10,
                        evidence_generation = ?11, account_committed = 1, control_committed = ?12, updated_at_ms = ?13
                 WHERE setup_id = ?1",
                params![
                    setup_id.as_bytes().as_slice(),
                    s::phase_text(record.phase),
                    s::setup_status_text(record.status),
                    c::to_json("created_resources_json", &record.created_resources)?,
                    record.preview_json.as_ref().map(|v| v.to_string()),
                    record.root_path.as_ref().map(|p| p.to_string_lossy().into_owned()),
                    record.mode.map(s::mode_text),
                    record.credential_ref.as_ref().map(|r| r.0.clone()),
                    record.probe_evidence_json.as_ref().map(|v| v.to_string()),
                    record.failure_reason.clone(),
                    schema::checked_i64(record.evidence_generation)?,
                    i64::from(record.control_committed),
                    now,
                ],
            )?;
            if changed == 0 {
                return Err(StateError::UnknownSetup(setup_id));
            }
        }
        let mirror = Self::setup_mirror_of(&record)?;
        self.write_setup_control_mirror(&mirror)?;
        {
            let account = self.account_conn(account_key)?;
            account.execute(
                "UPDATE setup_intents SET control_committed = 1 WHERE setup_id = ?1",
                params![setup_id.as_bytes().as_slice()],
            )?;
        }
        record.control_committed = true;
        Ok(record)
    }

    pub(crate) fn advance_setup(&mut self, setup_id: SetupId, phase: SetupPhase) -> SResult<SetupRecord> {
        self.mutate_setup(setup_id, |record| {
            if record.status != SetupStatus::Active {
                return Err(StateError::invalid_state("setup", setup_id, "setup is not active"));
            }
            if !record.phase.can_advance_to(phase) {
                return Err(StateError::IllegalSetupTransition { from: record.phase, to: phase });
            }
            record.phase = phase;
            Ok(())
        })
    }

    /// Records the setup's credential file reference. Replacing it invalidates
    /// previously collected probe and preview evidence: a writable resume must
    /// re-probe against the new credentials.
    pub(crate) fn record_setup_credentials(
        &mut self,
        setup_id: SetupId,
        credential_ref: CredentialRef,
    ) -> SResult<SetupRecord> {
        self.mutate_setup(setup_id, |record| {
            if record.status != SetupStatus::Active {
                return Err(StateError::invalid_state("setup", setup_id, "setup is not active"));
            }
            if record.credential_ref.as_ref() != Some(&credential_ref) {
                record.probe_evidence_json = None;
                record.preview_json = None;
                record.evidence_generation += 1;
            }
            record.credential_ref = Some(credential_ref);
            if record.phase < SetupPhase::CredentialsRecorded {
                record.phase = SetupPhase::CredentialsRecorded;
            }
            Ok(())
        })
    }

    pub(crate) fn record_probe_evidence(
        &mut self,
        setup_id: SetupId,
        evidence: serde_json::Value,
    ) -> SResult<SetupRecord> {
        self.mutate_setup(setup_id, |record| {
            if record.status != SetupStatus::Active {
                return Err(StateError::invalid_state("setup", setup_id, "setup is not active"));
            }
            record.probe_evidence_json = Some(evidence);
            if record.phase < SetupPhase::Probed {
                record.phase = SetupPhase::Probed;
            }
            Ok(())
        })
    }

    /// Attaches the local-root proof and access mode chosen at preview time.
    pub(crate) fn attach_setup_preview(
        &mut self,
        setup_id: SetupId,
        preview: serde_json::Value,
        root_path: PathBuf,
        mode: ConnectionMode,
    ) -> SResult<SetupRecord> {
        let text = root_path.to_str().ok_or_else(|| StateError::NonUtf8Path(root_path.clone()))?.to_owned();
        self.mutate_setup(setup_id, |record| {
            if record.status != SetupStatus::Active {
                return Err(StateError::invalid_state("setup", setup_id, "setup is not active"));
            }
            record.preview_json = Some(preview);
            record.root_path = Some(PathBuf::from(&text));
            record.mode = Some(mode);
            if record.phase < SetupPhase::PreviewReady {
                record.phase = SetupPhase::PreviewReady;
            }
            Ok(())
        })
    }

    pub(crate) fn record_created_resources(
        &mut self,
        setup_id: SetupId,
        resources: Vec<CreatedResource>,
    ) -> SResult<SetupRecord> {
        self.mutate_setup(setup_id, |record| {
            record.created_resources = resources;
            Ok(())
        })
    }

    pub(crate) fn fail_setup(&mut self, setup_id: SetupId, reason: String) -> SResult<SetupRecord> {
        self.mutate_setup(setup_id, |record| {
            record.status = SetupStatus::Failed;
            record.failure_reason = Some(reason);
            Ok(())
        })
    }

    /// Re-activates a failed setup and completes whichever journal side is
    /// missing. Explicit, never automatic.
    pub(crate) fn resume_setup(&mut self, setup_id: SetupId) -> SResult<SetupRecord> {
        let record = self.mutate_setup(setup_id, |record| {
            if record.status == SetupStatus::Failed {
                record.status = SetupStatus::Active;
                record.failure_reason = None;
            }
            Ok(())
        })?;
        if record.phase >= SetupPhase::Registering {
            return self.finalize_setup(setup_id);
        }
        Ok(record)
    }

    /// Idempotently commits a setup to the connection registry in both
    /// databases. The account-side row and the control-side row are separate
    /// transactions, reconciled by `reconcile_setup_commits`.
    pub(crate) fn finalize_setup(&mut self, setup_id: SetupId) -> SResult<SetupRecord> {
        let mut record = self
            .get_setup(setup_id)?
            .ok_or(StateError::UnknownSetup(setup_id))?;
        if record.status == SetupStatus::Failed {
            return Err(StateError::invalid_state("setup", setup_id, "setup failed and must be resumed first"));
        }
        if record.phase < SetupPhase::PreviewReady {
            return Err(StateError::IllegalSetupTransition { from: record.phase, to: SetupPhase::Registering });
        }
        let root_path = record
            .root_path
            .as_ref()
            .map(|p| p.to_str().map(str::to_owned).ok_or_else(|| StateError::NonUtf8Path(p.clone())))
            .transpose()?
            .unwrap_or_default();
        let mode = record.mode.unwrap_or(ConnectionMode::ReadOnly);
        let now = schema::checked_i64(schema::now_ms())?;
        let config = setup_config(&record);
        let config_text = c::to_json("config_json", &config)?;
        // The account's credential_ref names its OAuth envelope; the setup's
        // credential_ref names its publication (S3) envelope. Both are DPAPI
        // file names, never credential bytes.
        let account_record = self
            .get_account(record.account_key)?
            .ok_or(StateError::UnknownAccount(record.account_key))?;
        let oauth_ref = Some(account_record.credential_ref.0.clone());
        let s3_ref = record.credential_ref.as_ref().map(|r| r.0.clone());

        // Account-side registry commit.
        {
            let account = self.account_conn(record.account_key)?;
            account.execute(
                "INSERT INTO connections
                   (connection_id, account_key, workspace_id, owner_kind, owner_id, owner_namespace, bucket_id,
                    bucket_name, prefix, root_path, volume_guid, volume_serial, sync_root_id, oauth_ref, s3_ref,
                    schema_version, mode, observed_commit, published_commit, applied_commit, config_json,
                    created_at_ms, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, NULL, NULL, ?11, ?12, 1, ?13,
                         NULL, NULL, NULL, ?14, ?15, ?15)
                 ON CONFLICT(connection_id) DO UPDATE SET
                   root_path = excluded.root_path, oauth_ref = excluded.oauth_ref, s3_ref = excluded.s3_ref,
                   mode = excluded.mode, config_json = excluded.config_json, updated_at_ms = excluded.updated_at_ms",
                params![
                    record.connection_id.as_bytes().as_slice(),
                    record.account_key.as_bytes().as_slice(),
                    record.binding.workspace_id.as_bytes().as_slice(),
                    s::owner_kind_text(record.binding.bucket.owner_kind),
                    record.binding.bucket.owner_id.as_str(),
                    record.binding.bucket.owner_namespace.as_str(),
                    record.binding.bucket.bucket_id.as_str(),
                    record.binding.bucket.bucket_name.as_str(),
                    record.binding.prefix.as_str(),
                    root_path,
                    oauth_ref,
                    s3_ref,
                    s::mode_text(mode),
                    config_text,
                    now,
                ],
            )?;
        }
        record.account_committed = true;

        // Control-side registry commit (idempotent upsert).
        self.control.execute(
            "INSERT INTO connections
               (connection_id, account_key, workspace_id, owner_kind, owner_id, owner_namespace, bucket_id,
                bucket_name, prefix, root_path, mode, registered, volume_guid, volume_serial, sync_root_id,
                oauth_ref, s3_ref, config_json, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 1, NULL, NULL, NULL, ?12, ?13, ?14, ?15, ?15)
             ON CONFLICT(connection_id) DO UPDATE SET
               root_path = excluded.root_path, mode = excluded.mode, registered = 1,
               oauth_ref = excluded.oauth_ref, s3_ref = excluded.s3_ref,
               config_json = excluded.config_json, updated_at_ms = excluded.updated_at_ms",
            params![
                record.connection_id.as_bytes().as_slice(),
                record.account_key.as_bytes().as_slice(),
                record.binding.workspace_id.as_bytes().as_slice(),
                s::owner_kind_text(record.binding.bucket.owner_kind),
                record.binding.bucket.owner_id.as_str(),
                record.binding.bucket.owner_namespace.as_str(),
                record.binding.bucket.bucket_id.as_str(),
                record.binding.bucket.bucket_name.as_str(),
                record.binding.prefix.as_str(),
                root_path,
                s::mode_text(mode),
                oauth_ref,
                s3_ref,
                config_text,
                now,
            ],
        )?;
        record.control_committed = true;

        record.phase = SetupPhase::Connected;
        record.status = SetupStatus::Connected;
        let mirror = Self::setup_mirror_of(&record)?;
        self.write_setup_control_mirror(&mirror)?;
        {
            let account = self.account_conn(record.account_key)?;
            account.execute(
                "UPDATE setup_intents SET phase = ?2, status = ?3, account_committed = 1, control_committed = 1,
                        updated_at_ms = ?4
                 WHERE setup_id = ?1",
                params![
                    setup_id.as_bytes().as_slice(),
                    s::phase_text(record.phase),
                    s::setup_status_text(record.status),
                    now,
                ],
            )?;
        }
        Ok(record)
    }

    /// Completes whichever commit side of a setup journal entry is missing.
    /// The mirror is rewritten idempotently, so a lost control-side row is
    /// repaired even when the account side believed it had been written.
    pub(crate) fn reconcile_setup_commits(&mut self, setup_id: SetupId) -> SResult<SetupRecord> {
        let record = self
            .get_setup(setup_id)?
            .ok_or(StateError::UnknownSetup(setup_id))?;
        if record.phase == SetupPhase::Connected && (!record.account_committed || !record.control_committed) {
            return self.finalize_setup(setup_id);
        }
        let mirror = Self::setup_mirror_of(&record)?;
        self.write_setup_control_mirror(&mirror)?;
        let account = self.account_conn(record.account_key)?;
        account.execute(
            "UPDATE setup_intents SET control_committed = 1 WHERE setup_id = ?1",
            params![setup_id.as_bytes().as_slice()],
        )?;
        self.get_setup(setup_id)?.ok_or(StateError::UnknownSetup(setup_id))
    }

    /// Reconciles the connection registry: connected setups become registry
    /// rows; draft rows are never deleted silently.
    pub(crate) fn reconcile_connections(&mut self) -> SResult<Vec<ConnectionRecord>> {
        let setups = self.list_setups(None)?;
        for setup in setups {
            if setup.status == SetupStatus::Connected
                && (!setup.account_committed || !setup.control_committed)
            {
                self.finalize_setup(setup.setup_id)?;
            }
        }
        let mut out = Vec::new();
        for account in self.list_accounts()? {
            let conn = self.account_conn(account.account_key)?;
            out.extend(query_many(
                conn,
                &format!("SELECT {ACCOUNT_CONNECTION_COLUMNS} FROM connections ORDER BY created_at_ms"),
                [],
                s::read_account_connection,
            )?);
        }
        Ok(out)
    }

    // ---------------------------------------------------------------
    // Connection registry and publication baselines (account database)
    // ---------------------------------------------------------------

    pub(crate) fn get_connection(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
    ) -> SResult<Option<ConnectionRecord>> {
        let conn = self.account_conn(account)?;
        query_optional(
            conn,
            &format!("SELECT {ACCOUNT_CONNECTION_COLUMNS} FROM connections WHERE connection_id = ?1"),
            params![connection_id.as_bytes().as_slice()],
            s::read_account_connection,
        )
    }

    pub(crate) fn list_connections(&mut self, account: AccountKey) -> SResult<Vec<ConnectionRecord>> {
        let conn = self.account_conn(account)?;
        query_many(
            conn,
            &format!("SELECT {ACCOUNT_CONNECTION_COLUMNS} FROM connections ORDER BY created_at_ms"),
            [],
            s::read_account_connection,
        )
    }

    pub(crate) fn set_connection_root(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        root_path: &Path,
    ) -> SResult<()> {
        let text = root_path.to_str().ok_or_else(|| StateError::NonUtf8Path(root_path.to_owned()))?;
        let conn = self.account_conn(account)?;
        let changed = conn.execute(
            "UPDATE connections SET root_path = ?2, updated_at_ms = ?3 WHERE connection_id = ?1",
            params![connection_id.as_bytes().as_slice(), text, schema::checked_i64(schema::now_ms())?],
        )?;
        if changed == 0 {
            return Err(StateError::UnknownConnection(connection_id));
        }
        Ok(())
    }

    pub(crate) fn baseline(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
    ) -> SResult<PublicationBaseline> {
        let conn = self.account_conn(account)?;
        query_optional(
            conn,
            "SELECT observed_commit, published_commit, applied_commit FROM connections WHERE connection_id = ?1",
            params![connection_id.as_bytes().as_slice()],
            s::read_baseline,
        )?
        .ok_or(StateError::UnknownConnection(connection_id))
    }

    /// Advances one publication baseline. `Applied` is refused while any local
    /// action is still pending: applied never runs ahead of durable local
    /// outcomes.
    pub(crate) fn set_baseline(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        kind: BaselineKind,
        commit: Option<CommitId>,
    ) -> SResult<PublicationBaseline> {
        if matches!(kind, BaselineKind::Applied) && commit.is_some() {
            let pending = self.pending_local_actions(account, connection_id)?;
            if !pending.is_empty() {
                return Err(StateError::invalid_state(
                    "connection",
                    connection_id,
                    format!("{} local actions still pending", pending.len()),
                ));
            }
        }
        let column = match kind {
            BaselineKind::Observed => "observed_commit",
            BaselineKind::Published => "published_commit",
            BaselineKind::Applied => "applied_commit",
        };
        let sql = format!("UPDATE connections SET {column} = ?2, updated_at_ms = ?3 WHERE connection_id = ?1");
        let conn = self.account_conn(account)?;
        let changed = conn.execute(
            &sql,
            params![
                connection_id.as_bytes().as_slice(),
                commit.map(|id| *id.as_bytes()).map(|b| b.to_vec()),
                schema::checked_i64(schema::now_ms())?,
            ],
        )?;
        if changed == 0 {
            return Err(StateError::UnknownConnection(connection_id));
        }
        self.baseline(account, connection_id)
    }

    // ---------------------------------------------------------------
    // Outbox (account database)
    // ---------------------------------------------------------------

    /// Records a new durable intent. Entries always start as `Observed`.
    pub(crate) fn record_outbox(&mut self, account: AccountKey, entry: &OutboxEntry) -> SResult<OutboxEntry> {
        if entry.state != OutboxState::Observed {
            return Err(StateError::invalid_state("outbox", entry.operation_id, "new entries start as Observed"));
        }
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        conn.execute(
            "INSERT INTO outbox
               (connection_id, operation_id, item_id, base_commit, base_json, observed_generation, intent_json, state,
                snapshot_id, object_ref_json, candidate_commit, candidate_head_json, expected_etag, retry_class,
                next_attempt_at_ms, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'observed', NULL, NULL, NULL, NULL, NULL, 'none', NULL, ?8, ?8)",
            params![
                entry.connection_id.as_bytes().as_slice(),
                entry.operation_id.as_bytes().as_slice(),
                entry.item_id.map(|id| *id.as_bytes()).map(|b| b.to_vec()),
                entry.base_commit.map(|id| *id.as_bytes()).map(|b| b.to_vec()),
                entry.base_json.clone(),
                schema::checked_i64(entry.observed_generation)?,
                c::to_json("intent_json", &entry.intent_json)?,
                now,
            ],
        )?;
        self.outbox_entry(account, entry.connection_id, entry.operation_id)?
            .ok_or_else(|| StateError::not_found("outbox", entry.operation_id))
    }

    pub(crate) fn outbox_entry(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        operation_id: OperationId,
    ) -> SResult<Option<OutboxEntry>> {
        let conn = self.account_conn(account)?;
        query_optional(
            conn,
            &format!("SELECT {OUTBOX_COLUMNS} FROM outbox WHERE connection_id = ?1 AND operation_id = ?2"),
            params![connection_id.as_bytes().as_slice(), operation_id.as_bytes().as_slice()],
            s::read_outbox,
        )
    }

    pub(crate) fn list_outbox(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        state: Option<OutboxState>,
        limit: u32,
    ) -> SResult<Vec<OutboxEntry>> {
        let conn = self.account_conn(account)?;
        match state {
            None => query_many(
                conn,
                &format!("SELECT {OUTBOX_COLUMNS} FROM outbox WHERE connection_id = ?1 ORDER BY created_at_ms LIMIT ?2"),
                params![connection_id.as_bytes().as_slice(), i64::from(limit)],
                s::read_outbox,
            ),
            Some(state) => query_many(
                conn,
                &format!("SELECT {OUTBOX_COLUMNS} FROM outbox WHERE connection_id = ?1 AND state = ?2 ORDER BY created_at_ms LIMIT ?3"),
                params![connection_id.as_bytes().as_slice(), s::outbox_state_text(state), i64::from(limit)],
                s::read_outbox,
            ),
        }
    }

    pub(crate) fn work_counts(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
    ) -> SResult<ConnectionWorkCounts> {
        let conn = self.account_conn(account)?;
        let counts = conn.query_row(
            "SELECT
               (SELECT COUNT(DISTINCT o.item_id) FROM outbox o
                  JOIN items i ON i.connection_id = o.connection_id AND i.item_id = o.item_id
                  WHERE o.connection_id = ?1 AND o.state <> 'complete' AND i.kind = 'file'),
               (SELECT COUNT(*) FROM local_observations l
                  JOIN items i ON i.connection_id = l.connection_id AND i.item_id = l.item_id
                  WHERE l.connection_id = ?1 AND l.dirty = 1 AND i.kind = 'file'),
               (SELECT COUNT(*) FROM conflicts c
                  JOIN items i ON i.connection_id = c.connection_id AND i.item_id = c.item_id
                  WHERE c.connection_id = ?1 AND c.resolution_state = 'unresolved' AND i.kind = 'file')",
            params![connection_id.as_bytes().as_slice()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
        )?;
        let convert = |value| u32::try_from(value).map_err(|_| {
            StateError::invalid_state("connection", connection_id, "health count exceeds the protocol counter")
        });
        Ok(ConnectionWorkCounts {
            pending_files: convert(counts.0)?,
            dirty_files: convert(counts.1)?,
            conflict_files: convert(counts.2)?,
        })
    }

    pub(crate) fn storage_counts(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
    ) -> SResult<ConnectionStorageCounts> {
        let conn = self.account_conn(account)?;
        let counts = conn.query_row(
            "SELECT
               (SELECT COALESCE(SUM(s.size), 0) FROM outbox o
                  JOIN snapshots s ON s.connection_id = o.connection_id AND s.snapshot_id = o.snapshot_id
                  WHERE o.connection_id = ?1 AND o.state NOT IN ('published', 'local_apply_pending', 'complete')),
               (SELECT COUNT(*) FROM local_observations l
                  JOIN items i ON i.connection_id = l.connection_id AND i.item_id = l.item_id
                  WHERE l.connection_id = ?1 AND l.pin_requested = 1 AND l.pin_complete = 1 AND i.kind = 'file'),
               (SELECT COUNT(*) FROM local_observations l
                  JOIN items i ON i.connection_id = l.connection_id AND i.item_id = l.item_id
                  WHERE l.connection_id = ?1 AND l.pin_requested = 1 AND i.kind = 'file')",
            params![connection_id.as_bytes().as_slice()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
        )?;
        let convert = |value| u32::try_from(value).map_err(|_| {
            StateError::invalid_state("connection", connection_id, "pin count exceeds the protocol counter")
        });
        Ok(ConnectionStorageCounts {
            pending_upload_bytes: u64::try_from(counts.0)
                .map_err(|_| StateError::invalid_state("connection", connection_id, "negative pending upload bytes"))?,
            pinned_files: convert(counts.1)?,
            pin_requests: convert(counts.2)?,
        })
    }

    /// Applies one durable outbox state transition with its evidence. Snapshot
    /// evidence must be a `Ready` snapshot; `PublishUnknown` records the
    /// uncertainty and is resolved by reconciliation, never blind replay.
    pub(crate) fn transition_outbox(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        operation_id: OperationId,
        transition: OutboxTransition,
    ) -> SResult<OutboxEntry> {
        let entry = self
            .outbox_entry(account, connection_id, operation_id)?
            .ok_or_else(|| StateError::not_found("outbox", operation_id))?;
        let target = transition.target();
        if !entry.state.can_transition_to(target) {
            return Err(StateError::IllegalOutboxTransition { from: entry.state, to: target });
        }
        let (mut snapshot_id, mut object_ref, mut candidate_commit, mut candidate_head, mut etag, mut retry, mut next_attempt) =
            (
                entry.snapshot_id,
                entry.object_ref.clone(),
                entry.candidate_commit,
                entry.candidate_head_json.clone(),
                entry.expected_etag.clone(),
                RetryClass::None,
                entry.next_attempt_at_ms,
            );
        match &transition {
            OutboxTransition::SnapshotReady { snapshot_id: id } | OutboxTransition::Rebased { snapshot_id: id }
            | OutboxTransition::Recaptured { snapshot_id: id } => {
                let snapshot = self
                    .snapshot(account, connection_id, *id)?
                    .ok_or_else(|| StateError::not_found("snapshot", *id))?;
                if snapshot.status != SnapshotStatus::Ready {
                    return Err(StateError::invalid_state("snapshot", *id, "snapshot is not Ready"));
                }
                // A new snapshot invalidates earlier payload/commit evidence:
                // the operation restarts from a coherent capture.
                snapshot_id = Some(*id);
                object_ref = None;
                candidate_commit = None;
                candidate_head = None;
                etag = None;
                retry = RetryClass::None;
                next_attempt = None;
            }
            OutboxTransition::PayloadReady { object_ref: object } => {
                object_ref = Some(object.clone());
            }
            OutboxTransition::MetadataReady {
                candidate_commit: commit,
                candidate_head_json: head,
                expected_etag: tag,
            } => {
                candidate_commit = Some(*commit);
                candidate_head = Some(head.clone());
                etag = Some(tag.clone());
            }
            OutboxTransition::PublishUnknown { retry_class, next_attempt_at_ms } => {
                retry = *retry_class;
                next_attempt = *next_attempt_at_ms;
            }
            OutboxTransition::Published | OutboxTransition::LocalApplyPending => {}
        }
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        conn.execute(
            "UPDATE outbox SET state = ?3, snapshot_id = ?4, object_ref_json = ?5, candidate_commit = ?6,
                    candidate_head_json = ?7, expected_etag = ?8, retry_class = ?9, next_attempt_at_ms = ?10,
                    updated_at_ms = ?11
             WHERE connection_id = ?1 AND operation_id = ?2",
            params![
                connection_id.as_bytes().as_slice(),
                operation_id.as_bytes().as_slice(),
                s::outbox_state_text(target),
                snapshot_id.map(|id| *id.as_bytes()).map(|b| b.to_vec()),
                object_ref.as_ref().map(|r| c::to_json("object_ref_json", r)).transpose()?,
                candidate_commit.map(|id| *id.as_bytes()).map(|b| b.to_vec()),
                candidate_head.as_ref().map(|v| v.to_string()),
                etag,
                s::retry_class_text(retry),
                next_attempt.map(schema::checked_i64).transpose()?,
                now,
            ],
        )?;
        self.outbox_entry(account, connection_id, operation_id)?
            .ok_or_else(|| StateError::not_found("outbox", operation_id))
    }

    /// Completes the local side of an operation. The item's dirty flag is
    /// cleared only when the observed generation still matches; a newer local
    /// generation stays dirty for its own operation.
    pub(crate) fn complete_outbox(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        operation_id: OperationId,
    ) -> SResult<CompletionOutcome> {
        let entry = self
            .outbox_entry(account, connection_id, operation_id)?
            .ok_or_else(|| StateError::not_found("outbox", operation_id))?;
        if !entry.state.can_transition_to(OutboxState::Complete) {
            return Err(StateError::IllegalOutboxTransition {
                from: entry.state,
                to: OutboxState::Complete,
            });
        }
        let now = schema::checked_i64(schema::now_ms())?;
        {
            let conn = self.account_conn(account)?;
            conn.execute(
                "UPDATE outbox SET state = 'complete', updated_at_ms = ?3 WHERE connection_id = ?1 AND operation_id = ?2",
                params![connection_id.as_bytes().as_slice(), operation_id.as_bytes().as_slice(), now],
            )?;
        }
        let Some(item_id) = entry.item_id else {
            return Ok(CompletionOutcome::Completed { generation: entry.observed_generation });
        };
        let observation = self.observation(account, connection_id, item_id)?;
        match observation {
            Some(obs) if obs.generation == entry.observed_generation => {
                let conn = self.account_conn(account)?;
                conn.execute(
                    "UPDATE local_observations SET dirty = 0 WHERE connection_id = ?1 AND item_id = ?2",
                    params![connection_id.as_bytes().as_slice(), item_id.as_bytes().as_slice()],
                )?;
                Ok(CompletionOutcome::Completed { generation: obs.generation })
            }
            Some(obs) => Ok(CompletionOutcome::CompletedWithNewerGeneration {
                operation_generation: entry.observed_generation,
                current_generation: obs.generation,
            }),
            None => Ok(CompletionOutcome::Completed { generation: entry.observed_generation }),
        }
    }

    // ---------------------------------------------------------------
    // Snapshots (account database)
    // ---------------------------------------------------------------

    pub(crate) fn begin_snapshot(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        snapshot_id: SnapshotId,
        path: &Path,
    ) -> SResult<SnapshotRecord> {
        let text = path.to_str().ok_or_else(|| StateError::NonUtf8Path(path.to_owned()))?;
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        conn.execute(
            "INSERT INTO snapshots (connection_id, snapshot_id, path, size, sha256, status, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, NULL, NULL, 'capturing', ?4, ?4)",
            params![connection_id.as_bytes().as_slice(), snapshot_id.as_bytes().as_slice(), text, now],
        )?;
        self.snapshot(account, connection_id, snapshot_id)?
            .ok_or_else(|| StateError::not_found("snapshot", snapshot_id))
    }

    pub(crate) fn complete_snapshot(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        snapshot_id: SnapshotId,
        size: u64,
        sha256: Sha256Digest,
    ) -> SResult<SnapshotRecord> {
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        let changed = conn.execute(
            "UPDATE snapshots SET size = ?3, sha256 = ?4, status = 'ready', updated_at_ms = ?5
             WHERE connection_id = ?1 AND snapshot_id = ?2 AND status = 'capturing'",
            params![
                connection_id.as_bytes().as_slice(),
                snapshot_id.as_bytes().as_slice(),
                schema::checked_i64(size)?,
                sha256.as_bytes().as_slice(),
                now
            ],
        )?;
        if changed == 0 {
            return Err(StateError::invalid_state(
                "snapshot",
                snapshot_id,
                "snapshot is not capturing or does not exist",
            ));
        }
        self.snapshot(account, connection_id, snapshot_id)?
            .ok_or_else(|| StateError::not_found("snapshot", snapshot_id))
    }

    pub(crate) fn set_snapshot_status(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        snapshot_id: SnapshotId,
        status: SnapshotStatus,
    ) -> SResult<SnapshotRecord> {
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        let changed = conn.execute(
            "UPDATE snapshots SET status = ?3, updated_at_ms = ?4 WHERE connection_id = ?1 AND snapshot_id = ?2",
            params![
                connection_id.as_bytes().as_slice(),
                snapshot_id.as_bytes().as_slice(),
                s::snapshot_status_text(status),
                now
            ],
        )?;
        if changed == 0 {
            return Err(StateError::not_found("snapshot", snapshot_id));
        }
        self.snapshot(account, connection_id, snapshot_id)?
            .ok_or_else(|| StateError::not_found("snapshot", snapshot_id))
    }

    pub(crate) fn snapshot(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        snapshot_id: SnapshotId,
    ) -> SResult<Option<SnapshotRecord>> {
        let conn = self.account_conn(account)?;
        query_optional(
            conn,
            "SELECT connection_id, snapshot_id, path, size, sha256, status FROM snapshots
             WHERE connection_id = ?1 AND snapshot_id = ?2",
            params![connection_id.as_bytes().as_slice(), snapshot_id.as_bytes().as_slice()],
            s::read_snapshot,
        )
    }

    pub(crate) fn list_snapshots(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
    ) -> SResult<Vec<SnapshotRecord>> {
        let conn = self.account_conn(account)?;
        query_many(
            conn,
            "SELECT connection_id, snapshot_id, path, size, sha256, status FROM snapshots
             WHERE connection_id = ?1 ORDER BY created_at_ms",
            params![connection_id.as_bytes().as_slice()],
            s::read_snapshot,
        )
    }

    // ---------------------------------------------------------------
    // Transfers (account database)
    // ---------------------------------------------------------------

    pub(crate) fn record_transfer(&mut self, account: AccountKey, transfer: &TransferRecord) -> SResult<TransferRecord> {
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        conn.execute(
            "INSERT INTO transfers
               (connection_id, transfer_id, operation_id, direction, version_id, range_start, range_end, state,
                sdk_resume_json, logical_bytes, wire_bytes, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12)",
            params![
                transfer.connection_id.as_bytes().as_slice(),
                transfer.transfer_id.as_bytes().as_slice(),
                transfer.operation_id.map(|id| *id.as_bytes()).map(|b| b.to_vec()),
                s::direction_text(transfer.direction),
                transfer.version_id.map(|id| *id.as_bytes()).map(|b| b.to_vec()),
                transfer.range_start.map(schema::checked_i64).transpose()?,
                transfer.range_end.map(schema::checked_i64).transpose()?,
                s::transfer_state_text(transfer.state),
                transfer.sdk_resume_json.as_ref().map(|v| v.to_string()),
                schema::checked_i64(transfer.logical_bytes)?,
                schema::checked_i64(transfer.wire_bytes)?,
                now,
            ],
        )?;
        self.transfer(account, transfer.connection_id, transfer.transfer_id)?
            .ok_or_else(|| StateError::not_found("transfer", transfer.transfer_id))
    }

    pub(crate) fn update_transfer(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        transfer_id: TransferId,
        state: TransferState,
        logical_bytes: u64,
        wire_bytes: u64,
        sdk_resume_json: Option<&serde_json::Value>,
    ) -> SResult<TransferRecord> {
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        let changed = conn.execute(
            "UPDATE transfers SET state = ?3, logical_bytes = ?4, wire_bytes = ?5, sdk_resume_json = ?6, updated_at_ms = ?7
             WHERE connection_id = ?1 AND transfer_id = ?2",
            params![
                connection_id.as_bytes().as_slice(),
                transfer_id.as_bytes().as_slice(),
                s::transfer_state_text(state),
                schema::checked_i64(logical_bytes)?,
                schema::checked_i64(wire_bytes)?,
                sdk_resume_json.map(|v| v.to_string()),
                now
            ],
        )?;
        if changed == 0 {
            return Err(StateError::not_found("transfer", transfer_id));
        }
        self.transfer(account, connection_id, transfer_id)?
            .ok_or_else(|| StateError::not_found("transfer", transfer_id))
    }

    pub(crate) fn transfer(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        transfer_id: TransferId,
    ) -> SResult<Option<TransferRecord>> {
        let conn = self.account_conn(account)?;
        query_optional(
            conn,
            "SELECT connection_id, transfer_id, operation_id, direction, version_id, range_start, range_end, state,
                    sdk_resume_json, logical_bytes, wire_bytes
             FROM transfers WHERE connection_id = ?1 AND transfer_id = ?2",
            params![connection_id.as_bytes().as_slice(), transfer_id.as_bytes().as_slice()],
            s::read_transfer,
        )
    }

    // ---------------------------------------------------------------
    // Commits and retained ancestry (account database)
    // ---------------------------------------------------------------

    pub(crate) fn record_commit(&mut self, account: AccountKey, commit: &CommitRecord) -> SResult<CommitRecord> {
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        conn.execute(
            "INSERT INTO commits (connection_id, commit_id, parent_id, catalog_root, operation_ids_json, status, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            params![
                commit.connection_id.as_bytes().as_slice(),
                commit.commit_id.as_bytes().as_slice(),
                commit.parent_id.map(|id| *id.as_bytes()).map(|b| b.to_vec()),
                commit.catalog_root.map(|d| *d.as_bytes()).map(|b| b.to_vec()),
                c::to_json("operation_ids_json", &commit.operation_ids)?,
                s::commit_status_text(commit.status),
                now,
            ],
        )?;
        self.commit(account, commit.connection_id, commit.commit_id)?
            .ok_or_else(|| StateError::not_found("commit", commit.commit_id))
    }

    pub(crate) fn set_commit_status(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        commit_id: CommitId,
        status: CommitStatus,
    ) -> SResult<CommitRecord> {
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        let changed = conn.execute(
            "UPDATE commits SET status = ?3, updated_at_ms = ?4 WHERE connection_id = ?1 AND commit_id = ?2",
            params![
                connection_id.as_bytes().as_slice(),
                commit_id.as_bytes().as_slice(),
                s::commit_status_text(status),
                now
            ],
        )?;
        if changed == 0 {
            return Err(StateError::not_found("commit", commit_id));
        }
        self.commit(account, connection_id, commit_id)?
            .ok_or_else(|| StateError::not_found("commit", commit_id))
    }

    pub(crate) fn commit(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        commit_id: CommitId,
    ) -> SResult<Option<CommitRecord>> {
        let conn = self.account_conn(account)?;
        query_optional(
            conn,
            "SELECT connection_id, commit_id, parent_id, catalog_root, operation_ids_json, status
             FROM commits WHERE connection_id = ?1 AND commit_id = ?2",
            params![connection_id.as_bytes().as_slice(), commit_id.as_bytes().as_slice()],
            s::read_commit,
        )
    }

    /// Walks retained committed ancestry from `from` (or the newest committed
    /// commit) toward the root, resumable through `after`.
    pub(crate) fn list_ancestry(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        from: Option<CommitId>,
        after: Option<CommitId>,
        limit: u32,
    ) -> SResult<Vec<CommitRecord>> {
        let mut out = Vec::new();
        let mut cursor = match from {
            Some(id) => Some(id),
            None => self.newest_committed(account, connection_id)?,
        };
        let mut skipping = after.is_some();
        while let Some(commit_id) = cursor {
            let Some(record) = self.commit(account, connection_id, commit_id)? else {
                break;
            };
            let parent = record.parent_id;
            if skipping {
                if Some(commit_id) == after {
                    skipping = false;
                }
            } else {
                out.push(record);
                if out.len() >= limit as usize {
                    break;
                }
            }
            cursor = parent;
        }
        Ok(out)
    }

    fn newest_committed(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
    ) -> SResult<Option<CommitId>> {
        let conn = self.account_conn(account)?;
        query_optional(
            conn,
            "SELECT commit_id FROM commits WHERE connection_id = ?1 AND status = 'committed'
             ORDER BY created_at_ms DESC LIMIT 1",
            params![connection_id.as_bytes().as_slice()],
            |row| c::commit_id(row.get_ref(0)?),
        )
    }

    // ---------------------------------------------------------------
    // Event cursors and scan safety (account database)
    // ---------------------------------------------------------------

    /// Persists a remote invalidation and its opaque cursor in one transaction.
    /// The invalidation is durable before the cursor advances past it.
    pub(crate) fn record_head_invalidation(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        cursor: Option<&str>,
    ) -> SResult<ScanState> {
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        let changed = conn.execute(
            "UPDATE event_cursors SET pending_head_refresh = 1, cursor = ?2, updated_at_ms = ?3 WHERE connection_id = ?1",
            params![connection_id.as_bytes().as_slice(), cursor, now],
        )?;
        if changed == 0 {
            return Err(StateError::UnknownConnection(connection_id));
        }
        self.scan_state(account, connection_id)?.ok_or(StateError::UnknownConnection(connection_id))
    }

    pub(crate) fn ack_head_refresh(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
    ) -> SResult<ScanState> {
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        let changed = conn.execute(
            "UPDATE event_cursors SET pending_head_refresh = 0, updated_at_ms = ?2 WHERE connection_id = ?1",
            params![connection_id.as_bytes().as_slice(), now],
        )?;
        if changed == 0 {
            return Err(StateError::UnknownConnection(connection_id));
        }
        self.scan_state(account, connection_id)?.ok_or(StateError::UnknownConnection(connection_id))
    }

    pub(crate) fn begin_scan(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        volume_id: &str,
        journal_id: &str,
    ) -> SResult<ScanState> {
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        conn.execute(
            "UPDATE event_cursors SET scan_epoch = scan_epoch + 1, scan_complete = 0, scan_invalidated = 0,
                    volume_id = ?2, journal_id = ?3, usn_cursor = NULL, updated_at_ms = ?4
             WHERE connection_id = ?1",
            params![connection_id.as_bytes().as_slice(), volume_id, journal_id, now],
        )?;
        self.scan_state(account, connection_id)?.ok_or(StateError::UnknownConnection(connection_id))
    }

    pub(crate) fn complete_scan(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        usn_cursor: Option<u64>,
    ) -> SResult<ScanState> {
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        let changed = conn.execute(
            "UPDATE event_cursors SET scan_complete = 1, usn_cursor = ?2, updated_at_ms = ?3 WHERE connection_id = ?1",
            params![
                connection_id.as_bytes().as_slice(),
                usn_cursor.map(schema::checked_i64).transpose()?,
                now
            ],
        )?;
        if changed == 0 {
            return Err(StateError::UnknownConnection(connection_id));
        }
        self.scan_state(account, connection_id)?.ok_or(StateError::UnknownConnection(connection_id))
    }

    /// Overflow, journal reset/wrap, denied access, or an unavailable volume
    /// invalidate the scan's deletion evidence.
    pub(crate) fn invalidate_scan(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
    ) -> SResult<ScanState> {
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        let changed = conn.execute(
            "UPDATE event_cursors SET scan_invalidated = 1, scan_complete = 0, updated_at_ms = ?2 WHERE connection_id = ?1",
            params![connection_id.as_bytes().as_slice(), now],
        )?;
        if changed == 0 {
            return Err(StateError::UnknownConnection(connection_id));
        }
        self.scan_state(account, connection_id)?.ok_or(StateError::UnknownConnection(connection_id))
    }

    pub(crate) fn scan_state(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
    ) -> SResult<Option<ScanState>> {
        let conn = self.account_conn(account)?;
        query_optional(
            conn,
            "SELECT connection_id, cursor, pending_head_refresh, volume_id, journal_id, usn_cursor,
                    scan_epoch, scan_complete, scan_invalidated
             FROM event_cursors WHERE connection_id = ?1",
            params![connection_id.as_bytes().as_slice()],
            s::read_scan,
        )
    }

    /// Registers the durable event/scan cursor row for a connection.
    pub(crate) fn init_event_cursor(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        volume_id: &str,
        journal_id: &str,
    ) -> SResult<ScanState> {
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        conn.execute(
            "INSERT INTO event_cursors
               (connection_id, cursor, pending_head_refresh, volume_id, journal_id, usn_cursor, scan_epoch,
                scan_complete, scan_invalidated, updated_at_ms)
             VALUES (?1, NULL, 0, ?2, ?3, NULL, 0, 0, 0, ?4)
             ON CONFLICT(connection_id) DO UPDATE SET updated_at_ms = excluded.updated_at_ms",
            params![connection_id.as_bytes().as_slice(), volume_id, journal_id, now],
        )?;
        self.scan_state(account, connection_id)?.ok_or(StateError::UnknownConnection(connection_id))
    }

    // ---------------------------------------------------------------
    // Conflicts (account database)
    // ---------------------------------------------------------------

    pub(crate) fn record_conflict(&mut self, account: AccountKey, conflict: &ConflictRecord) -> SResult<ConflictRecord> {
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        conn.execute(
            "INSERT INTO conflicts
               (connection_id, conflict_id, item_id, competing_ops_json, revisions_json, original_names_json,
                resolution_state, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
             ON CONFLICT(connection_id, conflict_id) DO NOTHING",
            params![
                conflict.connection_id.as_bytes().as_slice(),
                conflict.conflict_id.as_bytes().as_slice(),
                conflict.item_id.as_bytes().as_slice(),
                c::to_json("competing_ops_json", &conflict.competing_ops)?,
                c::to_json("revisions_json", &conflict.revisions_json)?,
                c::to_json("original_names_json", &conflict.original_names)?,
                s::resolution_text(conflict.resolution_state),
                now,
            ],
        )?;
        self.conflict(account, conflict.connection_id, conflict.conflict_id)?
            .ok_or_else(|| StateError::not_found("conflict", conflict.conflict_id))
    }

    pub(crate) fn resolve_conflict(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        conflict_id: ConflictId,
        resolution: ConflictResolution,
    ) -> SResult<ConflictRecord> {
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        let changed = conn.execute(
            "UPDATE conflicts SET resolution_state = ?3, updated_at_ms = ?4 WHERE connection_id = ?1 AND conflict_id = ?2",
            params![
                connection_id.as_bytes().as_slice(),
                conflict_id.as_bytes().as_slice(),
                s::resolution_text(resolution),
                now
            ],
        )?;
        if changed == 0 {
            return Err(StateError::not_found("conflict", conflict_id));
        }
        self.conflict(account, connection_id, conflict_id)?
            .ok_or_else(|| StateError::not_found("conflict", conflict_id))
    }

    pub(crate) fn conflict(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        conflict_id: ConflictId,
    ) -> SResult<Option<ConflictRecord>> {
        let conn = self.account_conn(account)?;
        query_optional(
            conn,
            "SELECT connection_id, conflict_id, item_id, competing_ops_json, revisions_json, original_names_json,
                    resolution_state, created_at_ms
             FROM conflicts WHERE connection_id = ?1 AND conflict_id = ?2",
            params![connection_id.as_bytes().as_slice(), conflict_id.as_bytes().as_slice()],
            s::read_conflict,
        )
    }

    pub(crate) fn list_conflicts(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
    ) -> SResult<Vec<ConflictRecord>> {
        let conn = self.account_conn(account)?;
        query_many(
            conn,
            "SELECT connection_id, conflict_id, item_id, competing_ops_json, revisions_json, original_names_json,
                    resolution_state, created_at_ms
             FROM conflicts WHERE connection_id = ?1 ORDER BY created_at_ms, conflict_id",
            params![connection_id.as_bytes().as_slice()],
            s::read_conflict,
        )
    }

    // ---------------------------------------------------------------
    // Local actions (account database)
    // ---------------------------------------------------------------

    pub(crate) fn record_local_action(&mut self, account: AccountKey, action: &LocalAction) -> SResult<LocalAction> {
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        conn.execute(
            "INSERT INTO local_actions
               (connection_id, action_id, item_id, kind, expected_file_id, expected_generation, expected_usn,
                old_version, new_version, source_path, target_path, recovery_path, state, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?14)",
            params![
                action.connection_id.as_bytes().as_slice(),
                action.action_id.as_bytes().as_slice(),
                action.item_id.map(|id| *id.as_bytes()).map(|b| b.to_vec()),
                s::action_kind_text(action.kind),
                action.expected_file_id,
                action.expected_generation.map(schema::checked_i64).transpose()?,
                action.expected_usn.map(schema::checked_i64).transpose()?,
                action.old_version.map(|id| *id.as_bytes()).map(|b| b.to_vec()),
                action.new_version.map(|id| *id.as_bytes()).map(|b| b.to_vec()),
                action.source_path.as_ref().map(|p| c::path_text(p)).transpose()?,
                action.target_path.as_ref().map(|p| c::path_text(p)).transpose()?,
                action.recovery_path.as_ref().map(|p| c::path_text(p)).transpose()?,
                s::action_state_text(action.state),
                now,
            ],
        )?;
        self.local_action(account, action.connection_id, action.action_id)?
            .ok_or_else(|| StateError::not_found("local_action", action.action_id))
    }

    pub(crate) fn set_local_action_state(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        action_id: ActionId,
        state: LocalActionState,
    ) -> SResult<LocalAction> {
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        let changed = conn.execute(
            "UPDATE local_actions SET state = ?3, updated_at_ms = ?4 WHERE connection_id = ?1 AND action_id = ?2",
            params![
                connection_id.as_bytes().as_slice(),
                action_id.as_bytes().as_slice(),
                s::action_state_text(state),
                now
            ],
        )?;
        if changed == 0 {
            return Err(StateError::not_found("local_action", action_id));
        }
        self.local_action(account, connection_id, action_id)?
            .ok_or_else(|| StateError::not_found("local_action", action_id))
    }

    pub(crate) fn local_action(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        action_id: ActionId,
    ) -> SResult<Option<LocalAction>> {
        let conn = self.account_conn(account)?;
        query_optional(
            conn,
            &format!("SELECT {LOCAL_ACTION_COLUMNS} FROM local_actions WHERE connection_id = ?1 AND action_id = ?2"),
            params![connection_id.as_bytes().as_slice(), action_id.as_bytes().as_slice()],
            s::read_local_action,
        )
    }

    pub(crate) fn list_local_actions(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        state: Option<LocalActionState>,
    ) -> SResult<Vec<LocalAction>> {
        let conn = self.account_conn(account)?;
        match state {
            None => query_many(
                conn,
                &format!("SELECT {LOCAL_ACTION_COLUMNS} FROM local_actions WHERE connection_id = ?1 ORDER BY created_at_ms"),
                params![connection_id.as_bytes().as_slice()],
                s::read_local_action,
            ),
            Some(state) => query_many(
                conn,
                &format!("SELECT {LOCAL_ACTION_COLUMNS} FROM local_actions WHERE connection_id = ?1 AND state = ?2 ORDER BY created_at_ms"),
                params![connection_id.as_bytes().as_slice(), s::action_state_text(state)],
                s::read_local_action,
            ),
        }
    }

    pub(crate) fn pending_local_actions(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
    ) -> SResult<Vec<LocalAction>> {
        let conn = self.account_conn(account)?;
        query_many(
            conn,
            &format!("SELECT {LOCAL_ACTION_COLUMNS} FROM local_actions WHERE connection_id = ?1
             AND state IN ('pending', 'in_progress', 'requeued') ORDER BY created_at_ms"),
            params![connection_id.as_bytes().as_slice()],
            s::read_local_action,
        )
    }

    // ---------------------------------------------------------------
    // Local observations (account database)
    // ---------------------------------------------------------------

    /// Records a local observation: a new durable generation with `dirty` set.
    pub(crate) fn bump_observation(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        item_id: ItemId,
        observed_usn: Option<u64>,
    ) -> SResult<LocalObservation> {
        let conn = self.account_conn(account)?;
        conn.execute(
            "INSERT INTO local_observations
               (connection_id, item_id, generation, observed_usn, dirty, pin_requested, pin_complete, excluded, scan_epoch)
             VALUES (?1, ?2, 1, ?3, 1, 0, 0, 0, 0)
             ON CONFLICT(connection_id, item_id) DO UPDATE SET
               generation = local_observations.generation + 1,
               observed_usn = excluded.observed_usn,
               dirty = 1",
            params![
                connection_id.as_bytes().as_slice(),
                item_id.as_bytes().as_slice(),
                observed_usn.map(schema::checked_i64).transpose()?
            ],
        )?;
        self.observation(account, connection_id, item_id)?
            .ok_or_else(|| StateError::not_found("observation", item_id))
    }

    pub(crate) fn set_observation_flags(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        item_id: ItemId,
        flags: ObservationFlags,
    ) -> SResult<LocalObservation> {
        if flags.dirty.is_none()
            && flags.pin_requested.is_none()
            && flags.pin_complete.is_none()
            && flags.excluded.is_none()
        {
            return self
                .observation(account, connection_id, item_id)?
                .ok_or_else(|| StateError::not_found("observation", item_id));
        }
        // NULL keeps the existing column value; every parameter slot is always
        // bound so the statement has a fixed shape.
        let conn = self.account_conn(account)?;
        let changed = conn.execute(
            "UPDATE local_observations SET
                dirty = COALESCE(?3, dirty),
                pin_requested = COALESCE(?4, pin_requested),
                pin_complete = COALESCE(?5, pin_complete),
                excluded = COALESCE(?6, excluded)
             WHERE connection_id = ?1 AND item_id = ?2",
            params![
                connection_id.as_bytes().as_slice(),
                item_id.as_bytes().as_slice(),
                flags.dirty.map(i64::from),
                flags.pin_requested.map(i64::from),
                flags.pin_complete.map(i64::from),
                flags.excluded.map(i64::from),
            ],
        )?;
        if changed == 0 {
            return Err(StateError::not_found("observation", item_id));
        }
        self.observation(account, connection_id, item_id)?
            .ok_or_else(|| StateError::not_found("observation", item_id))
    }

    pub(crate) fn observation(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        item_id: ItemId,
    ) -> SResult<Option<LocalObservation>> {
        let conn = self.account_conn(account)?;
        query_optional(
            conn,
            "SELECT connection_id, item_id, generation, observed_usn, dirty, pin_requested, pin_complete, excluded, scan_epoch
             FROM local_observations WHERE connection_id = ?1 AND item_id = ?2",
            params![connection_id.as_bytes().as_slice(), item_id.as_bytes().as_slice()],
            s::read_observation,
        )
    }

    // ---------------------------------------------------------------
    // Common bases (account database)
    // ---------------------------------------------------------------

    /// Stores (or replaces) the remembered base item record for
    /// (connection, item, commit). `item_json` is canonical format bytes and
    /// is stored exactly as given: it is validated to be JSON but never
    /// re-serialized, so byte identity survives restart.
    pub(crate) fn put_common_base(
        &mut self,
        account: AccountKey,
        record: &CommonBaseRecord,
    ) -> SResult<CommonBaseRecord> {
        if serde_json::from_str::<serde_json::Value>(&record.item_json).is_err() {
            return Err(StateError::invalid_state(
                "common_base",
                record.item_id,
                "item_json is not valid JSON",
            ));
        }
        let conn = self.account_conn(account)?;
        conn.execute(
            "INSERT INTO common_bases (connection_id, item_id, commit_id, item_json)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(connection_id, item_id, commit_id) DO UPDATE SET item_json = excluded.item_json",
            params![
                record.connection_id.as_bytes().as_slice(),
                record.item_id.as_bytes().as_slice(),
                record.commit_id.as_bytes().as_slice(),
                record.item_json,
            ],
        )?;
        self.get_common_base(account, record.connection_id, record.item_id, record.commit_id)?
            .ok_or_else(|| StateError::not_found("common_base", record.item_id))
    }

    pub(crate) fn get_common_base(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        item_id: ItemId,
        commit_id: CommitId,
    ) -> SResult<Option<CommonBaseRecord>> {
        let conn = self.account_conn(account)?;
        query_optional(
            conn,
            "SELECT connection_id, item_id, commit_id, item_json FROM common_bases
             WHERE connection_id = ?1 AND item_id = ?2 AND commit_id = ?3",
            params![
                connection_id.as_bytes().as_slice(),
                item_id.as_bytes().as_slice(),
                commit_id.as_bytes().as_slice()
            ],
            s::read_common_base,
        )
    }

    pub(crate) fn list_common_bases(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
    ) -> SResult<Vec<CommonBaseRecord>> {
        let conn = self.account_conn(account)?;
        query_many(
            conn,
            "SELECT connection_id, item_id, commit_id, item_json FROM common_bases
             WHERE connection_id = ?1 ORDER BY item_id, commit_id",
            params![connection_id.as_bytes().as_slice()],
            s::read_common_base,
        )
    }

    // ---------------------------------------------------------------
    // Items (account database)
    // ---------------------------------------------------------------

    pub(crate) fn upsert_item(&mut self, account: AccountKey, item: &ItemRecord) -> SResult<ItemRecord> {
        let conn = self.account_conn(account)?;
        conn.execute(
            "INSERT INTO items
               (connection_id, item_id, parent_id, name, name_key, kind, revision, content_version_id, deleted, metadata_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(connection_id, item_id) DO UPDATE SET
               parent_id = excluded.parent_id, name = excluded.name, name_key = excluded.name_key,
               kind = excluded.kind, revision = excluded.revision, content_version_id = excluded.content_version_id,
               deleted = excluded.deleted, metadata_json = excluded.metadata_json",
            params![
                item.connection_id.as_bytes().as_slice(),
                item.item_id.as_bytes().as_slice(),
                item.parent_id.map(|id| *id.as_bytes()).map(|b| b.to_vec()),
                item.name,
                item.name_key,
                s::item_kind_text(item.kind),
                item.revision.as_bytes().as_slice(),
                item.content_version_id.map(|id| *id.as_bytes()).map(|b| b.to_vec()),
                i64::from(item.deleted),
                c::to_json("metadata_json", &item.metadata_json)?,
            ],
        )?;
        self.item(account, item.connection_id, item.item_id)?
            .ok_or_else(|| StateError::not_found("item", item.item_id))
    }

    pub(crate) fn item(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        item_id: ItemId,
    ) -> SResult<Option<ItemRecord>> {
        let conn = self.account_conn(account)?;
        query_optional(
            conn,
            &format!("SELECT {ITEM_COLUMNS} FROM items WHERE connection_id = ?1 AND item_id = ?2"),
            params![connection_id.as_bytes().as_slice(), item_id.as_bytes().as_slice()],
            s::read_item,
        )
    }

    pub(crate) fn list_children(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        parent_id: Option<ItemId>,
        include_deleted: bool,
    ) -> SResult<Vec<ItemRecord>> {
        let deleted_clause = if include_deleted { "" } else { " AND deleted = 0" };
        let conn = self.account_conn(account)?;
        match parent_id {
            Some(parent) => query_many(
                conn,
                &format!("SELECT {ITEM_COLUMNS} FROM items WHERE connection_id = ?1 AND parent_id = ?2{deleted_clause} ORDER BY name_key"),
                params![connection_id.as_bytes().as_slice(), parent.as_bytes().as_slice()],
                s::read_item,
            ),
            None => query_many(
                conn,
                &format!("SELECT {ITEM_COLUMNS} FROM items WHERE connection_id = ?1 AND parent_id IS NULL{deleted_clause} ORDER BY name_key"),
                params![connection_id.as_bytes().as_slice()],
                s::read_item,
            ),
        }
    }

    pub(crate) fn excluded_observations(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
    ) -> SResult<Vec<LocalObservation>> {
        let conn = self.account_conn(account)?;
        query_many(
            conn,
            "SELECT connection_id, item_id, generation, observed_usn, dirty, pin_requested, pin_complete, excluded, scan_epoch
             FROM local_observations WHERE connection_id = ?1 AND excluded = 1 ORDER BY item_id",
            params![connection_id.as_bytes().as_slice()],
            s::read_observation,
        )
    }

    pub(crate) fn list_all_items(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        include_deleted: bool,
    ) -> SResult<Vec<ItemRecord>> {
        let deleted_clause = if include_deleted { "" } else { " AND deleted = 0" };
        let conn = self.account_conn(account)?;
        query_many(
            conn,
            &format!("SELECT {ITEM_COLUMNS} FROM items WHERE connection_id = ?1{deleted_clause} ORDER BY parent_id, name_key, item_id"),
            params![connection_id.as_bytes().as_slice()],
            s::read_item,
        )
    }

    // ---------------------------------------------------------------
    // Probe created-key journal (account database)
    // ---------------------------------------------------------------

    /// Reserves one exact key the probe run may create. Reservations are
    /// written before any external create effect.
    pub(crate) fn reserve_probe_key(&mut self, account: AccountKey, record: &ProbeKeyRecord) -> SResult<ProbeKeyRecord> {
        if record.state != ProbeKeyState::Reserved {
            return Err(StateError::invalid_state("probe_key", &record.key, "keys start Reserved"));
        }
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        conn.execute(
            "INSERT INTO probe_keys (run_id, connection_id, setup_id, key, state, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, 'reserved', ?5, ?5)
             ON CONFLICT(run_id, connection_id, key) DO NOTHING",
            params![
                record.run_id.as_bytes().as_slice(),
                record.connection_id.as_bytes().as_slice(),
                record.setup_id.map(|id| *id.as_bytes()).map(|b| b.to_vec()),
                record.key,
                now
            ],
        )?;
        self.probe_key(account, record.connection_id, record.run_id, &record.key)?
            .ok_or_else(|| StateError::not_found("probe_key", &record.key))
    }

    pub(crate) fn set_probe_key_state(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        run_id: GenerationId,
        key: &str,
        state: ProbeKeyState,
    ) -> SResult<ProbeKeyRecord> {
        let now = schema::checked_i64(schema::now_ms())?;
        let conn = self.account_conn(account)?;
        let changed = conn.execute(
            "UPDATE probe_keys SET state = ?4, updated_at_ms = ?5 WHERE run_id = ?1 AND connection_id = ?2 AND key = ?3",
            params![
                run_id.as_bytes().as_slice(),
                connection_id.as_bytes().as_slice(),
                key,
                s::probe_key_state_text(state),
                now
            ],
        )?;
        if changed == 0 {
            return Err(StateError::not_found("probe_key", key));
        }
        self.probe_key(account, connection_id, run_id, key)?.ok_or_else(|| StateError::not_found("probe_key", key))
    }

    pub(crate) fn probe_key(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        run_id: GenerationId,
        key: &str,
    ) -> SResult<Option<ProbeKeyRecord>> {
        let conn = self.account_conn(account)?;
        query_optional(
            conn,
            "SELECT run_id, connection_id, setup_id, key, state FROM probe_keys
             WHERE run_id = ?1 AND connection_id = ?2 AND key = ?3",
            params![run_id.as_bytes().as_slice(), connection_id.as_bytes().as_slice(), key],
            s::read_probe_key,
        )
    }

    /// Lists every key reserved by exactly this run — the only keys cleanup may
    /// consider. Ordered deterministically.
    pub(crate) fn probe_keys(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        run_id: GenerationId,
    ) -> SResult<Vec<ProbeKeyRecord>> {
        let conn = self.account_conn(account)?;
        query_many(
            conn,
            "SELECT run_id, connection_id, setup_id, key, state FROM probe_keys
             WHERE run_id = ?1 AND connection_id = ?2 ORDER BY key",
            params![run_id.as_bytes().as_slice(), connection_id.as_bytes().as_slice()],
            s::read_probe_key,
        )
    }

    /// The exact confirmed-created keys of a run: the only deletable set.
    pub(crate) fn probe_cleanup_candidates(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
        run_id: GenerationId,
    ) -> SResult<Vec<ProbeKeyRecord>> {
        Ok(self
            .probe_keys(account, connection_id, run_id)?
            .into_iter()
            .filter(|record| record.state == ProbeKeyState::Created)
            .collect())
    }

    // ---------------------------------------------------------------
    // Settings (control for global scope, account for account scope)
    // ---------------------------------------------------------------

    pub(crate) fn set_settings(
        &mut self,
        account: Option<AccountKey>,
        scope_id: &str,
        value: &serde_json::Value,
        expected_revision: Option<u64>,
    ) -> SResult<SettingsRow> {
        let now = schema::checked_i64(schema::now_ms())?;
        let value_text = c::to_json("value_json", value)?;
        let existing = self.settings(account, scope_id)?;
        let revision = match (&existing, expected_revision) {
            (None, None) => 0u64,
            (None, Some(expected)) => return Err(StateError::RevisionMismatch { expected, actual: 0 }),
            (Some(row), None) => row.revision,
            (Some(row), Some(expected)) => {
                if row.revision != expected {
                    return Err(StateError::RevisionMismatch { expected, actual: row.revision });
                }
                row.revision
            }
        };
        let new_revision = revision + 1;
        let insert = existing.is_none();
        let conn = match account {
            None => &self.control,
            Some(key) => self.account_conn(key)?,
        };
        if insert {
            conn.execute(
                "INSERT INTO settings (scope_id, revision, value_json, updated_at_ms) VALUES (?1, ?2, ?3, ?4)",
                params![scope_id, schema::checked_i64(new_revision)?, value_text, now],
            )?;
        } else {
            conn.execute(
                "UPDATE settings SET revision = ?2, value_json = ?3, updated_at_ms = ?4 WHERE scope_id = ?1",
                params![scope_id, schema::checked_i64(new_revision)?, value_text, now],
            )?;
        }
        self.settings(account, scope_id)?.ok_or_else(|| StateError::not_found("settings", scope_id))
    }

    pub(crate) fn settings(&mut self, account: Option<AccountKey>, scope_id: &str) -> SResult<Option<SettingsRow>> {
        let conn = match account {
            None => &self.control,
            Some(key) => self.account_conn(key)?,
        };
        query_optional(
            conn,
            "SELECT scope_id, revision, value_json FROM settings WHERE scope_id = ?1",
            params![scope_id],
            s::read_settings,
        )
    }

    // ---------------------------------------------------------------
    // Retention accounting (read-only; no deletion method exists)
    // ---------------------------------------------------------------

    pub(crate) fn retention_snapshot(
        &mut self,
        account: AccountKey,
        connection_id: ConnectionId,
    ) -> SResult<RetentionSnapshot> {
        let conn = self.account_conn(account)?;
        let retained_commits: i64 = conn.query_row(
            "SELECT COUNT(*) FROM commits WHERE connection_id = ?1 AND status IN ('committed', 'applied')",
            params![connection_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        let pending_upload_reservations: i64 = conn.query_row(
            "SELECT COUNT(*) FROM outbox WHERE connection_id = ?1
             AND snapshot_id IS NOT NULL AND state NOT IN ('published', 'local_apply_pending', 'complete')",
            params![connection_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        Ok(RetentionSnapshot {
            epoch: 0,
            retained_commits: u64::try_from(retained_commits).unwrap_or(0),
            pending_upload_reservations: u64::try_from(pending_upload_reservations).unwrap_or(0),
        })
    }
}

// ------------------------------------------------------------------
// Supporting types and helpers
// ------------------------------------------------------------------

/// Internal shape mirroring a setup journal row for cross-database writes.
struct SetupMirror {
    setup_id: SetupId,
    connection_id: ConnectionId,
    operation_id: OperationId,
    account_key: AccountKey,
    binding_json: String,
    initialize: bool,
    bucket_creation_operation_id: Option<OperationId>,
    request_fingerprint: Sha256Digest,
    phase: SetupPhase,
    status: SetupStatus,
    created_resources_json: String,
    preview_json: Option<String>,
    root_path: Option<String>,
    mode: Option<ConnectionMode>,
    credential_ref: Option<String>,
    probe_evidence_json: Option<String>,
    failure_reason: Option<String>,
    evidence_generation: u64,
    account_committed: bool,
}

fn setup_config(record: &SetupRecord) -> serde_json::Value {
    let mut config = serde_json::json!({
        "setup_id": record.setup_id.to_string(),
        "initialize": record.initialize,
        "evidence_generation": record.evidence_generation,
    });
    for key in ["root_item_id", "visibility"] {
        if let Some(value) = record.preview_json.as_ref().and_then(|preview| preview.get(key)).cloned() {
            config[key] = value;
        }
    }
    config
}

/// Fingerprint binding one operation id to one exact setup request. Built from
/// the persisted column values so any difference in the request is visible.
fn setup_fingerprint(draft: &SetupDraft) -> SResult<Sha256Digest> {
    let mut hasher = Sha256::new();
    hasher.update(draft.operation_id.to_string().as_bytes());
    hasher.update([0]);
    hasher.update(draft.account_key.as_bytes());
    hasher.update([0]);
    hasher.update(draft.binding.workspace_id.as_bytes());
    hasher.update([0]);
    let bucket = &draft.binding.bucket;
    for part in [
        s::owner_kind_text(bucket.owner_kind),
        bucket.owner_id.as_str(),
        bucket.owner_namespace.as_str(),
        bucket.bucket_id.as_str(),
        bucket.bucket_name.as_str(),
        draft.binding.prefix.as_str(),
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    hasher.update([u8::from(draft.initialize)]);
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

/// Digest binding one operation id to one canonical request body.
pub(crate) fn request_digest(kind: &str, request: &serde_json::Value) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hasher.update(request.to_string().as_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

/// Durable outbox transitions with their evidence.
#[derive(Debug, Clone)]
pub enum OutboxTransition {
    SnapshotReady { snapshot_id: SnapshotId },
    Recaptured { snapshot_id: SnapshotId },
    PayloadReady { object_ref: hfdrive_core::storage::ObjectRef },
    MetadataReady {
        candidate_commit: CommitId,
        candidate_head_json: serde_json::Value,
        expected_etag: String,
    },
    PublishUnknown { retry_class: RetryClass, next_attempt_at_ms: Option<u64> },
    Published,
    Rebased { snapshot_id: SnapshotId },
    LocalApplyPending,
}

impl OutboxTransition {
    pub fn target(&self) -> OutboxState {
        match self {
            Self::SnapshotReady { .. } => OutboxState::SnapshotReady,
            Self::Recaptured { .. } => OutboxState::Observed,
            Self::PayloadReady { .. } => OutboxState::PayloadReady,
            Self::MetadataReady { .. } => OutboxState::MetadataReady,
            Self::PublishUnknown { .. } => OutboxState::PublishUnknown,
            Self::Published => OutboxState::Published,
            Self::Rebased { .. } => OutboxState::Observed,
            Self::LocalApplyPending => OutboxState::LocalApplyPending,
        }
    }
}

/// Result of completing an operation's local side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionOutcome {
    Completed { generation: u64 },
    CompletedWithNewerGeneration { operation_generation: u64, current_generation: u64 },
}

/// How the caller resolved an interrupted external operation.
#[derive(Debug, Clone)]
pub enum OperationResolution {
    EffectFound { result: serde_json::Value },
    EffectAbsentSafeToRetry,
    GiveUp { reason: String },
}

/// Selective flags for a local observation; `None` leaves the column alone.
#[derive(Debug, Clone, Copy, Default)]
pub struct ObservationFlags {
    pub dirty: Option<bool>,
    pub pin_requested: Option<bool>,
    pub pin_complete: Option<bool>,
    pub excluded: Option<bool>,
}

pub(crate) fn query_optional<T, F>(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
    map: F,
) -> SResult<Option<T>>
where
    F: FnOnce(&rusqlite::Row<'_>) -> SResult<T>,
{
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query(params)?;
    match rows.next()? {
        None => Ok(None),
        Some(row) => Ok(Some(map(row)?)),
    }
}

pub(crate) fn query_many<T, F>(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
    map: F,
) -> SResult<Vec<T>>
where
    F: Fn(&rusqlite::Row<'_>) -> SResult<T>,
{
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query(params)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(map(row)?);
    }
    Ok(out)
}
