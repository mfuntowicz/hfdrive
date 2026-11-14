//! Bounded, validated, resumable committed-ancestry traversal.
//!
//! The ancestry of a managed prefix is the parent chain of `commit` records
//! reachable from the current `HEAD`. This module walks that chain over any
//! commit-record reader ([`AncestrySource`]) and is the only recovery oracle
//! for an uncertain publication outcome: a conditional `HEAD` write whose
//! response was lost is resolved by finding its exact candidate commit (or its
//! exact operation UUIDs) in current committed ancestry — never by blindly
//! repeating the compare-and-swap and never by declaring rollback.
//!
//! Validation at every fetch:
//! - the record decodes as canonical bounded `CommitV1` bytes (a record naming
//!   a newer schema or unknown required feature is [`PublicationError::UnsupportedFormat`],
//!   corrupt bytes are [`PublicationError::InvalidResponse`]);
//! - the record's `commit_id` equals the requested id (key/body agreement);
//! - the record's `workspace_id` equals the walked workspace (anything else is
//!   [`PublicationError::BindingMismatch`]);
//! - the chain links by `parent_commit_id` and never revisits a commit within
//!   one call (a revisit is corruption, not a cycle to follow).
//!
//! A referenced record that cannot be fetched is
//! [`PublicationError::RemoteContentUnavailable`]: retryable evidence about
//! transport state, never a deletion signal and never "the commit does not
//! exist". Absence of an operation is only ever proven by consuming the chain
//! down to the initial commit (`parent_commit_id: null`) inside the bound; a
//! walk that hits its bound reports [`AncestryProgress::Paused`] with a
//! resumable [`AncestryCursor`] and is never silently "not found".
#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::future::Future;

use hfdrive_core::format::{self, CommitV1};
use hfdrive_core::ids::{CommitId, OperationId, WorkspaceId};
use hfdrive_hf::NativeLease;
use tokio_util::sync::CancellationToken;

use crate::coordinator::decode_commit;
use crate::transport::BoundedRecord;
use crate::PublicationError;

/// Bounds for one ancestry call. The defaults cover an uncertain-write
/// resolution in a single call while keeping the fetch set finite; callers may
/// narrow them (the probe uses a much smaller budget).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AncestryBounds {
    /// Maximum commit records fetched in one call.
    pub max_commits: u64,
    /// Maximum total record bytes fetched in one call.
    pub max_bytes: u64,
}

impl Default for AncestryBounds {
    fn default() -> Self {
        Self { max_commits: 256, max_bytes: 32 * 1024 * 1024 }
    }
}

/// A resumable position in one committed-ancestry search.
///
/// Persist this with uncertain-write evidence; a later call continues exactly
/// where a bounded call stopped. `next` is the next commit id to load (`None`
/// after the chain was fully consumed). The counters only bound progress;
/// they are not evidence of completeness.
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AncestryCursor {
    /// Next commit to load; `None` once the initial commit was consumed.
    pub next: Option<CommitId>,
    /// Commit records fetched so far.
    pub scanned: u64,
    /// Record bytes fetched so far.
    pub bytes: u64,
}

impl AncestryCursor {
    /// A fresh walk starting at `from` (usually the committed `HEAD` commit).
    pub fn begin(from: CommitId) -> Self {
        Self { next: Some(from), scanned: 0, bytes: 0 }
    }
}

/// What one walk searches for.
#[derive(Clone, Debug, Default)]
pub struct AncestryGoal {
    /// The exact candidate commit whose publication is being resolved.
    pub candidate: Option<CommitId>,
    /// Operation UUIDs whose committed location proves the intent was applied.
    pub operations: Vec<OperationId>,
}

/// One committed goal location found on the walked chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AncestryMatch {
    /// The commit that carries the match.
    pub commit_id: CommitId,
    /// True when this commit is exactly the candidate commit.
    pub is_candidate: bool,
    /// Goal operation UUIDs recorded by this commit.
    pub operations: Vec<OperationId>,
}

/// When a walk may stop early.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AncestryStop {
    /// Collect every goal location on the chain; stop only when the exact
    /// candidate commit is found (decisive) or the chain/bound is consumed.
    /// This is the uncertain-write resolution rule: full accounting of a
    /// candidate's operations, so a multi-commit workflow is never mistaken
    /// for complete after its first chunk.
    CandidateOrComplete,
    /// Stop at the first goal match of any kind. Used by the simple
    /// `find_committed_operation` convenience.
    FirstMatch,
}

/// The outcome of one bounded ancestry call.
#[derive(Clone, Debug)]
pub enum AncestryProgress {
    /// The exact candidate commit is committed at this id.
    Candidate {
        /// The committed candidate commit id (equal to `goal.candidate`).
        commit_id: CommitId,
        /// Goal operation locations found up to and including this commit.
        matches: Vec<AncestryMatch>,
    },
    /// The chain was fully consumed inside the bound. `matches` is the
    /// complete accounting of goal locations on the committed chain: an empty
    /// `matches` proves the goal is absent from committed ancestry.
    Complete {
        /// Every goal location found on the chain.
        matches: Vec<AncestryMatch>,
    },
    /// The bound stopped the search before a decisive answer. Resume with the
    /// cursor; the search is incomplete and must never be read as absence.
    Paused {
        /// Resumable position.
        cursor: AncestryCursor,
        /// Goal locations found so far.
        matches: Vec<AncestryMatch>,
    },
}

impl AncestryProgress {
    /// Goal locations found so far.
    pub fn matches(&self) -> &[AncestryMatch] {
        match self {
            Self::Candidate { matches, .. } | Self::Complete { matches } | Self::Paused { matches, .. } => {
                matches
            }
        }
    }
}

/// Reader of bounded committed `commit` records for one managed prefix.
///
/// The production implementation reads immutable metadata through the
/// publication store ([`crate::coordinator::PublicationStore::read_metadata`]);
/// the capability probe reads its tiny publication records through the owned
/// probe namespace. Implementations must return the record bytes of exactly
/// `commits/<commit-id>.json`; the walk validates key/body agreement itself.
pub trait AncestrySource {
    /// One bounded read of a commit record.
    fn read_commit(
        &self,
        lease: &NativeLease,
        commit: CommitId,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<BoundedRecord, PublicationError>> + Send;
}

/// Walks committed ancestry from `cursor.next`, validating every record and
/// collecting goal matches.
///
/// Stop rules:
/// - [`AncestryStop::CandidateOrComplete`] returns [`AncestryProgress::Candidate`]
///   the moment the exact candidate commit is on the chain; otherwise it walks
///   to the initial commit (or the bound).
/// - [`AncestryStop::FirstMatch`] returns [`AncestryProgress::Complete`] at the
///   first goal match (check [`AncestryProgress::matches`] for its location).
///
/// Errors: a missing referenced record is
/// [`PublicationError::RemoteContentUnavailable`] (retryable, never a deletion);
/// a corrupt, foreign or key-mismatched record is
/// [`PublicationError::InvalidResponse`] /
/// [`PublicationError::BindingMismatch`]; a bound hit is not an error but
/// [`AncestryProgress::Paused`]; cancellation is
/// [`PublicationError::Cancelled`] and discards partial progress (reads are
/// safe to repeat).
pub async fn walk_ancestry<R: AncestrySource + ?Sized>(
    source: &R,
    lease: &NativeLease,
    workspace: WorkspaceId,
    mut cursor: AncestryCursor,
    goal: &AncestryGoal,
    stop: AncestryStop,
    bounds: AncestryBounds,
    cancel: &CancellationToken,
) -> Result<AncestryProgress, PublicationError> {
    let mut matches: Vec<AncestryMatch> = Vec::new();
    let mut visited: HashSet<CommitId> = HashSet::new();
    loop {
        let Some(next) = cursor.next else {
            return Ok(AncestryProgress::Complete { matches });
        };
        if cursor.scanned >= bounds.max_commits || cursor.bytes >= bounds.max_bytes {
            return Ok(AncestryProgress::Paused { cursor, matches });
        }
        if cancel.is_cancelled() {
            return Err(PublicationError::Cancelled);
        }
        if !visited.insert(next) {
            // A repeated commit id on one chain is corruption; never loop.
            return Err(PublicationError::InvalidResponse);
        }
        let record = source.read_commit(lease, next, cancel).await.map_err(|err| match err {
            // A referenced record we cannot fetch is retryable transport
            // evidence, never evidence that the commit is absent.
            PublicationError::Absent => PublicationError::RemoteContentUnavailable,
            other => other,
        })?;
        if record.len() > format::MAX_COMMIT_BYTES {
            return Err(PublicationError::RecordTooLarge);
        }
        let commit = decode_commit(record.body(), next, workspace)?;
        cursor.scanned += 1;
        cursor.bytes += record.len() as u64;

        let hit: Vec<OperationId> = goal
            .operations
            .iter()
            .copied()
            .filter(|op| commit.operation_ids.contains(op))
            .collect();
        let is_candidate = goal.candidate == Some(next);
        if is_candidate || !hit.is_empty() {
            matches.push(AncestryMatch { commit_id: next, is_candidate, operations: hit });
            if is_candidate {
                return Ok(AncestryProgress::Candidate { commit_id: next, matches });
            }
            if stop == AncestryStop::FirstMatch {
                return Ok(AncestryProgress::Complete { matches });
            }
        }

        match commit.parent_commit_id {
            Some(parent) => cursor.next = Some(parent),
            None => {
                return Ok(AncestryProgress::Complete { matches });
            }
        }
    }
}

/// Loads and validates one commit record at a known id, with the same rules
/// the walk applies (canonical bounded bytes, key/body agreement, workspace
/// agreement). Used to inspect a candidate or base commit directly.
pub async fn load_commit<R: AncestrySource + ?Sized>(
    source: &R,
    lease: &NativeLease,
    workspace: WorkspaceId,
    commit: CommitId,
    cancel: &CancellationToken,
) -> Result<CommitV1, PublicationError> {
    let record = source.read_commit(lease, commit, cancel).await.map_err(|err| match err {
        PublicationError::Absent => PublicationError::RemoteContentUnavailable,
        other => other,
    })?;
    if record.len() > format::MAX_COMMIT_BYTES {
        return Err(PublicationError::RecordTooLarge);
    }
    decode_commit(record.body(), commit, workspace)
}
