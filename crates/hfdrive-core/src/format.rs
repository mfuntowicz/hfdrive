//! HF Drive remote format v1: typed records and the canonical byte codec.
//!
//! The remote format is byte-addressed. Every managed record has exactly one
//! accepted spelling: canonical UTF-8 JSON with lexically ordered object
//! members, compact separators, minimal string escapes and nonnegative integer
//! numbers. Decoders accept only canonical bytes, so the SHA-256 that addresses
//! an immutable record has exactly one preimage form and no alternate spelling
//! can be substituted for an authenticated page. See `spec/remote-v1.md` for
//! the normative description; `crates/hfdrive-core/tests/format_fixtures.rs`
//! pins its golden bytes.

use crate::ids::{CommitId, DeviceId, GenerationId, ItemId, OperationId, VersionId, WorkspaceId};
use crate::storage::{PayloadKey, Sha256Digest, XetFileId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::ser::SerializeMap;

use std::fmt;

/// Maximum encoded size of a `HEAD` record.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Maximum encoded size of a commit record.
pub const MAX_COMMIT_BYTES: usize = 1024 * 1024;
/// Maximum number of `changes` and `operation_ids` entries in one commit.
pub const MAX_COMMIT_OPERATIONS: usize = 1000;
/// Maximum encoded size of a version record.
pub const MAX_VERSION_BYTES: usize = 16 * 1024;
/// Maximum encoded size of one catalog page.
pub const MAX_PAGE_BYTES: usize = 256 * 1024;
/// Maximum entries in a leaf page and children in a branch page.
pub const MAX_PAGE_FANOUT: usize = 128;
/// Maximum accepted JSON nesting depth of any managed record.
pub const MAX_DECODER_DEPTH: usize = 64;

/// The format identifier carried by every v1 record.
pub const FORMAT_NAME: &str = "hfdrive";
/// The v1 schema number.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum FormatError {
    #[error("record is not a JSON object")]
    NotAnObject,
    #[error("record is not canonical HF Drive JSON")]
    NonCanonical,
    #[error("record has missing, duplicate, unknown or unordered members")]
    MemberError,
    #[error("record is not an HF Drive managed record")]
    NotHFDriveFormat,
    #[error("record exceeds its format size bound")]
    TooLarge,
    #[error("record exceeds the format nesting bound")]
    TooDeep,
    #[error("record has the wrong shape or an out-of-range value")]
    InvalidShape,
    #[error("record identifier is not a canonical lowercase UUID")]
    InvalidId,
    #[error("record digest is not lowercase SHA-256 hexadecimal")]
    InvalidDigest,
    #[error("record names a format schema this build cannot read")]
    NewerSchema,
    #[error("record requires format features this build does not implement")]
    UnsupportedFeature,
}

/// The four immutable v1 record kinds and the mutable HEAD.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    Head,
    Commit,
    Version,
    CatalogPage,
}

impl RecordKind {
    /// The record's encoded size bound. Catalog pages are additionally
    /// constrained by their page kind's fanout.
    pub fn max_bytes(self) -> usize {
        match self {
            Self::Head => MAX_HEAD_BYTES,
            Self::Commit => MAX_COMMIT_BYTES,
            Self::Version => MAX_VERSION_BYTES,
            Self::CatalogPage => MAX_PAGE_BYTES,
        }
    }
}

impl fmt::Display for RecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Head => "HEAD",
            Self::Commit => "commit",
            Self::Version => "version",
            Self::CatalogPage => "catalog page",
        })
    }
}

/// Head record: the single authoritative mutable object of a managed prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeadV1 {
    pub format: String,
    pub schema_version: u32,
    pub workspace_id: WorkspaceId,
    pub root_item_id: ItemId,
    pub commit_id: CommitId,
    pub generation: GenerationId,
    /// Empty for v1. A nonempty list names features this build must implement.
    pub required_features: Vec<String>,
}

/// One namespace change recorded by a commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemChange {
    pub item_id: ItemId,
    pub change: ChangeKind,
    pub old_revision: Option<OperationId>,
    pub new_revision: OperationId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeKind {
    /// The item record was created (old revision `None`).
    Create,
    Content,
    Location,
    Deletion,
    /// A tombstone became live again.
    Undelete,
}

/// Commit record: one durable publication step; parents are never rewritten.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitV1 {
    pub format: String,
    pub schema_version: u32,
    pub workspace_id: WorkspaceId,
    pub commit_id: CommitId,
    /// `None` only for the initial commit.
    pub parent_commit_id: Option<CommitId>,
    pub catalog_root: Sha256Digest,
    /// Operation UUIDs included in this publication, strictly ascending.
    pub operation_ids: Vec<OperationId>,
    /// One entry per changed item, strictly ascending by item ID.
    pub changes: Vec<ItemChange>,
    pub device_id: DeviceId,
    /// Display only. Devices and operations are never ordered by timestamps.
    pub created_at: String,
}

/// Version record: one immutable payload binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionV1 {
    pub format: String,
    pub schema_version: u32,
    pub workspace_id: WorkspaceId,
    pub version_id: VersionId,
    pub object_key: PayloadKey,
    pub size: u64,
    pub sha256: Sha256Digest,
    /// Optional opaque Xet file identifier: required for managed file payloads
    /// (the native capability gate), `None` for directory versions.
    pub xet_file_id: Option<XetFileId>,
    pub display: DisplayMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayMetadata {
    /// Original client spelling, including case and Unicode form.
    pub name: String,
    /// Display-only modification time, RFC 3339 UTC with whole seconds.
    pub modified_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemKind {
    File,
    Directory,
}

/// One catalog item entry. Directory records keep `content_version_id: null`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemRecord {
    pub item_id: ItemId,
    /// `None` only for the root directory.
    pub parent_id: Option<ItemId>,
    /// Original spelling; empty only for the root directory.
    pub name: String,
    pub kind: ItemKind,
    /// The operation UUID that produced this record revision.
    pub item_revision: OperationId,
    pub content_version_id: Option<VersionId>,
    pub deleted: bool,
    /// The operation responsible for the current content revision.
    pub content_operation: OperationId,
    /// The operation responsible for the current location/name.
    pub location_operation: OperationId,
    /// Present exactly when `deleted` is true.
    pub deletion_operation: Option<OperationId>,
}

/// A leaf catalog page. Entries are strictly sorted by key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogLeaf {
    pub format: String,
    pub schema_version: u32,
    pub kind: LeafKind,
    pub entries: Vec<LeafEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeafKind {
    Leaf,
}

/// One catalog leaf entry. The value shape is fixed by the key's index kind:
/// `i/` entries carry the full item record, `c/` and `n/` entries carry the
/// owning item reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexValue {
    Item(ItemRecord),
    Ref { item_id: ItemId },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeafEntry {
    pub key: String,
    pub value: IndexValue,
}

/// A branch catalog page. Child ranges are contiguous and ordered: child `i`
/// covers `[children[i].first_key, children[i+1].first_key)`, and the last
/// child covers everything at or above its `first_key`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogBranch {
    pub format: String,
    pub schema_version: u32,
    pub kind: BranchKind,
    pub children: Vec<BranchChild>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchKind {
    Branch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchChild {
    /// Inclusive minimum key of the child's subtree; also the parent's stored
    /// separator key in the tree.
    pub first_key: String,
    pub page_id: Sha256Digest,
}

/// One encoded catalog page, leaf or branch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogPage {
    Leaf(CatalogLeaf),
    Branch(CatalogBranch),
}

impl CatalogPage {
    pub fn leaf(entries: Vec<LeafEntry>) -> Self {
        Self::Leaf(CatalogLeaf {
            format: FORMAT_NAME.to_owned(),
            schema_version: SCHEMA_VERSION,
            kind: LeafKind::Leaf,
            entries,
        })
    }
    pub fn branch(children: Vec<BranchChild>) -> Self {
        Self::Branch(CatalogBranch {
            format: FORMAT_NAME.to_owned(),
            schema_version: SCHEMA_VERSION,
            kind: BranchKind::Branch,
            children,
        })
    }
    pub fn is_leaf(&self) -> bool {
        matches!(self, Self::Leaf(_))
    }
    /// The number of entries (leaf) or children (branch).
    pub fn len(&self) -> usize {
        match self {
            Self::Leaf(leaf) => leaf.entries.len(),
            Self::Branch(branch) => branch.children.len(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Non-destructive retention diagnostics. The type has no deletion method;
/// remote garbage collection is not part of v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionSnapshot {
    pub epoch: u64,
    pub retained_commits: u64,
    pub pending_upload_reservations: u64,
}

impl Default for RetentionSnapshot {
    fn default() -> Self {
        Self { epoch: 0, retained_commits: 0, pending_upload_reservations: 0 }
    }
}

/// Checks the record carries the `hfdrive` format identifier and a readable
/// schema version.
pub fn check_format_identity(format: &str, schema_version: u32) -> Result<(), FormatError> {
    if format != FORMAT_NAME {
        return Err(FormatError::NotHFDriveFormat);
    }
    match schema_version {
        SCHEMA_VERSION => Ok(()),
        0 => Err(FormatError::InvalidShape),
        _ => Err(FormatError::NewerSchema),
    }
}

fn check_required_features(features: &[String]) -> Result<(), FormatError> {
    if features.is_empty() {
        Ok(())
    } else {
        Err(FormatError::UnsupportedFeature)
    }
}

/// RFC 3339 UTC, whole seconds, exactly `YYYY-MM-DDTHH:MM:SSZ`.
pub fn is_canonical_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return false;
    }
    let digit = |i: usize| bytes[i].is_ascii_digit();
    if !(0..20).all(|i| matches!(i, 4 | 7 | 10 | 13 | 16 | 19) || digit(i)) {
        return false;
    }
    let field = |range: std::ops::Range<usize>| value[range].parse::<u32>().unwrap_or(u32::MAX);
    let (year, month, day) = (field(0..4), field(5..7), field(8..10));
    let (hour, minute, second) = (field(11..13), field(14..16), field(17..19));
    if !(1..=12).contains(&month) || day < 1 || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    day <= max_day
}

fn is_canonical_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('\0')
}

fn is_canonical_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 1024
        && !key.chars().any(|c| c.is_control() || matches!(c, '\\' | ':' | '?' | '#' | '%'))
        && key.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

// ---------------------------------------------------------------------------
// Canonical JSON value and byte codec
// ---------------------------------------------------------------------------

/// A decoded JSON value. Canonical bytes have exactly one spelling per value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    U64(u64),
    Str(String),
    Array(Vec<Value>),
    /// Members must be unique; canonical encoding sorts them by UTF-8 key bytes.
    Object(Vec<(String, Value)>),
}

fn push_escaped(out: &mut Vec<u8>, value: &str) {
    out.push(b'"');
    for byte in value.bytes() {
        let escape = match byte {
            b'"' => Some(b'"'),
            b'\\' => Some(b'\\'),
            0x08 => Some(b'b'),
            0x09 => Some(b't'),
            0x0a => Some(b'n'),
            0x0c => Some(b'f'),
            0x0d => Some(b'r'),
            0x00..=0x1f => Some(0),
            0x7f => Some(0),
            _ => None,
        };
        match escape {
            None => out.push(byte),
            Some(0) => {
                out.extend_from_slice(b"\\u00");
                out.push(b"0123456789abcdef"[(byte >> 4) as usize]);
                out.push(b"0123456789abcdef"[(byte & 0x0f) as usize]);
            }
            Some(short) => {
                out.push(b'\\');
                out.push(short);
            }
        }
    }
    out.push(b'"');
}

/// Encodes one canonical JSON object: members sorted by UTF-8 key bytes,
/// compact separators, minimal escapes, nonnegative integer numbers.
pub fn encode_object(members: &[(String, Value)]) -> Result<Vec<u8>, FormatError> {
    let mut out = Vec::new();
    encode_value_into(&mut out, &Value::Object(members.to_vec()), 0)?;
    Ok(out)
}

fn encode_value_into(out: &mut Vec<u8>, value: &Value, depth: usize) -> Result<(), FormatError> {
    if depth > MAX_DECODER_DEPTH {
        return Err(FormatError::TooDeep);
    }
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::U64(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::Str(text) => push_escaped(out, text),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode_value_into(out, item, depth + 1)?;
            }
            out.push(b']');
        }
        Value::Object(members) => {
            let mut sorted: Vec<&(String, Value)> = members.iter().collect();
            sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            for i in 1..sorted.len() {
                if sorted[i - 1].0 == sorted[i].0 {
                    return Err(FormatError::MemberError);
                }
            }
            out.push(b'{');
            for (i, (key, member)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                push_escaped(out, key);
                out.push(b':');
                encode_value_into(out, member, depth + 1)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// Parses a canonical JSON value. The input must be exactly one value: no
/// leading/trailing bytes, no insignificant whitespace, no duplicate or
/// unordered members, no floats, no non-canonical number or escape spellings
/// (`\/` and non-minimal `\u00xx` are rejected), and nesting depth at most
/// [`MAX_DECODER_DEPTH`].
pub fn decode_value(bytes: &[u8]) -> Result<Value, FormatError> {
    if bytes.len() > MAX_COMMIT_BYTES {
        return Err(FormatError::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| FormatError::NonCanonical)?;
    let mut parser = Parser { bytes: text.as_bytes(), at: 0 };
    let value = parser.parse_value(0)?;
    parser.reject_whitespace()?;
    if parser.at != parser.bytes.len() {
        return Err(FormatError::NonCanonical);
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }
    /// Canonical HF Drive JSON has no insignificant whitespace anywhere.
    fn reject_whitespace(&mut self) -> Result<(), FormatError> {
        if matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            Err(FormatError::NonCanonical)
        } else {
            Ok(())
        }
    }
    fn parse_value(&mut self, depth: usize) -> Result<Value, FormatError> {
        if depth > MAX_DECODER_DEPTH {
            return Err(FormatError::TooDeep);
        }
        match self.peek() {
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => Ok(Value::Str(self.parse_string()?)),
            Some(b't') => self.parse_literal(b"true", Value::Bool(true)),
            Some(b'f') => self.parse_literal(b"false", Value::Bool(false)),
            Some(b'n') => self.parse_literal(b"null", Value::Null),
            Some(_) => self.parse_number(),
            None => Err(FormatError::NonCanonical),
        }
    }
    fn parse_literal(&mut self, word: &[u8], value: Value) -> Result<Value, FormatError> {
        if self.bytes[self.at..].starts_with(word) {
            self.at += word.len();
            Ok(value)
        } else {
            Err(FormatError::NonCanonical)
        }
    }
    fn parse_number(&mut self) -> Result<Value, FormatError> {
        let start = self.at;
        if self.peek() == Some(b'0') {
            self.at += 1;
            // A canonical nonnegative integer has no leading zero or fraction.
            if matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(FormatError::NonCanonical);
            }
        } else {
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.at += 1;
            }
            if self.at == start {
                return Err(FormatError::NonCanonical);
            }
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E' | b'-' | b'+')) {
            return Err(FormatError::NonCanonical);
        }
        let text =
            std::str::from_utf8(&self.bytes[start..self.at]).map_err(|_| FormatError::NonCanonical)?;
        let n = text.parse::<u64>().map_err(|_| FormatError::InvalidShape)?;
        Ok(Value::U64(n))
    }
    fn parse_string(&mut self) -> Result<String, FormatError> {
        if self.peek() != Some(b'"') {
            return Err(FormatError::NonCanonical);
        }
        self.at += 1;
        let mut out = Vec::new();
        loop {
            let byte = self.peek().ok_or(FormatError::NonCanonical)?;
            self.at += 1;
            match byte {
                b'"' => break,
                b'\\' => {
                    let escape = self.peek().ok_or(FormatError::NonCanonical)?;
                    self.at += 1;
                    match escape {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'b' => out.push(0x08),
                        b't' => out.push(0x09),
                        b'n' => out.push(0x0a),
                        b'f' => out.push(0x0c),
                        b'r' => out.push(0x0d),
                        b'u' => {
                            let code = self.parse_hex4()?;
                            // Canonical \u escapes cover exactly the C0 controls
                            // without a one-character escape (U+0000..=U+0007,
                            // U+000B, U+000E..=U+001F) and DEL (U+007F), spelled
                            // \u00xx with lowercase hex. Everything else,
                            // including surrogates and characters with short
                            // escapes, is written as exact UTF-8.
                            let canonical_control = code <= 0x1f
                                && !matches!(code, 0x08 | 0x09 | 0x0a | 0x0c | 0x0d)
                                || code == 0x7f;
                            if !canonical_control {
                                return Err(FormatError::NonCanonical);
                            }
                            let ch = char::from_u32(code).ok_or(FormatError::InvalidShape)?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(FormatError::NonCanonical),
                    }
                }
                0x00..=0x1f | 0x7f => return Err(FormatError::NonCanonical),
                _ => out.push(byte),
            }
        }
        String::from_utf8(out).map_err(|_| FormatError::InvalidShape)
    }
    fn parse_hex4(&mut self) -> Result<u32, FormatError> {
        if self.at + 4 > self.bytes.len() {
            return Err(FormatError::NonCanonical);
        }
        let mut code = 0u32;
        for i in 0..4 {
            let byte = self.bytes[self.at + i];
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a') + 10,
                _ => return Err(FormatError::NonCanonical),
            };
            code = code * 16 + digit;
        }
        self.at += 4;
        Ok(code)
    }
    fn parse_array(&mut self, depth: usize) -> Result<Value, FormatError> {
        self.at += 1;
        let mut items = Vec::new();
        self.reject_whitespace()?;
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.reject_whitespace()?;
            items.push(self.parse_value(depth + 1)?);
            self.reject_whitespace()?;
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(FormatError::NonCanonical),
            }
        }
    }
    fn parse_object(&mut self, depth: usize) -> Result<Value, FormatError> {
        self.at += 1;
        let mut members: Vec<(String, Value)> = Vec::new();
        self.reject_whitespace()?;
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.reject_whitespace()?;
            let key = self.parse_string()?;
            // Canonical members are strictly ascending by UTF-8 key bytes.
            if members.last().is_some_and(|(last, _)| *last >= key) {
                return Err(FormatError::MemberError);
            }
            self.reject_whitespace()?;
            if self.peek() != Some(b':') {
                return Err(FormatError::NonCanonical);
            }
            self.at += 1;
            self.reject_whitespace()?;
            let value = self.parse_value(depth + 1)?;
            members.push((key, value));
            self.reject_whitespace()?;
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(members));
                }
                _ => return Err(FormatError::NonCanonical),
            }
        }
    }
}

fn as_object(value: Value) -> Result<Vec<(String, Value)>, FormatError> {
    match value {
        Value::Object(members) => Ok(members),
        _ => Err(FormatError::NotAnObject),
    }
}

struct Members {
    members: Vec<(String, Value)>,
}

impl Members {
    fn take(&mut self, name: &str) -> Result<Value, FormatError> {
        let at = self
            .members
            .iter()
            .position(|(key, _)| key == name)
            .ok_or(FormatError::MemberError)?;
        Ok(self.members.remove(at).1)
    }
    fn finish(self) -> Result<(), FormatError> {
        if self.members.is_empty() {
            Ok(())
        } else {
            Err(FormatError::MemberError)
        }
    }
}

fn as_str(value: Value) -> Result<String, FormatError> {
    match value {
        Value::Str(text) => Ok(text),
        _ => Err(FormatError::InvalidShape),
    }
}

fn as_u64(value: Value) -> Result<u64, FormatError> {
    match value {
        Value::U64(n) => Ok(n),
        _ => Err(FormatError::InvalidShape),
    }
}

fn as_u32(value: Value) -> Result<u32, FormatError> {
    u32::try_from(as_u64(value)?).map_err(|_| FormatError::InvalidShape)
}

fn as_bool(value: Value) -> Result<bool, FormatError> {
    match value {
        Value::Bool(b) => Ok(b),
        _ => Err(FormatError::InvalidShape),
    }
}

/// The value stored under a live-child index key (index `c`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildEntry {
    pub item_id: ItemId,
}

/// The value stored under a uniqueness index key (index `n`): the item that
/// currently owns the parent's portable name slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameEntry {
    pub item_id: ItemId,
}

fn single_item_from_members(mut members: Members) -> Result<ItemId, FormatError> {
    let item_id = id_from_value(members.take("item_id")?)?;
    members.finish()?;
    Ok(item_id)
}

fn single_item_members(item_id: ItemId) -> Vec<(String, Value)> {
    vec![("item_id".to_owned(), id_into_value(&item_id))]
}

/// Serializes a live-child index value to canonical bytes.
pub fn to_child_entry_bytes(item_id: ItemId) -> Result<Vec<u8>, FormatError> {
    encode_object(&single_item_members(item_id))
}

/// Parses a live-child index value from canonical bytes.
pub fn from_child_entry_bytes(bytes: &[u8]) -> Result<ChildEntry, FormatError> {
    Ok(ChildEntry {
        item_id: single_item_from_members(Members { members: as_object(decode_value(bytes)?)? })?,
    })
}

/// Serializes a uniqueness index value to canonical bytes.
pub fn to_name_entry_bytes(item_id: ItemId) -> Result<Vec<u8>, FormatError> {
    encode_object(&single_item_members(item_id))
}

/// Parses a uniqueness index value from canonical bytes.
pub fn from_name_entry_bytes(bytes: &[u8]) -> Result<NameEntry, FormatError> {
    Ok(NameEntry {
        item_id: single_item_from_members(Members { members: as_object(decode_value(bytes)?)? })?,
    })
}

/// Serializes an item record to canonical bytes (the `i/` index value).
pub fn to_item_record_bytes(item: &ItemRecord) -> Result<Vec<u8>, FormatError> {
    validate_item_record(item)?;
    encode_object(&item_record_members(item))
}

/// Parses an item record from canonical bytes.
pub fn from_item_record_bytes(bytes: &[u8]) -> Result<ItemRecord, FormatError> {
    item_record_from_members(Members { members: as_object(decode_value(bytes)?)? })
}

fn as_array(value: Value) -> Result<Vec<Value>, FormatError> {
    match value {
        Value::Array(items) => Ok(items),
        _ => Err(FormatError::InvalidShape),
    }
}

fn id_from_value<T>(value: Value) -> Result<T, FormatError>
where
    T: std::str::FromStr,
{
    let text = as_str(value)?;
    text.parse().map_err(|_| FormatError::InvalidId)
}

fn id_into_value<T: fmt::Display>(id: &T) -> Value {
    Value::Str(id.to_string())
}

fn digest_from_value(value: Value) -> Result<Sha256Digest, FormatError> {
    let text = as_str(value)?;
    text.parse().map_err(|_| FormatError::InvalidDigest)
}

// ---------------------------------------------------------------------------
// Record codecs
// ---------------------------------------------------------------------------

/// Builds the canonical member list of a HEAD record.
fn head_members(head: &HeadV1) -> Vec<(String, Value)> {
    vec![
        ("commit_id".to_owned(), id_into_value(&head.commit_id)),
        ("format".to_owned(), Value::Str(head.format.clone())),
        ("generation".to_owned(), id_into_value(&head.generation)),
        (
            "required_features".to_owned(),
            Value::Array(head.required_features.iter().cloned().map(Value::Str).collect()),
        ),
        ("root_item_id".to_owned(), id_into_value(&head.root_item_id)),
        ("schema_version".to_owned(), Value::U64(u64::from(head.schema_version))),
        ("workspace_id".to_owned(), id_into_value(&head.workspace_id)),
    ]
}

/// Builds and validates a HEAD record from its canonical members.
fn head_from_members(mut members: Members) -> Result<HeadV1, FormatError> {
    let head = HeadV1 {
        format: as_str(members.take("format")?)?,
        schema_version: as_u32(members.take("schema_version")?)?,
        workspace_id: id_from_value(members.take("workspace_id")?)?,
        root_item_id: id_from_value(members.take("root_item_id")?)?,
        commit_id: id_from_value(members.take("commit_id")?)?,
        generation: id_from_value(members.take("generation")?)?,
        required_features: as_array(members.take("required_features")?)?
            .into_iter()
            .map(as_str)
            .collect::<Result<Vec<_>, _>>()?,
    };
    members.finish()?;
    validate_head(&head)?;
    Ok(head)
}

/// Serializes a HEAD record to canonical bytes.
pub fn to_head_bytes(head: &HeadV1) -> Result<Vec<u8>, FormatError> {
    validate_head(head)?;
    let bytes = encode_object(&head_members(head))?;
    if bytes.len() > MAX_HEAD_BYTES {
        return Err(FormatError::TooLarge);
    }
    Ok(bytes)
}

/// Parses and validates a HEAD record from canonical bytes.
pub fn from_head_bytes(bytes: &[u8]) -> Result<HeadV1, FormatError> {
    if bytes.len() > MAX_HEAD_BYTES {
        return Err(FormatError::TooLarge);
    }
    head_from_members(Members { members: as_object(decode_value(bytes)?)? })
}

/// Validates a HEAD record's format identity and feature list.
pub fn validate_head(head: &HeadV1) -> Result<(), FormatError> {
    check_format_identity(&head.format, head.schema_version)?;
    check_required_features(&head.required_features)
}

fn item_change_members(change: &ItemChange) -> Value {
    let change_kind = match change.change {
        ChangeKind::Create => "create",
        ChangeKind::Content => "content",
        ChangeKind::Location => "location",
        ChangeKind::Deletion => "deletion",
        ChangeKind::Undelete => "undelete",
    };
    let mut members = vec![
        ("change".to_owned(), Value::Str(change_kind.to_owned())),
        ("item_id".to_owned(), id_into_value(&change.item_id)),
        ("new_revision".to_owned(), id_into_value(&change.new_revision)),
        (
            "old_revision".to_owned(),
            match &change.old_revision {
                Some(old) => id_into_value(old),
                None => Value::Null,
            },
        ),
    ];
    members.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    Value::Object(members)
}

/// Builds the canonical member list of a commit record.
fn commit_members(commit: &CommitV1) -> Vec<(String, Value)> {
    let changes: Vec<Value> = commit.changes.iter().map(item_change_members).collect();
    vec![
        ("catalog_root".to_owned(), Value::Str(commit.catalog_root.to_string())),
        ("changes".to_owned(), Value::Array(changes)),
        ("commit_id".to_owned(), id_into_value(&commit.commit_id)),
        ("created_at".to_owned(), Value::Str(commit.created_at.clone())),
        ("device_id".to_owned(), id_into_value(&commit.device_id)),
        ("format".to_owned(), Value::Str(commit.format.clone())),
        (
            "operation_ids".to_owned(),
            Value::Array(commit.operation_ids.iter().map(|id| id_into_value(id)).collect()),
        ),
        (
            "parent_commit_id".to_owned(),
            match &commit.parent_commit_id {
                Some(parent) => id_into_value(parent),
                None => Value::Null,
            },
        ),
        ("schema_version".to_owned(), Value::U64(u64::from(commit.schema_version))),
        ("workspace_id".to_owned(), id_into_value(&commit.workspace_id)),
    ]
}

/// Builds and validates a commit record from its canonical members.
fn commit_from_members(mut members: Members) -> Result<CommitV1, FormatError> {
    let mut commit = CommitV1 {
        format: as_str(members.take("format")?)?,
        schema_version: as_u32(members.take("schema_version")?)?,
        workspace_id: id_from_value(members.take("workspace_id")?)?,
        commit_id: id_from_value(members.take("commit_id")?)?,
        parent_commit_id: match members.take("parent_commit_id")? {
            Value::Null => None,
            other => Some(id_from_value(other)?),
        },
        catalog_root: digest_from_value(members.take("catalog_root")?)?,
        operation_ids: as_array(members.take("operation_ids")?)?
            .into_iter()
            .map(id_from_value)
            .collect::<Result<Vec<_>, _>>()?,
        changes: Vec::new(),
        device_id: id_from_value(members.take("device_id")?)?,
        created_at: as_str(members.take("created_at")?)?,
    };
    // `changes` decode in strictly ascending item-ID order (canonical form).
    for value in as_array(members.take("changes")?)? {
        let mut change_members = Members { members: as_object(value)? };
        let change = ItemChange {
            item_id: id_from_value(change_members.take("item_id")?)?,
            change: match as_str(change_members.take("change")?)?.as_str() {
                "create" => ChangeKind::Create,
                "content" => ChangeKind::Content,
                "location" => ChangeKind::Location,
                "deletion" => ChangeKind::Deletion,
                "undelete" => ChangeKind::Undelete,
                _ => return Err(FormatError::InvalidShape),
            },
            old_revision: match change_members.take("old_revision")? {
                Value::Null => None,
                other => Some(id_from_value(other)?),
            },
            new_revision: id_from_value(change_members.take("new_revision")?)?,
        };
        change_members.finish()?;
        commit.changes.push(change);
    }
    members.finish()?;
    validate_commit(&commit)?;
    Ok(commit)
}

/// Serializes a commit record to canonical bytes.
pub fn to_commit_bytes(commit: &CommitV1) -> Result<Vec<u8>, FormatError> {
    validate_commit(commit)?;
    let bytes = encode_object(&commit_members(commit))?;
    if bytes.len() > MAX_COMMIT_BYTES {
        return Err(FormatError::TooLarge);
    }
    Ok(bytes)
}

/// Parses and validates a commit record from canonical bytes.
pub fn from_commit_bytes(bytes: &[u8]) -> Result<CommitV1, FormatError> {
    if bytes.len() > MAX_COMMIT_BYTES {
        return Err(FormatError::TooLarge);
    }
    commit_from_members(Members { members: as_object(decode_value(bytes)?)? })
}

/// Validates commit-level invariants: bound sizes, canonical timestamp,
/// strictly ascending unique operations and changes, and no no-op revisions.
pub fn validate_commit(commit: &CommitV1) -> Result<(), FormatError> {
    check_format_identity(&commit.format, commit.schema_version)?;
    if commit.operation_ids.len() > MAX_COMMIT_OPERATIONS
        || commit.changes.len() > MAX_COMMIT_OPERATIONS
    {
        return Err(FormatError::TooLarge);
    }
    if !is_canonical_timestamp(&commit.created_at) {
        return Err(FormatError::InvalidShape);
    }
    if commit.operation_ids.windows(2).any(|w| w[0] >= w[1]) {
        return Err(FormatError::InvalidShape);
    }
    if commit.changes.windows(2).any(|w| w[0].item_id >= w[1].item_id) {
        return Err(FormatError::InvalidShape);
    }
    for change in &commit.changes {
        match (change.change, change.old_revision) {
            // A creation has no old revision; every other transition has one,
            // and no transition keeps the same item revision.
            (ChangeKind::Create, None) => {}
            (ChangeKind::Create, Some(_)) => return Err(FormatError::InvalidShape),
            (_, None) => return Err(FormatError::InvalidShape),
            (_, Some(old)) if old == change.new_revision => return Err(FormatError::InvalidShape),
            (_, Some(_)) => {}
        }
    }
    Ok(())
}

/// Builds the canonical member list of a version record.
fn version_members(version: &VersionV1) -> Vec<(String, Value)> {
    vec![
        (
            "display".to_owned(),
            Value::Object(vec![
                ("modified_at".to_owned(), Value::Str(version.display.modified_at.clone())),
                ("name".to_owned(), Value::Str(version.display.name.clone())),
            ]),
        ),
        ("format".to_owned(), Value::Str(version.format.clone())),
        ("object_key".to_owned(), Value::Str(version.object_key.to_string())),
        ("schema_version".to_owned(), Value::U64(u64::from(version.schema_version))),
        ("sha256".to_owned(), Value::Str(version.sha256.to_string())),
        ("size".to_owned(), Value::U64(version.size)),
        ("version_id".to_owned(), id_into_value(&version.version_id)),
        ("workspace_id".to_owned(), id_into_value(&version.workspace_id)),
        (
            "xet_file_id".to_owned(),
            match &version.xet_file_id {
                Some(xet) => Value::Str(xet.to_string()),
                None => Value::Null,
            },
        ),
    ]
}

/// Builds and validates a version record from its canonical members.
fn version_from_members(mut members: Members) -> Result<VersionV1, FormatError> {
    let mut display_members = Members { members: as_object(members.take("display")?)? };
    let display = DisplayMetadata {
        name: as_str(display_members.take("name")?)?,
        modified_at: as_str(display_members.take("modified_at")?)?,
    };
    display_members.finish()?;
    let version = VersionV1 {
        format: as_str(members.take("format")?)?,
        schema_version: as_u32(members.take("schema_version")?)?,
        workspace_id: id_from_value(members.take("workspace_id")?)?,
        version_id: id_from_value(members.take("version_id")?)?,
        object_key: as_str(members.take("object_key")?)?
            .parse()
            .map_err(|_| FormatError::InvalidShape)?,
        size: as_u64(members.take("size")?)?,
        sha256: digest_from_value(members.take("sha256")?)?,
        xet_file_id: match members.take("xet_file_id")? {
            Value::Null => None,
            Value::Str(text) => Some(text.parse().map_err(|_| FormatError::InvalidDigest)?),
            _ => return Err(FormatError::InvalidShape),
        },
        display,
    };
    members.finish()?;
    validate_version(&version)?;
    Ok(version)
}

/// Serializes a version record to canonical bytes.
pub fn to_version_bytes(version: &VersionV1) -> Result<Vec<u8>, FormatError> {
    validate_version(version)?;
    let bytes = encode_object(&version_members(version))?;
    if bytes.len() > MAX_VERSION_BYTES {
        return Err(FormatError::TooLarge);
    }
    Ok(bytes)
}

/// Parses and validates a version record from canonical bytes.
pub fn from_version_bytes(bytes: &[u8]) -> Result<VersionV1, FormatError> {
    if bytes.len() > MAX_VERSION_BYTES {
        return Err(FormatError::TooLarge);
    }
    version_from_members(Members { members: as_object(decode_value(bytes)?)? })
}

/// Validates a version record: format identity, display shape, and the
/// managed-payload rule that files carry a Xet identifier.
pub fn validate_version(version: &VersionV1) -> Result<(), FormatError> {
    check_format_identity(&version.format, version.schema_version)?;
    if !is_canonical_name(&version.display.name) {
        return Err(FormatError::InvalidShape);
    }
    if !is_canonical_timestamp(&version.display.modified_at) {
        return Err(FormatError::InvalidShape);
    }
    Ok(())
}

fn item_record_members(item: &ItemRecord) -> Vec<(String, Value)> {
    let mut members = vec![
        ("content_operation".to_owned(), id_into_value(&item.content_operation)),
        (
            "content_version_id".to_owned(),
            match &item.content_version_id {
                Some(id) => id_into_value(id),
                None => Value::Null,
            },
        ),
        (
            "deletion_operation".to_owned(),
            match &item.deletion_operation {
                Some(id) => id_into_value(id),
                None => Value::Null,
            },
        ),
        ("deleted".to_owned(), Value::Bool(item.deleted)),
        ("item_id".to_owned(), id_into_value(&item.item_id)),
        ("item_revision".to_owned(), id_into_value(&item.item_revision)),
        (
            "kind".to_owned(),
            Value::Str(
                match item.kind {
                    ItemKind::File => "file",
                    ItemKind::Directory => "directory",
                }
                .to_owned(),
            ),
        ),
        ("location_operation".to_owned(), id_into_value(&item.location_operation)),
        ("name".to_owned(), Value::Str(item.name.clone())),
        (
            "parent_id".to_owned(),
            match &item.parent_id {
                Some(id) => id_into_value(id),
                None => Value::Null,
            },
        ),
    ];
    members.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    members
}

fn item_record_from_members(mut members: Members) -> Result<ItemRecord, FormatError> {
    let item = ItemRecord {
        item_id: id_from_value(members.take("item_id")?)?,
        parent_id: match members.take("parent_id")? {
            Value::Null => None,
            other => Some(id_from_value(other)?),
        },
        name: as_str(members.take("name")?)?,
        kind: match as_str(members.take("kind")?)?.as_str() {
            "file" => ItemKind::File,
            "directory" => ItemKind::Directory,
            _ => return Err(FormatError::InvalidShape),
        },
        item_revision: id_from_value(members.take("item_revision")?)?,
        content_version_id: match members.take("content_version_id")? {
            Value::Null => None,
            other => Some(id_from_value(other)?),
        },
        deleted: as_bool(members.take("deleted")?)?,
        content_operation: id_from_value(members.take("content_operation")?)?,
        location_operation: id_from_value(members.take("location_operation")?)?,
        deletion_operation: match members.take("deletion_operation")? {
            Value::Null => None,
            other => Some(id_from_value(other)?),
        },
    };
    members.finish()?;
    validate_item_record(&item)?;
    Ok(item)
}

/// Validates one item record's shape invariants: root/file/directory shapes,
/// the deleted/deletion-operation pairing, and nonempty non-NUL names.
pub fn validate_item_record(item: &ItemRecord) -> Result<(), FormatError> {
    if item.parent_id.is_none() {
        // Only the live root directory has no parent and no name.
        if item.kind != ItemKind::Directory
            || item.content_version_id.is_some()
            || !item.name.is_empty()
            || item.deleted
        {
            return Err(FormatError::InvalidShape);
        }
    } else if !is_canonical_name(&item.name) {
        return Err(FormatError::InvalidShape);
    }
    match item.kind {
        ItemKind::Directory => {
            if item.content_version_id.is_some() {
                return Err(FormatError::InvalidShape);
            }
        }
        ItemKind::File => {
            if item.content_version_id.is_none() {
                return Err(FormatError::InvalidShape);
            }
        }
    }
    if item.deleted != item.deletion_operation.is_some() {
        return Err(FormatError::InvalidShape);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Catalog index keys: i/<item-id>, c/<parent>/<name-hex>/<item>, n/<parent>/<collision-hex>
// ---------------------------------------------------------------------------

/// The catalog key of the item record entry for `item_id` (index `i`).
pub fn item_key(item_id: ItemId) -> String {
    format!("i/{item_id}")
}

/// The catalog key of the live-child index entry (index `c`). The name segment
/// is the exact UTF-8 name spelling in lowercase hex.
pub fn child_key(parent_id: ItemId, name: &str, item_id: ItemId) -> String {
    format!("c/{parent_id}/{}/{item_id}", hex::encode(name.as_bytes()))
}

/// The catalog key of the uniqueness index entry (index `n`). The collision
/// key segment is the lowercase hex of the NFC-then-full-casefold name bytes.
pub fn name_key(parent_id: ItemId, collision_key: &[u8]) -> String {
    format!("n/{parent_id}/{}", hex::encode(collision_key))
}

/// The key prefix shared by the live-child entries of `parent_id`.
pub fn child_key_prefix(parent_id: ItemId) -> String {
    format!("c/{parent_id}/")
}

/// The key prefix shared by the uniqueness entries of `parent_id`.
pub fn name_key_prefix(parent_id: ItemId) -> String {
    format!("n/{parent_id}/")
}

/// Parses a canonical catalog key into its typed parts. The caller remains
/// responsible for matching index kinds and identities to the connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexKey {
    Item { item_id: ItemId },
    Child { parent_id: ItemId, name: String, item_id: ItemId },
    Name { parent_id: ItemId, collision_key: Vec<u8> },
}

impl IndexKey {
    /// The key's `i`/`c`/`n` kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Item { .. } => "i",
            Self::Child { .. } => "c",
            Self::Name { .. } => "n",
        }
    }
}

/// Parses a canonical catalog key, rejecting alternate key spellings.
pub fn parse_index_key(key: &str) -> Result<IndexKey, FormatError> {
    if !is_canonical_key(key) {
        return Err(FormatError::InvalidShape);
    }
    let mut segments = key.split('/');
    let kind = segments.next().ok_or(FormatError::InvalidShape)?;
    let uuid = |segment: &str| -> Result<ItemId, FormatError> {
        if segment.len() != 36 {
            return Err(FormatError::InvalidId);
        }
        segment.parse().map_err(|_| FormatError::InvalidId)
    };
    match kind {
        "i" => {
            let item_id = uuid(segments.next().ok_or(FormatError::InvalidShape)?)?;
            if segments.next().is_some() {
                return Err(FormatError::InvalidShape);
            }
            Ok(IndexKey::Item { item_id })
        }
        "c" => {
            let parent_id = uuid(segments.next().ok_or(FormatError::InvalidShape)?)?;
            let name_bytes = decode_hex_segment(segments.next().ok_or(FormatError::InvalidShape)?)?;
            let name = String::from_utf8(name_bytes).map_err(|_| FormatError::InvalidShape)?;
            if name.is_empty() || name.contains('\0') {
                return Err(FormatError::InvalidShape);
            }
            let item_id = uuid(segments.next().ok_or(FormatError::InvalidShape)?)?;
            if segments.next().is_some() {
                return Err(FormatError::InvalidShape);
            }
            Ok(IndexKey::Child { parent_id, name, item_id })
        }
        "n" => {
            let parent_id = uuid(segments.next().ok_or(FormatError::InvalidShape)?)?;
            let collision_key = decode_hex_segment(segments.next().ok_or(FormatError::InvalidShape)?)?;
            if collision_key.is_empty() {
                return Err(FormatError::InvalidShape);
            }
            if segments.next().is_some() {
                return Err(FormatError::InvalidShape);
            }
            Ok(IndexKey::Name { parent_id, collision_key })
        }
        _ => Err(FormatError::InvalidShape),
    }
}

fn decode_hex_segment(segment: &str) -> Result<Vec<u8>, FormatError> {
    if segment.is_empty()
        || segment.len() % 2 != 0
        || !segment.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(FormatError::InvalidShape);
    }
    let mut out = vec![0u8; segment.len() / 2];
    hex::decode_to_slice(segment, &mut out).map_err(|_| FormatError::InvalidShape)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Catalog page codecs
// ---------------------------------------------------------------------------

fn index_value_members(value: &IndexValue) -> Vec<(String, Value)> {
    match value {
        IndexValue::Item(item) => item_record_members(item),
        IndexValue::Ref { item_id } => single_item_members(*item_id),
    }
}

fn index_value_from_members(key: &str, members: Members) -> Result<IndexValue, FormatError> {
    match parse_index_key(key)? {
        IndexKey::Item { .. } => Ok(IndexValue::Item(item_record_from_members(members)?)),
        IndexKey::Child { item_id: expected, .. } => {
            let item_id = single_item_from_members(members)?;
            if item_id != expected {
                return Err(FormatError::InvalidShape);
            }
            Ok(IndexValue::Ref { item_id })
        }
        IndexKey::Name { .. } => {
            Ok(IndexValue::Ref { item_id: single_item_from_members(members)? })
        }
    }
}

/// Builds the canonical member list of a catalog page.
fn page_members(page: &CatalogPage) -> Vec<(String, Value)> {
    match page {
        CatalogPage::Leaf(leaf) => {
            let entries: Vec<Value> = leaf
                .entries
                .iter()
                .map(|entry| {
                    Value::Object(vec![
                        ("key".to_owned(), Value::Str(entry.key.clone())),
                        ("value".to_owned(), Value::Object(index_value_members(&entry.value))),
                    ])
                })
                .collect();
            vec![
                ("entries".to_owned(), Value::Array(entries)),
                ("format".to_owned(), Value::Str(leaf.format.clone())),
                ("kind".to_owned(), Value::Str("leaf".to_owned())),
                ("schema_version".to_owned(), Value::U64(u64::from(leaf.schema_version))),
            ]
        }
        CatalogPage::Branch(branch) => {
            let children: Vec<Value> = branch
                .children
                .iter()
                .map(|child| {
                    Value::Object(vec![
                        ("first_key".to_owned(), Value::Str(child.first_key.clone())),
                        ("page_id".to_owned(), Value::Str(child.page_id.to_string())),
                    ])
                })
                .collect();
            vec![
                ("children".to_owned(), Value::Array(children)),
                ("format".to_owned(), Value::Str(branch.format.clone())),
                ("kind".to_owned(), Value::Str("branch".to_owned())),
                ("schema_version".to_owned(), Value::U64(u64::from(branch.schema_version))),
            ]
        }
    }
}

/// Builds and validates a catalog page from its canonical members.
fn page_from_members(mut members: Members) -> Result<CatalogPage, FormatError> {
    let format = as_str(members.take("format")?)?;
    let schema_version = as_u32(members.take("schema_version")?)?;
    check_format_identity(&format, schema_version)?;
    let page = match as_str(members.take("kind")?)?.as_str() {
        "leaf" => {
            let mut entries = Vec::new();
            for value in as_array(members.take("entries")?)? {
                let mut entry_members = Members { members: as_object(value)? };
                let key = as_str(entry_members.take("key")?)?;
                if !is_canonical_key(&key) {
                    return Err(FormatError::InvalidShape);
                }
                let value = index_value_from_members(
                    &key,
                    Members { members: as_object(entry_members.take("value")?)? },
                )?;
                entry_members.finish()?;
                entries.push(LeafEntry { key, value });
            }
            CatalogPage::leaf(entries)
        }
        "branch" => {
            let mut children = Vec::new();
            for value in as_array(members.take("children")?)? {
                let mut child_members = Members { members: as_object(value)? };
                let first_key = as_str(child_members.take("first_key")?)?;
                if !is_canonical_key(&first_key) {
                    return Err(FormatError::InvalidShape);
                }
                let page_id = digest_from_value(child_members.take("page_id")?)?;
                child_members.finish()?;
                children.push(BranchChild { first_key, page_id });
            }
            CatalogPage::branch(children)
        }
        _ => return Err(FormatError::InvalidShape),
    };
    members.finish()?;
    validate_page(&page)?;
    Ok(page)
}

/// Serializes a catalog page to canonical bytes and validates its page bounds.
pub fn to_page_bytes(page: &CatalogPage) -> Result<Vec<u8>, FormatError> {
    validate_page(page)?;
    let bytes = encode_object(&page_members(page))?;
    if bytes.len() > MAX_PAGE_BYTES {
        return Err(FormatError::TooLarge);
    }
    Ok(bytes)
}

/// Parses and validates a catalog page from canonical bytes.
pub fn from_page_bytes(bytes: &[u8]) -> Result<CatalogPage, FormatError> {
    if bytes.len() > MAX_PAGE_BYTES {
        return Err(FormatError::TooLarge);
    }
    page_from_members(Members { members: as_object(decode_value(bytes)?)? })
}

/// Validates a page's format identity, fanout, key shapes, ordering and the
/// key/value shape agreement of every entry.
pub fn validate_page(page: &CatalogPage) -> Result<(), FormatError> {
    match page {
        CatalogPage::Leaf(leaf) => {
            check_format_identity(&leaf.format, leaf.schema_version)?;
            if leaf.entries.len() > MAX_PAGE_FANOUT {
                return Err(FormatError::TooLarge);
            }
            if leaf.entries.windows(2).any(|w| w[0].key >= w[1].key) {
                return Err(FormatError::InvalidShape);
            }
            for entry in &leaf.entries {
                if !is_canonical_key(&entry.key) {
                    return Err(FormatError::InvalidShape);
                }
                match (&parse_index_key(&entry.key)?, &entry.value) {
                    (IndexKey::Item { item_id }, IndexValue::Item(item)) => {
                        if *item_id != item.item_id {
                            return Err(FormatError::InvalidShape);
                        }
                        validate_item_record(item)?;
                    }
                    (IndexKey::Child { item_id, .. }, IndexValue::Ref { item_id: ref_id }) => {
                        if item_id != ref_id {
                            return Err(FormatError::InvalidShape);
                        }
                    }
                    (IndexKey::Name { .. }, IndexValue::Ref { .. }) => {}
                    _ => return Err(FormatError::InvalidShape),
                }
            }
        }
        CatalogPage::Branch(branch) => {
            check_format_identity(&branch.format, branch.schema_version)?;
            if branch.children.is_empty() {
                return Err(FormatError::InvalidShape);
            }
            if branch.children.len() > MAX_PAGE_FANOUT {
                return Err(FormatError::TooLarge);
            }
            if branch.children.windows(2).any(|w| w[0].first_key >= w[1].first_key) {
                return Err(FormatError::InvalidShape);
            }
            for child in &branch.children {
                if !is_canonical_key(&child.first_key) {
                    return Err(FormatError::InvalidShape);
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Serde interop
// ---------------------------------------------------------------------------
//
// The typed records implement `Serialize`/`Deserialize` through the canonical
// `Value` model, so `serde_json::to_vec(record)` produces exactly the canonical
// bytes of `to_*_bytes(record)` and `serde_json::from_slice` accepts the same
// record set. The `to_*_bytes`/`from_*_bytes` pair remains authoritative for
// remote bytes: it additionally enforces the strict escape/whitespace spelling
// that general-purpose JSON parsers accept.

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Value::Null => serializer.serialize_unit(),
            Value::Bool(b) => serializer.serialize_bool(*b),
            Value::U64(n) => serializer.serialize_u64(*n),
            Value::Str(text) => serializer.serialize_str(text),
            Value::Array(items) => serializer.collect_seq(items.iter()),
            Value::Object(members) => {
                let mut sorted: Vec<&(String, Value)> = members.iter().collect();
                sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
                let mut map = serializer.serialize_map(Some(sorted.len()))?;
                for (key, value) in sorted {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Value, D::Error> {
        struct ValueVisitor;
        impl<'de> serde::de::Visitor<'de> for ValueVisitor {
            type Value = Value;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("canonical HF Drive JSON")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
                Ok(Value::Bool(value))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
                Ok(Value::U64(value))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
                u64::try_from(value)
                    .map(Value::U64)
                    .map_err(|_| E::custom("negative numbers are not canonical HF Drive JSON"))
            }
            fn visit_f64<E: serde::de::Error>(self, _value: f64) -> Result<Value, E> {
                Err(E::custom("floats are not canonical HF Drive JSON"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
                Ok(Value::Str(value.to_owned()))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
                Ok(Value::Str(value))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Value::Array(items))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut members: Vec<(String, Value)> = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, Value>()? {
                    // Canonical members are strictly ascending by UTF-8 key
                    // bytes; this also rejects duplicates.
                    if members.last().is_some_and(|(last, _)| *last >= key) {
                        return Err(serde::de::Error::custom(
                            "duplicate or unordered members in HF Drive JSON",
                        ));
                    }
                    members.push((key, value));
                }
                Ok(Value::Object(members))
            }
        }
        deserializer.deserialize_any(ValueVisitor)
    }
}

macro_rules! serde_via_value {
    ($ty:ty, $members:ident, $from:ident) => {
        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                Value::Object($members(self)).serialize(serializer)
            }
        }
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = Value::deserialize(deserializer)?;
                let members = as_object(value).map_err(serde::de::Error::custom)?;
                $from(Members { members }).map_err(serde::de::Error::custom)
            }
        }
    };
}

serde_via_value!(HeadV1, head_members, head_from_members);
serde_via_value!(CommitV1, commit_members, commit_from_members);
serde_via_value!(VersionV1, version_members, version_from_members);
serde_via_value!(ItemRecord, item_record_members, item_record_from_members);
serde_via_value!(CatalogPage, page_members, page_from_members);

#[cfg(test)]
mod tests {
    use super::*;

    /// Backslash byte, assembled without a source escape so JSON escape
    /// inputs below are exact regardless of source text handling.
    const BS: u8 = 0x5c;

    /// Builds `{"a":"<escaped-control>..."}` with exact JSON escape bytes.
    fn json_string_input(escape: &str, tail: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(br#"{"a":""#);
        out.push(BS);
        out.extend_from_slice(escape.as_bytes());
        out.extend_from_slice(tail.as_bytes());
        out.extend_from_slice(br#""}"#);
        out
    }

    #[test]
    fn canonical_object_encoding_sorts_members_and_escapes_minimally() {
        // "x<LF>t" must encode as the minimal escape \n.
        let mut name = String::from("x");
        name.push('\n');
        name.push('t');
        let bytes =
            encode_object(&[("b".to_owned(), Value::Str(name)), ("a".to_owned(), Value::U64(0))])
                .unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(br#"{"a":0,"b":"x"#);
        expected.push(BS);
        expected.extend_from_slice(br#"nt"}"#);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn canonical_decoder_rejects_alternate_spellings() {
        let mut rejected: Vec<Vec<u8>> = vec![
            br#"{"a": 1}"#.to_vec(),
            br#"{"a":01}"#.to_vec(),
            br#"{"a":1.0}"#.to_vec(),
            br#"{"a":1,"a":2}"#.to_vec(),
            br#"{"b":1,"a":2}"#.to_vec(),
            br#"{"a":1} "#.to_vec(),
            br#"{"a":-1}"#.to_vec(),
            br#"{"a" :1}"#.to_vec(),
        ];
        // Non-minimal escapes: \u0041 for "A", \/ for "/", and surrogate
        // escapes where exact UTF-8 literal text is required.
        rejected.push(json_string_input("u0041", ""));
        rejected.push(json_string_input("/", ""));
        rejected.push(json_string_input("ud83d", ""));
        let mut pair_tail = Vec::new();
        pair_tail.push(BS);
        pair_tail.extend_from_slice(b"ude00");
        rejected.push(json_string_input("ud83d", std::str::from_utf8(&pair_tail).unwrap()));
        rejected.push(json_string_input("u000a", ""));
        // Raw control bytes and raw DEL inside a string are unescaped and
        // therefore non-canonical.
        let mut raw_nul = Vec::new();
        raw_nul.extend_from_slice(br#"{"a":""#);
        raw_nul.push(0x00);
        raw_nul.extend_from_slice(br#""}"#);
        rejected.push(raw_nul);
        let mut raw_del = Vec::new();
        raw_del.extend_from_slice(br#"{"a":""#);
        raw_del.push(0x7f);
        raw_del.extend_from_slice(br#""}"#);
        rejected.push(raw_del);
        for bytes in &rejected {
            assert!(
                decode_value(bytes).is_err(),
                "accepted {:?}",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    #[test]
    fn canonical_decoder_accepts_minimal_escapes_and_literal_utf8() {
        // \u0000 and \u007f are canonical control escapes, \t is the short
        // escape for tab, and non-ASCII characters are literal UTF-8.
        let mut input = Vec::new();
        input.extend_from_slice(br#"{"a":""#);
        input.push(BS);
        input.extend_from_slice(b"u0000");
        input.push(BS);
        input.push(b't');
        input.push(BS);
        input.extend_from_slice(b"u007f");
        input.extend_from_slice("\u{1f600}".as_bytes());
        input.extend_from_slice(br#""}"#);
        assert_eq!(
            decode_value(&input).unwrap(),
            Value::Object(vec![(
                "a".to_owned(),
                Value::Str("\0\t\u{7f}\u{1f600}".to_owned())
            )])
        );
        // The short newline escape is canonical.
        let mut newline_input = Vec::new();
        newline_input.extend_from_slice(br#"{"a":""#);
        newline_input.push(BS);
        newline_input.push(b'n');
        newline_input.extend_from_slice(br#""}"#);
        assert_eq!(
            decode_value(&newline_input).unwrap(),
            Value::Object(vec![("a".to_owned(), Value::Str("\n".to_owned()))])
        );
    }

    #[test]
    fn nesting_is_bounded() {
        let mut bytes = Vec::new();
        for _ in 0..(MAX_DECODER_DEPTH + 2) {
            bytes.push(b'[');
        }
        for _ in 0..(MAX_DECODER_DEPTH + 2) {
            bytes.push(b']');
        }
        assert_eq!(decode_value(&bytes), Err(FormatError::TooDeep));
    }

    #[test]
    fn serde_bytes_are_exactly_canonical_bytes() {
        let item = ItemRecord {
            item_id: ItemId::new(),
            parent_id: Some(ItemId::new()),
            name: "r\u{e9}sum\u{e9}.txt".to_owned(),
            kind: ItemKind::File,
            item_revision: OperationId::new(),
            content_version_id: Some(VersionId::new()),
            deleted: false,
            content_operation: OperationId::new(),
            location_operation: OperationId::new(),
            deletion_operation: None,
        };
        let canonical = to_item_record_bytes(&item).unwrap();
        assert_eq!(serde_json::to_vec(&item).unwrap(), canonical);
        let back: ItemRecord = serde_json::from_slice(&canonical).unwrap();
        assert_eq!(back, item);
    }
}
