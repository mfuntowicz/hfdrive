# HF Drive remote format v1

Normative specification of the managed remote format stored under one managed
prefix of an HF Bucket. The Rust model and canonical codec live in
`crates/hfdrive-core/src/format.rs`; the catalog tree lives in
`crates/hfdrive-core/src/catalog.rs`; portable names live in
`crates/hfdrive-core/src/names.rs`. Golden bytes are frozen in
`spec/fixtures/remote-v1/`. Any disagreement is resolved in favour of this
document and its frozen fixtures.

The remote format is byte-addressed: every record has exactly one accepted
spelling, and every immutable record is addressed by the SHA-256 of those exact
bytes. A decoder MUST accept only canonical bytes; an unknown required feature
or a newer schema MUST be rejected as unsupported, never reinterpreted, and a
managed prefix MUST NOT be initialized over an unsupported or foreign layout.

## Managed prefix layout

Under the configured managed prefix the application owns exactly:

| Key | Object | Mutability |
| --- | --- | --- |
| `HEAD` | head record | replaced by conditional write |
| `commits/<commit-uuid>.json` | commit record | immutable |
| `catalog/<sha256>.json` | catalog page | immutable |
| `versions/<version-uuid>.json` | version record | immutable |
| `objects/<upload-uuid>` | payload bytes | immutable |

UUID segments are lowercase hyphenated; `<sha256>` is 64 lowercase hex
characters. Ordinary objects outside this set are never imported or rewritten.
`HEAD` is never an immutable upload.

## Canonical JSON encoding

All managed records are UTF-8 JSON objects with exactly one accepted spelling:

1. Members are strictly ascending by their UTF-8 key bytes. Duplicate,
   missing, or unknown members are rejected.
2. Exactly one value per document; no trailing bytes.
3. Compact separators: `{"a":1,"b":[2]}`. Whitespace is never emitted and
   never accepted.
4. String escapes are minimal: `\"` `\\` `\b` `\t` `\n` `\f` `\r`, and
   `\u00xx` with lowercase hex for the remaining C0 controls
   (U+0000..U+0007, U+000B, U+000E..U+001F) and DEL (U+007F). Every other
   character, including all non-ASCII text and astral characters, is literal
   UTF-8. `\/`, surrogate escapes, non-minimal escapes, raw control bytes and
   raw DEL are rejected.
5. Numbers are nonnegative integers in canonical decimal: no sign, no leading
   zeros, no fraction, no exponent. Floats are rejected everywhere.
6. Every field of a record is present exactly once; an absent optional value
   is spelled `null`. Array order is part of the canonical spelling where this
   document defines one.
7. Nesting depth is at most 64.

## Common value rules

- Identifiers are non-nil UUIDs in lowercase hyphenated spelling. UUIDv4
  (OS CSPRNG) generates workspace, item, device, operation, upload, version,
  commit and generation identifiers; only deterministic conflict identities
  use UUIDv5. Item revisions are operation UUIDs.
- Digests are 64 lowercase hex characters (SHA-256 of exact bytes).
- Sizes and counts are nonnegative JSON integers within `u64`.
- Timestamps are RFC 3339 UTC with whole seconds, exactly
  `YYYY-MM-DDTHH:MM:SSZ`, with `Z` literal. Timestamps are display-only:
  devices and operations are never ordered by comparing them.

## Records

### HEAD

Size bound 16 KiB. Members: `commit_id`, `format`, `generation`,
`required_features`, `root_item_id`, `schema_version`, `workspace_id`.

- `format` is the string `hfdrive`; anything else is not an HF Drive record.
- `schema_version` is the integer `1` for this document. Any other value is an
  unsupported schema.
- `required_features` is an array of feature names required to interpret the
  prefix. It is empty for v1; a nonempty array names features this build does
  not implement and is rejected as unsupported. The array is canonically
  sorted and unique.
- `workspace_id` identifies the managed workspace; `root_item_id` identifies
  the single live root directory of the catalog.
- `commit_id` is the current committed publication; `generation` is a fresh
  UUID per successful publication (per successful HEAD replacement).

HEAD is the only authoritative mutable record. Publication replaces it with a
conditional write; that protocol is specified by the publication layer.

### Commit

Size bound 1 MiB; at most 1000 `operation_ids` and 1000 `changes`. Members:
`catalog_root`, `changes`, `commit_id`, `created_at`, `device_id`, `format`,
`operation_ids`, `parent_commit_id`, `schema_version`, `workspace_id`.

- `format`/`schema_version` carry the same values as HEAD.
- `parent_commit_id` is `null` only for the initial commit; otherwise the
  previous commit's ID. Commits are never rewritten.
- `catalog_root` is the hash of the catalog root page produced by this commit.
- `operation_ids` is the strictly ascending list of operation UUIDs included
  in this publication. Idempotent recovery searches this list in the
  committed ancestry.
- `changes` is an array of change entries in strictly ascending `item_id`
  order with at most one entry per item. Each entry has members `change`,
  `item_id`, `new_revision`, `old_revision` (in canonical member order
  `change`, `item_id`, `new_revision`, `old_revision`):
  - `change` is one of `create`, `content`, `location`, `deletion`,
    `undelete`.
  - `old_revision` is `null` exactly for `create`; every other change carries
    the item's previous revision and no change keeps the same revision.
  - `new_revision` is the item's revision after this commit.
- `device_id` records the publishing device. `created_at` is display-only.

### Version

Size bound 16 KiB. Members: `display`, `format`, `object_key`,
`schema_version`, `sha256`, `size`, `version_id`, `workspace_id`,
`xet_file_id`.

- `object_key` is exactly `objects/<upload-uuid>`; the payload is immutable.
- `size` is the payload length in bytes; `sha256` is the digest of the exact
  payload bytes. Digests, Xet identifiers and S3 ETags are distinct types and
  are never substituted for one another.
- `xet_file_id` is the opaque native Xet file identifier (64 lowercase hex in
  SDK spelling) and is required for managed file payloads; `None` is only
  valid for directory versions. An object without a required Xet identifier
  fails the native capability gate; managed payloads are never silently a
  generic HTTP/S3 format.
- `display` holds `modified_at` and `name`: the original client spelling and
  modification time for presentation only.

### Item record

The value of `i/` catalog entries. Members: `content_operation`,
`content_version_id`, `deleted`, `deletion_operation`, `item_id`,
`item_revision`, `kind`, `location_operation`, `name`, `parent_id`.

- `kind` is `file` or `directory`.
- `parent_id` is `null` only for the single live root directory. A non-root
  record has a nonempty name validated by the portable name rules.
- The root record is a live directory with an empty name and no content.
- Directories have `content_version_id: null`; files always carry a content
  version (empty files are valid: their version has `size: 0`).
- `deleted` is `true` exactly when `deletion_operation` is present. A deleted
  item stays in the tree as a tombstone forever (v1 has no garbage
  collection) and retains its identity, location and kind.
- `content_operation`, `location_operation` and `deletion_operation` are the
  operation UUIDs responsible for the current content, location/name and
  deletion state (`deletion_operation` is `null` while the deletion state was
  never changed). `item_revision` is one of these operations.

## Catalog pages and keys

One B+tree stores three index kinds in one key space:

| Key | Value | Purpose |
| --- | --- | --- |
| `i/<item-id>` | item record | the authoritative item entry |
| `c/<parent-id>/<name-hex>/<item-id>` | `{"item_id":<item-id>}` | live-child index |
| `n/<parent-id>/<collision-key-hex>` | `{"item_id":<item-id>}` | name-uniqueness index |

- `<name-hex>` is the lowercase hex of the name's exact UTF-8 spelling.
- `<collision-key-hex>` is the lowercase hex of the name's collision key
  (below). Both are nonempty.
- A live item has exactly one `i/` entry and, when it has a parent, exactly
  one `c/` and one `n/` entry naming it. Deleting (tombstoning) removes
  exactly the item's `c/` and `n/` entries and keeps `i/`. A name slot is
  never overwritten: the uniqueness index rejects a second live occupant.
- Keys compare by raw bytes. Global key order is strictly ascending.

Pages are `{"entries":[...],"format":"hfdrive","kind":"leaf",
"schema_version":1}` (leaf) or `{"children":[...],...,"kind":"branch"}`
(branch). A leaf entry is `{"key":...,"value":...}`; a branch child is
`{"first_key":...,"page_id":...}`. Entries are strictly ascending by key;
children are strictly ascending by `first_key`. A page holds at most 128
entries/children and encodes to at most 256 KiB. A branch child covers the key
range `[first_key, next child's first_key)`; the last child covers everything
at or above its `first_key` within the parent's range. `first_key` is the
inclusive lower bound of the child's subtree and equals its smallest key when
the child is created; it is retained as a lower bound as keys are deleted (v1
never merges or rebalances pages). An emptied leaf is dropped instead of
rebalanced.

A page's identity is the SHA-256 of its canonical encoding. A reader MUST
verify the hash of every loaded page, global key order, member/entry shapes
and child ranges against the parent's bounds. Tree nesting is bounded in
depth; a corrupt remote tree is an invariant error, never a silent rewrite.

The tree mutates copy-on-write: a mutation rewrites only the affected
root-to-leaf paths, splits overflow pages at the median, and shares every
unchanged subtree by hash. A save therefore rewrites `O(paths)` pages, not the
manifest. Exactly one live root, unique portable sibling names, live directory
parents and acyclic parent links are enforced before publication; the tree
never compares timestamps.

## Names and the portable collision key

Name spellings are preserved exactly (case and Unicode form included). A name
is accepted only if it is portable as a Windows final path component: at most
255 UTF-16 code units, no control characters or NUL, none of `< > : " / \ | ?
*`, no trailing dot or space, and not a reserved DOS device name (`CON`,
`PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`, `COM`/`LPT` followed by one digit,
including the superscript digit spellings `¹ ² ³ ⁰ ⁴ ⁵ ⁶ ⁷ ⁸ ⁹`, with or
without an extension). Remote names are validated with the same rules, so a
remote name can never be unrepresentable locally.

The collision key of a name is the UTF-8 bytes of the name after Unicode NFC
normalization followed by Unicode default (non-Turkic) full case folding. Two
names with equal collision keys must never share one parent; the winning item
keeps its original spelling.

The resolved data versions are frozen format inputs, pinned by
`spec/fixtures/remote-v1/name-collisions.json`:

- NFC: `unicode-normalization 0.1.26`, Unicode Character Database 18.0.0.
- Default full case folding: `unicode-casefold 0.2.0`, Unicode Character
  Database 9.0.0.

Changing either dependency's data version changes collision identities for
existing workspaces and requires a remote format migration.

## Retention

There is no remote garbage collection in v1. Every committed version, commit
and catalog page is retained for history and restore; retained history can
incur storage costs independently of Xet bandwidth deduplication. Diagnostics
can report a computed `RetentionSnapshot { epoch: 0, retained_commits,
pending_upload_reservations }`; the type is descriptive and has no deletion
method. Unknown usage is reported as unknown.

## Bounds summary

| Record | Bound |
| --- | --- |
| HEAD | 16 KiB |
| Commit | 1 MiB, 1000 operations, 1000 changes |
| Version | 16 KiB |
| Catalog page | 256 KiB, 128 entries/children |
| JSON nesting | 64 |
| Name | 255 UTF-16 code units |

## Versioning and migration

`schema_version` is `1`. A reader that meets a newer schema or an unknown
required feature rejects the record as unsupported and never initializes over
it. Canonical spelling, index grammar, name rules and the frozen collision
data versions are part of the format: changing any of them is a schema
migration with new golden fixtures, not an in-place edit.
