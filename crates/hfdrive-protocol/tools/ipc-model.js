// HF Drive IPC 1.0 model — single source for spec/ipc-v1.schema.json and spec/fixtures/*.
// Field spec DSL: name:[opt:][arr:]type, e.g. "retry_after_ms:opt:dec64",
// "granted_scopes:opt:arr:string", "changes:arr:obj:history_change", "limit:u32limit".
"use strict";

const snake = (n) => n.replace(/(?<!^)(?=[A-Z])/g, "_").toLowerCase();

const ENUMS = {
  client_role: ["Desktop", "Cli"],
  login_flow: ["Pkce", "Device"],
  login_purpose: ["Signin", "ReadStorage", "WriteStorage", "CreateStorage"],
  authentication_state: ["SignedOut", "SigningIn", "SignedIn", "NeedsSignIn"],
  login_phase: ["Pending", "Completed", "Cancelled", "Expired", "Denied", "Failed"],
  owner_kind: ["Personal", "Organization"],
  visibility: ["Private", "Public"],
  connection_mode: ["ReadOnly", "Writable"],
  capability_state: ["ReadOnly", "StorageSetupRequired", "WriteSyncPaused", "Writable"],
  connection_state: ["UpToDate", "PendingUpload", "Uploading", "PublishingChanges", "Downloading", "Offline", "NeedsSignIn", "StorageSetupRequired", "PermissionDenied", "Conflict", "DiskFull", "WriteSyncPaused"],
  pin_state: ["Unpinned", "Pinned", "Partial"],
  hydration_state: ["Full", "Partial", "OnlineOnly"],
  pin_mode: ["Pin", "Unpin"],
  free_space_mode: ["All", "ExceptPinned"],
  item_kind: ["File", "Directory"],
  activity_direction: ["Upload", "Download", "Metadata"],
  activity_phase: ["Observed", "Snapshot", "Uploading", "Publishing", "Downloading", "Completed", "Failed", "Conflict"],
  collision_kind: ["IdenticalContent", "DifferentContent", "LocalOnly", "RemoteOnly", "CaseCollision", "NameInvalid"],
  proposed_action: ["AdoptIdentical", "KeepBoth", "QueueLocal", "DownloadRemote", "RequiresReview"],
  history_change_kind: ["Create", "Content", "Location", "Delete"],
  conflict_kind: ["Content", "Rename", "DeleteEdit", "CaseCollision", "MoveCycle"],
  conflict_resolution: ["Unresolved", "KeepLocal", "KeepRemote", "KeepBoth", "Recovered"],
  unlink_mode: ["SafeRemove", "DisconnectKeepRegistration"],
  probe_check_kind: ["NativeUploadVisibleNatively", "NativeUploadVisibleS3", "GetBodyEtagCoherence", "GuardedCreate", "ConcurrentSameEtag", "StaleOverwriteRejected", "AmbiguousCasRecovery", "XetRangeReads"],
  probe_outcome: ["Passed", "Failed", "NotRun"],
  protocol_error_code: ["UnsupportedProtocol", "OAuthClientNotConfigured", "NeedsSignIn", "StorageSetupRequired", "PermissionDenied", "ReadOnly", "PreviewChanged", "UnsupportedFormat", "LocalRootInvalid", "Conflict", "DiskFull", "RemoteContentUnavailable", "Cancelled", "ProviderInOtherSession", "Busy", "InvalidRequest", "NotFound", "Internal", "Timeout", "FrameTooLarge", "MalformedFrame", "UnexpectedEof", "VersionMismatch", "Closed"],
};
// protocol_error_code overrides snake_case (see errors.rs wire()).
const ERR_WIRE = {
  UnsupportedProtocol: "unsupported_protocol", OAuthClientNotConfigured: "oauth_client_not_configured",
  NeedsSignIn: "needs_sign_in", StorageSetupRequired: "storage_setup_required", PermissionDenied: "permission_denied",
  ReadOnly: "read_only", PreviewChanged: "preview_changed", UnsupportedFormat: "unsupported_format",
  LocalRootInvalid: "local_root_invalid", Conflict: "conflict", DiskFull: "disk_full",
  RemoteContentUnavailable: "remote_content_unavailable", Cancelled: "cancelled",
  ProviderInOtherSession: "provider_in_other_session", Busy: "busy", InvalidRequest: "invalid_request",
  NotFound: "not_found", Internal: "internal", Timeout: "timeout", FrameTooLarge: "frame_too_large",
  MalformedFrame: "malformed_frame", UnexpectedEof: "unexpected_eof", VersionMismatch: "version_mismatch", Closed: "closed",
};
const wireEnum = (enumName, variant) =>
  enumName === "protocol_error_code" ? ERR_WIRE[variant] : snake(variant);

const OBJECTS = {
  error_object: ["code:enum:protocol_error_code", "message:string", "retry_after_ms:opt:dec64"],
  account_profile: ["account_key:string", "issuer:string", "subject:string", "namespace:string", "display_name:string", "granted_scopes:opt:arr:string"],
  login_progress: ["session_id:uuid", "flow:enum:login_flow", "purpose:enum:login_purpose", "phase:enum:login_phase", "expires_at:string"],
  account_status: ["state:enum:authentication_state", "profile:opt:obj:account_profile", "login:opt:obj:login_progress", "last_error:opt:obj:error_object"],
  publication_protection_context: ["connection_id:uuid", "account_key:string", "issuer:string", "subject:string", "owner_id:string", "owner_kind:enum:owner_kind", "bucket_id:string", "workspace_id:uuid", "prefix:string"],
  progress_update: ["completed:dec64", "total:opt:dec64", "phase:string"],
  owner: ["owner_kind:enum:owner_kind", "owner_id:string", "namespace:opt:string", "display_name:string", "role:opt:string", "restrictions:arr:string", "can_create:bool"],
  bucket: ["bucket_id:string", "name:string", "namespace:string", "visibility:enum:visibility"],
  remote_location: ["owner_namespace:string", "owner_id:string", "owner_kind:enum:owner_kind", "bucket:string", "bucket_id:string", "prefix:string"],
  remote_binding: ["owner_namespace:string", "owner_id:string", "owner_kind:enum:owner_kind", "bucket:string", "bucket_id:string", "prefix:string", "workspace_id:uuid"],
  probe_check: ["kind:enum:probe_check_kind", "expected:string", "observed:string", "outcome:enum:probe_outcome", "detail:opt:string"],
  collision: ["kind:enum:collision_kind", "relative_path:string", "item_id:opt:uuid", "proposed_action:enum:proposed_action"],
  collision_category_summary: ["kind:enum:collision_kind", "count:dec64"],
  proposed_action_record: ["item_id:opt:uuid", "action:enum:proposed_action", "description:string"],
  history_change: ["item_id:uuid", "kind:enum:history_change_kind", "name:string", "parent_id:opt:uuid"],
  history_record: ["commit_id:uuid", "parent_commit_id:opt:uuid", "generation:opt:uuid", "device_id:uuid", "created_at:string", "changes:arr:obj:history_change"],
  conflict_record: ["conflict_id:uuid", "item_id:uuid", "kind:enum:conflict_kind", "competing_operation_ids:arr:uuid", "revisions:arr:uuid", "original_names:arr:string", "detected_at:string", "resolution_state:enum:conflict_resolution"],
  activity_record: ["activity_id:uuid", "connection_id:uuid", "item_id:opt:uuid", "item_name:string", "direction:enum:activity_direction", "phase:enum:activity_phase", "bytes_completed:dec64", "bytes_total:opt:dec64", "started_at:string", "last_error:opt:obj:error_object"],
  connection_status: ["connection_id:uuid", "workspace_id:uuid", "owner:obj:owner", "bucket:obj:bucket", "prefix:string", "root_path:string", "mode:enum:connection_mode", "capability:enum:capability_state", "state:enum:connection_state", "pin:enum:pin_state", "hydration:enum:hydration_state", "observed_commit:opt:uuid", "published_commit:opt:uuid", "applied_commit:opt:uuid", "observed_generation:opt:dec64", "pending_files:u32", "dirty_files:u32", "conflict_files:u32", "online_only_files:u32", "pinned_files:u32", "pending_upload_bytes:dec64", "local_bytes:dec64", "staging_used_bytes:dec64", "range_cache_used_bytes:dec64", "transfer_memory_used_bytes:dec64", "last_error:opt:obj:error_object", "updated_at:string"],
  status_snapshot: ["sequence:dec64", "account:obj:account_status", "connections:arr:obj:connection_status"],
  settings_patch: ["key:string", "value_json:opt:string"],
  settings_entry: ["key:string", "value_json:string"],
  inspect_item: ["item_id:uuid", "parent_id:opt:uuid", "name:string", "kind:enum:item_kind", "item_revision:uuid", "content_version_id:opt:uuid"],
  status_changed_event: ["sequence:dec64", "snapshot:bool", "account:obj:account_status", "changes:arr:obj:connection_status", "removed_connection_ids:arr:uuid"],
  activity_changed_event: ["sequence:dec64", "changes:arr:obj:activity_record"],
  conflicts_changed_event: ["sequence:dec64", "changes:arr:obj:conflict_record", "removed_conflict_ids:arr:uuid"],
};

const REQUESTS = {
  hello: ["protocol_major:u32", "protocol_minor:u32", "role:enum:client_role", "build_version:string"],
  get_status: [],
  subscribe_status: ["last_sequence:opt:dec64"],
  cancel_request: ["target_request_id:uuid"],
  start_login: ["operation_id:uuid", "flow:enum:login_flow", "purpose:enum:login_purpose", "organization_id:opt:string"],
  cancel_login: ["operation_id:uuid", "session_id:uuid"],
  sign_out: ["operation_id:uuid"],
  list_owners: ["cursor:opt:string", "limit:u32limit"],
  list_buckets: ["owner_namespace:string", "cursor:opt:string", "limit:u32limit"],
  create_bucket: ["operation_id:uuid", "owner_id:string", "owner_kind:enum:owner_kind", "owner_namespace:string", "bucket_name:string", "region:opt:string"],
  inspect_drive: ["connection_id:opt:uuid", "location:opt:obj:remote_location", "cursor:opt:string", "limit:u32limit"],
  begin_setup: ["operation_id:uuid", "account_key:string", "binding:obj:remote_binding", "initialize:bool", "bucket_creation_operation_id:opt:uuid"],
  set_publication_credentials: ["operation_id:uuid", "connection_id:uuid", "protected_credentials:string"],
  probe_storage: ["operation_id:uuid", "connection_id:uuid", "run_id:uuid"],
  preview_connect: ["operation_id:uuid", "connection_id:uuid", "root_path:string", "mode:enum:connection_mode"],
  connect: ["operation_id:uuid", "preview_id:uuid"],
  pause: ["operation_id:uuid", "connection_id:opt:uuid"],
  resume: ["operation_id:uuid", "connection_id:opt:uuid"],
  set_pin: ["operation_id:uuid", "connection_id:uuid", "item_id:opt:uuid", "mode:enum:pin_mode"],
  free_space: ["operation_id:uuid", "connection_id:uuid", "item_id:opt:uuid", "mode:enum:free_space_mode"],
  set_selective_sync: ["operation_id:uuid", "connection_id:uuid", "exclude_item_ids:arr:uuid"],
  update_settings: ["operation_id:uuid", "scope_id:string", "expected_revision:dec64", "settings:arr:obj:settings_patch"],
  list_history: ["connection_id:uuid", "item_id:opt:uuid", "cursor:opt:string", "limit:u32limit"],
  restore: ["operation_id:uuid", "connection_id:uuid", "item_id:uuid", "version_id:uuid"],
  list_conflicts: ["connection_id:uuid", "cursor:opt:string", "limit:u32limit"],
  resolve_conflict: ["operation_id:uuid", "connection_id:uuid", "conflict_id:uuid", "resolution:enum:conflict_resolution"],
  export_diagnostics: ["operation_id:uuid", "connection_id:opt:uuid", "destination_path:string"],
  prepare_unlink: ["operation_id:uuid", "connection_id:uuid", "mode:enum:unlink_mode"],
  unlink: ["operation_id:uuid", "connection_id:uuid", "mode:enum:unlink_mode"],
  prepare_upgrade: ["operation_id:uuid"],
  exit_provider: ["operation_id:uuid"],
};

const RESULTS = {
  hello: ["protocol_major:u32", "protocol_minor:u32", "provider_version:string", "supported_features:arr:string", "supported_min_protocol_minor:u32"],
  get_status: ["event_sequence:dec64", "account:obj:account_status", "connections:arr:obj:connection_status"],
  subscribe_status: ["subscribed:bool", "snapshot:obj:status_snapshot"],
  cancel_request: ["accepted:bool"],
  start_login: ["session_id:uuid", "authorization_url:opt:string", "user_code:opt:string", "verification_uri:opt:string", "expires_at:string"],
  cancel_login: ["cancelled:bool"],
  sign_out: ["signed_out:bool"],
  list_owners: ["items:arr:obj:owner", "next_cursor:opt:string"],
  list_buckets: ["items:arr:obj:bucket", "next_cursor:opt:string"],
  create_bucket: ["bucket:obj:bucket", "completed:bool"],
  inspect_drive: ["binding:opt:obj:remote_binding", "head_generation:opt:uuid", "is_managed_drive:bool", "prefix_empty:bool", "items:arr:obj:inspect_item", "next_cursor:opt:string"],
  begin_setup: ["setup_id:uuid", "connection_id:uuid", "binding:obj:remote_binding", "protection_context:obj:publication_protection_context"],
  set_publication_credentials: ["stored:bool", "capability:enum:capability_state"],
  probe_storage: ["run_id:uuid", "capability:enum:capability_state", "checks:arr:obj:probe_check", "report_path:opt:string"],
  preview_connect: ["preview_id:uuid", "connection_id:uuid", "binding:obj:remote_binding", "visibility:enum:visibility", "head_generation:opt:uuid", "local_scan_generation:dec64", "collision_summary:arr:obj:collision_category_summary", "collisions:arr:obj:collision", "proposed_action_count:dec64", "proposed_actions:arr:obj:proposed_action_record", "requires_review:bool"],
  connect: ["connection_id:uuid", "status:obj:connection_status"],
  pause: ["paused_connection_ids:arr:uuid"],
  resume: ["resumed_connection_ids:arr:uuid"],
  set_pin: ["pin_state:enum:pin_state", "pinned_files:u32"],
  free_space: ["freed_bytes:dec64", "dehydrated_files:u32"],
  set_selective_sync: ["excluded_item_ids:arr:uuid", "retained_dirty_item_ids:arr:uuid"],
  update_settings: ["revision:dec64", "settings:arr:obj:settings_entry"],
  list_history: ["items:arr:obj:history_record", "next_cursor:opt:string"],
  restore: ["operation_id:uuid", "status:obj:connection_status"],
  list_conflicts: ["items:arr:obj:conflict_record", "next_cursor:opt:string"],
  resolve_conflict: ["conflict_id:uuid", "resolution_state:enum:conflict_resolution"],
  export_diagnostics: ["archive_path:string", "redacted:bool"],
  prepare_unlink: ["safe_to_unlink:bool", "online_only_files:u32", "partial_files:u32", "dirty_files:u32", "conflict_files:u32", "required_export_bytes:dec64", "blocking_reasons:arr:string"],
  unlink: ["connection_id:uuid", "unregistered:bool", "retained_for_recovery:bool"],
  prepare_upgrade: ["checkpointed:bool", "pending_operations:u32"],
  exit_provider: ["accepted:bool"],
};

const EVENTS = {
  status_changed: OBJECTS.status_changed_event,
  activity_changed: OBJECTS.activity_changed_event,
  conflicts_changed: OBJECTS.conflicts_changed_event,
};

const MUTATION_REQUESTS = new Set([
  "start_login", "cancel_login", "sign_out", "create_bucket", "begin_setup", "set_publication_credentials",
  "probe_storage", "preview_connect", "connect", "pause", "resume", "set_pin", "free_space",
  "set_selective_sync", "update_settings", "restore", "resolve_conflict", "export_diagnostics",
  "prepare_unlink", "unlink", "prepare_upgrade", "exit_provider",
]);

function parseField(spec) {
  const parts = spec.split(":");
  const name = parts.shift();
  function parseType() {
    const kind = parts.shift();
    if (kind === "opt" || kind === "arr") {
      return { modifier: kind, inner: parseType() };
    }
    return { modifier: null, kind, ref: parts.length ? parts.join(":") : null };
  }
  return { name, ...parseType() };
}

module.exports = { snake, ENUMS, ERR_WIRE, wireEnum, OBJECTS, REQUESTS, RESULTS, EVENTS, MUTATION_REQUESTS, parseField };
