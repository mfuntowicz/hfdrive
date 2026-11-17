#!/usr/bin/env node
// Generates spec/ipc-v1.schema.json and spec/fixtures/** from ipc-model.js.
// Regenerate with: node crates/hfdrive-protocol/tools/gen-fixtures.js
"use strict";

const fs = require("fs");
const path = require("path");
const model = require("./ipc-model.js");
const { parseField, wireEnum, snake } = model;

const REPO = path.resolve(__dirname, "..", "..", "..");
const SPEC = path.join(REPO, "spec");
const FIXTURES = path.join(SPEC, "fixtures");

// ---------------------------------------------------------------------------
// Deterministic sample values.
// ---------------------------------------------------------------------------

function uuidFor(name) {
  // Deterministic v4-shaped lowercase UUID derived from the field name.
  let h1 = 0x811c9dc5, h2 = 0x01000193;
  for (const ch of name) {
    h1 = Math.imul(h1 ^ ch.charCodeAt(0), 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ (ch.charCodeAt(0) + 17), 0x85ebca6b) >>> 0;
  }
  const hex = (n, len) => n.toString(16).padStart(len, "0").slice(0, len);
  const a = hex(h1, 8), b = hex(h2, 4), c = "4" + hex((h1 ^ h2) >>> 0, 3), d = "8" + hex((h2 ^ h1) >>> 0, 3);
  const e = hex(h1 * 3 + h2, 12);
  return `${a}-${b}-${c}-${d}-${e}`;
}

const DEC64_VALUES = ["0", "1", "42", "1099511627776", "18446744073709551615"];
function dec64For(name) {
  let sum = 0;
  for (const ch of name) sum = (sum + ch.charCodeAt(0)) % DEC64_VALUES.length;
  return DEC64_VALUES[sum];
}

const SAMPLE_ACCOUNT_KEY = require("crypto").createHash("sha256")
  .update("https://huggingface.co\0test-person").digest("hex");

function stringFor(name) {
  switch (name) {
    case "root_path": return "C:\\Users\\Public\\HFDriveTest";
    case "prefix": return "hfdrive/0e5f6c4a-1111-4c2a-8b3b-0f9f2d6c7a01";
    case "build_version": return "0.1.0";
    case "provider_version": return "0.1.0";
    case "expires_at": case "created_at": case "detected_at": case "started_at": case "updated_at":
      return "2026-11-13T12:00:00Z";
    case "namespace": case "owner_namespace": return "acme-labs";
    case "owner_id": return "6581f0d3a1b2c3d4e5f60718";
    case "bucket": case "bucket_name": case "name": return "hfdrive-test-bucket";
    case "bucket_id": return "6581f0d3a1b2c3d4e5f60719";
    case "display_name": return "Acme Labs";
    case "avatar_url": return "https://cdn-avatars.huggingface.co/v1/production/uploads/test-avatar.jpeg";
    case "account_key": return SAMPLE_ACCOUNT_KEY;
    case "issuer": return "https://huggingface.co";
    case "subject": return "test-person";
    case "destination_path": case "archive_path": case "report_path":
      return "C:\\Users\\Public\\HFDriveTest\\diagnostics.zip";
    case "protected_credentials": return "MARKER-PROTECTED-SECRET-DO-NOT-LOG";
    case "authorization_url": return "https://huggingface.co/oauth/authorize?state=marker";
    case "verification_uri": return "https://huggingface.co/oauth/device";
    case "user_code": return "ABCD-EFGH";
    case "scope_id": return "global";
    case "value_json": return "1048576";
    case "key": return "upload_bytes_per_second";
    case "message": case "detail": case "description": case "expected": case "observed": case "phase":
      return "display text";
    case "relative_path": return "docs\\hello.txt";
    case "path": return "C:\\Users\\Public\\HFDriveTest\\docs\\hello.txt";
    case "item_name": return "hello.txt";
    case "role": return "maintainer";
    case "item_revision": return uuidFor("item_revision");
    case "preview_fingerprint": return "6b8f2c1d0a9e7f6c5d4b3a291807060504030201000f0e0d0c0b0a0908070605";
    default: return `sample-${name}`;
  }
}

function sampleValue(spec, name) {
  const f = parseField(`${name}:${spec}`);
  return sampleOf(f, name);
}

function sampleOf(f, name) {
  if (f.modifier === "arr") {
    return [sampleOf(f.inner, name + "_a"), sampleOf(f.inner, name + "_b")];
  }
  if (f.modifier === "opt") {
    // Opt-in presence is decided by the fixture author via optionalsPresent.
    return sampleOf(f.inner, name);
  }
  switch (f.kind) {
    case "uuid": return uuidFor(name);
    case "string": return stringFor(name);
    case "bool": return true;
    case "u32": return name === "protocol_major" ? 1 : name === "protocol_minor" ? 0 : 3;
    case "u32limit": return 200;
    case "dec64": return name === "transfer_memory_used_bytes" ? "18446744073709551615" : dec64For(name);
    case "enum": {
      const variants = model.ENUMS[f.ref];
      const pick = {
        connection_state: "UpToDate", capability_state: "Writable", connection_mode: "Writable",
        pin_state: "Pinned", hydration_state: "Full", client_role: "Desktop", login_flow: "Pkce",
        login_purpose: "Signin", owner_kind: "Organization", visibility: "Private",
        probe_outcome: "Passed", conflict_resolution: "KeepBoth", activity_phase: "Publishing",
        authentication_state: "SignedIn", login_phase: "Pending",
      }[f.ref] || variants[0];
      return wireEnum(f.ref, pick);
    }
    case "obj": return sampleObject(f.ref);
    default: throw new Error(`unknown field kind for ${name}`);
  }
}

function sampleObject(objectName) {
  const out = {};
  for (const spec of model.OBJECTS[objectName]) {
    const f = parseField(spec);
    if (f.modifier === "opt" && OPTION_ABSENCE.has(`${objectName}.${f.name}`)) continue;
    out[f.name] = sampleOf(f, f.name);
  }
  if (objectName === "account_profile") {
    out.namespace = "fixture-person";
    out.display_name = "Fixture Person";
    out.granted_scopes = ["openid", "profile", "read-memberships", "read-repos"];
  }
  return out;
}

// Optional fields deliberately left absent in the fixtures (others are present).
const OPTION_ABSENCE = new Set([
  "account_status.login",
  "account_status.last_error",
  "owner.role",
  "probe_check.detail",
  "collision.item_id",
  "history_change.parent_id",
  "history_record.parent_commit_id",
  "activity_record.item_id",
  "activity_record.bytes_total",
  "activity_record.last_error",
  "connection_status.observed_commit",
  "connection_status.applied_commit",
  "connection_status.last_error",
  "settings_patch.value_json",
  "inspect_item.parent_id",
  "start_login.organization_id",
  "import_request.files_cursor",
  "import_result.next_cursor",
]);

// ---------------------------------------------------------------------------
// Canonical JSON writer (must match the Rust and C# canonical writers).
// ---------------------------------------------------------------------------

function canonicalValue(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("floats are not allowed in this protocol");
    return String(value);
  }
  if (typeof value === "string") return quote(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalValue).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value)
      .filter((k) => value[k] !== null && value[k] !== undefined)
      .sort();
    return "{" + keys.map((k) => quote(k) + ":" + canonicalValue(value[k])).join(",") + "}";
  }
  throw new Error("unsupported value");
}

function quote(text) {
  let out = "\"";
  for (const chRaw of text) {
    // Iterate by code points; raw UTF-8 output for non-ASCII.
    const cp = chRaw.codePointAt(0);
    if (cp > 0xFFFF) { out += chRaw; continue; }
    const c = cp;
    switch (c) {
      case 0x22: out += "\\\""; break;
      case 0x5C: out += "\\\\"; break;
      case 0x08: out += "\\b"; break;
      case 0x09: out += "\\t"; break;
      case 0x0A: out += "\\n"; break;
      case 0x0C: out += "\\f"; break;
      case 0x0D: out += "\\r"; break;
      default:
        if (c < 0x20 || c === 0x7F) out += "\\u00" + c.toString(16).padStart(2, "0");
        else out += chRaw;
    }
  }
  return out + "\"";
}

const encoder = new TextEncoder();
const toBytes = (text) => encoder.encode(text);
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function frameHex(payloadBytes) {
  const header = new Uint8Array(4);
  new DataView(header.buffer).setUint32(0, payloadBytes.length, true);
  return hex(new Uint8Array([...header, ...payloadBytes]));
}

// ---------------------------------------------------------------------------
// Envelope + message construction.
// ---------------------------------------------------------------------------

function requestEnvelope(requestId, method, body) {
  return {
    protocol_major: 1,
    protocol_minor: 0,
    request_id: requestId,
    kind: "request",
    method,
    body,
  };
}

function responseEnvelope(requestId, method, outcome) {
  return {
    protocol_major: 1,
    protocol_minor: 0,
    request_id: requestId,
    kind: "response",
    method,
    body: outcome.error ? { error: outcome.error } : { result: outcome.result },
  };
}

function eventEnvelope(eventId, method, body) {
  return {
    protocol_major: 1,
    protocol_minor: 0,
    request_id: eventId,
    kind: "event",
    method,
    body,
  };
}

function requestBody(method, overrides = {}) {
  const out = {};
  for (const spec of model.REQUESTS[method]) {
    const f = parseField(spec);
    if (f.modifier === "opt" && (f.name in overrides) === false) continue;
    out[f.name] = f.name in overrides ? overrides[f.name] : sampleOf(f, f.name);
  }
  for (const key of Object.keys(overrides)) {
    if (!(key in out)) out[key] = overrides[key];
  }
  return out;
}

function resultBody(method, overrides = {}) {
  const out = {};
  for (const spec of model.RESULTS[method]) {
    const f = parseField(spec);
    if (f.modifier === "opt" && (f.name in overrides) === false) continue;
    out[f.name] = f.name in overrides ? overrides[f.name] : sampleOf(f, f.name);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Golden fixtures.
// ---------------------------------------------------------------------------

const goldens = [];
const gold = (name, description, envelope, extra = {}) => {
  const payload = toBytes(canonicalValue(envelope));
  goldens.push({
    name,
    description,
    class: "golden",
    expectation: { parse: "accept", ...extra.expectation },
    frame_hex: frameHex(payload),
    payload_hex: hex(payload),
    envelope,
    ...extra.fields,
  });
};

const REQUEST_ID = uuidFor("request_id");
const EVENT_ID = uuidFor("event_id");

gold("hello_request", "hello request envelope at protocol 1.0",
  requestEnvelope(REQUEST_ID, "hello",
    requestBody("hello", { protocol_major: 1, protocol_minor: 0, role: "desktop", build_version: "0.1.0" })));

gold("hello_request_from_v2", "hello request from a future protocol version: normal parse must reject, handshake parse must accept",
  { ...requestEnvelope(REQUEST_ID, "hello",
      requestBody("hello", { protocol_major: 2, protocol_minor: 3, role: "cli", build_version: "9.9.9" })),
    protocol_major: 2, protocol_minor: 3 },
  { expectation: { parse: "reject:unsupported_protocol", parse_handshake: "accept" } });

gold("hello_response_result", "hello result with provider capabilities",
  responseEnvelope(REQUEST_ID, "hello", {
    result: resultBody("hello", {
      protocol_major: 1, protocol_minor: 0, provider_version: "0.1.0",
      supported_features: ["sync_v1", "events_v1"], supported_min_protocol_minor: 0,
    }),
  }));

gold("get_status_request", "get_status request with empty body",
  requestEnvelope(REQUEST_ID, "get_status", requestBody("get_status")));

gold("get_status_response_result", "get_status result carrying one full connection status (u64 decimal strings, nested objects, omitted optionals)",
  responseEnvelope(REQUEST_ID, "get_status", {
    result: {
      event_sequence: "4294967296",
      account: sampleObject("account_status"),
      connections: [sampleObject("connection_status")],
    },
  }));

gold("get_status_response_error", "response error shape with retry hint",
  responseEnvelope(REQUEST_ID, "get_status", {
    error: { code: "busy", message: "provider is at capacity", retry_after_ms: "250" },
  }));

gold("start_login_response_oauth_client_not_configured",
  "OAuth configuration error uses the canonical cross-language wire spelling",
  responseEnvelope(REQUEST_ID, "start_login", {
    error: { code: "oauth_client_not_configured", message: "the product OAuth client is not configured" },
  }));

gold("subscribe_status_request", "subscribe_status request with last_sequence",
  requestEnvelope(REQUEST_ID, "subscribe_status", requestBody("subscribe_status", { last_sequence: "7" })));

gold("status_changed_event", "status_changed event with a snapshot, one changed connection and one removal",
  eventEnvelope(EVENT_ID, "status_changed", {
    sequence: "12",
    snapshot: true,
    account: sampleObject("account_status"),
    changes: [sampleObject("connection_status")],
    removed_connection_ids: [uuidFor("removed_connection_a"), uuidFor("removed_connection_b")],
  }));

gold("activity_changed_event", "activity_changed event batch",
  eventEnvelope(EVENT_ID, "activity_changed", {
    sequence: "13",
    changes: [sampleObject("activity_record")],
  }));

gold("conflicts_changed_event", "conflicts_changed event batch",
  eventEnvelope(EVENT_ID, "conflicts_changed", {
    sequence: "14",
    changes: [sampleObject("conflict_record")],
    removed_conflict_ids: [uuidFor("removed_conflict_a")],
  }));

gold("set_publication_credentials_request",
  "set_publication_credentials request; parsers must accept it and log helpers must never include the protected secret (marker: MARKER-PROTECTED-SECRET-DO-NOT-LOG)",
  requestEnvelope(REQUEST_ID, "set_publication_credentials",
    requestBody("set_publication_credentials")),
  { expectation: { parse: "accept", describe_for_log_must_not_contain: "MARKER-PROTECTED-SECRET-DO-NOT-LOG" } });

gold("cancel_request_request", "cancel_request targeting another request id",
  requestEnvelope(REQUEST_ID, "cancel_request",
    requestBody("cancel_request", { target_request_id: uuidFor("target_request_id") })));

gold("start_login_request_pkce", "start_login (pkce) with organization_id omitted",
  requestEnvelope(REQUEST_ID, "start_login",
    requestBody("start_login", { flow: "pkce", purpose: "signin" })));

gold("start_login_request_device", "start_login (device) with organization_id present",
  requestEnvelope(REQUEST_ID, "start_login",
    requestBody("start_login", {
      flow: "device", purpose: "write_storage", organization_id: "6581f0d3a1b2c3d4e5f60718",
    })));

gold("update_settings_request", "update_settings request with nested settings patch (nested optional omitted)",
  requestEnvelope(REQUEST_ID, "update_settings",
    requestBody("update_settings", {
      scope_id: "global",
      expected_revision: "3",
      settings: [
        { key: "upload_bytes_per_second", value_json: "1048576" },
        { key: "start_at_login" },
      ],
    })));

gold("preview_connect_request", "preview_connect request for a previously reserved binding",
  requestEnvelope(REQUEST_ID, "preview_connect", requestBody("preview_connect")));

gold("begin_setup_request", "explicit initialization intent before credentials or root registration",
  requestEnvelope(REQUEST_ID, "begin_setup", requestBody("begin_setup")));

gold("begin_setup_response_result", "reserved setup and connection with exact public DPAPI protection context",
  responseEnvelope(REQUEST_ID, "begin_setup", { result: resultBody("begin_setup") }));

gold("list_activity_request", "list_activity read-only request scoped to one connection with a continuation cursor (no operation id)",
  requestEnvelope(REQUEST_ID, "list_activity",
    requestBody("list_activity", { cursor: "activity:1" })));

gold("list_activity_response_result", "list_activity result page with nested activity record and next_cursor",
  responseEnvelope(REQUEST_ID, "list_activity", {
    result: {
      items: [sampleObject("activity_record")],
      next_cursor: "activity:2",
    },
  }));

gold("list_history_response_result", "list_history result with nested history changes",
  responseEnvelope(REQUEST_ID, "list_history", {
    result: {
      items: [sampleObject("history_record")],
    },
  }));

gold("connect_response_result", "connect result carrying the new connection status",
  responseEnvelope(REQUEST_ID, "connect", {
    result: {
      connection_id: uuidFor("connection_id"),
      status: sampleObject("connection_status"),
    },
  }));

const UNLINK_PREVIEW_ID = uuidFor("unlink_preview_id");
const UNLINK_FINGERPRINT = stringFor("preview_fingerprint");

gold("prepare_unlink_response_result", "prepare_unlink result with block counts and the provider-reviewed unlink preview",
  responseEnvelope(REQUEST_ID, "prepare_unlink", {
    result: resultBody("prepare_unlink", {
      safe_to_unlink: false,
      online_only_files: 12, partial_files: 1, dirty_files: 2, conflict_files: 0,
      required_export_bytes: "1048576",
      blocking_reasons: ["2 files retain unsynchronized local changes"],
      preview_id: UNLINK_PREVIEW_ID,
      preview_fingerprint: UNLINK_FINGERPRINT,
      online_only_data_loss: true,
      affected_files: [
        { path: "C:\\Users\\Public\\HFDriveTest\\docs\\hello.txt", size: "18", partial: false },
        { path: "C:\\Users\\Public\\HFDriveTest\\data.bin", size: "18446744073709551615", partial: true },
      ],
    }),
  }));

gold("prepare_unlink_response_result_remove_unavailable",
  "prepare_unlink result for the RemoveUnavailable mode: proceeding destroys online-only bytes and requires explicit affirmative consent; affected_files is producer-bounded at 200 entries",
  responseEnvelope(REQUEST_ID, "prepare_unlink", {
    result: resultBody("prepare_unlink", {
      safe_to_unlink: true,
      online_only_files: 1, partial_files: 0, dirty_files: 0, conflict_files: 0,
      required_export_bytes: "0",
      blocking_reasons: [],
      preview_id: UNLINK_PREVIEW_ID,
      preview_fingerprint: UNLINK_FINGERPRINT,
      online_only_data_loss: true,
      affected_files: [
        { path: "C:\\Users\\Public\\HFDriveTest\\online-only.bin", size: "4294967296", partial: true },
      ],
    }),
  }));

gold("unlink_request_remove_unavailable",
  "unlink request selecting RemoveUnavailable with the preview identity and explicit online-only data-loss consent (operation_id stays a fresh mutation id, never the preview id)",
  requestEnvelope(REQUEST_ID, "unlink", requestBody("unlink", {
    operation_id: uuidFor("operation_id"),
    connection_id: uuidFor("connection_id"),
    mode: "remove_unavailable",
    preview_id: UNLINK_PREVIEW_ID,
    accept_online_only_data_loss: true,
  })));

gold("list_owners_response_result", "list_owners result page with next_cursor",
  responseEnvelope(REQUEST_ID, "list_owners", {
    result: {
      items: [sampleObject("owner"), sampleObject("bucket")].slice(0, 1).concat([{
        owner_kind: "personal", owner_id: "6581f0d3a1b2c3d4e5f60717",
        namespace: "octocat", display_name: "Octo Cat", restrictions: [], can_create: true,
      }]),
      next_cursor: "owner:6581f0d3a1b2c3d4e5f60717",
    },
  }));

gold("exit_provider_request", "exit_provider request (mutation operation id)",
  requestEnvelope(REQUEST_ID, "exit_provider", requestBody("exit_provider")));

gold("exit_provider_response_result", "exit_provider result",
  responseEnvelope(REQUEST_ID, "exit_provider", { result: { accepted: true } }));

gold("probe_storage_response_result", "probe_storage result with per-check expectations and observations",
  responseEnvelope(REQUEST_ID, "probe_storage", {
    result: resultBody("probe_storage", {
      run_id: uuidFor("run_id"),
      capability: "writable",
      checks: [{
        kind: "concurrent_same_etag",
        expected: "exactly one writer wins",
        observed: "exactly one writer wins",
        outcome: "passed",
      }],
      report_path: "C:\\Users\\Public\\HFDriveTest\\capabilities.json",
    }),
  }));

gold("set_publication_credentials_response_result", "set_publication_credentials result (no secret material)",
  responseEnvelope(REQUEST_ID, "set_publication_credentials", {
    result: { stored: true, capability: "writable" },
  }));

gold("repair_storage_request",
  "repair_storage request reusing one source setup reservation's verified publication credentials for an existing connected drive; no secret material travels on the wire",
  requestEnvelope(REQUEST_ID, "repair_storage", requestBody("repair_storage")));

gold("repair_storage_response_result",
  "repair_storage result with the repaired connection status and the fresh probe/report identity (no secret material)",
  responseEnvelope(REQUEST_ID, "repair_storage", {
    result: resultBody("repair_storage", {
      connection_id: uuidFor("connection_id"),
      repaired: true,
      run_id: uuidFor("run_id"),
      report_path: "C:\\Users\\Public\\HFDriveTest\\capabilities.json",
    }),
  }));

// Raw bucket import (initiated by Explorer): the target object, the source
// paths, the exact import prefix, and the per-file result fields are the
// contract; the decimal u64 fields exercise the full wire range. Per-directory
// empty outcomes and source-to-key mappings stay in the provider journal; only
// the bounded empty-directory count is repeated on each wire-result page.
const IMPORT_ID = uuidFor("import_id");
const IMPORT_PREFIX = `hfdrive-imports/${IMPORT_ID}`;
const sha256Hex = (text) => require("crypto").createHash("sha256").update(text, "utf8").digest("hex");

gold("import_request",
  "import request with the exact target object and raw bucket source paths (mutation operation id)",
  requestEnvelope(REQUEST_ID, "import", {
    operation_id: uuidFor("operation_id"),
    import_id: IMPORT_ID,
    target: sampleObject("import_target"),
    sources: [
      "C:\\Users\\Public\\HFDriveTest\\import-source\\hello.txt",
      "C:\\Users\\Public\\HFDriveTest\\import-source\\docs\\data.bin",
    ],
  }));

gold("import_response_result",
  "import result with the exact hfdrive-imports/<import_id> prefix (no trailing slash), per-file result records and full-width decimal u64 sizes/counts",
  responseEnvelope(REQUEST_ID, "import", {
    result: {
      import_id: IMPORT_ID,
      prefix: IMPORT_PREFIX,
      files: [
        {
          key: `${IMPORT_PREFIX}/folder-a/report.txt`,
          size: "18446744073709551615",
          sha256: sha256Hex("hfdrive-import-fixture-file-a"),
          xet_file_id: sha256Hex("hfdrive-import-fixture-xet-a"),
        },
        {
          key: `${IMPORT_PREFIX}/empty.bin`,
          size: "0",
          sha256: sha256Hex("hfdrive-import-fixture-file-b"),
          xet_file_id: sha256Hex("hfdrive-import-fixture-xet-b"),
        },
      ],
      file_count: 2,
      total_bytes: "18446744073709551615",
      empty_directory_count: 0,
    },
  }));

gold("import_response_result_paged",
  "import result page carrying next_cursor: one page of per-file records with complete import_id/prefix/file_count/total_bytes repeated on every page",
  responseEnvelope(REQUEST_ID, "import", {
    result: {
      import_id: IMPORT_ID,
      prefix: IMPORT_PREFIX,
      files: [
        {
          key: `${IMPORT_PREFIX}/folder-a/report.txt`,
          size: "1024",
          sha256: sha256Hex("hfdrive-import-fixture-file-a"),
          xet_file_id: sha256Hex("hfdrive-import-fixture-xet-a"),
        },
      ],
      next_cursor: "import-files-v1:00112233-0000-4000-8000-000000000000:1",
      file_count: 2,
      total_bytes: "18446744073709551615",
      empty_directory_count: 0,
    },
  }));

gold("import_request_files_cursor",
  "import request page continuation carrying files_cursor for the same operation (read replay, never a second mutation)",
  requestEnvelope(REQUEST_ID, "import", {
    operation_id: uuidFor("operation_id"),
    import_id: IMPORT_ID,
    target: sampleObject("import_target"),
    sources: [
      "C:\\Users\\Public\\HFDriveTest\\import-source\\hello.txt",
    ],
    files_cursor: "import-files-v1:00112233-0000-4000-8000-000000000000:1",
  }));

// ---------------------------------------------------------------------------
// Invalid fixtures.
// ---------------------------------------------------------------------------

const invalids = [];
const inv = (name, description, stage, expectErrorCode, frameHexValue, reason) => {
  invalids.push({
    name,
    description,
    class: "invalid",
    stage,
    expectation: { error_code: expectErrorCode, reason },
    frame_hex: frameHexValue,
  });
};

const over = 1024 * 1024 + 1;
const overHeader = new Uint8Array(4);
new DataView(overHeader.buffer).setUint32(0, over, true);
inv("reject_oversized_frame", "declared frame length exceeds 1 MiB and is rejected before the payload is read",
  "frame", "frame_too_large", hex(overHeader), "frame length 1048577 exceeds the maximum");

inv("reject_zero_length_frame", "a zero-length frame is invalid",
  "frame", "malformed_frame", "00000000", "invalid frame length");

inv("reject_truncated_header", "stream ends inside the 4-byte length prefix",
  "frame", "unexpected_eof", "0100", "unexpected end of stream");

const truncPayload = toBytes("{\"a\"");
const truncHeader = new Uint8Array(4);
new DataView(truncHeader.buffer).setUint32(0, 10, true);
inv("reject_truncated_payload", "declared payload length is not delivered",
  "frame", "unexpected_eof", hex(new Uint8Array([...truncHeader, ...truncPayload])), "unexpected end of stream");

const payloadCases = [
  ["reject_not_json", "payload is not JSON", "malformed_frame", "{\"a\""],
  ["reject_trailing_garbage", "valid JSON followed by trailing bytes", "malformed_frame", "{\"protocol_major\":1}x"],
  ["reject_duplicate_key", "duplicate envelope member name", "malformed_frame",
    "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID + "\",\"kind\":\"request\",\"method\":\"get_status\",\"body\":{},\"kind\":\"request\"}"],
  ["reject_unknown_envelope_member", "unknown envelope member", "malformed_frame",
    "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID + "\",\"kind\":\"request\",\"method\":\"get_status\",\"body\":{},\"extra\":1}"],
  ["reject_unknown_body_member", "unknown body member", "malformed_frame",
    "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID + "\",\"kind\":\"request\",\"method\":\"get_status\",\"body\":{\"nope\":1}}"],
  ["reject_missing_body", "envelope without body", "malformed_frame",
    "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID + "\",\"kind\":\"request\",\"method\":\"get_status\"}"],
  ["reject_oauth_client_not_configured_legacy_spelling",
    "OAuth configuration error rejects the general .NET acronym spelling",
    "malformed_frame",
    "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID + "\",\"kind\":\"response\",\"method\":\"start_login\",\"body\":{\"error\":{\"code\":\"o_auth_client_not_configured\",\"message\":\"x\"}}}"],
  ["reject_both_result_and_error", "response body with both result and error", "malformed_frame",
    "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID + "\",\"kind\":\"response\",\"method\":\"get_status\",\"body\":{\"result\":{},\"error\":{\"code\":\"busy\",\"message\":\"x\"}}}"],
  ["reject_neither_result_nor_error", "response body with neither result nor error", "malformed_frame",
    "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID + "\",\"kind\":\"response\",\"method\":\"get_status\",\"body\":{}}"],
  ["reject_method_unknown", "unknown method name", "invalid_request",
    "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID + "\",\"kind\":\"request\",\"method\":\"nope\",\"body\":{}}"],
  ["reject_event_method_unknown", "request method used on an event envelope", "invalid_request",
    "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + EVENT_ID + "\",\"kind\":\"event\",\"method\":\"get_status\",\"body\":{}}"],
  ["reject_u64_number", "u64 field sent as a JSON number instead of a decimal string", "malformed_frame",
    "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID + "\",\"kind\":\"request\",\"method\":\"subscribe_status\",\"body\":{\"last_sequence\":7}}"],
  ["reject_u64_leading_zero", "decimal string with a leading zero", "malformed_frame",
    "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID + "\",\"kind\":\"request\",\"method\":\"subscribe_status\",\"body\":{\"last_sequence\":\"07\"}}"],
  ["reject_u64_overflow", "decimal string beyond u64 range", "malformed_frame",
    "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID + "\",\"kind\":\"request\",\"method\":\"subscribe_status\",\"body\":{\"last_sequence\":\"18446744073709551616\"}}"],
  ["reject_uuid_uppercase", "non-lowercase UUID spelling", "malformed_frame",
    "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID.toUpperCase() + "\",\"kind\":\"request\",\"method\":\"get_status\",\"body\":{}}"],
  ["reject_uuid_unhyphenated", "non-hyphenated UUID spelling", "malformed_frame",
    "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID.replace(/-/g, "") + "\",\"kind\":\"request\",\"method\":\"get_status\",\"body\":{}}"],
  ["reject_unknown_enum", "unknown enum variant in hello body", "malformed_frame",
    "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID + "\",\"kind\":\"request\",\"method\":\"hello\",\"body\":{\"protocol_major\":1,\"protocol_minor\":0,\"role\":\"superuser\",\"build_version\":\"1\"}}"],
  ["reject_version_mismatch", "get_status from a foreign protocol version", "unsupported_protocol",
    "{\"protocol_major\":2,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID + "\",\"kind\":\"request\",\"method\":\"get_status\",\"body\":{}}"],
  ["reject_hello_body_mismatch", "hello envelope at 1.0 whose body announces another version: body and envelope versions must agree", "malformed_frame",
    "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID + "\",\"kind\":\"request\",\"method\":\"hello\",\"body\":{\"protocol_major\":2,\"protocol_minor\":0,\"role\":\"cli\",\"build_version\":\"1\"}}"],
  ["reject_deep_nesting", "JSON nesting deeper than the 64 level limit is rejected before typed decode", "malformed_frame",
    "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID + "\",\"kind\":\"request\",\"method\":\"get_status\",\"body\":{\"nested\":" + "[".repeat(65) + "]".repeat(65) + "}}"],
];
for (const [name, description, code, raw] of payloadCases) {
  inv(name, description, "envelope", code, frameHex(toBytes(raw)), description);
}
// Raw (unescaped) control byte inside a string literal: invalid JSON.
const controlRaw = new Uint8Array([
  ...toBytes("{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\""), ...toBytes(REQUEST_ID),
  ...toBytes("\",\"kind\":\"request\",\"method\":\"get_status\",\"body\":{\"cursor\":\"a"), 0x01,
  ...toBytes("b\"}}"),
]);
inv("reject_raw_control_character", "unescaped control byte inside a string literal is invalid JSON",
  "envelope", "malformed_frame", frameHex(controlRaw), "invalid JSON payload");
inv("reject_non_utf8_payload", "payload bytes are not valid UTF-8",
  "envelope", "malformed_frame", frameHex(new Uint8Array([0x22, 0xC3, 0x28, 0x22])), "payload is not UTF-8");

// Import contract fixtures: the exact target object, source array, prefix and
// per-file fields, and the decimal u64 sizes/counts are enforced by the typed
// codecs; unknown members and non-canonical values are rejected.
const importRequestRaw = (bodyRaw) =>
  "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID +
  "\",\"kind\":\"request\",\"method\":\"import\",\"body\":" + bodyRaw + "}";
const importResponseRaw = (resultRaw) =>
  "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID +
  "\",\"kind\":\"response\",\"method\":\"import\",\"body\":{\"result\":" + resultRaw + "}}";
const IMPORT_OPERATION_ID = uuidFor("operation_id");
const IMPORT_TARGET_RAW =
  "{\"bucket_id\":\"6581f0d3a1b2c3d4e5f60719\",\"bucket_name\":\"hfdrive-test-bucket\"," +
  "\"owner_id\":\"6581f0d3a1b2c3d4e5f60718\",\"owner_kind\":\"organization\"," +
  "\"owner_namespace\":\"acme-labs\",\"visibility\":\"private\"}";
const importRequestBody = (targetRaw, sourcesRaw) =>
  "{\"import_id\":\"" + IMPORT_ID + "\",\"operation_id\":\"" + IMPORT_OPERATION_ID +
  "\",\"sources\":" + sourcesRaw + ",\"target\":" + targetRaw + "}";
const importResultBody = (prefixRaw, filesRaw, fileCountRaw, totalBytesRaw, emptyDirectoryCountRaw = "0") =>
  "{\"file_count\":" + fileCountRaw + ",\"files\":" + filesRaw + ",\"import_id\":\"" + IMPORT_ID +
  "\",\"prefix\":" + prefixRaw + ",\"total_bytes\":" + totalBytesRaw +
  ",\"empty_directory_count\":" + emptyDirectoryCountRaw + "}";
const IMPORT_FILE_RAW = (suffix, sizeRaw) =>
  "{\"key\":\"" + IMPORT_PREFIX + "/folder-" + suffix + "/report.txt" +
  "\",\"sha256\":\"" + sha256Hex("hfdrive-import-fixture-file-" + suffix) +
  "\",\"size\":" + sizeRaw +
  ",\"xet_file_id\":\"" + sha256Hex("hfdrive-import-fixture-xet-" + suffix) + "\"}";
const importInvalids = [
  ["reject_import_target_unknown_member",
    "import request whose target object carries an unknown member is rejected",
    importRequestRaw(importRequestBody("{\"bucket_id\":\"x\",\"bucket_name\":\"y\",\"owner_id\":\"z\",\"owner_kind\":\"organization\",\"owner_namespace\":\"acme-labs\",\"visibility\":\"private\",\"extra\":1}", "[\"src/a.txt\"]"))],
  ["reject_import_target_missing_field",
    "import request whose target object omits a required field is rejected",
    importRequestRaw(importRequestBody("{\"bucket_id\":\"x\",\"bucket_name\":\"y\",\"owner_id\":\"z\",\"owner_kind\":\"organization\",\"owner_namespace\":\"acme-labs\"}", "[\"src/a.txt\"]"))],
  ["reject_import_target_enum",
    "import request whose target visibility is an unknown enum variant is rejected",
    importRequestRaw(importRequestBody("{\"bucket_id\":\"x\",\"bucket_name\":\"y\",\"owner_id\":\"z\",\"owner_kind\":\"organization\",\"owner_namespace\":\"acme-labs\",\"visibility\":\"secret\"}", "[\"src/a.txt\"]"))],
  ["reject_import_sources_not_string",
    "import request whose sources array contains a non-string entry is rejected",
    importRequestRaw(importRequestBody(IMPORT_TARGET_RAW, "[\"src/a.txt\",7]"))],
  ["reject_import_sources_missing",
    "import request without the required sources array is rejected",
    importRequestRaw("{\"import_id\":\"" + IMPORT_ID + "\",\"operation_id\":\"" + IMPORT_OPERATION_ID + "\",\"target\":" + IMPORT_TARGET_RAW + "}")],
  ["reject_import_unknown_body_member",
    "import request body with an unknown member is rejected",
    importRequestRaw("{\"import_id\":\"" + IMPORT_ID + "\",\"operation_id\":\"" + IMPORT_OPERATION_ID + "\",\"sources\":[\"src/a.txt\"],\"target\":" + IMPORT_TARGET_RAW + ",\"dry_run\":true}")],
  ["reject_import_result_prefix_wrong_type",
    "import result whose prefix is not a string is rejected",
    importResponseRaw(importResultBody("7", "[" + IMPORT_FILE_RAW("a", "\"42\"") + "]", "1", "\"1\""))],
  ["reject_import_result_prefix_mismatch",
    "import result whose prefix is not exactly hfdrive-imports/<import_id> (no trailing slash) is rejected",
    importResponseRaw(importResultBody("\"hfdrive-imports/other-import/\"", "[" + IMPORT_FILE_RAW("a", "\"42\"") + "]", "1", "\"42\""))],
  ["reject_import_result_file_unknown_member",
    "import result whose per-file record carries an unknown member is rejected",
    importResponseRaw(importResultBody("\"" + IMPORT_PREFIX + "\"", "[" + IMPORT_FILE_RAW("a", "\"42\"").replace(/\}$/, ",\"etag\":\"x\"") + "]", "1", "\"42\""))],
  ["reject_import_result_file_missing_field",
    "import result whose per-file record omits xet_file_id is rejected",
    importResponseRaw(importResultBody("\"" + IMPORT_PREFIX + "\"",
      "[{\"key\":\"" + IMPORT_PREFIX + "/folder-a/report.txt" + "\",\"sha256\":\"" + sha256Hex("hfdrive-import-fixture-file-a") + "\",\"size\":\"42\"}]",
      "1", "\"42\""))],
  ["reject_import_size_number",
    "import result per-file size sent as a JSON number instead of a decimal string is rejected",
    importResponseRaw(importResultBody("\"" + IMPORT_PREFIX + "\"", "[" + IMPORT_FILE_RAW("a", "42") + "]", "1", "\"42\""))],
  ["reject_import_size_leading_zero",
    "import result total_bytes with a leading zero is rejected",
    importResponseRaw(importResultBody("\"" + IMPORT_PREFIX + "\"", "[" + IMPORT_FILE_RAW("a", "\"42\"") + "]", "1", "\"00\""))],
  ["reject_import_size_overflow",
    "import result total_bytes beyond u64 range is rejected",
    importResponseRaw(importResultBody("\"" + IMPORT_PREFIX + "\"", "[" + IMPORT_FILE_RAW("a", "\"42\"") + "]", "1", "\"18446744073709551616\""))],
  ["reject_import_files_cursor_number",
    "import request files_cursor sent as a JSON number instead of a string is rejected",
    importRequestRaw("{\"import_id\":\"" + IMPORT_ID + "\",\"operation_id\":\"" + IMPORT_OPERATION_ID +
      "\",\"sources\":[\"src/a.txt\"],\"target\":" + IMPORT_TARGET_RAW + ",\"files_cursor\":7}")],
  ["reject_import_next_cursor_number",
    "import result next_cursor sent as a JSON number instead of a string is rejected",
    importResponseRaw("{\"file_count\":1,\"files\":[],\"import_id\":\"" + IMPORT_ID +
      "\",\"next_cursor\":7,\"prefix\":\"" + IMPORT_PREFIX + "\",\"total_bytes\":\"1\",\"empty_directory_count\":0}")],
  ["reject_import_file_count_string",
    "import result file_count sent as a decimal string instead of a u32 JSON number is rejected",
    importResponseRaw(importResultBody("\"" + IMPORT_PREFIX + "\"", "[" + IMPORT_FILE_RAW("a", "\"42\"") + "]", "\"1\"", "\"42\""))],
  ["reject_import_empty_directory_count_string",
    "import result empty_directory_count sent as a decimal string instead of a u32 JSON number is rejected",
    importResponseRaw(importResultBody("\"" + IMPORT_PREFIX + "\"", "[" + IMPORT_FILE_RAW("a", "\"42\"") + "]", "1", "\"42\"", "\"0\""))],
];
for (const [name, description, raw] of importInvalids) {
  inv(name, description, "envelope", "malformed_frame", frameHex(toBytes(raw)), description);
}

// Unlink contract fixtures: the preview identity, the online-only data-loss
// signal/consent pair, and the affected-file records are enforced by the typed
// codecs; wrong types, unknown members and unknown enum variants are rejected.
const unlinkRequestRaw = (bodyRaw) =>
  "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID +
  "\",\"kind\":\"request\",\"method\":\"unlink\",\"body\":" + bodyRaw + "}";
const prepareUnlinkResponseRaw = (resultRaw) =>
  "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"" + REQUEST_ID +
  "\",\"kind\":\"response\",\"method\":\"prepare_unlink\",\"body\":{\"result\":" + resultRaw + "}}";
const UNLINK_OPERATION_ID = uuidFor("operation_id");
const UNLINK_CONNECTION_ID = uuidFor("connection_id");
const unlinkRequestBody = (overridesRaw) =>
  "{\"accept_online_only_data_loss\":true,\"connection_id\":\"" + UNLINK_CONNECTION_ID +
  "\",\"mode\":\"remove_unavailable\",\"operation_id\":\"" + UNLINK_OPERATION_ID +
  "\",\"preview_id\":\"" + UNLINK_PREVIEW_ID + "\"" + (overridesRaw ? "," + overridesRaw : "") + "}";
const UNLINK_AFFECTED_FILE_RAW =
  "{\"partial\":false,\"path\":\"C:\\\\Users\\\\Public\\\\HFDriveTest\\\\docs\\\\hello.txt\",\"size\":\"18\"}";
const prepareUnlinkResultBody = (affectedFilesRaw, previewFingerprintRaw, onlineOnlyDataLossRaw) =>
  "{\"affected_files\":" + affectedFilesRaw + ",\"blocking_reasons\":[],\"conflict_files\":0," +
  "\"dirty_files\":0,\"online_only_data_loss\":" + onlineOnlyDataLossRaw + ",\"online_only_files\":1," +
  "\"partial_files\":0,\"preview_fingerprint\":" + previewFingerprintRaw + ",\"preview_id\":\"" + UNLINK_PREVIEW_ID +
  "\",\"required_export_bytes\":\"0\",\"safe_to_unlink\":true}";
const unlinkInvalids = [
  ["reject_unlink_preview_id_number",
    "unlink request whose preview_id is a JSON number instead of a UUID string is rejected",
    unlinkRequestRaw("{\"accept_online_only_data_loss\":true,\"connection_id\":\"" + UNLINK_CONNECTION_ID + "\",\"mode\":\"remove_unavailable\",\"operation_id\":\"" + UNLINK_OPERATION_ID + "\",\"preview_id\":7}")],
  ["reject_unlink_preview_id_malformed",
    "unlink request whose preview_id is not a lowercase hyphenated UUID is rejected",
    unlinkRequestRaw("{\"accept_online_only_data_loss\":true,\"connection_id\":\"" + UNLINK_CONNECTION_ID + "\",\"mode\":\"remove_unavailable\",\"operation_id\":\"" + UNLINK_OPERATION_ID + "\",\"preview_id\":\"not-a-uuid\"}")],
  ["reject_unlink_accept_consent_string",
    "unlink request whose accept_online_only_data_loss is a string instead of a bool is rejected",
    unlinkRequestRaw("{\"accept_online_only_data_loss\":\"true\",\"connection_id\":\"" + UNLINK_CONNECTION_ID + "\",\"mode\":\"remove_unavailable\",\"operation_id\":\"" + UNLINK_OPERATION_ID + "\",\"preview_id\":\"" + UNLINK_PREVIEW_ID + "\"}")],
  ["reject_unlink_consent_missing",
    "unlink request without the required accept_online_only_data_loss consent is rejected",
    unlinkRequestRaw("{\"connection_id\":\"" + UNLINK_CONNECTION_ID + "\",\"mode\":\"remove_unavailable\",\"operation_id\":\"" + UNLINK_OPERATION_ID + "\",\"preview_id\":\"" + UNLINK_PREVIEW_ID + "\"}")],
  ["reject_unlink_mode_unknown",
    "unlink request whose mode is an unknown unlink_mode variant is rejected",
    unlinkRequestRaw(unlinkRequestBody("").replace("\"remove_unavailable\"", "\"remove_all\""))],
  ["reject_unlink_unknown_body_member",
    "unlink request body with an unknown member is rejected",
    unlinkRequestRaw(unlinkRequestBody("\"force\":true"))],
  ["reject_prepare_unlink_result_fingerprint_number",
    "prepare_unlink result whose preview_fingerprint is a JSON number instead of a string is rejected",
    prepareUnlinkResponseRaw(prepareUnlinkResultBody("[" + UNLINK_AFFECTED_FILE_RAW + "]", "7", "true"))],
  ["reject_prepare_unlink_result_consent_signal_string",
    "prepare_unlink result whose online_only_data_loss is a string instead of a bool is rejected",
    prepareUnlinkResponseRaw(prepareUnlinkResultBody("[" + UNLINK_AFFECTED_FILE_RAW + "]", "\"" + UNLINK_FINGERPRINT + "\"", "\"true\""))],
  ["reject_prepare_unlink_result_affected_files_not_array",
    "prepare_unlink result whose affected_files is not an array is rejected",
    prepareUnlinkResponseRaw(prepareUnlinkResultBody("\"x\"", "\"" + UNLINK_FINGERPRINT + "\"", "true"))],
  ["reject_prepare_unlink_result_affected_file_size_number",
    "prepare_unlink result whose affected-file size is a JSON number instead of a decimal string is rejected",
    prepareUnlinkResponseRaw(prepareUnlinkResultBody(
      "[{\"partial\":false,\"path\":\"C:\\\\Users\\\\Public\\\\HFDriveTest\\\\docs\\\\hello.txt\",\"size\":18}]",
      "\"" + UNLINK_FINGERPRINT + "\"", "true"))],
  ["reject_prepare_unlink_result_affected_file_unknown_member",
    "prepare_unlink result whose affected-file record carries an unknown member is rejected",
    prepareUnlinkResponseRaw(prepareUnlinkResultBody(
      "[" + UNLINK_AFFECTED_FILE_RAW.replace(/\}$/, ",\"etag\":\"x\"") + "]",
      "\"" + UNLINK_FINGERPRINT + "\"", "true"))],
  ["reject_prepare_unlink_result_affected_file_missing_field",
    "prepare_unlink result whose affected-file record omits partial is rejected",
    prepareUnlinkResponseRaw(prepareUnlinkResultBody(
      "[{\"path\":\"C:\\\\Users\\\\Public\\\\HFDriveTest\\\\docs\\\\hello.txt\",\"size\":\"18\"}]",
      "\"" + UNLINK_FINGERPRINT + "\"", "true"))],
  ["reject_prepare_unlink_result_preview_id_missing",
    "prepare_unlink result without the required preview_id is rejected",
    prepareUnlinkResponseRaw(
      "{\"affected_files\":[],\"blocking_reasons\":[],\"conflict_files\":0,\"dirty_files\":0," +
      "\"online_only_data_loss\":true,\"online_only_files\":1,\"partial_files\":0," +
      "\"preview_fingerprint\":\"" + UNLINK_FINGERPRINT + "\",\"required_export_bytes\":\"0\",\"safe_to_unlink\":true}")],
];
for (const [name, description, raw] of unlinkInvalids) {
  inv(name, description, "envelope", "malformed_frame", frameHex(toBytes(raw)), description);
}

// ---------------------------------------------------------------------------
// spec/ipc-v1.schema.json
// ---------------------------------------------------------------------------

const uuidSchema = { type: "string", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" };
const dec64Schema = { type: "string", pattern: "^(0|[1-9][0-9]{0,19})$", description: "canonical decimal u64" };
const u32Schema = { type: "integer", minimum: 0, maximum: 4294967295 };
const u32LimitSchema = { type: "integer", minimum: 1, maximum: 200, description: "page size limit (max 200)" };

function schemaForField(f) {
  if (f.modifier === "arr") return { type: "array", items: schemaForField(f.inner) };
  if (f.modifier === "opt") return {
    anyOf: [schemaForField(f.inner), { type: "null" }],
    description: "nullable; optional object properties are omitted from canonical output",
  };
  let base;
  switch (f.kind) {
    case "uuid": base = uuidSchema; break;
    case "string": base = { type: "string" }; break;
    case "bool": base = { type: "boolean" }; break;
    case "u32": base = u32Schema; break;
    case "u32limit": base = u32LimitSchema; break;
    case "dec64": base = dec64Schema; break;
    case "enum": base = { type: "string", enum: model.ENUMS[f.ref].map((v) => wireEnum(f.ref, v)) }; break;
    case "obj": base = { $ref: `#/$defs/${f.ref}` }; break;
    default: throw new Error("unknown kind");
  }
  return base;
}

function objectSchema(objectName) {
  const props = {};
  const required = [];
  for (const spec of model.OBJECTS[objectName]) {
    const f = parseField(spec);
    props[f.name] = schemaForField(f);
    if (f.modifier !== "opt") required.push(f.name);
  }
  return {
    type: "object",
    additionalProperties: false,
    properties: props,
    required,
  };
}

const defs = {};
for (const name of Object.keys(model.OBJECTS)) defs[name] = objectSchema(name);
for (const [name, variants] of Object.entries(model.ENUMS)) {
  defs[name] = { type: "string", enum: variants.map((v) => wireEnum(name, v)) };
}
for (const method of Object.keys(model.REQUESTS)) {
  const props = {}, required = [];
  for (const spec of model.REQUESTS[method]) {
    const f = parseField(spec);
    props[f.name] = schemaForField(f);
    if (f.modifier !== "opt") required.push(f.name);
  }
  defs[`${method}_request`] = {
    type: "object", additionalProperties: false, properties: props, required,
    description: `body of a "${method}" request`,
  };
  const rprops = {}, rrequired = [];
  for (const spec of model.RESULTS[method]) {
    const f = parseField(spec);
    rprops[f.name] = schemaForField(f);
    if (f.modifier !== "opt") rrequired.push(f.name);
  }
  defs[`${method}_result`] = {
    type: "object", additionalProperties: false, properties: rprops, required: rrequired,
    description: `body.result of a "${method}" response`,
  };
}
for (const [eventName, fields] of Object.entries(model.EVENTS)) {
  const props = {}, required = [];
  for (const spec of fields) {
    const f = parseField(spec);
    props[f.name] = schemaForField(f);
    if (f.modifier !== "opt") required.push(f.name);
  }
  defs[`${eventName}_event`] = {
    type: "object", additionalProperties: false, properties: props, required,
    description: `body of the "${eventName}" event`,
  };
}

defs.error_object = objectSchema("error_object");
defs.response_body = {
  type: "object",
  additionalProperties: false,
  oneOf: [
    {
      properties: {
        result: {
          type: "object",
          description: "typed result body matching the response method (#/$defs/<method>_result)",
        },
      },
      required: ["result"],
    },
    {
      properties: { error: { $ref: "#/$defs/error_object" } },
      required: ["error"],
    },
  ],
  description: "exactly one of result or error",
};

defs.envelope = {
  type: "object",
  additionalProperties: false,
  properties: {
    protocol_major: { type: "integer", const: 1 },
    protocol_minor: { type: "integer", const: 0 },
    request_id: uuidSchema,
    kind: { type: "string", enum: ["request", "response", "event"] },
    method: { type: "string", description: "snake_case method or event name; must agree with kind and body" },
    body: {
      description: "typed body selected by kind+method (see body map below); never raw dispatch JSON",
      type: "object",
    },
  },
  required: ["protocol_major", "protocol_minor", "request_id", "kind", "method", "body"],
};

defs.body_map = {
  description: [
    "kind=request  -> body matches #/$defs/<method>_request;",
    "kind=response -> body matches #/$defs/response_body whose result matches #/$defs/<method>_result;",
    "kind=event    -> body matches #/$defs/<method>_event (method is one of status_changed, activity_changed, conflicts_changed).",
  ].join(" "),
  request_methods: Object.keys(model.REQUESTS).sort(),
  event_methods: Object.keys(model.EVENTS).sort(),
};

const schema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://huggingface.co/hfdrive/spec/ipc-v1.schema.json",
  title: "HF Drive IPC 1.0",
  description: [
    "Normative wire contract for HF Drive provider IPC.",
    "Frame: 4-byte little-endian length (1..=1048576) followed by this envelope as UTF-8 JSON.",
    "Canonical bytes: members in UTF-8 byte-lexicographic key order (typed serializers emit declaration order, which matches for ASCII keys),",
    "compact separators, minimal string escapes (\\\" \\\\ \\b \\t \\n \\f \\r and \\u00xx lowercase for other C0/DEL controls),",
    "u64 fields as canonical decimal strings (no leading zeros, no sign), u32 fields as JSON integers, UUIDs lowercase hyphenated,",
    "optional fields omitted (a JSON null for an optional field decodes as absent and is never emitted),",
    "duplicate member names, unknown members, unknown enum variants, floats, and NaN/Infinity are rejected.",
    "Protocol version is exactly 1.0; only a hello request with another version is parsed (so the provider can answer with supported versions and close).",
    "List pages return items + next_cursor and accept cursor + limit (<= 200).",
    "Every mutation request carries a unique operation_id (operation UUID); reusing it must not duplicate the durable mutation.",
    "prepare_unlink returns a persisted preview identity (preview_id + preview_fingerprint) and an affected_files list producer-bounded at 200 entries; online_only_data_loss signals that proceeding destroys managed-storage-only bytes and unlink then requires accept_online_only_data_loss.",
    "set_publication_credentials carries a user-scoped DPAPI ciphertext envelope; raw key/secret bytes never appear on the wire and this envelope is never logged.",
  ].join(" "),
  $defs: defs,
};

// ---------------------------------------------------------------------------
// Write artifacts + index.
// ---------------------------------------------------------------------------

fs.mkdirSync(path.join(FIXTURES, "golden"), { recursive: true });
fs.mkdirSync(path.join(FIXTURES, "invalid"), { recursive: true });

for (const item of goldens) {
  fs.writeFileSync(path.join(FIXTURES, "golden", `${item.name}.json`), JSON.stringify(item, null, 2) + "\n");
}
for (const item of invalids) {
  fs.writeFileSync(path.join(FIXTURES, "invalid", `${item.name}.json`), JSON.stringify(item, null, 2) + "\n");
}

const index = {
  description: "Cross-language golden frames for HF Drive IPC 1.0. Both the Rust and the C# codecs MUST parse each golden fixture and reproduce payload bytes byte-for-byte from the typed model, and MUST reject each invalid fixture with the listed error code.",
  canonical_rules: "see spec/ipc-v1.schema.json description",
  golden: goldens.map((g) => ({
    name: g.name, file: `golden/${g.name}.json`, description: g.description, expectation: g.expectation,
  })),
  invalid: invalids.map((i) => ({
    name: i.name, file: `invalid/${i.name}.json`, stage: i.stage,
    error_code: i.expectation.error_code, description: i.description,
  })),
};
fs.writeFileSync(path.join(FIXTURES, "index.json"), JSON.stringify(index, null, 2) + "\n");
fs.mkdirSync(SPEC, { recursive: true });
fs.writeFileSync(path.join(SPEC, "ipc-v1.schema.json"), JSON.stringify(schema, null, 2) + "\n");

console.log(`wrote ${goldens.length} golden + ${invalids.length} invalid fixtures and spec/ipc-v1.schema.json`);

// Cross-language DPAPI entropy vectors catch UUID mixed-endian and Unicode drift.
const protectionContext = sampleObject("publication_protection_context");
const protectionVectors = [
  { context: protectionContext, operation_id: "00112233-4455-4677-8899-aabbccddeeff" },
  { context: { ...protectionContext, prefix: "hfdrive/é/測試" }, operation_id: "ffeeddcc-bbaa-4988-8776-554433221100" },
].map((value) => ({
  ...value,
  entropy: Array.from(require("crypto").createHash("sha256")
    .update(canonicalValue(value.context), "utf8")
    .update(Buffer.from(value.operation_id.replaceAll("-", ""), "hex")).digest()),
}));
fs.writeFileSync(path.join(FIXTURES, "publication-protection.json"),
  JSON.stringify({ vectors: protectionVectors }, null, 2) + "\n");
