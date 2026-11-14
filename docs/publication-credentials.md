# Publication credentials and the S3 transport boundary

This document describes the implemented `hfdrive-publication` boundary: what
authorizes it, how the supplemental S3 credential pair is bound and stored, and
which trust behaviors are **not** equivalent to the HF/Xet stack.

## Two separate authorizations

HF Drive publication uses two independent credential paths. Neither can replace
the other.

| | Native authorization | Supplemental publication authorization |
|---|---|---|
| Source | HF OAuth (`hfdrive-auth`) | HF token settings (S3 key/secret pair) |
| Wire form | Bearer access token | AWS SigV4 over the explicit pair |
| Gate in this crate | `AuthorizationLease::check()` + `lease.account() == binding.account_key()` before every dispatch | Exact binding agreement of `SupplementalCredentialRecord` at `S3Transport::bind` |
| Scope | Native resource permissions (`read-repos`, `write-repos`, `manage-repos`) | May cover the **whole bucket**, not just the managed prefix |
| Meaning | Real resource authorization, checked by the provider before every publication transaction | Storage write authorization only |

Consequences enforced by design:

- **An epoch is not resource permission.** The lease gate in this crate only
  proves that the account authorization generation is live and belongs to the
  bound account. The provider MUST verify current native resource
  authorization (and pause on denial/sign-out) before calling this transport.
- The S3 key/secret pair **does not prove the OAuth person's identity**, is
  never accepted as a PAT/OAuth substitute, and its scope may exceed the
  managed prefix. Users generate the pair through HF token settings
  (<https://huggingface.co/docs/hub/storage-buckets-s3>).
- `Writable` capability requires all of: current native resource
  authorization, exact binding agreement, this supplemental authorization, and
  successful probe evidence. Denial or sign-out on either path stops both.

## Credential record

`SupplementalCredentialRecord` is the whole-pair plaintext payload the provider
protects with user-scoped DPAPI (never `CRYPTPROTECT_LOCAL_MACHINE`). Its JSON
shape (serde, `deny_unknown_fields`) is:

```json
{
  "context": {
    "connection_id": "…uuid…",
    "account_key": "…64 lowercase hex…",
    "issuer": "https://huggingface.co",
    "subject": "…",
    "owner_id": "…",
    "owner_kind": "personal",
    "bucket_id": "…",
    "workspace_id": "…uuid…",
    "prefix": "hfdrive/…"
  },
  "key_id": "…",
  "secret_key": "…"
}
```

Rules:

- `encode()` returns zeroizing bytes (the DPAPI plaintext); `decode()` parses
  and re-validates. There is no other serialization path for the pair.
- `Debug` redacts both pair fields; `key_id`/`secret_key` accessors are
  crate-internal, so no IPC, status, or diagnostics path can read the pair.
- Entropy is composed by the provider as
  `hfdrive_protocol::PublicationProtectionContext::entropy(operation_id)`
  (canonical context bytes || operation UUID RFC/network-order bytes). This
  crate never derives entropy and holds no second JSON convention.
- The provider validates the exact expected context
  (`SupplementalCredentialRecord::validate_context`, including `connection_id`)
  before constructing the pair. The plaintext pair and `key_id` never cross
  the IPC boundary; only base64 DPAPI ciphertext does.

## Binding agreement

`PublicationBinding` retains the immutable identity — issuer, subject, account
key (`sha256(issuer || 0x00 || subject)`), stable owner and bucket identities,
owner kind, workspace, managed prefix — plus display locators (verified
namespace, bare bucket name) used only to address the endpoint. A rename of the
namespace or bucket never changes identity.

`S3Transport::bind` requires:

1. `DriveBinding.account_key == AccountKey::from_subject(issuer, subject)`;
2. exact stable-field agreement between the binding and the credential record's
   context (issuer, subject, account key, owner, bucket, workspace, prefix).

`connection_id` is deliberately absent from the stored transport binding; the
provider owns it in the protection context.

## Transport configuration (fixed)

- Endpoint: `https://<canonical-namespace>.s3.hf.co` (namespace = verified
  owner namespace; safe as one DNS component).
- Bare bucket name with **path-style** addressing; signing region `us-east-1`.
- Request and response checksums `WhenRequired`.
- `BehaviorVersion::latest()`, AWS SDK **supported default connector**
  (rustls/AWS-LC); no Schannel connector, TLS fork, or runtime backend switch.
- Explicit stored credentials only — never ambient AWS credential discovery
  (no environment, profile, or instance metadata chain).
- **One dispatch attempt per call.** Automatic retries are disabled
  (`RetryConfig::disabled`), so no blind PUT retry can double-apply anything.
- Signed requests never follow redirects; any 3xx answer classifies as
  `InvalidResponse` and is never re-dispatched to the `Location` target.

## Conditional write and outcome semantics

Only two key zones are writable through this transport: the managed `HEAD`
(`<prefix>/HEAD`) and owned probe records (`hfdrive-probe/<run-id>/<name>`).
Immutable versions/catalog/commits and payload objects are produced through the
native Xet path; this transport can only read them back (bounded) for ancestry
and coherence.

- Create: exactly one `If-None-Match: *`.
- Replace: exactly one `If-Match` with the preserved strong ETag.
- Outcomes: `Committed`, `PreconditionFailed`, `Ambiguous`.
- Errors stay distinct: `Absent` (404), `PermissionDenied` (401/403),
  `Transport` (definite transport/5xx failure), `InvalidResponse` (3xx/other
  unexplained answers), `RecordTooLarge`, `KeyOutOfScope`, `NeedsSignIn`,
  `BindingMismatch`.
- `Ambiguous` is returned whenever a dispatched mutation produced no usable
  verdict: timeout, dispatch failure, unparseable response, or cancellation
  after dispatch began. The caller must search committed ancestry for the
  persisted operation/commit before attempting any further CAS; it must never
  replay a stale whole catalog or report the operation as rolled back. A
  cancellation before dispatch is a plain `Cancelled` error (nothing was sent).
- Reads never report `Ambiguous`; one bounded GET returns the body together
  with the ETag preserved from that same response.

## ETag validator

`OpaqueEtag` accepts exactly one strong quoted tag (`"..."`, RFC 9110 `etagc`
octets). Wildcards (`*`), lists (`"a", "b"`), weak tags (`W/"…"`), unquoted
values and control octets are rejected, so a validator can never broaden a
conditional request or inject header content.

## Bounds

| Record | Bound |
|---|---|
| Managed `HEAD` | 16 KiB |
| Immutable version record | 16 KiB |
| Immutable catalog page | 256 KiB |
| Immutable commit record | 1 MiB |
| Probe record | 16 KiB |
| Probe verification read | 64 MiB |

## Owned probe cleanup

The probe namespace `hfdrive-probe/<run-id>/` is created only by an explicit
setup/CLI action. Keys are validated bucket-relative names (nested paths such
as `objects/<upload-uuid>` are allowed; traversal and reserved octets are not).
`ProbeNamespace::delete_owned` deletes exactly the recorded keys of the same
run — there is no listing API, no prefix delete, and no general remote garbage
collection. Deletion is idempotent, so a cancelled cleanup converges by
re-running the same recorded list.

## Trust and proxy behavior is not equivalent across the two HTTP stacks

The AWS connector and the HF/Xet (`reqwest`) connector are different stacks
(verified in the pinned `aws-sdk-s3 1.159.0` / `aws-smithy-runtime 1.16.3` /
`aws-smithy-http-client 1.5.2` sources):

- AWS: the SDK's supported default connector is a hyper 1.x client with
  rustls/AWS-LC (`rustls_provider::CryptoMode::AwsLc`). It imports the OS root
  store through `rustls-native-certs` and verifies with rustls/webpki — it does
  **not** perform Windows chain building or revocation checking. With
  `BehaviorVersion::latest()` it resolves proxies from environment variables
  (`ProxyConfig::from_env()`).
- HF/Xet: `reqwest` 0.13 with `rustls-platform-verifier` delegates certificate
  chain and revocation checking to Windows, plus `system-proxy` discovery from
  Windows settings (not just environment variables).

Therefore enterprise trust anchors, certificate chain/revocation behavior, and
proxy routing can differ between the two stacks on the same machine. A failure
must be reported against the stack that produced it and must never be "fixed"
by disabling certificate or hostname validation. Proxy misrouting is not a TLS
backend issue; neither stack may silently fall back to a different TLS backend.

The workspace's default `aws-sdk-s3` feature set also compiles the legacy
hyper 0.14/rustls 0.21/ring connector (`rustls` feature); with
`default-https-client` enabled the runtime selects the rustls/AWS-LC default
connector above and the legacy stack stays unused.

## What this crate does not do

- No OAuth, no token storage, no native resource authorization (provider owns
  those; the lease gate here is deliberately only an epoch/account check).
- No payload or immutable-metadata writes (native Xet path owns them).
- No ambient credential discovery, no environment/PAT/argv credential input.
- No plaintext `key_id` or secret on IPC, logs, status, or diagnostics.
