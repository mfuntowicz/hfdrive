# Architecture decisions

## ADR 001 — One state owner

The Rust provider owns synchronization state, OAuth/S3 credentials, network mutation and Windows Cloud Files callbacks. The CLI and WinUI application communicate through authenticated local IPC. UI exit does not terminate the provider. A Windows user has one provider writer across sessions; a mutex alone is insufficient without the state-owner file lock.

Core identities and synchronization rules are platform-independent. Windows adapters own unsafe generated API calls; SDK types stay behind native storage adapters. Client cancellation does not erase accepted durable intent.

Accepted mutation execution belongs to the provider, not an IPC session. A durable request-body digest binds each operation ID to one request; completed operations replay their typed receipt, failed operations require a deliberate new ID, and dispatched external effects stay pending until evidence-based reconciliation. Credential storage, account selection and authorization-epoch admission must agree before native clients can use an account. Provider exit and upgrade close mutation admission, drain accepted work, checkpoint SQLite, then stop only after the reply. Replaying a historical exit receipt never stops a new provider instance.

Owner namespaces for storage operations are resolved from the authenticated `whoami-v2` stable owner IDs. OIDC organization names and role/membership hints are not storage locators or creation authorization. New bucket identities are recorded in the durable setup journal; partial creation and setup outcomes are not silently adopted as an existing drive.

## ADR 002 — Managed namespace, not a raw bucket mount

Explorer presents the HF Drive catalog namespace, not the bucket object listing. Managed immutable payloads, versions, catalog pages and commits live under an explicitly selected prefix. Only conditional replacement of HEAD publishes a change. An ordinary bucket is not silently converted or imported.

Payload transport is native HF/Xet. S3 is the conditional publication channel, not a replacement payload backend. An Xet identifier, application SHA-256 and S3 ETag are distinct types. Retained committed history is not automatically garbage-collected and may incur storage costs.

## ADR 003 — Separate credential authorities

OAuth authenticates the person and authorizes native HF access. The supplemental S3 pair authorizes conditional publication and does not prove the OAuth person's identity. Both are required for writable mode; sign-out disables both paths. Every remote mutation must recheck the account authorization epoch and exact resource binding.

Secrets are protected with current-user DPAPI, outside sync roots, with restrictive filesystem ACLs. S3 input crosses IPC only as a binding-specific DPAPI envelope after mutual process verification. Tokens, credential envelopes, signed URL queries, request bodies and file contents are excluded from diagnostics. Immutable .NET strings cannot be promised reliable erasure.

## ADR 004 — Pinned Windows build stack

Rust 1.100.0 targets MSVC x64. Build Tools 2026's 18.12 line supplies MSVC v145 14.52.37025 and full x64 MSBuild. Native compilation and packaging use Windows SDK 10.0.28000.0. The supported managed API target remains net11.0-windows10.0.26100.0 with projection 10.0.26100.87; minimum OS is Windows 11 22H2 (22621). These version numbers have different purposes. No preview-target validation bypass or fallback to .NET 10/VS2022 is permitted.

The developer shell's `cl.exe` path is checked against the pinned compiler. Global `CC=cl.exe` lets BLAKE3 select its MSVC/MASM sources; target-specific `CC`/`CXX` retain absolute pinned paths. An absolute global `CC` caused BLAKE3 1.8.7 to select GNU assembly under MSVC.

The runtime is self-contained .NET 11.0.0/Windows App SDK 2.6.5. Installed tool versions alone do not prove XAML, package deployment, minimum-OS or clean-machine compatibility; actual acceptance records must state what ran.

## ADR 005 — Rustls transport with Windows trust

Application-owned reqwest clients explicitly select rustls. HF/Xet use rustls-tls; AWS uses its supported default rustls/AWS-LC connector. Reqwest's platform verifier retains Windows certificate-chain/trust verification, not Schannel cipher/protocol policy. AWS's native-root connector does not imply identical chain/revocation behavior. TLS library fixes require rebuilding and releasing the application. AWS-LC includes native code; this is not an all-Rust or FIPS claim.

Do not disable certificate or hostname verification. Proxy routing/authentication and enterprise trust are separate acceptance checks. A disposable VM, not the developer trust store, is used for certificate-policy acceptance.

## ADR 006 — Scope runtime pins to their framework

The .NET 11 SDK applies a global `RuntimeFrameworkVersion` to the shared Windows projection runtime pack as well as .NET. The first real build selected nonexistent `Microsoft.Windows.SDK.NET.Ref 11.0.0` and failed with `NETSDK1112`. Pin `RuntimeFrameworkVersion=11.0.0` on the `Microsoft.NETCore.App` framework reference instead; leave Windows projection selection at `WindowsSdkPackageVersion=10.0.26100.87`. Build/publish commands must not pass a global `/p:RuntimeFrameworkVersion`. The .NET runtime, managed API target and native SDK versions remain unchanged.

## ADR 007 — CFAPI callback context ownership

CFAPI's opaque callback-context pointer is only a registry key, never a pointer Rust dereferences directly. A process-global synchronized registry owns `Arc<CallbackContext>` values. Callback entry clones the Arc under the registry lock before incrementing the in-flight count; disconnect removes the entry only after `CfDisconnectSyncRoot` succeeds and then drains callbacks that already acquired an Arc. A failed disconnect retains the registry entry for process-lifetime safety and allows an explicit retry. Failed connects remove the entry; late callbacks find no entry and return without dereferencing it.

The pump propagates cancellation into all range workers, drains queued requests with terminal statuses, and joins workers rather than aborting them. Every accepted fetch has a disarmable terminal guard. Only the proven last connection owner calls consuming shutdown, and its result reaches the engine; failure is not treated as successful disconnection.

## ADR 008 — Supplemental credential entropy lifetimes

The managed-to-provider credential envelope uses entropy derived from the exact protection context and the request operation UUID. The provider re-encodes the validated whole pair plus context and stores it with entropy derived from the same context and the stable connection UUID. This avoids persisting a request operation ID while keeping restart derivation deterministic. IPC and at-rest DPAPI envelopes are separate artifacts with separate purposes; neither exposes plaintext on the pipe or in diagnostics.

## ADR 009 — Evidence-bearing history and conflicts

Commit ancestry supplies immutable device/time/change records and each commit's catalog supplies the names and parents after those changes. A historical HEAD generation is emitted only when current HEAD or a persisted local candidate proves it; older remote commits may have unknown generation, so the IPC field is optional rather than fabricated. Conflict projection requires the frozen kind tag, both side revisions, deterministic preservation identity for keep-both, and the database detection timestamp. Legacy records lacking those fields fail closed. Keep-local and keep-remote queue fresh content/location or deletion operations; they never rewrite history or mark a label without durable work.
