# Verification and external gates

Only an executed check with recorded results is evidence. A source implementation, dependency version, fake HTTP fixture, rendered mock status, or successful compile is not evidence of live Hugging Face or Cloud Files behavior.

## Recorded results

- Passed: `pwsh -NoProfile -NonInteractive -Command '. ./scripts/tests/BuildEnvironment.Tests.ps1; Initialize-HfDriveBuildEnvironment | ConvertTo-Json -Depth 8'`. The real selector resolved Build Tools instance `8bd08afc` / `18.12.12405.243`, MSVC `14.52.37025`, Windows SDK `10.0.28000.0` serviced as `10.0.28000.2957`, and .NET SDK `11.0.100`. Its exact-path check now normalizes redundant developer-shell separators without accepting an older SDK.
- Observed: OAuth client ID and production publisher/certificate/timestamp configuration are absent. Packaging tools MakeAppx, MakePri and SignTool are present under SDK 28000. Details: `artifacts/acceptance/prerequisites.json`.
- Passed: 20 Windows adapter unit tests (including DPAPI persistence/atomic replacement and peer-policy rejection), the live authenticated named-pipe round trip, and 5 ownership tests. The pipe test initially created its handle outside a Tokio reactor; its runtime scope was corrected before the successful run.
- Resolved TLS features are recorded in `artifacts/build/tls-features.json`: HF/Xet select `rustls-tls`, reqwest 0.13.5 selects rustls/platform-verifier 0.7.1, and no native-tls/OpenSSL package is selected for Windows. AWS's default graph also includes a legacy rustls 0.21/ring connector alongside rustls 0.23/AWS-LC; it is not a fully deduplicated TLS graph.
- Initial Rust restore installed the named `1.99.1` rustup toolchain even though the preexisting active compiler reported that version. Build initialization now sets process-local `RUSTUP_AUTO_INSTALL=0`; future missing toolchains fail instead of installing automatically.
- Passed: the pinned Rust workspace build, including HF Git revision `473de943` with Xet 1.8.1, AWS-LC and bundled SQLite; full Build Tools MSBuild also compiled the WinUI XAML and CsWin32 surface.
- Observed: the first `dotnet vstest` invocation triggered SDK first-run ASP.NET developer-certificate creation. No certificate-trust command was run. Build initialization now disables that SDK side effect and CLI telemetry for its process.
- Passed: real CLI JSON/human status against the authenticated provider, followed by a second provider launch that joined the existing owner instead of taking another writer lease.
- Passed: 27 Rust protocol tests and 35 C# protocol tests, including byte-identical shared fixtures, invalid-frame codes, request correlation, cancellation and closed-peer handling. Core identity (2), auth epoch/redaction (3), opaque ETag (1) and provider admission (3) checks also passed.
- Passed: the actual WinUI window authenticated the provider and displayed its observed status. Closing the window left the provider reachable through CLI; explicit confirmed provider exit then stopped the host with exit code 0. Evidence: `artifacts/acceptance/desktop-uia.json`, `desktop-smoke.log`, and `desktop-foundation.png`. The throwaway UI script was removed after capture. Its legacy PowerShell process used `RemoteSigned` only for that process; machine/user policy was not changed.
- Passed: provider-session integration tests (3): no shutdown before Hello, foreign-major negotiation followed by close, and status snapshot recovery with exit acknowledgement preceding shutdown.
- Passed: the expanded .NET 11 protocol suite (36 tests), including account/login snapshots, durable setup reservation shapes and cross-language DPAPI entropy vectors covering UUID network byte order and Unicode prefixes. Full Build Tools MSBuild compiled the protocol/test projects; shared generation produced 26 golden and 25 invalid frames. Evidence: `artifacts/tests/protocol/momo-_G33K_2026-11-13_18_09_36_net11.0.trx`. This does not claim live OAuth or setup acceptance.
- Passed: the refined account/owner/login-redaction contract and complete desktop solution build; .NET protocol tests passed 37/37. Evidence: `artifacts/tests/protocol/momo-_G33K_2026-11-13_19_18_57_net11.0.trx`. Subsequent bounded-preview contract work has a separate verification gate.
- Passed: actual C# `PublicationCredentialProtection.CreateRequest` -> Rust `CredentialStore::unprotect`, with independently recomputed canonical context/UUID entropy and exact plaintext comparison. Changed entropy was rejected. Only deterministic fixture inputs were used; ciphertext stayed in process pipes and was never written to logs or artifacts. Throwaway harness sources were removed after this proof. This is DPAPI interoperability evidence, not live S3 authorization.
- No HF transfer or CFAPI acceptance has run. The explicit capability-gate record is `artifacts/capabilities/not-run.json` and `artifacts/capabilities/not-run.md`; it names the missing OAuth registration and authorized disposable HF/S3 fixtures rather than claiming a live probe.
- Integration-segment focused checks passed: 6 remote-watch tests; 6 provider-session tests (including externally pending replay and writer-owned exit); 7 outbox tests (including legacy intent recovery); 6 exact catalog-diff tests; and the canonical OAuth error-code test. Full Rust protocol verification passed 24 unit tests, 4 fixture suites, login redaction and DPAPI protection vectors.
- Locked provider verification passed all 44 library tests, including all 9 scheduler tests, conflict/history/settings, preview/digest/fingerprint, diagnostics archive and remote watch; the 6 session tests also passed again. Locked Windows verification passed all 49 tests, including x64 CFAPI `ParamSize` assertions (40 bytes for data/placeholders, 16 for rename/delete ACKs) and strict range/name handling.
- All 33 state tests passed: generation/outbox, idempotency, migration, partial setup, reopen and scan safety. This includes last-owner worker drop followed immediately by reopen, canonical bytes, forward migration, preservation of rejected databases, and a child process that exits without `close` or `Drop` before the parent verifies an externally pending operation is replayed as `OperationNotReplayable`, not executed again.
- All 40 auth tests passed (protocol/leases, credential redaction, login security, refresh lifecycle and identity restoration). All 35 HF tests passed (wire/event/range cache, native failures and wire budget), including normal EOF, overlapping cache insertion and pending-chunk preservation. All 48 publication tests passed (credentials/transport, ancestry, probe, guarded publication and immutable records).
- Final locked production check passed for `hfdrive-provider`, `hfdrive-cli`, `hfdrive-windows`, `hfdrive-hf`, and `hfdrive-publication` on `x86_64-pc-windows-msvc` with `--locked --offline`. This build includes PreviewConnect/Connect with full-fingerprint freshness validation, evidence-based status, pin/free-space/selective-sync, ProbeStorage, unlink, diagnostics ZIP export and the CLI command surface. Protocol verification passed 24 unit tests, 4 fixture suites, redaction and protection vectors.
- The full desktop solution built with the pinned Build Tools 2026/.NET 11 environment and the managed protocol suite passed 37/37. The build includes the nine-step Setup wizard, Operations page and native tray with stable GUID and Open/Exit actions. UI Automation selected Setup and observed the account section while the process and tray remained alive; evidence: `artifacts/acceptance/desktop-setup-smoke.log`. Operations UI Automation observed settings, connection controls, history and conflicts sections with the process alive; evidence: `artifacts/acceptance/operations-smoke.log`. The session was at the Windows lock screen, so visual screenshot verification was unavailable and no invalid screenshot is retained. No login/storage mutation was triggered.
- Concurrent reconciliation passed all 20 race tests; immutable history/restore passed all 6 tests. File deletion now includes the target itself, and read-only mode emits no remote operations. Core verification also passed 21 library tests, 7 format fixtures, 2 identity tests and 3 storage/range tests.
- Release catalog scale passed: 100,101 items, 4,213 manifest pages / 78,943,779 bytes; one save wrote 7 pages / 112,287 bytes, below the affected-path and 5% bounds. Test time 466.37s. Raw evidence: `artifacts/acceptance/catalog-scale.json`. A debug attempt timed out at 1200s and is not used as acceptance evidence.
- Authorized full 4-GiB local stream passed in 3.70s with a 4-MiB cache budget and correct rolling eviction/retention; no upload was performed. Raw evidence: `artifacts/acceptance/range-scale-4gib.json`.
- `scripts/build.ps1 -Configuration Release -Locked` completed the full Rust workspace and managed solution with 0 errors. Provenance: `artifacts/build/build-provenance-Release.json`. This is build evidence, not package installation or live acceptance.
- Real debug-provider startup, allowlisted CLI `status --json`, and acknowledged provider exit passed with a signed-out account and no connections; evidence: `artifacts/acceptance/cli-status.json`. No OAuth or storage mutation was performed.
- Live OAuth/read/write re-consent and supplemental S3 setup completed for `mfuntowicz/drive-dev`. Native Xet upload/range and conditional publication passed. S3 nevertheless reports native payload and mini-commit records absent after bounded retries, so ancestry recovery and full writable capability are not claimed. Evidence: `artifacts/capabilities/not-run.json`, `artifacts/capabilities/not-run.md`, and the partial report `0adbbc79-9848-429b-b38a-30835249b4df.json` under `%LOCALAPPDATA%\HFDrive\capabilities`.
- The provider uses an explicit 16-MiB Tokio worker stack; the previous default stack overflowed during AWS S3 dispatch. Probe CLI requests have a bounded 180-second window instead of the generic 30-second timeout. Native batch `success: false` is never accepted as complete.
- Authorized real local CFAPI acceptance passed registration, connection, placeholder creation, resident conversion, dirty-content preservation, disconnect and unregister. The test proved extended-path normalization, `CfCloseHandle` ownership and metadata-handle separation. Evidence: `artifacts/acceptance/cfapi-local.json`. No HF network calls were made, so native-HF content acceptance remains separate.
- `git apply -p0 --reverse --check vendor/xet-core/xet-client.patch` passed, confirming that the patch record and all compiled vendored Xet changes agree.
- Static packaging lifecycle regression passed (`scripts/tests/Packaging.Tests.ps1`, 563 manifest tokens). No signing, trust, installation, registration, upgrade or uninstall action was performed.
- These results establish deterministic and locked-build verification only. The 100,000-item release catalog gate passed; the 4-GiB transfer scale scenario and every live HF, Explorer, package, clean-VM, second-device and minimum-OS acceptance gate remain separate and unpassed. Exact blockers are recorded in `artifacts/acceptance/external-gates.json`.

## Required gates

| Gate | Required environment | What constitutes evidence |
| --- | --- | --- |
| Foundation | Pinned Windows x64 build tools | Rust and XAML/CsWin32 build; protocol tests; real mutually authenticated local pipe; actual WinUI surface |
| OAuth | HF Drive's registered public client; user consent | PKCE and explicit device flow; issuer/signature/subject validation; observed scopes, refresh behavior and denial results |
| Storage | Explicit disposable personal/org bucket; separate supplemental keys | Native Xet upload and range bytes; guarded S3 create/replacement; same-ETag single winner; ambiguous-response ancestry recovery |
| Explorer | Local fixed NTFS; actual provider registration | Normal file I/O retrieves native content; byte/range equality; pin/offline/dehydrate/cancel; provider/UI lifetime independence |
| Recovery | Isolated fault-enabled build and disposable drive | Abrupt kills at durable boundaries preserve committed and newer dirty bytes; restart reconciles durable intent |
| Two devices | Two independently installed Windows machines or VMs | Both conflicting byte sequences survive once; identical conflict identities; advancing restore ancestry |
| TLS and proxy | Disposable Windows acceptance VM | Trusted enterprise certificate accepted; untrusted/expired/wrong-host certificates rejected on both connectors; proxy routing measured separately |
| Scale | Explicit storage/transfer-cost consent; required free space | 100,000-item catalog, deterministic 4-GiB payload, actual wire-rate limits, measured page rewrites and resource use |
| Package | Explicit developer signing/trust setup or production signing identity | Signed MSIX verifies, installs and runs on clean machine without preinstalled app runtimes; state survives upgrade/uninstall |
| Minimum OS | Windows 11 22H2 acceptance VM | Actual launch and CFAPI behavior on build 22621, not inference from newer-SDK compilation |

Evidence reports use `passed`, `failed`, or `not_run`; include environment, exact command/scenario, expected versus observed behavior, and named blockers. Do not include tokens, credential envelopes, authorization codes, signed URLs, raw HTTP traces, databases or file contents in diagnostics. Dedicated acceptance fixtures may intentionally contain deterministic public test bytes; they are not user content.

The implementation can proceed without external credentials, but these gates cannot be marked passed on that basis. A failed publication guarantee leaves write sync paused rather than authorizing an alternate writable format.

## Compact WinUI onboarding — 2026-11-14

This replaces the earlier nine-page setup presentation with four stages; the
provider's storage, preview, collision, and initialization gates are unchanged.

- **passed** — Debug x64 desktop build with the pinned .NET 11.0.100, Build Tools
  18.12.12405.243/MSVC 14.52.37025, managed 26100 target, and native SDK 28000.
  Actual XAML and CsWin32 compilation, not a markup-only check. Command/tool
  evidence: `artifacts/acceptance/onboarding-build.json`.
- **passed** — launched the real WinUI window with no configured drives. Observed
  the compact 660 × 760 window at 100% scaling, official Hugging Face graphic,
  Storage-inspired dark theme, four-step progress, no normal navigation shell,
  and a fixed primary action inside the window bounds.
- **passed** — selected personal owner `mfuntowicz` and fixture bucket `drive-dev`
  explicitly from real account/bucket lists. Continue inspected the new managed
  location without writing objects and displayed Folder & access, a suggested
  local folder, access mode, and separate storage-key inputs. Opened the native
  Select Folder dialog, dismissed it through its window automation provider,
  and exercised Back to Bucket. Report: `artifacts/acceptance/onboarding-ui.json`;
  actual captures: `artifacts/acceptance/onboarding-ui.png` and
  `artifacts/acceptance/onboarding-folder-ui.png`.
- **passed** — cold UI startup launched the trusted Debug provider, completed
  authenticated IPC, and obtained a real zero-connection status. The provider
  still answered CLI status after UI exit:
  `artifacts/acceptance/onboarding-provider-lifetime.json`.
- **not_run** — new OAuth consent, Check & review/storage probes, Connect/drive
  registration, live removal of an existing connection, packaged launch, and the
  light/high-contrast/DPI matrix. The UI smoke performed no remote writes and
  registered no root. Existing storage/publication and package gates remain open.

The temporary UI automation and pipe-diagnostic scripts were removed after proof;
the JSON records and actual-window captures remain.

## Rust warning cleanup — 2026-11-14

- Nullable SQLite ID readers are generated only where nullable columns consume
  them. The unused control-row reader and column list were removed; strict
  UUID/blob/null validation and account-local row readers are unchanged.
- Unused private Windows helpers, stored process IDs, placeholder identity
  copies, metadata fields, and callback-interest fields were removed after
  workspace/test consumer checks. Actual PID/token/integrity verification,
  callback identity validation, transfer cancellation, and handle ownership stay
  intact. OS-provided callback transfer keys are still never released.
- Batch `processed` counts remain mandatory and validated against the submitted
  and successful/failed operation counts; only the redundant stored copy was
  removed. Pagination now consumes URLs through `Into<String>`.
- Publication ancestry no longer assigns a discarded completion cursor. The
  coordinator intentionally obtains and validates fresh authorization for each
  ancestry read rather than reusing the walk's initial lease.
- Setup no longer allocates unused full-path collision keys for every local and
  remote view. Parent/name collision grouping and preview validation are unchanged.
- No blanket warning suppressions or dummy consumers were introduced.

Passed: `cargo +1.99.1 check --workspace --locked --target x86_64-pc-windows-msvc`
with the selected v145/SDK 28000 environment, with no compiler warnings.
The Windows identity test fixtures also now construct a real oversized buffer
instead of slicing beyond an array and pass the UUID byte slice without an extra
reference; the unused smoke-test import was removed.
Transfer-planning rejection fixtures now create ranges against their captured
size before checking them against a smaller current EOF; invalid test setup no
longer panics before the planner can reject the request. The native-failure test
binding helper no longer accepts an unused account argument, and the unused
probe-test trait import was removed.

Affected verification passed on the pinned Windows x64 toolchain: 235 distinct
tests across state, Windows, native HF, publication, and provider library targets.
Thirteen existing scale/manual/live CFAPI cases stayed ignored; no live HF writes
or sync-root registration were performed. Initial test-only fixture/compiler
failures were corrected and the affected targets rerun without weakening assertions.
MSVC still emits informational import-library creation output as `linker_messages`
while linking some tests; the workspace `cargo check` itself is warning-free.
