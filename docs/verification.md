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

## Rust 1.100.0 toolchain upgrade

The repository toolchain and workspace minimum Rust version are pinned to
`1.100.0`. The exact named toolchain was installed explicitly; build initialization
still disables automatic toolchain installation.

Passed: default `rustc --version` and `cargo --version` both select `1.100.0`.
Passed: `cargo check --workspace --locked --target x86_64-pc-windows-msvc` in the
pinned Windows build environment, with no warnings or errors.

Cargo 1.100's unused-workspace-dependency lint exposed the unused
`aws-credential-types` workspace declaration. Only that declaration was removed;
S3's transitive dependency remains, and no lockfile regeneration was required.
Earlier Rust 1.99.1 verification records remain historical; tests were not rerun
for this toolchain-only change.

## Probe namespace isolation

The saved failing probe report and its durable setup binding confirmed a namespace
mismatch: native payload/catalog/commit uploads used the managed-drive prefix,
while S3 reads and cleanup addressed `hfdrive-probe/<run-id>/`. This caused both
the missing S3 payload and unavailable ancestry records despite successful
conditional-write checks.

Probes now open a separate native store at the request's run-scoped prefix while
keeping supplemental credentials bound to the original setup. A mismatched native
prefix is rejected before journaling, uploads, or interrupted-run cleanup.

Passed on Rust 1.100.0 in the pinned Windows environment:
`cargo test -p hfdrive-publication --test probe --locked --target x86_64-pc-windows-msvc`
(5 tests) and
`cargo test -p hfdrive-provider --lib --locked --target x86_64-pc-windows-msvc`
(44 tests). The regression protects existing workspace and foreign-run content.
MSVC informational import-library messages remain during linking.

No live probe was rerun and no bucket objects were deleted during investigation.
Older faulty probes may have left native records under the managed prefix; their
S3 cleanup reports do not prove those differently addressed records were removed.

The subsequent user-initiated full probe
`84394b5c-765d-4648-bf24-d38833a446ad` passed all eight checks, including native
upload visibility through S3 and ambiguous-CAS ancestry recovery. Its persisted
report was read from `%LOCALAPPDATA%\HFDrive\capabilities` during the
2026-11-15 Explorer investigation; that investigation did not rerun the probe.
The later disconnected CFAPI root is a separate local lifecycle failure.

## Activity state and tray readiness evidence

Passed: `cargo test -p hfdrive-state --locked --target x86_64-pc-windows-msvc`
on Rust 1.100.0 (40 tests). Coverage includes the account v2-to-v3 migration with
an online v2 backup, preserved rows, durable snapshot/operation bindings,
persisted work errors and transactional error clearing, and bounded
connection-scoped keyset pages that tolerate deleted anchors and sentinel positions.
These checks used temporary state, not the user's database.

Passed: 33 tray-readiness regressions compiling the exact shipped pure evaluator
against protocol DTOs in an isolated .NET 11 test project. Read-only and
remote-device commits may be up to date without a matching local publication;
missing, failed, stale, paged-away or other-drive work blocks celebration.
The temporary project was removed; TRX evidence remains under
`artifacts/tests/tray-readiness-isolated/`.

### Activity wire compatibility

`list_activity` is an additive, typed, read-only IPC query. Its normative model
generates the schema and the two new golden frames; generated fixtures retain
canonical cross-language bytes. The Rust protocol gate passed **31 tests** and
the managed protocol gate passed **70 tests** (including the 33 readiness cases
above), with no failures or skips. Evidence: `artifacts/tests/activity-wire.json`
and `artifacts/tests/tray-protocol/tray-protocol.trx`.

### Setup celebration gate

The built desktop's `SetupViewModel.IsSetupWorking` getter passed ten isolated
checks: accepted writable/browse-only setup, initial synchronization, preview-only
state, disconnected/stale sessions, failed permission/capability, conflicts, and
no drive. Evidence: `artifacts/tests/setup-celebration.json`. No production UI
status was injected. The temporary getter harness and its build output were
removed. A successful connected-root GIF run still requires a configured drive;
the local acceptance account has none.

### Scoped tray issue selection

Seven isolated checks against the compiled operations view model passed:
the requested conflict is selected by its real id rather than row position,
late-page arrival is handled, missing ids never select another row, and later
manual selection is not overwritten after navigation completes. Evidence:
`artifacts/tests/tray-conflict-selection.json`. These checks do not inject state
into the production UI or perform a conflict resolution.

### Final Rust integration

Rust 1.100.0 passed locked, offline `cargo check --workspace --all-targets`
for `x86_64-pc-windows-msvc` with zero warnings/errors. The ignored live-acceptance
adapter now compiles against the current budget, publication, and HEAD APIs;
its explicit consent/ignore gates remain intact and it was not executed.

The relevant suites passed 275 tests: auth 40, protocol 31, provider 89,
publication 49, state 40, and core history/reconciliation 26. One live HF/CFAPI
acceptance test remained ignored. The provider binary built successfully.
Evidence: `artifacts/tests/tray-rust.json` and `tray-all-targets.json`.

The existing durability regression also exposed a real FILETIME display bug:
100-nanosecond ticks were divided as if they were nanoseconds, compressing dates
toward 1970. Whole-second conversion now uses 10,000,000 ticks per second;
`display_timestamps_are_canonical_whole_seconds` passes without changing its
expected date. No live HF writes or root registration ran during these gates.

### Native desktop and tray acceptance

The complete Debug/x64 WinUI solution built with the pinned Build Tools and
Windows SDK; managed protocol/readiness verification passed 70 tests. Evidence:
`artifacts/tests/tray-managed.json` and the retained TRX.

The actual desktop and Shell notification icon passed the native scenario:
CatchingHuggy rendering, compact onboarding, native close-to-tray without process
exit, a real notification-area mouse click opening the bottom-right panel,
hover not opening it, Escape dismissal, reopen, and outside/taskbar dismissal.
The 620-DIP preferred viewport shows the complete SuperHuggy illustration and
setup action; irrelevant pause/resume is absent without configured drives.
Native MSAA activated the real **Exit HF Drive** menu item and the provider
remained running. Evidence: `artifacts/acceptance/huggy-tray-ui.json`,
`tray-exit-ui.json`, and `huggy-desktop.png` / `huggy-tray.png` /
`huggy-tray-reopened.png`. Capture temporarily raised only the test process's
windows and restored their prior topmost flag; no provider data was injected.

The account had no configured drives, so activity/history/issues tabs were
correctly hidden and the all-synced GIF was absent. Positive HF-backed transfer,
history/conflict rows and successful-setup/all-synced animations remain live
fixture gates, not claims made by these screenshots. Their projection,
readiness and targeting rules have the isolated regression evidence above.
No storage probe, remote write or root registration was run. Throwaway UI and
selection/getter harness sources were removed after proof.

## Provider restart and Fluent window chrome

- **passed** — 43 state tests on the pinned Windows x64 toolchain, including
  first-invalidation bookkeeping, repair of a connected connection missing
  event state, and preservation of existing cursor/scan evidence.
  Evidence: `artifacts/tests/provider-reconnect-state.json` and the two
  `provider-reconnect-state*.log` files.
- **passed** — current Debug/x64 WinUI build and 85 managed protocol/view-model
  tests, including tray authorization failures, independent error clearing,
  same-session out-of-order responses, and existing-drive issue navigation.
  Evidence: `artifacts/tests/window-chrome-final-build.log` and
  `artifacts/tests/storage-repair-managed/storage-repair-tray.trx`.
- **passed** — 75 Windows library tests, including exact registered cloud-root
  admission, DOS/extended-path registration adoption, callback path boundaries,
  and empty placeholder completion. Evidence:
  `artifacts/tests/provider-callback-paths-windows.log`.
- **passed** — 83 provider library tests, including startup failure publication,
  watcher-local cancellation, runtime liveness, and resumable paused-error
  status. Evidence: `artifacts/tests/provider-reconnect-provider.log`.
- **passed** — 31 Rust protocol tests, including typed storage-repair request/
  result fixtures, complete method coverage, and credential redaction.
  Evidence: `artifacts/tests/storage-repair-protocol.log`.
- **passed** — actual WinUI setup/tray acceptance with real mouse/keyboard
  input and the native tray menu: 660×760 setup and 400×620 tray have no visible
  nonclient border, use native rounded corners, and keep the provider alive.
  Setup dragging, custom close, preserving setup on reopen, normal caption
  restoration, and tray close/reopen/Escape/deactivation passed. Evidence:
  `artifacts/acceptance/window-fluent-chrome.json`,
  `setup-fluent-chrome.png`, `tray-fluent-chrome.png`, and
  `normal-fluent-restored.png` in that acceptance directory.
- **passed** — the real tray displays the existing connection's authorization
  failures under Issues, not “No sync issues”, and explains that an empty queue
  is blocked. Evidence: `artifacts/acceptance/tray-issues-before-repair.json`
  and the matching screenshot.
- **observed** — the existing registered HF Drive directory carries Windows
  cloud reparse tag `0x9000101a`, not a junction. Its disconnected root identity
  was recorded before recovery; no registration or user files were removed.
- **identified** — the former startup restore-error path held a status-watch
  read guard while taking its write lock, before binding IPC. Root restoration
  also rejected its own registered cloud root. Live recovery and final native
  frame acceptance are separate from the build/test results above.

### Setup folder collision feedback

The user-reported `LocalRootInvalid` message discarded the filesystem rejection
twice: admission replaced it with “root validation failed”, then the protocol
mapping replaced that again. The root admission detail now reaches the UI;
ownership, overlap, NTFS and reparse checks are unchanged.

Passed: the compiled `SetupPage` suggestion method preserves an unused path,
avoids existing directories and files, leaves their content unchanged, and
does not create the proposed folder. The proof used isolated temporary fixtures
and the actual desktop assembly, not a copy of the implementation.
Evidence: `artifacts/acceptance/local-root-suggestion-proof.json` and
`artifacts/tests/local-root-suggestion-build.log`. Throwaway harness sources
were removed. The alternate build output avoided replacing the user's running
desktop.

The subsequent user-initiated full probe
`0e9d4c8c-5c84-401a-afae-874a1550edd5` also passed all eight checks for the same
bucket identity. It was read, not rerun. This does not authorize replacing the
existing connection's registration or assuming that its older supplemental
credentials have the same current authorization.

### Existing root binding recovery

Passed: authenticated provider status and native CFAPI reconnection report
Windows provider status `1`; sync-root file ID `003D00000003D6C3` is unchanged.
No registration, local file or credential was removed. Evidence:
`artifacts/acceptance/provider-binding-restored.json`.

Passed: directory enumeration and actual Explorer navigation to that same
existing root after the callback-path repair. Evidence:
`artifacts/acceptance/existing-root-enumeration.json` and
`artifacts/acceptance/existing-root-explorer.json`. No new workspace, registration
reset, file deletion, or storage probe was used.

Passed: connection-scoped CLI pause/resume restored the original unpaused
intent while preserving its root and workspace. Evidence:
`artifacts/acceptance/existing-drive-scoped-recovery.json`.

The desktop alone launched the exact trusted provider; authenticated status
was available in 5,714 ms and the desktop rendered its signed-in account.
Evidence: `artifacts/acceptance/desktop-provider-autolaunch.json`. The development
provider must be built with `Initialize-HfDriveBuildEnvironment` so the exact
desktop executable is present in its peer allowlist.

The original stored supplemental credentials returned HTTP 403 on S3 reads,
although the native bucket precheck succeeded. Evidence:
`artifacts/acceptance/desktop-autostart.out.log`. Only operation and HTTP status
are logged, never credentials, response bodies, or signed URLs. The read
classification regression passed (`artifacts/tests/publication-denial-diagnostics.log`).

### Existing-connection credential repair

The approved live `repair-storage` operation succeeded against the original
workspace. Target probe `63e24ef4-87ce-4e2a-a4a8-44be2eb0e78a` passed all eight
checks; the connection reports writable capability and no authorization error.
The original root file ID, workspace, configuration, and registration were
preserved. The source setup and protected credential record have unchanged hashes.
Evidence: `artifacts/acceptance/storage-repair-live.log`,
`storage-repair-preservation.json`, and `storage-repair-root-verified.json`.

Focused gates passed: 92 provider library tests, 24 publication library tests,
and three state repair-transaction tests. A further provider regression passed
after reproducing an account commit followed by control-mirror failure: the
adopted protected credential record must survive that partial commit.
Evidence: `artifacts/tests/storage-repair-provider-publication.log`,
`storage-repair-state.log`, and `storage-repair-commit-boundary-after.log`.

Storage checks and directory enumeration do not prove file creation. The first
approved real copy into the empty connected root failed with Windows
`0x80070781` (“The name of the file cannot be resolved by the system”), matching
the user's Explorer report. No user file was altered or reported as uploaded.

### Native copy and notification defects

The populated-directory completion now sends Windows' terminal
`DISABLE_ON_DEMAND_POPULATION` flag after the complete authoritative listing.
The same-root copy then returned successfully without registration changes.
The upload wait exposed a separate loss: no observation, item, or outbox row
was created. Evidence: `artifacts/acceptance/file-copy-native-failure.json`,
`native-population-root-verified.json`, and `file-copy-observation-failure.json`.

The native decoder read each name at byte 14 instead of the documented byte 12,
discarding single-record batches. Ten focused watcher tests passed, including
actual root and nested file creation in an isolated ordinary temporary folder.
The independent wire fixtures cover the flexible-array padding boundary.
Evidence: `artifacts/tests/native-file-observation-windows.log`.

A guarded published-file binding regression also passed: mismatched capture
identity preserves the current file's bytes and leaves it unconverted.
Evidence: `artifacts/tests/published-file-guard-windows.log`.

The provider library gate passed all 100 tests, including startup discovery of
an existing local file, atomic observation/outbox rollback, and quiet-HEAD
observation without falsely advancing Applied or Published.
Evidence: `artifacts/tests/file-sync-recovery-provider.log`.

The committed-payload resume regression passed against an isolated local HTTP
fixture: a durable CAS checkpoint binds the exact payload without rereading or
reingesting the staged source, and a different target is rejected.
Evidence: `artifacts/tests/committed-payload-resume.log`.

The real workspace prefix exposed a second upload defect: binding succeeded,
but `BoundObject::payload_ref` parsed the full bucket key as a relative payload
key. The regression reproduced `InvalidResponse`, then passed with exact
prefix stripping and sibling-prefix rejection.
Evidence: `artifacts/tests/prefixed-payload-reference-before.log` and
`prefixed-payload-reference-after.log`.

Passed: the original 78-byte copied fixture recovered without rewriting after
restart and published commit `85b7f9be-4f4c-401d-ae32-2380091c5957`.
Observed, Published, and Applied converged with no pending, dirty, or conflicted
files. Native Cloud Files tag `0x9000601a` and a post-publication SHA-256 check
confirmed the local placeholder retained the source bytes. Exact-item remote
history reports its real Create under the original root item.
Evidence: `artifacts/acceptance/recovered-file-upload.json`,
`published-file-native-verified.json`, and `file-copy-item-history.log`.

The cleanup attempt exposed historical common-base records being combined into
one namespace: the root item appeared under both the initial and uploaded
commits, producing `InvalidView("duplicate item id")`. Planning now selects the
exact Applied commit in SQL while retaining all historical records.
The focused regression passed with distinct old, Applied, and merely Observed
namespaces, and refuses to borrow a namespace when no Applied commit exists.
Evidence: `artifacts/tests/applied-common-base-selection.log`.

Repeated removal observations then exposed `InconsistentIntent("double delete")`.
Two focused core regressions passed for repeated file deletion, committed
replay, and parent/child subtree removal: one tombstone effect, preserved
provenance, and converged replay without recreation.
Evidence: `artifacts/tests/delete-observation-replay.log`.

Passed: the recovered fixture's real Delete appears in committed history
`93a1f43d-cd9c-470b-93c1-e4d6e4469146`; its own temporary source was removed.
Observed, Published, and Applied converge with zero pending, dirty, or
conflicted files. Native Windows provider status is `1`, the original root
file ID `003D00000003D6C3` is unchanged, and actual Explorer navigation succeeds.
No user file, registration, or original workspace was removed.
Evidence: `artifacts/acceptance/recovered-file-roundtrip.json`,
`file-copy-item-history-after-cleanup.log`, and `file-roundtrip-root-verified.json`.

A second fresh live copy reached `PayloadReady`, then exposed missing
tombstone digests (`InvalidView("file without content binding")`). The resolver
now retains deleted files' bindings and caches by immutable version rather
than item. Its focused regression passed for tombstones and distinct revisions.
Evidence: `artifacts/tests/tombstone-version-digests.log`.

Passed: that fresh 78-byte fixture completed upload
`9ec29ecc-107f-469a-a358-d6a4d93d53c5` and synced deletion
`963053c8-405f-4c2c-8709-9ccd1f45e525`. Post-publication native placeholder
and SHA-256 checks passed; exact-item remote history contains Create and Delete.
All three cursors agree with zero pending, dirty, or conflicted files.
The original native root identity and actual Explorer access remain intact;
both test fixtures and their temporary sources were removed, not user files.
Evidence: `artifacts/acceptance/file-copy-roundtrip.json`,
`fresh-published-file-native-verified.json`, `fresh-file-item-history.log`, and
`final-file-sync-root-verified.json`. The three temporary native QA scripts
were removed after verification.

### Reconciliation refresh generations

Passed: seven migration and eight scan-safety tests. Account schema 5 retains
the committed migration sequence, creates a WAL-consistent pre-migration
backup, and adds a monotonic HEAD-refresh generation. A completed read cannot
acknowledge a newer invalidation, even when polling retained the same opaque
SSE cursor; the pending dispatch survives an actual database close/reopen.
Evidence: `artifacts/tests/reconciliation-state.log`.

This gate used isolated temporary databases, not the registered user drive.

A further focused regression passed for directory-only metadata publication:
with zero pending files, ambiguous publication remains parked before its
durable retry deadline and becomes eligible at that deadline after reopen.
Evidence: `artifacts/tests/reconciliation-directory-deadline.log`.

Passed: 40 provider `sync::` tests, including no idle HEAD reread, durable
invalidation wake-up, pause/resume retention, directory-only dispatch, missing
established HEAD preservation, and refused namespace application. The guarded
application case retains actual local bytes and the old Applied baseline;
replanning keeps one original journal entry instead of replacing its guard.
Evidence: `artifacts/tests/reconciliation-provider.log`.

These are deterministic local-state/temporary-filesystem gates. No readable
bucket projection, arbitrary website-edit import, live migration, or new
two-device acceptance is claimed by this change.

## Fluent desktop settings — 2026-11-16

- **passed** — Debug/x64 desktop solution build with locked restore, the pinned
  Build Tools 2026 MSBuild, .NET SDK 11.0.100, and Windows SDK 28000.
  Evidence: `artifacts/tests/settings-desktop-final-build.log`.
- **passed** — 175 managed regression tests, including 90 exact quantity and
  settings-draft tests. Coverage includes full-width integer round trips,
  fractional-byte rejection, unlimited rates, and preserving a dirty field
  without turning an untouched remotely changed field into a stale overwrite.
  Evidence: `artifacts/tests/settings-managed-final/settings-managed-final.trx`
  and `artifacts/tests/settings-quantities.log`.
- **passed** — actual WinUI settings, account, connections, advanced operations,
  and setup navigation. Native captures cover 1100×820 and 800×720 viewports;
  lower storage fields scroll into view while all three settings actions remain
  visible. The configured caption returns `HTCAPTION`, retains resizing, and
  uses native DWM rounding; setup retains exactly one custom close control.
- **passed** — actual provider-backed load, malformed-input feedback, dirty
  draft preservation on reload, cancel/confirm discard, tray Settings routing,
  close-to-tray and reopening. Live settings stayed at revision 1. No valid
  settings mutation, root reset, registration change, or provider restart was
  requested; existing connection/workspace/bucket/prefix/root/mode bindings
  match their before/after records.

Consolidated evidence: `artifacts/acceptance/settings-rework.json`. Visuals:
`settings-final.png`, `settings-narrow-storage.png`, `settings-account.png`,
`settings-connections.png`, `settings-advanced.png`, and `settings-setup.png`
in that acceptance directory. The temporary native QA script was removed.

Visual inspection covered the current Windows 11 x64 dark theme; other themes,
DPI settings, and packaged installation were not exercised in this change.
C# LSP was unavailable, so diagnostics came from the real build and runtime.
MVVM Toolkit/CsWinRT AOT advisories remain with NativeAOT/trimming disabled.
Optional full-file whitespace verification reported five DTO-initializer layout
diagnostics in `MainViewModel.cs`; those layouts were left untouched.

## HF palette, quiet status, and Mica — 2026-11-16

- **passed** — Debug/x64 desktop build with locked restore; zero errors. The
  existing 96 MVVM Toolkit/CsWinRT AOT advisories remain. Evidence:
  `artifacts/tests/hf-palette-desktop-build.log`.
- **passed** — actual WinUI composition Mica backdrop visible through the
  transparent shell, caption, and navigation. HF content remains opaque:
  sampled card `#0D121E` and input `#0B0F19`. The selected left navigation
  item is rectangular; its corner and interior both sample `#192331`.
- **passed** — clean provider-loaded settings show neither “No unsaved
  changes.” nor “Settings loaded.” A temporary valid draft displayed “You have
  unsaved changes.” and enabled Save; it was never submitted, and the restarted
  UI shows the persisted `Unlimited` value with Save disabled.

Evidence: `artifacts/acceptance/hf-palette.json`,
`hf-palette-settings.json`, and `hf-palette-settings.png`. The temporary UI
verification script was removed. Verification covered the current Windows 11
x64 desktop and theme, not packaged installation or other themes/DPI settings.

## Default Fluent content over Mica — 2026-11-16

- **passed** — Debug/x64 desktop build with locked restore; zero errors. The
  custom settings textbox, button, expander, accent, and navy card overrides
  were removed in favor of native WinUI theme resources. Evidence:
  `artifacts/tests/default-mica-desktop-build.log`.
- **passed** — actual Mica settings window uses neutral default card/input
  surfaces (sampled `#32332E` and `#3F3E3A` on the current desktop), not the
  previous navy `#0D121E`/`#0B0F19`. Square left navigation and Mica remain.
- **passed** — provider values remain loaded (`Upload speed = Unlimited`), Save
  remains disabled without edits, and neither clean-state footer message is
  present. No settings mutation was requested.

Evidence: `artifacts/acceptance/default-mica.json`,
`default-mica-settings.json`, and `default-mica-settings.png`. The temporary
capture script was removed after use.

## Account navigation resource fix — 2026-11-16

- **fixed** — removing the custom primary-button style left five cross-page
  `StaticResource` consumers: two in Account and three in Advanced. Those
  buttons now use WinUI's `AccentButtonStyle`, matching Settings and avoiding
  the runtime missing-resource navigation failure.
- **passed** — Debug/x64 desktop build with locked restore; zero errors.
  Evidence: `artifacts/tests/account-navigation-fix-build.log`.
- **passed** — actual desktop navigation opened Account, Connections, Advanced,
  and returned to Settings without the UI process exiting. Account rendered
  its signed-in identity and storage owners; Advanced rendered its connection,
  conflict, and history controls. Settings still showed the persisted values,
  disabled Save without edits, and no clean-state footer messages.

Evidence: `artifacts/acceptance/account-navigation-fix.json` and the
`account-navigation-*.json`/PNG files in that directory. The provider remained
running and no settings mutation was requested. The temporary UI navigation
script was removed after verification.

## Tray launch, theme scope, and bucket creation — 2026-11-16

- **passed** — final Debug/x64 desktop build with locked restore; zero errors.
  Evidence: `artifacts/tests/tray-launch-theme-creation-build.log`.
- **passed** — launching the desktop left both native windows hidden. The
  provider session started independently of window `Loaded`. The tray panel
  opened with its opaque HF page/header (`#0B0F19`) and Huggy branding; the
  main window did not appear until Open HF Drive was explicitly invoked.
- **passed** — explicit Settings retained default Fluent/Mica content and the
  persisted `Unlimited` values. Add Drive now uses the same default card,
  action, and footer resources rather than its former navy surfaces. The
  existing `drive-private-test` draft and Use an existing HF Drive selection
  were restored without submitting them, then the UI returned to tray-only.
- **fixed** — Create private bucket now requests `manage-repos` before creation
  when that grant is absent, includes the selected organization in re-consent,
  and places creation/consent failures beside the button with scroll-into-view.
  The original provider denial was `PermissionDenied: Storage access was denied`.
- **not_run** — no new re-consent or live bucket creation was attempted during
  verification, so remote creation success is not claimed. No settings or
  remote resources were mutated; the existing provider remained running.

Evidence: `artifacts/acceptance/shell-regression.json` and the
`shell-regression-*.json`/PNG files in that directory. The temporary native UI
script was removed after verification. An optional shell icon-rectangle query
in the QA harness returned `E_INVALIDARG`; it is not used as acceptance evidence.

## Tray profile, playback, and actions — 2026-11-16

- **passed** — desktop solution build with locked restore; zero errors. Managed
  protocol/tray/settings suite: 175/175. Rust IPC protocol: 31/31. Auth:
  48/48, including bearer-only userinfo with no OAuth client ID and subject
  mismatch rejection. Provider/CLI: 127/127 with one authorized-live-CFAPI
  test intentionally ignored. C# LSP and the rustfmt component were unavailable.
- **passed** — the restored account with no `HFDRIVE_OAUTH_CLIENT_ID` received
  its real HF `picture` URL through bounded, subject-validated userinfo. The
  circular profile image renders in the left header slot with Huggy fallback;
  HF Drive is centered with Inter/native-font fallback, and no signed-in text
  remains in the header or body. No bearer token is attached to the image load.
- **passed** — the celebration occupies the former body account line. Frame
  hashes differ during playback and are identical at 10.5 and 11.5 seconds,
  confirming the GIF stopped after its two-play, 9.68-second budget.
- **passed** — Pause/Add/Open have equal heights and alignment (widths differ
  only by one rounded pixel). Add bucket has an HF yellow background and dark
  plus, and opens bucket setup without creating storage or starting consent.
  The app returned to tray-only afterward; provider and settings were unchanged.

Evidence: `artifacts/acceptance/tray-feedback.json`,
`tray-feedback-tray.png`, `tray-feedback-two-play.json`, and the associated
frame/layout captures. Rust builds used an isolated Cargo target because the
original target's proc-macro DLLs were locked; no build artifacts were deleted.
The temporary native QA script was removed after verification.

## Activity tabs and idle confirmation — 2026-11-16

- **passed** — desktop solution build with locked restore and 175/175 managed
  regression tests. Evidence: `artifacts/tests/activity-tabs-desktop-build.log`
  and `activity-tabs-managed-tests.log`.
- **passed** — actual tray presents equal-width Syncing now / Recent activity
  tabs with card content. Syncing shows a green check and “Everything is up to
  date” only for the provider's proven all-synced state. Recent activity
  selection displays real committed history; Issues and footer actions remain
  visible and unchanged.

Evidence: `artifacts/acceptance/activity-tabs.json`,
`activity-tabs-sync.png`, and `activity-tabs-history.png`. No settings or remote
resources were mutated. The temporary tab-verification script was removed.
