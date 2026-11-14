# HF Drive — package lifecycle

Install, startup, upgrade, unlink and removal semantics for the per-user HF Drive
MSIX. Everything here is implemented by `scripts/upgrade.ps1`,
`scripts/install-dev.ps1`, `scripts/verify-lifecycle.ps1` and the provider/CLI
hooks listed at the end. Verification status uses `passed` / `failed` / `not_run`
with named blockers; nothing below claims a run that did not happen.

## Identities that must remain stable

Package name `HFDrive`, package publisher (development `CN=HFDrive Development`,
production the real certificate Subject), application IDs `HFDrive` / `Provider` /
`Cli`, startup task `HFDrive.Provider`, the `hfdrive.exe` alias, the provider GUID
(`f727443d-0db5-4746-a08f-16afb2d2f289`), sync-root IDs
(`HFDrive!<user-SID>!<connection-uuid>`) and the IPC protocol. Changing any of
these after release breaks registration, roots and upgrades.

## Install

`scripts/install-dev.ps1 -Package <msix>` installs the development-signed package
per user after full identity/publisher/signature validation (see
`docs/build-install.md`). State lives at `%LOCALAPPDATA%\HFDrive`, excluded from
MSIX write virtualization (`virtualization:FileSystemWriteVirtualization` +
`unvirtualizedResources`, fine-grained, **no** global opt-out), so state,
snapshots and recovery data physically survive package removal. Ordinary sync
folders live outside package-owned storage and are never virtualized or removed.

## Startup

- The manifest declares `uap5:StartupTask TaskId="HFDrive.Provider" Enabled="false"`:
  the provider does **not** start at logon by default.
- The explicit desktop preference invokes the supported
  `Windows.ApplicationModel.StartupTask` enable flow and reflects
  `DisabledByUser` / `DisabledByPolicy` states back to the user. No Run-key,
  service or scheduled-task workaround is used.
- Tray startup is a separate UI preference and is never required for provider
  operation (the provider runs independently of the desktop UI).
- First UI launch can activate the provider immediately
  (`shell:AppsFolder\<family>!Provider`); closing the UI never stops the provider.

## Upgrade (coordinated, acknowledgment-required)

`scripts/upgrade.ps1 -Package <newer.msix>` implements the approved flow:

1. Validate the new package: identity Name and publisher match the installed
   package exactly, version is **strictly higher** (four-part; downgrades
   refused), Authenticode signature `Valid` and signer = publisher.
2. Require the running provider's **actual** `PrepareUpgrade` acknowledgment —
   never kill-and-pretend:

   ```
   cli\hfdrive.exe provider prepare-upgrade --json
   ```

   Required CLI contract: exit code 0 and exactly one JSON object on stdout:

   ```json
   {"checkpointed": true, "pending_operations": 0}
   ```

   `checkpointed` (bool) must be `true`; `pending_operations` (uint) is the count
   of durably recorded uncertain/pending operations. The provider stops
   scheduling, persists uncertainty/intent, checkpoints and exits as part of this
   acknowledgment. If the handshake fails or `checkpointed` is false, the script
   aborts without installing anything. When no provider process exists there is
   nothing to stop; the handshake is recorded as skipped, not faked.
3. Wait (bounded, default 60 s) for the provider process to exit. A provider that
   acknowledged but did not exit is never force-killed.
4. `Add-AppxPackage` with the higher version.
5. Reactivate the provider by packaged application ID
   (`<package-family>!Provider`) and verify it starts; state migration runs on
   provider start (forward-only, with backup; an old binary refuses a newer
   database).

### Interrupted / forced upgrades

An interruption after the acknowledgment (before/after `Add-AppxPackage`) leaves
durable intent intact: re-running `scripts/upgrade.ps1` completes the swap.
Unexpected OS termination (including task kill) is handled by the provider's
recovery engine — the same machinery as crash recovery — never assumed away.
`scripts/verify-lifecycle.ps1 -Suite Upgrade` exercises the coordinated path and
`-Suite ForcedTermination -ConsentForcedTermination -UpgradePackage <msix>`
exercises abrupt provider kill + interrupted-upgrade recovery (explicit consent).

## Pause vs sign-out vs unlink vs uninstall

These are distinct operations and never substitute for each other:

| Operation | Effect |
| --- | --- |
| Pause | Cancels new background/mutation scheduling; observation and durable intent remain; user-requested reads can continue. |
| Sign-out | Increments the authorization epoch, cancels native/S3 work, removes usable OAuth session secrets, disables stored S3 bindings, keeps local work. Resume requires explicit sign-in + capability checks. |
| Unlink | Removes a single connection's binding/registration after the safe export flow (below). |
| Uninstall | Removes the whole package. Never deletes remote data or external local/state directories. |

## Unlink / disconnect (safe by default)

The CLI (`hfdrive unlink --connection <id> [--accept-preview <id>] [--export-to <dir>]`)
and the typed IPC `PrepareUnlink`/`Unlink` commands implement:

- `PrepareUnlink` counts online-only/partial/dirty/conflict files and required
  export space; the preview must be reviewed and explicitly accepted
  (`--accept-preview <id>`).
- **Safe default**: hydrate/export committed content, preserve every dirty and
  recovered snapshot (recovery area outside sync roots), convert fully resident
  placeholders to normal files, disconnect and unregister
  (`StorageProviderSyncRootManager.Unregister`).
- If unavailable bytes or unsynchronized content cannot be retained/exported,
  unlink is **blocked** and the affected files are listed — never a silent loss.
- The only offline alternative is explicitly labeled
  **“Disconnect, keep registration for recovery”**: binding, registration and
  remote references are retained; online-only bytes cannot open until reconnect.
  This is never reported as completed unlink and never partially unregisters
  hydrated data.

## Uninstall (direct MSIX removal)

- In-app “Remove HF Drive” runs the safe unlink/export flow first, then package
  removal.
- Direct `Remove-AppxPackage` (or Windows Settings removal) cannot be assumed to
  run a cleanup callback. It must never delete remote data or the external state
  directory. Because `%LOCALAPPDATA%\HFDrive` is excluded from write
  virtualization, state/snapshots/recovery **physically persist**; remaining
  placeholders may need reinstall/reconnect. No uninstall action is registered
  that blindly unregisters partial/dirty roots.
- Reinstalling the package adopts the existing state (provider restarts and
  reconciles); nothing is recreated or silently lost.

## Verification

```
pwsh -NoProfile -File scripts/verify-lifecycle.ps1 -Suite Package -Package <msix>
pwsh -NoProfile -File scripts/verify-lifecycle.ps1 -Suite Install -Package <msix>
pwsh -NoProfile -File scripts/verify-lifecycle.ps1 -Suite Startup
pwsh -NoProfile -File scripts/verify-lifecycle.ps1 -Suite Upgrade -UpgradePackage <newer.msix>
pwsh -NoProfile -File scripts/verify-lifecycle.ps1 -Suite ForcedTermination -ConsentForcedTermination [-UpgradePackage <newer.msix>]
pwsh -NoProfile -File scripts/verify-lifecycle.ps1 -Suite Unlink -ConnectionId <uuid> [-ConsentUnlink -PreviewId <uuid>]
pwsh -NoProfile -File scripts/verify-lifecycle.ps1 -Suite Uninstall -ConsentUninstall [-Package <msix>]
```

`-PlanOnly` enumerates every step as `not_run` without executing. Destructive or
terminating steps require explicit consent switches
(`-ConsentUninstall`/`-ConsentForcedTermination`/`-ConsentUnlink`); nothing in
this script trusts certificates or mutates remote storage. Each run writes
`artifacts/acceptance/lifecycle-<timestamp>.json` and `.md` with
`passed`/`failed`/`not_run` per check and exact blockers.

## External gates (not run)

| Gate | Requirement | Status |
| --- | --- | --- |
| Coordinated upgrade with real provider | Installed package + running provider acknowledging `PrepareUpgrade` | `not_run` (no package/provider session in this slice; script implemented) |
| Interrupted upgrade recovery | Same, plus deliberate interruption and re-run | `not_run` |
| Startup enable/disable round trip | Interactive desktop session exercising the supported `StartupTask` API (`DisabledByUser`/`DisabledByPolicy` reflection) | `not_run` (interactive; procedure above) |
| Logon activation | Explicit logoff/logon cycle on a verification account | `not_run` |
| Safe unlink/export | Disposable connection fixtures (dedicated test resources only) | `not_run` (no fixtures) |
| Direct uninstall + preserved state | Real package store; verify `%LOCALAPPDATA%\HFDrive` persistence and no remote mutation | `not_run` |
| Placeholder residue after direct uninstall | Manual observation on a synced folder | `not_run` (documented expected behavior: placeholders may remain until reinstall/reconnect) |
| Two-device / remote acceptance | See `docs/verification.md` | `not_run` (out of this slice's scope) |

## Provider/CLI hooks used (parent-owned)

| Hook | Usage |
| --- | --- |
| `hfdrive provider prepare-upgrade --json` | Required before every coordinated upgrade; must print `{"checkpointed": <bool>, "pending_operations": <uint>}` and exit 0 on acknowledgment. |
| `hfdrive provider exit --confirm` | Explicit provider exit; leaves work/registrations intact (used by UI/CLI, not by upgrade). |
| `hfdrive status --json` | Health/IPC check used by lifecycle verification. |
| `hfdrive unlink --connection <id> --accept-preview <id> --export-to <dir>` | Safe unlink with explicit preview acceptance. |
| Typed IPC `PrepareUpgrade` / `PrepareUnlink` / `Unlink` | Same operations for the desktop UI. |
| AUMID activation `<package-family>!Provider` / `!HFDrive` / `!Cli` | Activation used by install/upgrade/verification scripts. |
