# HF Drive

HF Drive is a Windows 11 application for synchronizing local folders with Hugging Face Buckets. It combines a Rust Cloud Files API provider and CLI with a WinUI 3 desktop and tray application.

> **Status:** Active development. The deterministic build and test suites pass. Live Hugging Face, signing/installation, second-device, clean-VM, and minimum-OS acceptance remain separate gates; see [Verification](#verification-and-limitations).

## Features

- Explorer placeholders with on-demand hydration, pinning, free-space controls, and selective sync.
- Hugging Face OAuth for personal and organization connections.
- Native Bucket/Xet storage and conditional S3 HEAD publication.
- Durable offline work, crash recovery, multi-device conflict handling, history, and restore.
- Desktop tray, CLI, redacted diagnostics, and per-user MSIX packaging.
- No custom filesystem driver, companion Git repository, or synchronization server.

## Repository layout

| Path | Purpose |
| --- | --- |
| `crates/hfdrive-provider` | Provider composition, scheduling, synchronization, and recovery |
| `crates/hfdrive-windows` | CFAPI, NTFS, secure IPC, ownership, and DPAPI adapters |
| `crates/hfdrive-core` | Immutable catalog, remote format, and reconciliation |
| `crates/hfdrive-state` | SQLite state, durable intent, migrations, and recovery |
| `crates/hfdrive-auth` | OAuth, credential lifecycle, and authorization epochs |
| `crates/hfdrive-hf` | Native Bucket and Xet clients |
| `crates/hfdrive-publication` | Guarded S3 publication and ancestry recovery |
| `crates/hfdrive-cli` | `hfdrive.exe` command-line client |
| `desktop` | WinUI 3 application, protocol models, and managed tests |
| `spec` | IPC and remote-format contracts |
| `scripts` | Pinned build, package, install, and verification commands |

## Prerequisites

- Windows 11 22H2 or later, x64, with local NTFS folders.
- Rust `1.100.0` with the `x86_64-pc-windows-msvc` target.
- .NET SDK `11.0.100`.
- Visual Studio Build Tools 2026 `18.12`, with MSVC v145 `14.52.37025`.
- Windows SDK `10.0.28000.0`.
- PowerShell 7.

The build scripts select the pinned toolchain through `scripts/Initialize-BuildEnvironment.ps1`; they do not fall back to older compilers, SDKs, or runtimes.

## Build

```powershell
git clone git@github.com:mfuntowicz/hfdrive.git
cd hfdrive
pwsh -NoProfile -File scripts/build.ps1 -Configuration Debug -Locked
```

For an optimized build:

```powershell
pwsh -NoProfile -File scripts/build.ps1 -Configuration Release -Locked
```

Lockfiles are committed. Use `-InitializeLocks` only when intentionally creating or updating dependency lockfiles.

## Test

Run the complete Rust workspace, including the CLI and Windows targets:

```powershell
cargo test --workspace --all-targets --locked --offline --target x86_64-pc-windows-msvc
```

Run the managed protocol and view-model tests after building:

```powershell
dotnet test desktop/HfDrive.Protocol.Tests -c Debug --no-build --no-restore -p:Platform=x64
```

Current deterministic verification:

- **770** Rust tests passed, **0 failed**; 15 explicit manual/live tests remained ignored.
- **183** managed tests passed.
- **6** Explorer shell contract tests passed.
- The 100,000-item catalog scale test passed.

See [docs/verification.md](docs/verification.md) for commands, logs, and acceptance records.

## Run

Start the provider in one PowerShell window:

```powershell
cargo run -p hfdrive-provider --target x86_64-pc-windows-msvc
```

Use the CLI in another:

```powershell
cargo run -p hfdrive-cli --target x86_64-pc-windows-msvc -- status
cargo run -p hfdrive-cli --target x86_64-pc-windows-msvc -- status --json
cargo run -p hfdrive-cli --target x86_64-pc-windows-msvc -- login
```

Stop the provider only when intended:

```powershell
cargo run -p hfdrive-cli --target x86_64-pc-windows-msvc -- provider exit --confirm
```

Sign-in uses the application's registered Hugging Face OAuth client. Writable connections also require supplemental S3 credentials entered through the protected setup flow. Never pass secrets as command-line arguments.

## Package and install

Build a development MSIX:

```powershell
pwsh -NoProfile -File scripts/package.ps1 -Configuration Release -Development -Version 0.1.0.0
```

Install it for the current user:

```powershell
pwsh -NoProfile -File scripts/install-dev.ps1 -Package artifacts/package/HFDrive_0.1.0.0_x64.msix
```

Development signing requires a previously created development certificate. Certificate creation and trust are separate, explicit user-authorized steps; packaging and installation never create or trust certificates automatically. Production signing requires a real publisher certificate and timestamp configuration.

## Verification and limitations

The deterministic build and test suites are green. This does **not** claim completion of live external acceptance. The following remain separately gated:

- Live OAuth, Bucket/Xet, and conditional-publication scenarios.
- New CFAPI root registration and Explorer acceptance.
- Signed package installation, clean-VM, and minimum-OS validation.
- Two-device conflict and recovery acceptance.

The ignored tests are explicit manual/live cases, not skipped deterministic failures. Detailed evidence and exact blockers are recorded in [docs/verification.md](docs/verification.md).

## License

HF Drive is available under the [MIT License](LICENSE).
